package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/castracloud/castracloud/internal/ai"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

func (s *Server) resolveAIClient(r *http.Request) (*ai.Client, error) {
	key := r.Header.Get("X-AI-API-Key")
	baseURL := r.Header.Get("X-AI-Base-URL")
	model := r.Header.Get("X-AI-Model")
	provider := r.Header.Get("X-AI-Provider")

	if key != "" {
		return ai.New(ai.Config{
			APIKey:   key,
			BaseURL:  baseURL,
			Model:    model,
			Provider: provider,
		})
	}
	if s.ai != nil {
		return s.ai, nil
	}
	return nil, errors.New("ai: no API key configured. Enter your API key in the settings above or set AI_API_KEY")
}

// handleAIAnalyze explains a finding using the configured LLM.
func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	client, err := s.resolveAIClient(r)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, err)
		return
	}

	var body struct {
		FindingID   string `json:"finding_id"`
		RuleID      string `json:"rule_id"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Source      string `json:"source"`
		Description string `json:"description"`
		Remediation string `json:"remediation"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	var f store.Finding
	if body.FindingID != "" && s.db != nil {
		id, parseErr := uuid.Parse(body.FindingID)
		if parseErr != nil {
			s.writeError(w, http.StatusBadRequest, parseErr)
			return
		}
		finding, dbErr := s.db.GetFinding(r.Context(), tenantFrom(r.Context()), id)
		if dbErr == store.ErrNotFound {
			s.writeError(w, http.StatusNotFound, nil)
			return
		}
		if dbErr == nil && finding != nil {
			f = *finding
		}
	}
	if f.RuleID == "" {
		f = store.Finding{
			RuleID:      body.RuleID,
			Title:       body.Title,
			Severity:    body.Severity,
			Source:      body.Source,
			Description: body.Description,
			Remediation: body.Remediation,
		}
		if f.Severity == "" {
			f.Severity = "medium"
		}
	}

	system, user := ai.AnalyzeFindingPrompt(f)
	out, chatErr := client.Chat(r.Context(), system, user)
	if chatErr != nil {
		s.writeError(w, http.StatusBadGateway, chatErr)
		return
	}
	s.audit(r.Context(), "ai.analyze", f.RuleID, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]string{"analysis": out})
}

// chatTurn is a single message in the assistant conversation.
type chatTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatAssistantSystemPrompt is the default persona for the security co-pilot.
const chatAssistantSystemPrompt = `You are CastraCloud Security Assistant, an expert cloud security co-pilot.
You help operators triage cloud misconfigurations, vulnerabilities, attack paths, and compliance gaps across AWS, GCP, and Azure.
You are given the tenant's current open findings as live context below; use it to answer questions about their posture and to triage results directly.
Be concise, specific, and actionable. Use markdown for structure (headings, lists, short code spans) but keep prose tight.
When asked about remediation, give step-by-step guidance with the affected resource.`

// findingsContext builds a compact summary of the tenant's open findings so the
// assistant can reference live scan results without the operator pasting them.
func (s *Server) findingsContext(ctx context.Context) (string, bool) {
	findings, err := s.db.ListFindings(ctx, tenantFrom(ctx), "", "open", 100)
	if err != nil || len(findings) == 0 {
		return "", false
	}

	counts := make(map[string]int, len(findings))
	for _, f := range findings {
		counts[f.Severity]++
	}

	var b strings.Builder
	b.WriteString("Current open findings in this tenant:\n")
	b.WriteString("- Totals by severity: ")
	parts := make([]string, 0, 5)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\n- Findings:\n")
	for i, f := range findings {
		if i >= 25 {
			b.WriteString(fmt.Sprintf("  - ... and %d more\n", len(findings)-25))
			break
		}
		b.WriteString(fmt.Sprintf("  - [%s] %s (%s)\n", f.Severity, f.Title, f.RuleID))
	}
	return b.String(), true
}

// handleAIChat answers a multi-turn conversation using the configured LLM.
func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	client, err := s.resolveAIClient(r)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, err)
		return
	}

	var body struct {
		System   string     `json:"system"`
		Messages []chatTurn `json:"messages"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(body.Messages) == 0 {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if len(body.Messages) > 50 {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	system := body.System
	if system == "" {
		system = chatAssistantSystemPrompt
	}
	if s.db != nil {
		if ctxBlock, ok := s.findingsContext(r.Context()); ok {
			system = system + "\n\nLive data:\n" + ctxBlock
		}
	}

	history := make([]ai.Message, 0, len(body.Messages))
	for _, m := range body.Messages {
		history = append(history, ai.Message{Role: m.Role, Content: m.Content})
	}

	out, chatErr := client.ChatMessages(r.Context(), system, history)
	if chatErr != nil {
		s.writeError(w, http.StatusBadGateway, chatErr)
		return
	}
	s.audit(r.Context(), "ai.chat", "conversation", map[string]any{"turns": len(history)})
	s.writeJSON(w, http.StatusOK, map[string]string{"reply": out})
}

// handleAISummary produces a threat brief over the tenant's open findings.
func (s *Server) handleAISummary(w http.ResponseWriter, r *http.Request) {
	client, err := s.resolveAIClient(r)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, err)
		return
	}

	var findings []store.Finding
	if s.db != nil {
		fList, listErr := s.db.ListFindings(r.Context(), tenantFrom(r.Context()), "", "open", 100)
		if listErr != nil {
			s.writeError(w, http.StatusInternalServerError, listErr)
			return
		}
		findings = fList
	}
	if len(findings) == 0 {
		s.writeJSON(w, http.StatusOK, map[string]string{"summary": "No open findings to summarize."})
		return
	}

	system, user := ai.SummarizeFindingsPrompt(findings)
	out, chatErr := client.Chat(r.Context(), system, user)
	if chatErr != nil {
		s.writeError(w, http.StatusBadGateway, chatErr)
		return
	}
	s.audit(r.Context(), "ai.summary", "findings", map[string]any{"count": len(findings)})
	s.writeJSON(w, http.StatusOK, map[string]string{"summary": out})
}
