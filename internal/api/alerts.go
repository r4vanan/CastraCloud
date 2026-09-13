package api

import (
	"context"
	"net/http"

	"github.com/castracloud/castracloud/internal/notify"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// dispatchFindings sends notifications to a tenant's enabled alert channels.
func (s *Server) dispatchFindings(ctx context.Context, tenantID uuid.UUID, provider string, findings []store.Finding) {
	channels, err := s.db.ListAlertChannels(ctx, tenantID)
	if err != nil || len(channels) == 0 {
		return
	}

	msg := notify.Message{
		Event:    "finding.new",
		TenantID: tenantID.String(),
		Provider: provider,
		Count:    len(findings),
		Findings: make([]notify.Finding, 0, len(findings)),
	}
	for _, f := range findings {
		msg.Findings = append(msg.Findings, notify.Finding{
			RuleID:      f.RuleID,
			Title:       f.Title,
			Severity:    f.Severity,
			Provider:    provider,
			RiskScore:   f.RiskScore,
			Description: f.Description,
		})
	}

	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		n, err := notify.New(ch.Type, ch.Config)
		if err != nil {
			s.log.Error("alert channel build failed", "channel", ch.Name, "error", err)
			continue
		}
		if err := n.Send(ctx, msg); err != nil {
			s.log.Error("alert send failed", "channel", ch.Name, "error", err)
		}
	}
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	channels, err := s.db.ListAlertChannels(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, channels)
}

func (s *Server) handleCreateAlert(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var body struct {
		Name    string         `json:"name"`
		Type    string         `json:"type"`
		Config  map[string]any `json:"config"`
		Enabled *bool          `json:"enabled"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Name == "" || body.Type == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if _, err := notify.New(body.Type, body.Config); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	ch := &store.AlertChannel{
		TenantID: tenant,
		Name:     body.Name,
		Type:     body.Type,
		Config:   body.Config,
		Enabled:  enabled,
	}
	if err := s.db.CreateAlertChannel(r.Context(), ch); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r.Context(), "alerts.create", "alerts", map[string]any{"name": ch.Name, "type": ch.Type})
	s.writeJSON(w, http.StatusCreated, ch)
}

func (s *Server) handleDeleteAlert(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.db.DeleteAlertChannel(r.Context(), tenant, id); err != nil {
		if err == store.ErrNotFound {
			s.writeError(w, http.StatusNotFound, err)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"deleted": id.String()})
}
