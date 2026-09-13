package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/castracloud/castracloud/internal/risk"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		_ = json.Unmarshal([]byte(v), &limit)
	}
	findings, err := s.db.ListFindings(r.Context(), tenant, q.Get("severity"), q.Get("status"), limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, findings)
}

// handleSummary returns posture score and severity/status counts for the tenant.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	sum, err := s.db.FindingSummary(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	score := 100 - (sum.Critical*10 + sum.High*5 + sum.Medium*2 + sum.Low*1)
	if score < 0 {
		score = 0
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"posture_score": score,
		"total":         sum.Total,
		"open":          sum.Open,
		"resolved":      sum.Resolved,
		"suppressed":    sum.Suppressed,
		"by_severity": map[string]int{
			"critical": sum.Critical,
			"high":     sum.High,
			"medium":   sum.Medium,
			"low":      sum.Low,
			"info":     sum.Info,
		},
	})
}

type ingestRequest struct {
	TenantID  string          `json:"tenant_id"`
	Provider  string          `json:"provider"`
	ScannedAt time.Time       `json:"scanned_at"`
	Findings  []ingestFinding `json:"findings"`
}

type ingestFinding struct {
	RuleID       string            `json:"rule_id"`
	Title        string            `json:"title"`
	Severity     string            `json:"severity"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ResourceName string            `json:"resource_name"`
	Region       string            `json:"region"`
	Details      map[string]string `json:"details"`
}

func (s *Server) handleIngestFindings(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var req ingestRequest
	if err := parseBody(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.TenantID != "" {
		if id, err := uuid.Parse(req.TenantID); err == nil {
			tenant = id
		}
	}

	ingested := 0
	var saved []store.Finding
	for _, f := range req.Findings {
		sf := &store.Finding{
			TenantID:    tenant,
			Source:      "cspm",
			RuleID:      f.RuleID,
			Title:       f.Title,
			Severity:    f.Severity,
			Status:      "open",
			Description: f.Description,
			Remediation: f.Remediation,
			RiskScore:   risk.SeverityScore(f.Severity),
		}
		if sf.Severity == "" {
			sf.Severity = "medium"
			sf.RiskScore = risk.SeverityScore(sf.Severity)
		}

		if f.ResourceType != "" && f.ResourceID != "" {
			props := make(map[string]any, len(f.Details))
			for k, v := range f.Details {
				props[k] = v
			}
			asset := &store.Asset{
				TenantID:   tenant,
				Provider:   req.Provider,
				AssetType:  f.ResourceType,
				ExternalID: f.ResourceID,
				Region:     f.Region,
				Name:       f.ResourceName,
				Properties: props,
			}
			if asset.Name == "" {
				asset.Name = f.ResourceID
			}
			if asset.Properties == nil {
				asset.Properties = map[string]any{}
			}
			if err := s.db.UpsertAsset(r.Context(), asset); err != nil {
				s.log.Error("asset upsert failed", "error", err)
			} else {
				sf.AssetID = asset.ID
			}
		}

		if err := s.db.IngestFinding(r.Context(), sf); err != nil {
			s.log.Error("ingest finding failed", "error", err)
			continue
		}
		saved = append(saved, *sf)
		ingested++
	}

	if len(saved) > 0 {
		s.dispatchFindings(r.Context(), tenant, req.Provider, saved)
	}
	s.audit(r.Context(), "findings.ingest", "findings", map[string]any{"provider": req.Provider, "count": ingested})
	s.writeJSON(w, http.StatusCreated, map[string]int{"ingested": ingested})
}

func (s *Server) handleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.db.UpdateFindingStatus(r.Context(), tenant, id, body.Status); err != nil {
		if err == store.ErrNotFound {
			s.writeError(w, http.StatusNotFound, err)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r.Context(), "finding.update", id.String(), map[string]any{"status": body.Status})
	s.writeJSON(w, http.StatusOK, map[string]string{"status": body.Status})
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	assets, err := s.db.ListAssets(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, assets)
}

func (s *Server) handleListWAFRules(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	rules, err := s.db.ListWAFRules(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleCreateWAFRule(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var body struct {
		Name     string `json:"name"`
		Phase    string `json:"phase"`
		Action   string `json:"action"`
		Match    string `json:"match"`
		Enabled  *bool  `json:"enabled"`
		Priority int    `json:"priority"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if body.Phase == "" {
		body.Phase = "request"
	}
	if body.Action == "" {
		body.Action = "block"
	}
	rule := &store.WAFRule{
		TenantID: tenant,
		Name:     body.Name,
		Phase:    body.Phase,
		Action:   body.Action,
		Match:    body.Match,
		Enabled:  enabled,
		Priority: body.Priority,
	}
	if err := s.db.CreateWAFRule(r.Context(), rule); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleDeleteWAFRule(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.db.DeleteWAFRule(r.Context(), tenant, id); err != nil {
		if err == store.ErrNotFound {
			s.writeError(w, http.StatusNotFound, err)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"deleted": id.String()})
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	domains, err := s.db.ListDomains(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, domains)
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var body struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Provider == "" {
		body.Provider = "route53"
	}
	d := &store.Domain{TenantID: tenant, Name: body.Name, Provider: body.Provider}
	if err := s.db.CreateDomain(r.Context(), d); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r.Context(), "domain.create", d.Name, map[string]any{"provider": d.Provider})
	s.writeJSON(w, http.StatusCreated, d)
}

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	domainID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	records, err := s.db.ListDNSRecords(r.Context(), domainID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, records)
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	domainID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	var body struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
		TTL   int    `json:"ttl"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	rec := &store.DNSRecord{
		DomainID: domainID,
		Type:     body.Type,
		Name:     body.Name,
		Value:    body.Value,
		TTL:      body.TTL,
	}
	if rec.TTL == 0 {
		rec.TTL = 300
	}
	if err := s.db.CreateDNSRecord(r.Context(), rec); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, rec)
}
