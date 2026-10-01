package api

import (
	"encoding/json"
	"net/http"
	"strconv"
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

// handleSummaryTrend returns the findings-detected-per-day series.
func (s *Server) handleSummaryTrend(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	trend, err := s.db.FindingTrend(r.Context(), tenant, days)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, trend)
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

		inserted, err := s.db.IngestFinding(r.Context(), sf)
		if err != nil {
			s.log.Error("ingest finding failed", "error", err)
			continue
		}
		if !inserted {
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
