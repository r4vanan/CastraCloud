package api

import (
	"fmt"
	"net/http"

	"github.com/castracloud/castracloud/internal/risk"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/castracloud/castracloud/internal/vuln"
	"github.com/google/uuid"
)

type vulnScanRequest struct {
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	ResourceName string         `json:"resource_name"`
	Region       string         `json:"region"`
	Packages     []vuln.Package `json:"packages"`
}

// handleVulnScan evaluates a workload's packages against the CVE database and
// ingests any matches as findings.
func (s *Server) handleVulnScan(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var req vulnScanRequest
	if err := parseBody(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	results := vuln.Scan(req.Packages)

	var assetID uuid.UUID
	if req.ResourceType != "" && req.ResourceID != "" {
		asset := &store.Asset{
			TenantID:   tenant,
			Provider:   "workload",
			AssetType:  req.ResourceType,
			ExternalID: req.ResourceID,
			Region:     req.Region,
			Name:       req.ResourceName,
			Properties: map[string]any{},
		}
		if asset.Name == "" {
			asset.Name = req.ResourceID
		}
		if err := s.db.UpsertAsset(r.Context(), asset); err != nil {
			s.log.Error("asset upsert failed", "error", err)
		} else {
			assetID = asset.ID
		}
	}

	var saved []store.Finding
	for _, res := range results {
		f := &store.Finding{
			TenantID:    tenant,
			Source:      "vuln",
			RuleID:      res.CVE,
			Title:       res.Title,
			Severity:    res.Severity,
			Status:      "open",
			Description: fmt.Sprintf("%s@%s is affected by %s (fixed in %s).", res.Package, res.Installed, res.CVE, res.Fixed),
			Remediation: fmt.Sprintf("Upgrade %s to %s or later.", res.Package, res.Fixed),
			RiskScore:   risk.SeverityScore(res.Severity),
		}
		if assetID != uuid.Nil {
			f.AssetID = assetID
		}
		if inserted, err := s.db.IngestFinding(r.Context(), f); err != nil {
			s.log.Error("vuln finding ingest failed", "error", err)
			continue
		} else if !inserted {
			continue
		}
		saved = append(saved, *f)
	}

	if len(saved) > 0 {
		s.dispatchFindings(r.Context(), tenant, "workload", saved)
	}
	s.audit(r.Context(), "vulns.scan", req.ResourceName, map[string]any{
		"packages": len(req.Packages), "vulnerabilities": len(results),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"scanned":         len(req.Packages),
		"vulnerabilities": len(results),
		"results":         results,
	})
}
