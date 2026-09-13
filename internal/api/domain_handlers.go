package api

import (
	"net/http"
	"time"

	"github.com/castracloud/castracloud/internal/domain"
	"github.com/castracloud/castracloud/internal/risk"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// domain finding rule IDs.
const (
	ruleTakeover     = "CASTRA-DOM-001"
	ruleCertExpiry   = "CASTRA-DOM-002"
	ruleShadowIT     = "CASTRA-DOM-003"
	ruleDNSDrift     = "CASTRA-DOM-004"
)

func (s *Server) handleListSubdomains(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	domainID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := s.db.GetDomain(r.Context(), tenant, domainID); err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	subs, err := s.db.ListSubdomains(r.Context(), domainID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, subs)
}

func (s *Server) handleEnumerateSubdomains(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	domainID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	d, err := s.db.GetDomain(r.Context(), tenant, domainID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}

	names, err := domain.Enumerate(r.Context(), d.Name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	existing, err := s.db.ListSubdomains(r.Context(), domainID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	known := map[string]bool{}
	for _, sub := range existing {
		known[sub.Name] = true
	}

	var discovered []store.Subdomain
	for _, name := range names {
		sub := &store.Subdomain{TenantID: tenant, DomainID: domainID, Name: name, Source: "crt.sh"}
		if err := s.db.UpsertSubdomain(r.Context(), sub); err != nil {
			s.log.Error("subdomain upsert failed", "error", err)
			continue
		}
		discovered = append(discovered, *sub)
		if !known[name] {
			// Shadow IT / unregistered subdomain.
			saveDomainFinding(r, s, tenant, &store.Finding{
				Source:      "domain",
				RuleID:      ruleShadowIT,
				Title:       "Unregistered subdomain discovered",
				Severity:    "info",
				Status:      "open",
				Description: "Subdomain " + name + " is active in certificate transparency but not tracked.",
				Remediation: "Register or document this subdomain in the inventory.",
				RiskScore:   risk.SeverityScore("info"),
			})
		}
	}
	s.audit(r.Context(), "domain.enumerate", d.Name, map[string]any{"discovered": len(discovered)})
	s.writeJSON(w, http.StatusOK, discovered)
}

func (s *Server) handleScanDomain(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	domainID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	d, err := s.db.GetDomain(r.Context(), tenant, domainID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}

	subs, err := s.db.ListSubdomains(r.Context(), domainID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	hosts := []string{d.Name}
	for _, sub := range subs {
		hosts = append(hosts, sub.Name)
	}

	var counts = map[string]int{"takeover": 0, "cert": 0, "drift": 0}

	// Certificate expiry (apex only) and takeover (all hosts).
	exp, err := domain.CheckCert(r.Context(), d.Name)
	if err == nil {
		_ = s.db.UpdateDomainCertExpiry(r.Context(), domainID, exp)
		switch {
		case exp.Before(time.Now()):
			saveDomainFinding(r, s, tenant, domainFinding(d.Name, ruleCertExpiry, "TLS certificate has expired", "high",
				"Certificate for "+d.Name+" expired on "+exp.Format(time.RFC3339), "Renew and deploy a new certificate."))
			counts["cert"]++
		case exp.Before(time.Now().Add(30 * 24 * time.Hour)):
			saveDomainFinding(r, s, tenant, domainFinding(d.Name, ruleCertExpiry, "TLS certificate expiring soon", "medium",
				"Certificate for "+d.Name+" expires on "+exp.Format(time.RFC3339), "Renew before expiry."))
			counts["cert"]++
		}
	}

	for _, host := range hosts {
		target, dangling, err := domain.DanglingCNAME(host)
		if err == nil && dangling {
			saveDomainFinding(r, s, tenant, domainFinding(host, ruleTakeover, "Subdomain takeover risk (dangling CNAME)", "high",
				host+" points to "+target+" which no longer resolves.", "Remove the dangling CNAME or reclaim the target."))
			counts["takeover"]++
		}
	}

	// DNS drift for the apex (compare resolved addresses to stored records).
	if current, err := domain.ResolveA(d.Name); err == nil {
		stored := map[string]bool{}
		for _, rec := range s.dbRecords(r, domainID, "A") {
			stored[rec.Value] = true
		}
		for _, ip := range current {
			if !stored[ip] {
				saveDomainFinding(r, s, tenant, domainFinding(d.Name, ruleDNSDrift, "DNS record drift detected", "medium",
					"A record "+ip+" is live but not in the stored inventory.", "Update the DNS inventory or investigate the change."))
				counts["drift"]++
			}
		}
	}

	s.audit(r.Context(), "domain.scan", d.Name, map[string]any{
		"hosts": len(hosts), "takeover": counts["takeover"], "cert": counts["cert"], "drift": counts["drift"],
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"hosts": len(hosts), "findings": counts})
}

func (s *Server) dbRecords(r *http.Request, domainID uuid.UUID, rtype string) []store.DNSRecord {
	records, _ := s.db.ListDNSRecords(r.Context(), domainID)
	var out []store.DNSRecord
	for _, rec := range records {
		if rec.Type == rtype {
			out = append(out, rec)
		}
	}
	return out
}

func domainFinding(name, ruleID, title, severity, description, remediation string) *store.Finding {
	return &store.Finding{
		Source:      "domain",
		RuleID:      ruleID,
		Title:       title,
		Severity:    severity,
		Status:      "open",
		Description: description,
		Remediation: remediation,
		RiskScore:   risk.SeverityScore(severity),
	}
}

func saveDomainFinding(r *http.Request, s *Server, tenant uuid.UUID, f *store.Finding) {
	f.TenantID = tenant
	if err := s.db.IngestFinding(r.Context(), f); err != nil {
		s.log.Error("domain finding ingest failed", "error", err)
	}
}
