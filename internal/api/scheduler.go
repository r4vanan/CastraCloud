package api

import (
	"context"
	"errors"
	"time"

	"github.com/castracloud/castracloud/internal/config"
	"github.com/castracloud/castracloud/internal/connector"
	credentialcrypto "github.com/castracloud/castracloud/internal/crypto"
	"github.com/castracloud/castracloud/internal/risk"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// runScan decrypts a connector's credentials, runs a CSPM scan, and ingests the
// resulting findings (deduplicated). It is shared by the on-demand scan handler
// and the background scheduler.
func (s *Server) runScan(ctx context.Context, tenant uuid.UUID, conn *store.CloudConnector) (scanned, ingested int, err error) {
	credentials := ""
	if len(conn.CredentialsEncrypted) > 0 {
		key := config.Env("CREDENTIAL_ENCRYPTION_KEY", "")
		if key == "" {
			return 0, 0, errors.New("CREDENTIAL_ENCRYPTION_KEY is not set")
		}
		credentials, err = credentialcrypto.Decrypt(key, conn.CredentialsEncrypted)
		if err != nil {
			return 0, 0, err
		}
	}

	connSDK, err := connector.New(ctx, connector.Config{
		Provider:    conn.Provider,
		Region:      conn.Region,
		Credentials: credentials,
	})
	if err != nil {
		return 0, 0, err
	}

	findings, err := connSDK.Scan(ctx)
	if err != nil {
		return 0, 0, err
	}

	ingested = 0
	for _, f := range findings {
		var assetID uuid.UUID
		if f.ResourceType != "" && f.ResourceID != "" {
			props := make(map[string]any, len(f.Details))
			for k, v := range f.Details {
				props[k] = v
			}
			asset := &store.Asset{
				TenantID:   tenant,
				Provider:   conn.Provider,
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
			if err := s.db.UpsertAsset(ctx, asset); err == nil {
				assetID = asset.ID
			}
		}

		sf := &store.Finding{
			TenantID:    tenant,
			AssetID:     assetID,
			Source:      "cspm",
			RuleID:      f.RuleID,
			Title:       f.Title,
			Severity:    string(f.Severity),
			Status:      "open",
			Description: f.Description,
			Remediation: f.Remediation,
			RiskScore:   risk.SeverityScore(string(f.Severity)),
		}
		if inserted, err := s.db.IngestFinding(ctx, sf); err == nil && inserted {
			ingested++
		}
	}
	_ = s.db.UpdateConnectorScanTime(ctx, tenant, conn.ID)
	return len(findings), ingested, nil
}

// scanAllConnectors scans every configured connector once.
func (s *Server) scanAllConnectors(ctx context.Context) {
	conns, err := s.db.ListAllConnectors(ctx)
	if err != nil {
		s.log.Error("scheduled scan list failed", "error", err)
		return
	}
	for _, c := range conns {
		scanned, ingested, err := s.runScan(ctx, c.TenantID, &c)
		if err != nil {
			s.log.Error("scheduled scan failed", "connector", c.Name, "error", err)
			continue
		}
		s.log.Info("scheduled scan complete", "connector", c.Name, "scanned", scanned, "ingested", ingested)
	}
}

// ScheduleScans runs a background loop that periodically scans all connectors.
func (s *Server) ScheduleScans(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		s.scanAllConnectors(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.scanAllConnectors(ctx)
			}
		}
	}()
}
