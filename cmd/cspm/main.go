// Command cspm runs the CastraCloud CSPM collector against a cloud provider
// via the connector SDK, emitting findings as JSON (and optionally reporting
// them to the control plane).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/castracloud/castracloud/internal/config"
	"github.com/castracloud/castracloud/internal/connector"
	_ "github.com/castracloud/castracloud/internal/connector/aws"   // registers the aws provider
	_ "github.com/castracloud/castracloud/internal/connector/azure" // registers the azure provider
	_ "github.com/castracloud/castracloud/internal/connector/gcp"   // registers the gcp provider
	"github.com/castracloud/castracloud/internal/cspm"
	"github.com/castracloud/castracloud/internal/logging"
)

func main() {
	log := logging.New(config.Env("LOG_LEVEL", "info"))
	ctx := context.Background()

	provider := config.Env("CSPM_PROVIDER", "aws")
	region := config.Env("AWS_REGION", "us-east-1")

	conn, err := connector.New(ctx, connector.Config{Provider: provider, Region: region})
	if err != nil {
		log.Error("connector init failed", "provider", provider, "error", err)
		os.Exit(1)
	}

	log.Info("running CSPM scan", "provider", provider, "region", region)
	start := time.Now()
	findings, err := conn.Scan(ctx)
	if err != nil {
		log.Error("scan failed", "error", err)
		os.Exit(1)
	}
	log.Info("scan complete", "findings", len(findings), "duration", time.Since(start))

	report := struct {
		TenantID  string        `json:"tenant_id"`
		Provider  string        `json:"provider"`
		ScannedAt time.Time     `json:"scanned_at"`
		Findings  []cspmFinding `json:"findings"`
	}{
		TenantID:  config.Env("CSPM_TENANT_ID", ""),
		Provider:  provider,
		ScannedAt: time.Now().UTC(),
		Findings:  toReport(findings),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)

	if api := config.Env("CSPM_API_URL", ""); api != "" {
		if err := postFindings(api, report); err != nil {
			log.Error("reporting to API failed", "error", err)
			os.Exit(1)
		}
	}
}

// cspmFinding mirrors the finding shape used by the API ingest endpoint.
type cspmFinding struct {
	RuleID       string            `json:"rule_id"`
	Title        string            `json:"title"`
	Severity     string            `json:"severity"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ResourceName string            `json:"resource_name"`
	Region       string            `json:"region"`
	Details      map[string]string `json:"details,omitempty"`
}

func toReport(in []cspm.Finding) []cspmFinding {
	out := make([]cspmFinding, 0, len(in))
	for _, f := range in {
		out = append(out, cspmFinding{
			RuleID:       f.RuleID,
			Title:        f.Title,
			Severity:     string(f.Severity),
			Description:  f.Description,
			Remediation:  f.Remediation,
			ResourceType: f.ResourceType,
			ResourceID:   f.ResourceID,
			ResourceName: f.ResourceName,
			Region:       f.Region,
			Details:      f.Details,
		})
	}
	return out
}

func postFindings(api string, report any) error {
	body, _ := json.Marshal(report)
	req, err := http.NewRequest(http.MethodPost, api+"/v1/findings/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.Env("CSPM_API_TOKEN", ""))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("api returned %s", resp.Status)
	}
	return nil
}
