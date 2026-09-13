// Package gcp implements the CastraCloud CSPM connector for Google Cloud
// Platform using Application Default Credentials (read-only service account).
package gcp

import (
	"context"
	"os"
	"strings"

	"github.com/castracloud/castracloud/internal/connector"
	"github.com/castracloud/castracloud/internal/cspm"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

// GCP is the CSPM connector for Google Cloud Platform.
type GCP struct {
	project string
	storage *storage.Service
	compute *compute.Service
}

// New builds a GCP connector from Application Default Credentials.
func New(ctx context.Context, cfg connector.Config) (connector.Connector, error) {
	creds, err := google.FindDefaultCredentials(ctx, storage.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	project := os.Getenv("GCP_PROJECT")
	if project == "" {
		project = creds.ProjectID
	}

	st, err := storage.NewService(ctx, option.WithTokenSource(creds.TokenSource))
	if err != nil {
		return nil, err
	}
	co, err := compute.NewService(ctx, option.WithTokenSource(creds.TokenSource))
	if err != nil {
		return nil, err
	}
	return &GCP{project: project, storage: st, compute: co}, nil
}

// Provider reports the provider name.
func (g *GCP) Provider() string { return "gcp" }

// Scan evaluates the GCP baseline rule set and returns the findings.
func (g *GCP) Scan(ctx context.Context) ([]cspm.Finding, error) {
	var all []cspm.Finding

	public, err := g.publicBuckets(ctx)
	if err != nil {
		return nil, err
	}
	all = append(all, public...)

	open, err := g.openFirewalls(ctx)
	if err != nil {
		return nil, err
	}
	all = append(all, open...)

	return all, nil
}

func (g *GCP) publicBuckets(ctx context.Context) ([]cspm.Finding, error) {
	buckets, err := g.storage.Buckets.List(g.project).Do()
	if err != nil {
		return nil, err
	}
	var findings []cspm.Finding
	for _, b := range buckets.Items {
		pol, err := g.storage.Buckets.GetIamPolicy(b.Name).Do()
		if err != nil {
			continue
		}
		if why := publicPolicyReason(pol); why != "" {
			findings = append(findings, newFinding(
				"CASTRA-GCP-001", "GCS bucket is publicly accessible", cspm.SeverityCritical,
				"gcs_bucket", b.Name, b.Name, b.Location, map[string]string{"reason": why}))
		}
	}
	return findings, nil
}

func (g *GCP) openFirewalls(ctx context.Context) ([]cspm.Finding, error) {
	list, err := g.compute.Firewalls.List(g.project).Do()
	if err != nil {
		return nil, err
	}
	var findings []cspm.Finding
	for _, fw := range list.Items {
		if fw.Direction == "EGRESS" || !hasOpenRange(fw.SourceRanges) {
			continue
		}
		findings = append(findings, newFinding(
			"CASTRA-GCP-002", "Firewall rule allows traffic from the internet", cspm.SeverityHigh,
			"firewall", fw.Name, fw.Name, "", map[string]string{
				"rules": allowedSummary(fw.Allowed),
			}))
	}
	return findings, nil
}

func publicPolicyReason(p *storage.Policy) string {
	for _, b := range p.Bindings {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				return "IAM binding grants " + m + " via role " + b.Role
			}
		}
	}
	return ""
}

func hasOpenRange(ranges []string) bool {
	for _, r := range ranges {
		if r == "0.0.0.0/0" || r == "::/0" {
			return true
		}
	}
	return false
}

func allowedSummary(allowed []*compute.FirewallAllowed) string {
	var parts []string
	for _, a := range allowed {
		p := a.IPProtocol
		if len(a.Ports) > 0 {
			p += ":" + strings.Join(a.Ports, ",")
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

func newFinding(ruleID, title string, sev cspm.Severity, resType, id, name, region string, details map[string]string) cspm.Finding {
	return cspm.Finding{
		RuleID:       ruleID,
		Title:        title,
		Severity:     sev,
		Description:  title,
		Remediation:  "See CastraCloud remediation guidance for " + ruleID + ".",
		Provider:     "gcp",
		ResourceType: resType,
		ResourceID:   id,
		ResourceName: name,
		Region:       region,
		Details:      details,
	}
}

func init() {
	connector.Register("gcp", New)
}
