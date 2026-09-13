// Package cspm implements Cloud Security Posture Management: discovery of
// cloud assets and evaluation of misconfiguration rules against them.
package cspm

import "context"

// Severity ranks the risk of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is a single misconfiguration or risk detected by a rule.
type Finding struct {
	RuleID       string            `json:"rule_id"`
	Title        string            `json:"title"`
	Severity     Severity          `json:"severity"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	Provider     string            `json:"provider"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ResourceName string            `json:"resource_name"`
	Region       string            `json:"region"`
	Details      map[string]string `json:"details,omitempty"`
}

// CheckFunc inspects cloud state and returns any findings.
type CheckFunc func(ctx context.Context, c *AWS) ([]Finding, error)

// Rule binds metadata to a check function.
type Rule struct {
	ID           string
	Title        string
	Severity     Severity
	Description  string
	Remediation  string
	ResourceType string
	Check        CheckFunc
}

// Registry is an ordered set of rules.
type Registry struct {
	rules []Rule
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends a rule.
func (r *Registry) Register(rule Rule) { r.rules = append(r.rules, rule) }

// Rules returns the registered rules.
func (r *Registry) Rules() []Rule { return r.rules }

// Run evaluates every rule and aggregates the findings.
func (r *Registry) Run(ctx context.Context, c *AWS) ([]Finding, error) {
	var all []Finding
	for _, rule := range r.rules {
		findings, err := rule.Check(ctx, c)
		if err != nil {
			return all, err
		}
		all = append(all, findings...)
	}
	return all, nil
}
