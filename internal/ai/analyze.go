package ai

import (
	"strings"

	"github.com/castracloud/castracloud/internal/store"
)

// AnalyzeFinding returns the prompt pair for explaining a single finding.
func AnalyzeFindingPrompt(f store.Finding) (system, user string) {
	system = `You are a senior cloud security engineer. Explain the finding to an operator in plain language.
Respond in three short sections with markdown headings:
## Risk assessment
## Impact
## Recommended remediation
Be specific and concise (under 200 words).`
	user = "Analyze this security finding:\n" +
		"- Rule: " + f.RuleID + "\n" +
		"- Title: " + f.Title + "\n" +
		"- Severity: " + f.Severity + "\n" +
		"- Source: " + f.Source + "\n" +
		"- Description: " + f.Description + "\n" +
		"- Remediation hint: " + f.Remediation
	return system, user
}

// SummarizeFindingsPrompt builds a prompt that summarizes a set of findings
// into an actionable threat brief.
func SummarizeFindingsPrompt(findings []store.Finding) (system, user string) {
	system = `You are a SOC analyst. Summarize the findings into a threat brief for leadership.
Use markdown headings:
## Executive summary
## Top risks
## Recommended priorities
Keep it under 250 words and prioritize by severity.`

	var b strings.Builder
	b.WriteString("Summarize the following open findings:\n")
	for _, f := range findings {
		b.WriteString("- [" + strings.ToUpper(f.Severity) + "] " + f.RuleID + " - " + f.Title + "\n")
	}
	return system, b.String()
}
