// Package risk maps severity levels to numeric risk scores.
package risk

import "strings"

// SeverityScore returns a 0-100 risk score for a severity string.
func SeverityScore(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 0
	}
}
