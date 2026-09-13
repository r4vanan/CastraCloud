package risk

import "testing"

func TestSeverityScore(t *testing.T) {
	cases := map[string]int{
		"critical": 100,
		"high":     75,
		"medium":   50,
		"low":      25,
		"info":     0,
		"":         0,
		"bogus":    0,
	}
	for sev, want := range cases {
		if got := SeverityScore(sev); got != want {
			t.Errorf("SeverityScore(%q) = %d, want %d", sev, got, want)
		}
	}
}
