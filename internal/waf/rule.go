// Package waf implements the Web Application Firewall engine: a reverse proxy
// that inspects requests/responses, evaluates rules, enforces rate limits and
// IP blocklists, and emits security events.
package waf

// Action is what the engine does when a rule matches.
type Action string

const (
	ActionBlock     Action = "block"
	ActionAllow     Action = "allow"
	ActionLog       Action = "log"
	ActionChallenge Action = "challenge"
)

// Phase is the point at which a rule is evaluated.
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

// Condition is a single matching predicate evaluated against a request.
type Condition struct {
	Field  string `json:"field"`  // ip, method, uri, path, header:<name>, query:<name>, body, user_agent
	Op     string `json:"op"`     // eq, ne, contains, icontains, regex, cidr, exists
	Value  string `json:"value"`  // pattern / literal
	Negate bool   `json:"negate"` // invert the match result
}

// Rule is a single WAF rule composed of ANDed conditions.
type Rule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Phase      Phase       `json:"phase"`
	Action     Action      `json:"action"`
	Conditions []Condition `json:"conditions"`
	Priority   int         `json:"priority"`
	Enabled    bool        `json:"enabled"`
}

// MatchResult is the outcome of evaluating the ruleset for one request.
type MatchResult struct {
	Blocked bool
	Action  Action
	Rule    *Rule
}

// MatchAll returns true if every condition in the rule matches the subject.
func (r *Rule) MatchAll(subject *Subject) bool {
	if !r.Enabled || len(r.Conditions) == 0 {
		return false
	}
	for _, c := range r.Conditions {
		if !c.Evaluate(subject) {
			return false
		}
	}
	return true
}
