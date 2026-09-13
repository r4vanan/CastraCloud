package waf

// sqlPattern matches common SQL injection payloads.
const sqlPattern = `(?i)(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+\d+=\d+|and\s+\d+=\d+|'--|/\*.*\*/|;\s*select)`

// xssPattern matches common reflected XSS payloads.
const xssPattern = `(?i)(<script|javascript:|onerror=|onload=|onmouseover=|alert\(|document\.cookie|<img[^>]+src=)`

// traversalPattern matches path traversal attempts.
const traversalPattern = `(\.\./|\.\.%2f|/etc/passwd|/proc/self|/windows/win\.ini|%00)`

// DefaultRuleset returns a baseline set of rules modelled on OWASP Core Rule
// Set categories. These are overridable/extensible via the control plane.
func DefaultRuleset() []Rule {
	return []Rule{
		{
			ID:     "CRS-942100",
			Name:   "SQL Injection attempt in request URI",
			Phase:  PhaseRequest,
			Action: ActionBlock,
			Conditions: []Condition{
				{Field: "uri", Op: "regex", Value: sqlPattern},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:     "CRS-942101",
			Name:   "SQL Injection attempt in body",
			Phase:  PhaseRequest,
			Action: ActionBlock,
			Conditions: []Condition{
				{Field: "body", Op: "regex", Value: sqlPattern},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:     "CRS-941100",
			Name:   "XSS attempt in request URI",
			Phase:  PhaseRequest,
			Action: ActionBlock,
			Conditions: []Condition{
				{Field: "uri", Op: "regex", Value: xssPattern},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:     "CRS-941101",
			Name:   "XSS attempt in body",
			Phase:  PhaseRequest,
			Action: ActionBlock,
			Conditions: []Condition{
				{Field: "body", Op: "regex", Value: xssPattern},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:     "CRS-930120",
			Name:   "Path traversal attempt",
			Phase:  PhaseRequest,
			Action: ActionBlock,
			Conditions: []Condition{
				{Field: "uri", Op: "regex", Value: traversalPattern},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:     "CRS-932160",
			Name:   "Command injection attempt",
			Phase:  PhaseRequest,
			Action: ActionBlock,
			Conditions: []Condition{
				{Field: "uri", Op: "regex", Value: `(?i)(;\s*(cat|ls|id|wget|curl|sh\s|bash|whoami)|\$\{|` + "`" + `|\|\s*\w+|<%\s*@)`},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:     "CUSTOM-913100",
			Name:   "Known scanner/bot user agent",
			Phase:  PhaseRequest,
			Action: ActionLog,
			Conditions: []Condition{
				{Field: "user_agent", Op: "icontains", Value: "sqlmap"},
				{Field: "user_agent", Op: "icontains", Value: "nikto"},
				{Field: "user_agent", Op: "icontains", Value: "nmap"},
			},
			Priority: 20,
			Enabled:  true,
		},
	}
}
