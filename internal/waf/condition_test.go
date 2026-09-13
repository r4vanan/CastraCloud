package waf

import "testing"

func TestConditionEvaluate(t *testing.T) {
	s := &Subject{
		IP:        "203.0.113.7",
		Method:    "POST",
		Path:      "/admin/login",
		Query:     "id=1",
		Body:      "SELECT * FROM users",
		UserAgent: "curl/8.0",
		Headers:   map[string][]string{"x-api-key": {"abc123"}},
	}

	cases := []struct {
		name string
		c    Condition
		want bool
	}{
		{"ip eq", Condition{Field: "ip", Op: "eq", Value: "203.0.113.7"}, true},
		{"ip cidr", Condition{Field: "ip", Op: "cidr", Value: "203.0.113.0/24"}, true},
		{"ip cidr miss", Condition{Field: "ip", Op: "cidr", Value: "10.0.0.0/8"}, false},
		{"method eq", Condition{Field: "method", Op: "eq", Value: "POST"}, true},
		{"path regex", Condition{Field: "path", Op: "regex", Value: `^/admin`}, true},
		{"body sql regex", Condition{Field: "body", Op: "regex", Value: `(?i)select\s+\*`}, true},
		{"ua contains", Condition{Field: "user_agent", Op: "icontains", Value: "CURL"}, true},
		{"header exists", Condition{Field: "header:x-api-key", Op: "exists", Value: ""}, true},
		{"query eq", Condition{Field: "query:id", Op: "eq", Value: "1"}, true},
		{"negate", Condition{Field: "method", Op: "eq", Value: "GET", Negate: true}, true},
		{"xss miss", Condition{Field: "uri", Op: "regex", Value: `(?i)<script`}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.Evaluate(s); got != tc.want {
				t.Fatalf("Evaluate(%+v) = %v, want %v", tc.c, got, tc.want)
			}
		})
	}
}

func TestRuleMatchAll(t *testing.T) {
	subject := &Subject{Body: "1 OR 1=1 --", Method: "GET"}
	rules := DefaultRuleset()

	var sqlBody *Rule
	for i := range rules {
		if rules[i].ID == "CRS-942101" {
			sqlBody = &rules[i]
		}
	}
	if sqlBody == nil || !sqlBody.MatchAll(subject) {
		t.Fatal("expected body SQL injection rule to match")
	}

	clean := &Subject{Body: "hello", Method: "GET", UserAgent: "Mozilla/5.0", URI: "/health"}
	for _, r := range rules {
		if r.MatchAll(clean) {
			t.Fatalf("rule %s should not match clean request", r.ID)
		}
	}
}
