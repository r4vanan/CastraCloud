package waf

import (
	"strings"
	"testing"
)

func TestImportCRS(t *testing.T) {
	input := `
# comment line
SecRule REQUEST_URI "@rx (?i)union\s+select" "id:942100,phase:1,deny,msg:'SQL Injection attempt',severity:'CRITICAL'"
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap" "id:913100,phase:1,log,msg:'Scanner UA'"
SecRule REQUEST_BODY "@badop" "id:999999,phase:1,deny,msg:'skip me'"
`
	rules, err := ImportCRS(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d: %+v", len(rules), rules)
	}

	sql := rules[0]
	if sql.ID != "942100" {
		t.Fatalf("expected id 942100, got %s", sql.ID)
	}
	if sql.Action != ActionBlock {
		t.Fatalf("expected block action, got %s", sql.Action)
	}
	if sql.Conditions[0].Field != "uri" || sql.Conditions[0].Op != "regex" {
		t.Fatalf("unexpected condition: %+v", sql.Conditions[0])
	}

	ua := rules[1]
	if ua.Conditions[0].Field != "header:User-Agent" {
		t.Fatalf("expected header condition, got %s", ua.Conditions[0].Field)
	}
	if ua.Action != ActionLog {
		t.Fatalf("expected log action, got %s", ua.Action)
	}
}

func TestImportCRSMultipleVariables(t *testing.T) {
	input := `SecRule ARGS,REQUEST_URI "@rx (?i)select" "id:100,phase:1,deny,msg:'multi'"`
	rules, err := ImportCRS(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (one per variable), got %d", len(rules))
	}
	if rules[0].Conditions[0].Field != "query" || rules[1].Conditions[0].Field != "uri" {
		t.Fatalf("unexpected fields: %s, %s",
			rules[0].Conditions[0].Field, rules[1].Conditions[0].Field)
	}
}

func TestMapCRSVariable(t *testing.T) {
	cases := map[string]string{
		"REQUEST_URI":               "uri",
		"REQUEST_BODY":              "body",
		"ARGS":                      "query",
		"REQUEST_METHOD":            "method",
		"REQUEST_HEADERS:User-Agent": "header:User-Agent",
	}
	for in, want := range cases {
		got, ok := mapCRSVariable(in)
		if !ok || got != want {
			t.Errorf("mapCRSVariable(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}
