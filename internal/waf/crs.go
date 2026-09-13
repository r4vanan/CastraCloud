package waf

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ImportCRS parses OWASP ModSecurity Core Rule Set directives (SecRule lines)
// and converts the regex-based rules into CastraCloud WAF rules.
//
// ModSecurity evaluates a SecRule's variable list with OR semantics, so each
// mapped variable becomes its own single-condition rule (preserving "match any").
// Only @rx (regex) operators are supported; other operators are skipped.
func ImportCRS(r io.Reader) ([]Rule, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	var rules []Rule
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "SecRule") {
			continue
		}
		imported := parseSecRule(line)
		rules = append(rules, imported...)
	}
	return rules, scanner.Err()
}

// parseSecRule converts one SecRule directive into one or more WAF rules.
func parseSecRule(line string) []Rule {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "SecRule"))

	i := strings.Index(rest, `"`)
	if i < 0 {
		return nil
	}
	variables := strings.TrimSpace(rest[:i])

	rest = rest[i+1:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return nil
	}
	operator := rest[:j]

	after := rest[j+1:]
	k := strings.Index(after, `"`)
	if k < 0 {
		return nil
	}
	after = after[k+1:]
	m := strings.Index(after, `"`)
	if m < 0 {
		return nil
	}
	actions := after[:m]

	pattern, ok := rxPattern(operator)
	if !ok {
		return nil
	}

	id := crsID(actions)
	msg := crsMsg(actions)
	if msg == "" {
		msg = "CRS rule " + id
	}
	action := crsAction(actions)
	phase := PhaseRequest
	if strings.Contains(actions, "phase:2") || strings.Contains(actions, "phase:4") {
		phase = PhaseResponse
	}

	var out []Rule
	for n, raw := range strings.Split(variables, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		negate := strings.HasPrefix(raw, "!")
		field, ok := mapCRSVariable(strings.TrimPrefix(raw, "!"))
		if !ok {
			continue
		}
		ruleID := id
		if n > 0 {
			ruleID = fmt.Sprintf("%s.%d", id, n+1)
		}
		out = append(out, Rule{
			ID:    ruleID,
			Name:  msg,
			Phase: phase,
			Action: action,
			Conditions: []Condition{{
				Field:  field,
				Op:     "regex",
				Value:  pattern,
				Negate: negate,
			}},
			Priority: 10,
			Enabled:  true,
		})
	}
	return out
}

// rxPattern extracts the regex from an "@rx ..." operator.
func rxPattern(operator string) (string, bool) {
	operator = strings.TrimSpace(operator)
	if !strings.HasPrefix(operator, "@rx ") {
		return "", false
	}
	pattern := strings.TrimSpace(strings.TrimPrefix(operator, "@rx "))
	if pattern == "" {
		return "", false
	}
	// Validate the pattern compiles before accepting it.
	if _, err := regexp.Compile(pattern); err != nil {
		return "", false
	}
	return pattern, true
}

var idRe = regexp.MustCompile(`(?:^|,)id:(\d+)`)
var msgRe = regexp.MustCompile(`msg:'([^']*)'`)

func crsID(actions string) string {
	if m := idRe.FindStringSubmatch(actions); m != nil {
		return m[1]
	}
	return "CRS-unknown"
}

func crsMsg(actions string) string {
	if m := msgRe.FindStringSubmatch(actions); m != nil {
		return m[1]
	}
	return ""
}

func crsAction(actions string) Action {
	switch {
	case strings.Contains(actions, "deny"), strings.Contains(actions, "block"):
		return ActionBlock
	case strings.Contains(actions, "pass"):
		return ActionAllow
	default:
		return ActionLog
	}
}

// mapCRSVariable maps a ModSecurity target variable to a CastraCloud subject field.
func mapCRSVariable(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if name, ok := strings.CutPrefix(v, "REQUEST_HEADERS:"); ok {
		name = strings.TrimSpace(name)
		if name == "" {
			return "", false
		}
		return "header:" + name, true
	}
	switch v {
	case "REQUEST_URI", "REQUEST_LINE", "REQUEST_FILENAME", "REQUEST_URI_RAW", "REQUEST_BASENAME":
		return "uri", true
	case "REQUEST_BODY", "REQUEST_BODY_LENGTH":
		return "body", true
	case "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST", "QUERY_STRING":
		return "query", true
	case "REQUEST_METHOD":
		return "method", true
	case "REQUEST_COOKIES":
		return "header:Cookie", true
	case "REQUEST_HEADERS":
		return "user_agent", false // unsupported: headers-as-whole
	default:
		return "", false
	}
}
