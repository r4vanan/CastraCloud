package waf

import (
	"net"
	"regexp"
	"strings"
)

// Subject is the normalized view of a request the rule engine evaluates.
type Subject struct {
	IP          string
	Method      string
	URI         string
	Path        string
	Query       string
	Headers     map[string][]string
	Body        string
	UserAgent   string
	ContentType string
}

// Evaluate evaluates a single condition against the request subject.
func (c Condition) Evaluate(s *Subject) bool {
	field := c.Field
	value := ""
	missing := false

	// Support "header:X" and "query:X" dynamic fields.
	if name, ok := strings.CutPrefix(field, "header:"); ok {
		v, present := s.Headers[strings.ToLower(name)]
		if !present {
			missing = true
		} else {
			value = strings.Join(v, ", ")
		}
	} else if name, ok := strings.CutPrefix(field, "query:"); ok {
		value = extractQueryValue(s.Query, name)
		if value == "" {
			missing = true
		}
	} else {
		switch field {
		case "ip":
			value = s.IP
		case "method":
			value = s.Method
		case "uri":
			value = s.URI
		case "path":
			value = s.Path
		case "body":
			value = s.Body
		case "user_agent":
			value = s.UserAgent
		}
	}

	var result bool
	if missing {
		result = c.op("", "exists", "")
	} else {
		result = c.op(value, c.Op, c.Value)
	}
	if c.Negate {
		result = !result
	}
	return result
}

func (c Condition) op(value, op, pattern string) bool {
	switch op {
	case "eq":
		return value == pattern
	case "ne":
		return value != pattern
	case "contains":
		return strings.Contains(value, pattern)
	case "icontains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	case "regex":
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case "cidr":
		_, ipnet, err := net.ParseCIDR(pattern)
		if err != nil {
			return net.ParseIP(value) != nil && net.ParseIP(value).String() == pattern
		}
		ip := net.ParseIP(value)
		return ip != nil && ipnet.Contains(ip)
	case "exists":
		return value != ""
	case "gte":
		return len(value) >= parseIntSafe(pattern)
	case "lte":
		return len(value) <= parseIntSafe(pattern)
	default:
		return false
	}
}

func extractQueryValue(query, name string) string {
	for _, pair := range strings.Split(query, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if ok && k == name {
			return v
		}
	}
	return ""
}

func parseIntSafe(s string) int {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}
