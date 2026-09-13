// Package notify dispatches findings to alert channels: Slack, Microsoft
// Teams, generic webhooks, email, and Wazuh-compatible syslog/JSON (UDP).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Finding is a compact view of a security finding for notifications.
type Finding struct {
	RuleID       string `json:"rule_id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Provider     string `json:"provider"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	RiskScore    int    `json:"risk_score"`
	Description  string `json:"description,omitempty"`
}

// Message is the payload delivered to notifiers.
type Message struct {
	Event    string    `json:"event"`
	TenantID string    `json:"tenant_id"`
	Provider string    `json:"provider"`
	Count    int       `json:"count"`
	Findings []Finding `json:"findings"`
}

// Notifier delivers a Message to a destination.
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// New builds a notifier from a channel type and its config map.
func New(kind string, cfg map[string]any) (Notifier, error) {
	switch strings.ToLower(kind) {
	case "slack":
		return &slackNotifier{url: str(cfg, "url")}, nil
	case "teams":
		return &teamsNotifier{url: str(cfg, "url")}, nil
	case "webhook":
		return &webhookNotifier{url: str(cfg, "url"), headers: headers(cfg)}, nil
	case "email":
		return &emailNotifier{
			host: str(cfg, "host"), port: intv(cfg, "port"),
			from: str(cfg, "from"), to: strSlice(cfg, "to"),
			username: str(cfg, "username"), password: str(cfg, "password"),
		}, nil
	case "syslog", "wazuh":
		return &syslogNotifier{host: str(cfg, "host"), port: intv(cfg, "port")}, nil
	default:
		return nil, fmt.Errorf("notify: unknown channel type %q", kind)
	}
}

// Dispatch sends a message to all notifiers, logging failures without aborting.
func Dispatch(ctx context.Context, m Message, notifiers []Notifier) []error {
	var errs []error
	for _, n := range notifiers {
		if n == nil {
			continue
		}
		if err := n.Send(ctx, m); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// --- formatting ---

func summaryText(m Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CastraCloud: %d new finding(s) [%s]\n", m.Count, m.Provider)
	for i, f := range m.Findings {
		if i >= 10 {
			fmt.Fprintf(&b, "... and %d more\n", len(m.Findings)-10)
			break
		}
		if f.ResourceName != "" {
			fmt.Fprintf(&b, "- [%s] %s (%s)\n", strings.ToUpper(f.Severity), f.Title, f.ResourceName)
		} else {
			fmt.Fprintf(&b, "- [%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- helpers ---

func str(cfg map[string]any, key string) string {
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

func intv(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

func strSlice(cfg map[string]any, key string) []string {
	switch v := cfg[key].(type) {
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(v, ",") {
			out = append(out, strings.TrimSpace(s))
		}
		return out
	}
	return nil
}

func headers(cfg map[string]any) map[string]string {
	out := map[string]string{}
	if v, ok := cfg["headers"].(map[string]any); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

func postJSON(ctx context.Context, url string, body []byte, hdrs map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: HTTP %s", resp.Status)
	}
	return nil
}

// --- slack ---

type slackNotifier struct{ url string }

func (n *slackNotifier) Send(ctx context.Context, m Message) error {
	if n.url == "" {
		return fmt.Errorf("notify: slack url not configured")
	}
	body, _ := json.Marshal(map[string]string{"text": summaryText(m)})
	return postJSON(ctx, n.url, body, nil)
}

// --- teams ---

type teamsNotifier struct{ url string }

func (n *teamsNotifier) Send(ctx context.Context, m Message) error {
	if n.url == "" {
		return fmt.Errorf("notify: teams url not configured")
	}
	body, _ := json.Marshal(map[string]string{"text": summaryText(m)})
	return postJSON(ctx, n.url, body, nil)
}

// --- webhook ---

type webhookNotifier struct {
	url     string
	headers map[string]string
}

func (n *webhookNotifier) Send(ctx context.Context, m Message) error {
	if n.url == "" {
		return fmt.Errorf("notify: webhook url not configured")
	}
	body, _ := json.Marshal(m)
	return postJSON(ctx, n.url, body, n.headers)
}

// --- email ---

type emailNotifier struct {
	host     string
	port     int
	from     string
	to       []string
	username string
	password string
}

func (n *emailNotifier) Send(ctx context.Context, m Message) error {
	if n.host == "" || n.from == "" || len(n.to) == 0 {
		return fmt.Errorf("notify: email not fully configured")
	}
	addr := net.JoinHostPort(n.host, strconv.Itoa(n.port))
	subject := fmt.Sprintf("[CastraCloud] %d new findings", m.Count)
	msg := []byte("Subject: " + subject + "\r\n\r\n" + summaryText(m))
	var auth smtp.Auth
	if n.username != "" {
		auth = smtp.PlainAuth("", n.username, n.password, n.host)
	}
	return smtp.SendMail(addr, auth, n.from, n.to, msg)
}

// --- syslog / Wazuh ---

type syslogNotifier struct {
	host string
	port int
}

func (n *syslogNotifier) Send(ctx context.Context, m Message) error {
	if n.host == "" {
		return fmt.Errorf("notify: syslog host not configured")
	}
	if n.port == 0 {
		n.port = 514
	}
	conn, err := net.Dial("udp", net.JoinHostPort(n.host, strconv.Itoa(n.port)))
	if err != nil {
		return err
	}
	defer conn.Close()

	// Emit one Wazuh-compatible JSON event per finding.
	for _, f := range m.Findings {
		evt := map[string]any{
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"event":      m.Event,
			"tenant_id":  m.TenantID,
			"rule_id":    f.RuleID,
			"severity":   f.Severity,
			"title":      f.Title,
			"provider":   f.Provider,
			"resource":   f.ResourceName,
			"risk_score": f.RiskScore,
		}
		b, err := json.Marshal(evt)
		if err != nil {
			return err
		}
		if _, err := io.Copy(conn, bytes.NewReader(append(b, '\n'))); err != nil {
			return err
		}
	}
	return nil
}
