// Package domain implements the Domain Manager: subdomain enumeration via
// certificate transparency (crt.sh), certificate expiry checks, and DNS
// takeover (dangling CNAME) detection.
package domain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

const crtSH = "https://crt.sh/"

type crtEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// Enumerate queries crt.sh certificate-transparency logs for subdomains of base.
func Enumerate(ctx context.Context, base string) ([]string, error) {
	base = strings.TrimSuffix(strings.ToLower(base), ".")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s?q=%%25.%s&output=json", crtSH, base), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "castracloud-domain-manager/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crt.sh returned %s", resp.Status)
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse: %w", err)
	}
	return ParseSubdomains(entries, base), nil
}

// ParseSubdomains extracts unique subdomain names from crt.sh entries for base.
func ParseSubdomains(entries []crtEntry, base string) []string {
	base = strings.TrimSuffix(strings.ToLower(base), ".")
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "*.")
		n = strings.TrimSuffix(n, ".")
		if n == "" || n == base || !strings.HasSuffix(n, "."+base) {
			return
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, e := range entries {
		add(e.CommonName)
		for _, n := range strings.Split(e.NameValue, "\n") {
			add(n)
		}
	}
	sort.Strings(out)
	return out
}

// CheckCert connects via TLS and returns the leaf certificate's expiry time.
func CheckCert(ctx context.Context, host string) (time.Time, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificate presented")
	}
	return certs[0].NotAfter, nil
}

// DanglingCNAME reports whether host's CNAME target no longer resolves,
// which is the classic subdomain-takeover signature.
func DanglingCNAME(host string) (target string, dangling bool, err error) {
	cname, err := net.LookupCNAME(host)
	if err != nil {
		return "", false, err
	}
	if strings.TrimSuffix(cname, ".") == strings.TrimSuffix(host, ".") {
		return "", false, nil // no CNAME record
	}
	if _, err := net.LookupHost(cname); err != nil {
		return cname, true, nil
	}
	return cname, false, nil
}

// ResolveA returns the A/AAAA addresses for host.
func ResolveA(host string) ([]string, error) {
	return net.LookupHost(host)
}
