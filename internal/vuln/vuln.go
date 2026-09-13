// Package vuln implements a lightweight software-composition vulnerability
// scanner backed by a curated CVE database. It is designed to be embedded in
// the CSPM collector or invoked via the API to flag known-vulnerable packages
// in workloads.
package vuln

import (
	"strconv"
	"strings"
)

// Package is a dependency in a workload (name + installed version).
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Result is a matched vulnerability for a package.
type Result struct {
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	CVE       string `json:"cve"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
}

// cve is a curated vulnerability record.
type cve struct {
	id        string
	pkg       string
	fixed     string // first fixed version ("" = no fix yet)
	introduced string // optional: vulnerable from this version
	severity  string
	title     string
}

// db is the built-in, seedable CVE catalog.
var db = []cve{
	{"CVE-2021-44228", "log4j-core", "2.17.0", "", "critical", "Log4Shell RCE in log4j-core"},
	{"CVE-2021-45046", "log4j-core", "2.16.0", "", "high", "Log4j DoS/RCE in message lookups"},
	{"CVE-2022-22965", "spring-beans", "5.3.18", "", "critical", "Spring4Shell RCE"},
	{"CVE-2022-22965", "spring-web", "5.3.18", "", "critical", "Spring4Shell RCE"},
	{"CVE-2014-0160", "openssl", "1.0.1g", "", "high", "Heartbleed information disclosure"},
	{"CVE-2017-5638", "struts2-core", "2.3.32", "", "critical", "Apache Struts2 RCE"},
	{"CVE-2020-8203", "lodash", "4.17.19", "", "high", "Lodash prototype pollution"},
	{"CVE-2017-12617", "tomcat", "7.0.82", "", "high", "Apache Tomcat RCE via PUT"},
	{"CVE-2023-38545", "curl", "8.4.0", "", "high", "curl SOCKS5 heap overflow"},
	{"CVE-2022-40304", "libxml2", "2.10.2", "", "high", "libxml2 use-after-free"},
	{"CVE-2023-4863", "libwebp", "1.3.2", "", "critical", "WebP heap buffer overflow"},
}

// Scan evaluates packages against the CVE database and returns matches.
func Scan(packages []Package) []Result {
	seen := map[string]bool{}
	var out []Result
	for _, p := range packages {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if name == "" {
			continue
		}
		for _, c := range db {
			if strings.ToLower(c.pkg) != name {
				continue
			}
			if !vulnerable(p.Version, c.introduced, c.fixed) {
				continue
			}
			key := c.id + "|" + name + "|" + p.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Result{
				Package:   p.Name,
				Installed: p.Version,
				Fixed:     c.fixed,
				CVE:       c.id,
				Severity:  c.severity,
				Title:     c.title,
			})
		}
	}
	return out
}

// vulnerable reports whether installed is within the affected version range.
func vulnerable(installed, introduced, fixed string) bool {
	if installed == "" {
		return false
	}
	if fixed != "" && compareVersions(installed, fixed) >= 0 {
		return false // already patched
	}
	if introduced != "" && compareVersions(installed, introduced) < 0 {
		return false // before the vulnerable range
	}
	return true
}

// compareVersions compares two dot-separated versions. Numeric segments are
// compared numerically; otherwise they fall back to lexical comparison.
func compareVersions(a, b string) int {
	pa := strings.Split(strings.TrimPrefix(a, "v"), ".")
	pb := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x == y {
			continue
		}
		xn, xe := strconv.Atoi(x)
		yn, ye := strconv.Atoi(y)
		if xe == nil && ye == nil {
			switch {
			case xn < yn:
				return -1
			case xn > yn:
				return 1
			}
			continue
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}
