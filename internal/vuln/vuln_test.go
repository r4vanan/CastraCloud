package vuln

import "testing"

func TestScanLog4Shell(t *testing.T) {
	results := Scan([]Package{
		{Name: "log4j-core", Version: "2.14.1"},
		{Name: "log4j-core", Version: "2.17.0"},
	})
	if len(results) == 0 {
		t.Fatalf("expected at least 1 vulnerability, got 0")
	}
	found := false
	for _, r := range results {
		if r.CVE == "CVE-2021-44228" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Log4Shell, got %+v", results)
	}
}

func TestScanPatched(t *testing.T) {
	results := Scan([]Package{{Name: "openssl", Version: "1.1.1s"}})
	if len(results) != 0 {
		t.Fatalf("expected no vulnerabilities, got %+v", results)
	}
}

func TestScanHeartbleedRange(t *testing.T) {
	vuln := Scan([]Package{{Name: "openssl", Version: "1.0.1f"}})
	if len(vuln) != 1 {
		t.Fatalf("expected heartbleed hit, got %+v", vuln)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.1", -1},
		{"2.14.1", "2.17.0", -1},
		{"2.17.0", "2.17.0", 0},
		{"2.17.1", "2.17.0", 1},
		{"1.0.1f", "1.0.1g", -1},
		{"10.0", "9.9", 1},
		{"v1.2.3", "1.2.4", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
