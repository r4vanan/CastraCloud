package domain

import (
	"reflect"
	"testing"
)

func TestParseSubdomains(t *testing.T) {
	entries := []crtEntry{
		{CommonName: "example.com", NameValue: "example.com\nwww.example.com\napi.example.com"},
		{CommonName: "*.example.com", NameValue: "foo.example.com\nbar.example.com"},
		{CommonName: "other.org", NameValue: "other.org\nx.other.org"}, // not ours
	}
	got := ParseSubdomains(entries, "example.com")
	want := []string{"api.example.com", "bar.example.com", "foo.example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseSubdomains = %v, want %v", got, want)
	}
}

func TestParseSubdomainsDedupe(t *testing.T) {
	entries := []crtEntry{
		{CommonName: "a.example.com", NameValue: "a.example.com\nA.EXAMPLE.COM\na.example.com."},
	}
	got := ParseSubdomains(entries, "example.com")
	if len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("ParseSubdomains = %v, want [a.example.com]", got)
	}
}
