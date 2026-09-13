package connector

import (
	"context"
	"testing"

	"github.com/castracloud/castracloud/internal/cspm"
)

type fakeConnector struct{}

func (fakeConnector) Provider() string { return "fake" }
func (fakeConnector) Scan(ctx context.Context) ([]cspm.Finding, error) {
	return nil, nil
}

func fakeFactory(ctx context.Context, cfg Config) (Connector, error) {
	return fakeConnector{}, nil
}

func TestRegisterAndNew(t *testing.T) {
	Register("fake", fakeFactory)
	defer delete(factories, "fake")

	c, err := New(context.Background(), Config{Provider: "fake"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Provider() != "fake" {
		t.Fatalf("Provider = %q, want fake", c.Provider())
	}
}

func TestNewUnknownProvider(t *testing.T) {
	if _, err := New(context.Background(), Config{Provider: "does-not-exist"}); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestProvidersSorted(t *testing.T) {
	Register("zprovider", fakeFactory)
	Register("aprovider", fakeFactory)
	defer func() {
		delete(factories, "zprovider")
		delete(factories, "aprovider")
	}()

	got := Providers()
	if len(got) < 2 {
		t.Fatalf("Providers() = %v, want at least 2", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("Providers() not sorted: %v", got)
		}
	}
}
