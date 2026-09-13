// Package connector defines the pluggable cloud-connector SDK. New cloud
// providers (GCP, Azure, OCI, ...) are added by implementing the Connector
// interface and registering a Factory, without touching core code.
package connector

import (
	"context"
	"fmt"
	"sort"

	"github.com/castracloud/castracloud/internal/cspm"
)

// Connector scans a single cloud provider and returns CSPM findings.
type Connector interface {
	Provider() string
	Scan(ctx context.Context) ([]cspm.Finding, error)
}

// Config carries the provider name, region, and decrypted credentials for a
// connector instance.
type Config struct {
	Provider    string
	Region      string
	Credentials string // decrypted read-only credentials (JSON)
}

// Factory constructs a Connector from a Config.
type Factory func(ctx context.Context, cfg Config) (Connector, error)

var factories = map[string]Factory{}

// Register adds a provider factory. Called from provider packages' init().
func Register(provider string, f Factory) {
	factories[provider] = f
}

// New builds a connector for the given provider.
func New(ctx context.Context, cfg Config) (Connector, error) {
	f, ok := factories[cfg.Provider]
	if !ok {
		return nil, fmt.Errorf("connector: unknown provider %q", cfg.Provider)
	}
	return f(ctx, cfg)
}

// Providers returns the registered provider names, sorted.
func Providers() []string {
	out := make([]string, 0, len(factories))
	for p := range factories {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
