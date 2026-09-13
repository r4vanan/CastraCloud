// Package store contains the domain models and PostgreSQL persistence layer.
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tenant is a multi-tenant account (a Wiz-like "organization").
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// User is an authenticated operator within a tenant.
type User struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Email        string    `json:"email"`
	Role         string    `json:"role"` // owner | admin | analyst | viewer
	FullName     string    `json:"full_name"`
	IsActive     bool      `json:"is_active"`
	PasswordHash string    `json:"-"` // never serialized
	CreatedAt    time.Time `json:"created_at"`
}

// Asset is a discovered cloud resource.
type Asset struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	Provider   string    `json:"provider"` // aws | azure | gcp
	AssetType  string    `json:"asset_type"`
	ExternalID string    `json:"external_id"`
	Region     string    `json:"region"`
	Name       string    `json:"name"`
	Properties map[string]any `json:"properties"`
	RiskScore  int       `json:"risk_score"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Finding is a security issue detected by CSPM or the WAF.
type Finding struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	AssetID     uuid.UUID `json:"asset_id,omitempty"`
	Source      string    `json:"source"` // cspm | waf | domain
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"` // critical | high | medium | low | info
	Status      string    `json:"status"`   // open | resolved | suppressed
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	RiskScore   int       `json:"risk_score"`
	DetectedAt  time.Time `json:"detected_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// FindingSummary aggregates finding counts for the dashboard.
type FindingSummary struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	Resolved   int `json:"resolved"`
	Suppressed int `json:"suppressed"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
}

// WAFRule defines a Web Application Firewall rule.
type WAFRule struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Phase       string    `json:"phase"`   // request | response
	Action      string    `json:"action"`  // block | allow | log | challenge
	Match       string    `json:"match"`   // condition (operator:field:pattern)
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
}

// Domain is a managed DNS zone.
type Domain struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Name          string     `json:"name"`
	Provider      string     `json:"provider"` // route53 | cloudflare | ...
	CertExpiresAt *time.Time `json:"cert_expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// DNSRecord is a record within a Domain.
type DNSRecord struct {
	ID       uuid.UUID `json:"id"`
	DomainID uuid.UUID `json:"domain_id"`
	Type     string    `json:"type"` // A | AAAA | CNAME | TXT | MX ...
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	TTL      int       `json:"ttl"`
}

// DB wraps the connection pool and exposes typed queries.
type DB struct {
	Pool *pgxpool.Pool
}

// New connects to Postgres and verifies connectivity.
func New(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.Pool.Close() }

// Migrate applies embedded SQL migrations from the migrations directory.
func (db *DB) Migrate(ctx context.Context, migrationsDir string) error {
	// Simple, dependency-free runner: apply *.sql files in lexical order
	// only if not already recorded in schema_migrations.
	_, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	if err != nil {
		return err
	}
	return applyMigrations(ctx, db.Pool, migrationsDir)
}

// tx begins a transaction and commits/rolls back on fn error.
func (db *DB) tx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
