package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Subdomain is a discovered DNS name under a managed domain.
type Subdomain struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	DomainID  uuid.UUID `json:"domain_id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// GetDomain returns a single managed domain by id for a tenant.
func (db *DB) GetDomain(ctx context.Context, tenantID, id uuid.UUID) (*Domain, error) {
	d := &Domain{}
	err := db.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, provider, cert_expires_at, created_at
		 FROM domains WHERE id = $1 AND tenant_id = $2`, id, tenantID).
		Scan(&d.ID, &d.TenantID, &d.Name, &d.Provider, &d.CertExpiresAt, &d.CreatedAt)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// ListSubdomains returns discovered subdomains for a domain.
func (db *DB) ListSubdomains(ctx context.Context, domainID uuid.UUID) ([]Subdomain, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, tenant_id, domain_id, name, source, first_seen, last_seen
		 FROM subdomains WHERE domain_id = $1 ORDER BY name`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Subdomain, 0)
	for rows.Next() {
		var s Subdomain
		if err := rows.Scan(&s.ID, &s.TenantID, &s.DomainID, &s.Name, &s.Source, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpsertSubdomain inserts or refreshes a discovered subdomain.
func (db *DB) UpsertSubdomain(ctx context.Context, s *Subdomain) error {
	return db.Pool.QueryRow(ctx,
		`INSERT INTO subdomains (tenant_id, domain_id, name, source)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (domain_id, name)
		 DO UPDATE SET last_seen = now(), source = EXCLUDED.source
		 RETURNING id, first_seen, last_seen`,
		s.TenantID, s.DomainID, s.Name, s.Source).Scan(&s.ID, &s.FirstSeen, &s.LastSeen)
}

// UpdateDomainCertExpiry records a domain's certificate expiry.
func (db *DB) UpdateDomainCertExpiry(ctx context.Context, domainID uuid.UUID, t time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE domains SET cert_expires_at = $1 WHERE id = $2`, t, domainID)
	return err
}

// ErrDomainNotFound is returned when a domain does not exist.
var ErrDomainNotFound = pgx.ErrNoRows
