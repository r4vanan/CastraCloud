package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListConnectors returns all configured cloud account integrations for a tenant.
func (db *DB) ListConnectors(ctx context.Context, tenantID uuid.UUID) ([]CloudConnector, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, tenant_id, name, provider, region, credentials_encrypted, status, last_scanned_at, created_at
		 FROM cloud_connectors WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CloudConnector, 0)
	for rows.Next() {
		var c CloudConnector
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Provider, &c.Region, &c.CredentialsEncrypted, &c.Status, &c.LastScannedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllConnectors returns every configured connector across all tenants.
func (db *DB) ListAllConnectors(ctx context.Context) ([]CloudConnector, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, tenant_id, name, provider, region, credentials_encrypted, status, last_scanned_at, created_at
		 FROM cloud_connectors ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CloudConnector, 0)
	for rows.Next() {
		var c CloudConnector
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Provider, &c.Region, &c.CredentialsEncrypted, &c.Status, &c.LastScannedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateConnector inserts a new cloud connector configuration.
func (db *DB) CreateConnector(ctx context.Context, c *CloudConnector) error {
	if c.Status == "" {
		c.Status = "connected"
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.CredentialsEncrypted == nil {
		c.CredentialsEncrypted = []byte{}
	}
	return db.Pool.QueryRow(ctx,
		`INSERT INTO cloud_connectors (tenant_id, name, provider, region, credentials_encrypted, status)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 RETURNING id, created_at`,
		c.TenantID, c.Name, c.Provider, c.Region, c.CredentialsEncrypted, c.Status).
		Scan(&c.ID, &c.CreatedAt)
}

// DeleteConnector removes a cloud connector configuration.
func (db *DB) DeleteConnector(ctx context.Context, tenantID, id uuid.UUID) error {
	ct, err := db.Pool.Exec(ctx,
		`DELETE FROM cloud_connectors WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateConnectorScanTime marks the last successful scan timestamp.
func (db *DB) UpdateConnectorScanTime(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE cloud_connectors SET last_scanned_at = now() WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

// GetConnector fetches a single cloud connector by ID.
func (db *DB) GetConnector(ctx context.Context, tenantID, id uuid.UUID) (*CloudConnector, error) {
	c := &CloudConnector{}
	err := db.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, provider, region, credentials_encrypted, status, last_scanned_at, created_at
		 FROM cloud_connectors WHERE id = $1 AND tenant_id = $2`, id, tenantID).
		Scan(&c.ID, &c.TenantID, &c.Name, &c.Provider, &c.Region, &c.CredentialsEncrypted, &c.Status, &c.LastScannedAt, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}
