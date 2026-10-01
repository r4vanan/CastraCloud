package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// EnsureTenant finds a tenant by slug or creates it.
func (db *DB) EnsureTenant(ctx context.Context, slug, name string) (*Tenant, error) {
	t := &Tenant{}
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, $2)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id, name, slug, created_at`,
		slug, name).Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// CreateUser inserts a new user into a tenant.
func (db *DB) CreateUser(ctx context.Context, tenantID uuid.UUID, email, role string) (*User, error) {
	u := &User{TenantID: tenantID}
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, role) VALUES ($1, $2, $3)
		 RETURNING id, tenant_id, email, role`,
		tenantID, email, role).Scan(&u.ID, &u.TenantID, &u.Email, &u.Role)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUserWithPassword inserts a new user with a password hash.
func (db *DB) CreateUserWithPassword(ctx context.Context, tenantID uuid.UUID, email, fullName, role, passwordHash string) (*User, error) {
	u := &User{TenantID: tenantID}
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, role, full_name, password_hash)
		 VALUES ($1,$2,$3,$4,$5)
		 RETURNING id, tenant_id, email, role, full_name, is_active, mfa_enabled, created_at`,
		tenantID, email, role, fullName, passwordHash).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.FullName, &u.IsActive, &u.MFAEnabled, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByEmail fetches a user (including password hash) by email.
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := db.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, role, full_name, is_active, mfa_enabled, password_hash, created_at
		 FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.FullName, &u.IsActive, &u.MFAEnabled, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByID fetches a user by ID.
func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	u := &User{}
	err := db.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, role, full_name, is_active, mfa_enabled, created_at
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.FullName, &u.IsActive, &u.MFAEnabled, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CountUsers returns the number of users in a tenant (used for owner bootstrap).
func (db *DB) CountUsers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = $1`, tenantID).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpsertAsset inserts or refreshes a discovered asset.
func (db *DB) UpsertAsset(ctx context.Context, a *Asset) error {
	props, err := json.Marshal(a.Properties)
	if err != nil {
		return err
	}
	return db.Pool.QueryRow(ctx,
		`INSERT INTO assets (tenant_id, provider, asset_type, external_id, region, name, properties)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (tenant_id, provider, asset_type, external_id)
		 DO UPDATE SET name = EXCLUDED.name, properties = EXCLUDED.properties, last_seen = now()
		 RETURNING id`,
		a.TenantID, a.Provider, a.AssetType, a.ExternalID, a.Region, a.Name, props).
		Scan(&a.ID)
}

// IngestFinding stores a finding, linking it to its asset if known. It skips
// (returns false) when an identical open finding already exists, so re-scanning
// the same account does not create duplicates.
func (db *DB) IngestFinding(ctx context.Context, f *Finding) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM findings
			WHERE tenant_id = $1 AND source = $2 AND rule_id = $3
			  AND asset_id IS NOT DISTINCT FROM $4 AND status = 'open'
		)`, f.TenantID, f.Source, f.RuleID, nullUUID(f.AssetID)).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	err = db.Pool.QueryRow(ctx,
		`INSERT INTO findings (tenant_id, asset_id, source, rule_id, title, severity, status, description, remediation, risk_score)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id, detected_at`,
		f.TenantID, nullUUID(f.AssetID), f.Source, f.RuleID, f.Title, f.Severity, f.Status,
		f.Description, f.Remediation, f.RiskScore).
		Scan(&f.ID, &f.DetectedAt)
	if err != nil {
		return false, err
	}
	return true, nil
}

// nullUUID returns nil when id is the zero UUID, so the column stays NULL.
func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// ListFindings returns findings for a tenant, optionally filtered.
func (db *DB) ListFindings(ctx context.Context, tenantID uuid.UUID, severity, status string, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT id, tenant_id, asset_id, source, rule_id, title, severity, status, description, remediation, risk_score, detected_at, resolved_at
		 FROM findings
		 WHERE tenant_id = $1
		   AND ($2 = '' OR severity = $2)
		   AND ($3 = '' OR status = $3)
		 ORDER BY detected_at DESC
		 LIMIT $4`,
		tenantID, severity, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.TenantID, &f.AssetID, &f.Source, &f.RuleID, &f.Title,
			&f.Severity, &f.Status, &f.Description, &f.Remediation, &f.RiskScore, &f.DetectedAt, &f.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFinding fetches a single finding by id for a tenant.
func (db *DB) GetFinding(ctx context.Context, tenantID, id uuid.UUID) (*Finding, error) {
	f := &Finding{}
	err := db.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, asset_id, source, rule_id, title, severity, status, description, remediation, risk_score, detected_at, resolved_at
		 FROM findings WHERE id = $1 AND tenant_id = $2`, id, tenantID).
		Scan(&f.ID, &f.TenantID, &f.AssetID, &f.Source, &f.RuleID, &f.Title,
			&f.Severity, &f.Status, &f.Description, &f.Remediation, &f.RiskScore, &f.DetectedAt, &f.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// UpdateFindingStatus resolves or suppresses a finding.
func (db *DB) UpdateFindingStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	ct, err := db.Pool.Exec(ctx,
		`UPDATE findings SET status = $1, resolved_at = CASE WHEN $1 = 'resolved' THEN now() ELSE resolved_at END
		 WHERE id = $2 AND tenant_id = $3`,
		status, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindingSummary aggregates finding counts for the dashboard. Severity counts
// are restricted to open findings so the posture score reflects current risk.
func (db *DB) FindingSummary(ctx context.Context, tenantID uuid.UUID) (*FindingSummary, error) {
	s := &FindingSummary{}
	err := db.Pool.QueryRow(ctx,
		`SELECT
			COUNT(*)                                                        AS total,
			COUNT(*) FILTER (WHERE status = 'open')                         AS open_count,
			COUNT(*) FILTER (WHERE status = 'resolved')                     AS resolved_count,
			COUNT(*) FILTER (WHERE status = 'suppressed')                   AS suppressed_count,
			COUNT(*) FILTER (WHERE status = 'open' AND severity = 'critical') AS critical,
			COUNT(*) FILTER (WHERE status = 'open' AND severity = 'high')     AS high,
			COUNT(*) FILTER (WHERE status = 'open' AND severity = 'medium')   AS medium,
			COUNT(*) FILTER (WHERE status = 'open' AND severity = 'low')      AS low,
			COUNT(*) FILTER (WHERE status = 'open' AND severity = 'info')     AS info
		 FROM findings WHERE tenant_id = $1`, tenantID).
		Scan(&s.Total, &s.Open, &s.Resolved, &s.Suppressed, &s.Critical, &s.High, &s.Medium, &s.Low, &s.Info)
	if err != nil {
		return nil, err
	}
	return s, nil
}
