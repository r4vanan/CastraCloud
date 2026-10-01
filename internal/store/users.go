package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListUsers returns all users in a tenant, excluding password hashes.
func (db *DB) ListUsers(ctx context.Context, tenantID uuid.UUID) ([]User, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, tenant_id, email, role, full_name, is_active, mfa_enabled, created_at
		 FROM users WHERE tenant_id = $1 ORDER BY created_at ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.FullName, &u.IsActive, &u.MFAEnabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser updates a user's role and/or active status within a tenant.
func (db *DB) UpdateUser(ctx context.Context, tenantID, userID uuid.UUID, role *string, isActive *bool) (*User, error) {
	u := &User{}
	err := db.Pool.QueryRow(ctx,
		`UPDATE users
		 SET role = COALESCE($3, role), is_active = COALESCE($4, is_active), updated_at = now()
		 WHERE id = $1 AND tenant_id = $2
		 RETURNING id, tenant_id, email, role, full_name, is_active, mfa_enabled, created_at`,
		userID, tenantID, role, isActive).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.FullName, &u.IsActive, &u.MFAEnabled, &u.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// DeactivateUser soft-deletes a user by setting is_active = false.
func (db *DB) DeactivateUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	ct, err := db.Pool.Exec(ctx,
		`UPDATE users SET is_active = false, updated_at = now() WHERE id = $1 AND tenant_id = $2 AND is_active = true`,
		userID, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
