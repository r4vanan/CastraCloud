package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PasswordResetToken is a single-use password-reset token record.
type PasswordResetToken struct {
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// CreatePasswordResetToken stores a hashed reset token for a user.
func (db *DB) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expiresAt)
	return err
}

// GetPasswordResetToken returns a reset token record by its hash.
func (db *DB) GetPasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error) {
	t := &PasswordResetToken{}
	err := db.Pool.QueryRow(ctx,
		`SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = $1`, tokenHash).
		Scan(&t.UserID, &t.ExpiresAt, &t.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ConsumePasswordResetToken marks a token as used.
func (db *DB) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) error {
	ct, err := db.Pool.Exec(ctx,
		`UPDATE password_reset_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL`, tokenHash)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateUserPassword sets a user's password hash.
func (db *DB) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	ct, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, passwordHash, userID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
