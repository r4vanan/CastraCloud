package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetMFAPendingSecret stores an encrypted TOTP secret awaiting verification.
func (db *DB) SetMFAPendingSecret(ctx context.Context, userID uuid.UUID, encrypted []byte) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET mfa_pending_secret_encrypted = $1 WHERE id = $2`, encrypted, userID)
	return err
}

// GetMFAPendingSecret returns the encrypted pending TOTP secret, or nil.
func (db *DB) GetMFAPendingSecret(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	var b []byte
	err := db.Pool.QueryRow(ctx,
		`SELECT mfa_pending_secret_encrypted FROM users WHERE id = $1`, userID).Scan(&b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// EnableMFA promotes the pending secret to the active secret and flips the
// mfa_enabled flag.
func (db *DB) EnableMFA(ctx context.Context, userID uuid.UUID, encrypted []byte) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET mfa_secret_encrypted = $1, mfa_pending_secret_encrypted = NULL, mfa_enabled = true WHERE id = $2`,
		encrypted, userID)
	return err
}

// GetMFASecret returns the encrypted active TOTP secret, or nil.
func (db *DB) GetMFASecret(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	var b []byte
	err := db.Pool.QueryRow(ctx,
		`SELECT mfa_secret_encrypted FROM users WHERE id = $1`, userID).Scan(&b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DisableMFA clears MFA state and deletes any recovery codes.
func (db *DB) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	return db.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET mfa_enabled = false, mfa_secret_encrypted = NULL, mfa_pending_secret_encrypted = NULL WHERE id = $1`,
			userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		return nil
	})
}

// ReplaceRecoveryCodes atomically swaps a user's recovery-code set.
func (db *DB) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error {
	return db.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// ConsumeRecoveryCode deletes a single recovery code if it exists, reporting
// whether it was present (and therefore valid).
func (db *DB) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, hash []byte) (bool, error) {
	ct, err := db.Pool.Exec(ctx,
		`DELETE FROM mfa_recovery_codes WHERE user_id = $1 AND code_hash = $2`, userID, hash)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}
