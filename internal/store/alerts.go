package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AlertChannel is a notification destination for findings.
type AlertChannel struct {
	ID        uuid.UUID      `json:"id"`
	TenantID  uuid.UUID      `json:"tenant_id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"` // slack | teams | email | webhook | syslog
	Config    map[string]any `json:"config"`
	Enabled   bool           `json:"enabled"`
	CreatedAt time.Time      `json:"created_at"`
}

// ListAlertChannels returns alert channels for a tenant.
func (db *DB) ListAlertChannels(ctx context.Context, tenantID uuid.UUID) ([]AlertChannel, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, tenant_id, name, type, config, enabled, created_at
		 FROM alert_channels WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertChannel, 0)
	for rows.Next() {
		var c AlertChannel
		var cfg []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Type, &cfg, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cfg, &c.Config)
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateAlertChannel inserts a new alert channel.
func (db *DB) CreateAlertChannel(ctx context.Context, c *AlertChannel) error {
	cfg, err := json.Marshal(c.Config)
	if err != nil {
		return err
	}
	return db.Pool.QueryRow(ctx,
		`INSERT INTO alert_channels (tenant_id, name, type, config, enabled)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		c.TenantID, c.Name, c.Type, cfg, c.Enabled).Scan(&c.ID, &c.CreatedAt)
}

// DeleteAlertChannel removes an alert channel.
func (db *DB) DeleteAlertChannel(ctx context.Context, tenantID, id uuid.UUID) error {
	ct, err := db.Pool.Exec(ctx,
		`DELETE FROM alert_channels WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
