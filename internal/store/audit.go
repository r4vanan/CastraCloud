package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// CreateAuditLog records a platform action for the audit trail.
func (db *DB) CreateAuditLog(ctx context.Context, tenantID uuid.UUID, actor, action, resource string, metadata map[string]any) error {
	meta, err := json.Marshal(metadata)
	if err != nil {
		meta = []byte("{}")
	}
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO audit_logs (tenant_id, actor, action, resource, metadata)
		 VALUES ($1,$2,$3,$4,$5)`,
		tid, actor, action, resource, meta)
	return err
}
