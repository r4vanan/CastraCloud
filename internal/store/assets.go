package store

import (
	"context"

	"github.com/google/uuid"
)

// ListAssets returns assets for a tenant, computing each asset's risk score as
// the maximum open-finding severity among its linked findings.
func (db *DB) ListAssets(ctx context.Context, tenantID uuid.UUID) ([]Asset, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT a.id, a.tenant_id, a.provider, a.asset_type, a.external_id, a.region, a.name, a.properties,
		        COALESCE((SELECT MAX(f.risk_score) FROM findings f
		                  WHERE f.asset_id = a.id AND f.status = 'open'), 0),
		        a.first_seen, a.last_seen
		 FROM assets a
		 WHERE a.tenant_id = $1
		 ORDER BY a.last_seen DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Asset, 0)
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Provider, &a.AssetType, &a.ExternalID,
			&a.Region, &a.Name, &a.Properties, &a.RiskScore, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
