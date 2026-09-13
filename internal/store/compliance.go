package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Framework is a compliance framework (CIS, NIST CSF, ISO 27001, ...).
type Framework struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// Control is a compliance control within a framework.
type Control struct {
	ID          uuid.UUID `json:"id"`
	FrameworkID uuid.UUID `json:"framework_id"`
	ControlID   string    `json:"control_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
}

// UpsertFramework creates or updates a framework for a tenant.
func (db *DB) UpsertFramework(ctx context.Context, tenantID uuid.UUID, name, version string) (*Framework, error) {
	f := &Framework{TenantID: tenantID}
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO compliance_frameworks (tenant_id, name, version)
		 VALUES ($1,$2,$3)
		 ON CONFLICT (tenant_id, name, version) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id, name, version, created_at`,
		tenantID, name, version).Scan(&f.ID, &f.Name, &f.Version, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// UpsertControl creates or updates a control within a framework.
func (db *DB) UpsertControl(ctx context.Context, frameworkID uuid.UUID, controlID, title, description string) (*Control, error) {
	c := &Control{FrameworkID: frameworkID}
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO compliance_controls (framework_id, control_id, title, description)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (framework_id, control_id) DO UPDATE
		   SET title = EXCLUDED.title, description = EXCLUDED.description
		 RETURNING id, control_id, title, description`,
		frameworkID, controlID, title, description).Scan(&c.ID, &c.ControlID, &c.Title, &c.Description)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// MapRuleControl associates a rule with a compliance control.
func (db *DB) MapRuleControl(ctx context.Context, ruleID string, controlID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO rule_controls (rule_id, control_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		ruleID, controlID)
	return err
}

// ListFrameworks returns compliance frameworks for a tenant with control counts.
func (db *DB) ListFrameworks(ctx context.Context, tenantID uuid.UUID) ([]Framework, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT f.id, f.tenant_id, f.name, f.version, f.created_at
		 FROM compliance_frameworks f
		 WHERE f.tenant_id = $1 ORDER BY f.name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Framework, 0)
	for rows.Next() {
		var f Framework
		if err := rows.Scan(&f.ID, &f.TenantID, &f.Name, &f.Version, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListControls returns controls for a framework.
func (db *DB) ListControls(ctx context.Context, frameworkID uuid.UUID) ([]Control, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, framework_id, control_id, title, description
		 FROM compliance_controls WHERE framework_id = $1 ORDER BY control_id`, frameworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Control, 0)
	for rows.Next() {
		var c Control
		if err := rows.Scan(&c.ID, &c.FrameworkID, &c.ControlID, &c.Title, &c.Description); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListControlsForRule returns controls mapped to a detection rule.
func (db *DB) ListControlsForRule(ctx context.Context, ruleID string) ([]Control, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT c.id, c.framework_id, c.control_id, c.title, c.description
		 FROM rule_controls rc
		 JOIN compliance_controls c ON c.id = rc.control_id
		 WHERE rc.rule_id = $1 ORDER BY c.control_id`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Control, 0)
	for rows.Next() {
		var c Control
		if err := rows.Scan(&c.ID, &c.FrameworkID, &c.ControlID, &c.Title, &c.Description); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
