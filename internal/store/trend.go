package store

import (
	"context"

	"github.com/google/uuid"
)

// TrendPoint is a single day in a findings trend series.
type TrendPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// FindingTrend returns the number of findings detected per day over the last
// `days` days, zero-filled so the series is continuous for charting.
func (db *DB) FindingTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]TrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	if days > 90 {
		days = 90
	}

	rows, err := db.Pool.Query(ctx, `
		SELECT to_char(days.day, 'YYYY-MM-DD') AS day, COUNT(f.id)::int AS count
		FROM generate_series(
			CURRENT_DATE - ($2 - 1)::int,
			CURRENT_DATE,
			interval '1 day'
		) AS days(day)
		LEFT JOIN findings f
		  ON f.tenant_id = $1
		 AND f.detected_at::date = days.day::date
		GROUP BY days.day
		ORDER BY days.day`, tenantID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]TrendPoint, 0, days)
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Date, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
