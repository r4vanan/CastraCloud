package attack

import (
	"testing"

	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

func asset(t *testing.T, typ, external, name string, props map[string]any) store.Asset {
	t.Helper()
	return store.Asset{
		ID:         uuid.New(),
		Provider:   "aws",
		AssetType:  typ,
		ExternalID: external,
		Name:       name,
		Properties: props,
	}
}

func TestAnalyzeExposureAndRelations(t *testing.T) {
	web := asset(t, "ec2", "i-111", "web-1", map[string]any{
		"public_ip":  "1.2.3.4",
		"related_to": []any{"bucket-prod"},
	})
	bucket := asset(t, "s3", "bucket-prod", "bucket-prod", map[string]any{})
	db := asset(t, "rds", "db-1", "db-1", map[string]any{})

	findings := []store.Finding{
		{AssetID: web.ID, Status: "open", RuleID: "CASTRA-EC2-001", RiskScore: 100},
	}

	g := Analyze([]store.Asset{web, bucket, db}, findings)

	if len(g.Nodes) != 4 { // internet + 3 assets
		t.Fatalf("expected 4 nodes, got %d", len(g.Nodes))
	}

	// exposure edge: internet -> web
	foundExposure := false
	for _, e := range g.Edges {
		if e.From == InternetID && e.To == web.ID.String() && e.Kind == "exposure" {
			foundExposure = true
		}
	}
	if !foundExposure {
		t.Fatal("expected exposure edge from internet to web-1")
	}

	// relation edge: web -> bucket
	foundRelation := false
	for _, e := range g.Edges {
		if e.From == web.ID.String() && e.To == bucket.ID.String() && e.Kind == "relation" {
			foundRelation = true
		}
	}
	if !foundRelation {
		t.Fatal("expected relation edge from web-1 to bucket-prod")
	}

	// paths: web (1 hop), bucket (2 hops); db unreachable
	reachable := map[string]int{}
	for _, p := range g.Paths {
		reachable[p.Target] = p.Hops
	}
	if reachable[web.ID.String()] != 1 {
		t.Fatalf("expected web-1 at 1 hop, got %d", reachable[web.ID.String()])
	}
	if reachable[bucket.ID.String()] != 2 {
		t.Fatalf("expected bucket-prod at 2 hops, got %d", reachable[bucket.ID.String()])
	}
	if _, ok := reachable[db.ID.String()]; ok {
		t.Fatal("db-1 should not be reachable")
	}
}

func TestAnalyzeExposureRule(t *testing.T) {
	bucket := asset(t, "s3", "bucket-public", "bucket-public", map[string]any{})

	g := Analyze([]store.Asset{bucket}, []store.Finding{
		{AssetID: bucket.ID, Status: "open", RuleID: "CASTRA-S3-001", RiskScore: 100},
	})

	if len(g.Paths) != 1 || g.Paths[0].Hops != 1 {
		t.Fatalf("expected a single 1-hop path, got %+v", g.Paths)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	g := Analyze(nil, nil)
	if len(g.Nodes) != 1 || g.Nodes[0].ID != InternetID {
		t.Fatalf("expected only the internet node, got %+v", g.Nodes)
	}
	if len(g.Paths) != 0 || len(g.Edges) != 0 {
		t.Fatalf("expected empty graph, got edges=%d paths=%d", len(g.Edges), len(g.Paths))
	}
}
