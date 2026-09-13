// Package attack builds an attack-path graph over cloud assets, modelling how
// an external attacker can reach sensitive resources through internet-facing
// exposures and inter-asset relationships.
package attack

import (
	"sort"

	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// Node is a vertex in the attack graph.
type Node struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // internet | asset
	Type  string `json:"type,omitempty"`
	Risk  int    `json:"risk"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // exposure | relation
}

// Path is a reachable route from the internet to an asset.
type Path struct {
	Target string   `json:"target"`
	Label  string   `json:"label"`
	Nodes  []string `json:"nodes"`
	Hops   int      `json:"hops"`
	Risk   int      `json:"risk"`
}

// Graph is the computed attack surface.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Paths []Path `json:"paths"`
}

// InternetID is the synthetic attacker source node.
const InternetID = "internet"

// exposureRules mark findings whose presence makes an asset internet-facing.
var exposureRules = map[string]bool{
	"CASTRA-S3-001":  true, // S3 bucket publicly accessible
	"CASTRA-S3-002":  true, // S3 missing block public access
	"CASTRA-EC2-001": true, // security group open to the internet
	"CASTRA-DOM-001": true, // subdomain takeover
	"CASTRA-DOM-003": true, // shadow IT / unregistered subdomain
}

// Analyze computes the attack graph for a tenant's assets and findings.
func Analyze(assets []store.Asset, findings []store.Finding) Graph {
	g := Graph{
		Nodes: []Node{{ID: InternetID, Label: "Internet", Kind: "internet", Risk: 0}},
		Edges: []Edge{},
		Paths: []Path{},
	}

	riskByAsset := map[string]int{}
	exposedRule := map[string]bool{}
	for _, f := range findings {
		if f.Status != "open" || f.AssetID == uuid.Nil {
			continue
		}
		id := f.AssetID.String()
		if f.RiskScore > riskByAsset[id] {
			riskByAsset[id] = f.RiskScore
		}
		if exposureRules[f.RuleID] {
			exposedRule[id] = true
		}
	}

	byID := map[string]Node{}
	byExternal := map[string]string{}
	byName := map[string]string{}
	for _, a := range assets {
		id := a.ID.String()
		label := a.Name
		if label == "" {
			label = a.ExternalID
		}
		n := Node{ID: id, Label: label, Kind: "asset", Type: a.AssetType, Risk: riskByAsset[id]}
		g.Nodes = append(g.Nodes, n)
		byID[id] = n
		byExternal[a.ExternalID] = id
		if a.Name != "" {
			byName[a.Name] = id
		}
	}

	for _, a := range assets {
		id := a.ID.String()
		if isExposed(a.Properties, exposedRule[id]) {
			g.Edges = append(g.Edges, Edge{From: InternetID, To: id, Kind: "exposure"})
		}
		for _, ref := range relatedTo(a.Properties) {
			if dst, ok := byExternal[ref]; ok && dst != id {
				g.Edges = append(g.Edges, Edge{From: id, To: dst, Kind: "relation"})
			} else if dst, ok := byName[ref]; ok && dst != id {
				g.Edges = append(g.Edges, Edge{From: id, To: dst, Kind: "relation"})
			}
		}
	}

	g.Paths = computePaths(g, byID)
	return g
}

// isExposed reports whether an asset is reachable from the internet.
func isExposed(props map[string]any, hasExposureRule bool) bool {
	if hasExposureRule {
		return true
	}
	for _, k := range []string{"public_ip", "public", "exposed"} {
		v, ok := props[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case bool:
			if t {
				return true
			}
		case string:
			if t != "" && t != "false" && t != "0" {
				return true
			}
		}
	}
	return false
}

// relatedTo extracts inter-asset references from an asset's properties.
func relatedTo(props map[string]any) []string {
	raw, ok := props["related_to"]
	if !ok {
		return nil
	}
	var out []string
	switch t := raw.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, t...)
	case string:
		out = append(out, t)
	}
	return out
}

// computePaths runs BFS from the internet node and reconstructs shortest paths
// to each reachable asset.
func computePaths(g Graph, byID map[string]Node) []Path {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	prev := map[string]string{}
	visited := map[string]bool{InternetID: true}
	queue := []string{InternetID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range adj[cur] {
			if visited[nxt] {
				continue
			}
			visited[nxt] = true
			prev[nxt] = cur
			queue = append(queue, nxt)
		}
	}

	paths := make([]Path, 0)
	for id, n := range byID {
		if !visited[id] {
			continue
		}
		var nodes []string
		for cur := id; cur != ""; cur = prev[cur] {
			nodes = append(nodes, cur)
		}
		// reverse to get internet -> ... -> target
		for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
			nodes[i], nodes[j] = nodes[j], nodes[i]
		}
		paths = append(paths, Path{
			Target: id,
			Label:  n.Label,
			Nodes:  nodes,
			Hops:   len(nodes) - 1,
			Risk:   n.Risk,
		})
	}

	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Hops != paths[j].Hops {
			return paths[i].Hops < paths[j].Hops
		}
		return paths[i].Risk > paths[j].Risk
	})
	return paths
}
