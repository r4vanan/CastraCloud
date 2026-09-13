import { api, type AttackGraph } from "@/lib/api";

function riskBadge(risk: number) {
  if (risk >= 75) return "critical";
  if (risk >= 50) return "high";
  if (risk >= 25) return "medium";
  return "low";
}

export default async function AttackPathPage() {
  let g: AttackGraph = { nodes: [], edges: [], paths: [] };
  try {
    g = await api.attackPath();
  } catch {
    g = { nodes: [], edges: [], paths: [] };
  }

  const labelById = new Map(g.nodes.map((n) => [n.id, n.label]));

  return (
    <>
      <h1>Attack Paths</h1>

      <div className="card">
        <h2>Exposed assets reachable from the internet</h2>
        {g.paths.length === 0 ? (
          <div className="empty">
            No exposure paths found. Ingest assets with public exposure to see
            attack paths.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Hops</th>
                <th>Risk</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {g.paths.map((p) => (
                <tr key={p.target}>
                  <td>
                    {p.label}{" "}
                    <span className={`badge ${riskBadge(p.risk)}`}>{p.risk}</span>
                  </td>
                  <td>{p.hops}</td>
                  <td>{p.risk}</td>
                  <td className="mono">
                    {p.nodes.map((n) => labelById.get(n) ?? n).join("  →  ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>Exposure edges</h2>
        {g.edges.length === 0 ? (
          <div className="empty">No exposure or relation edges.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>From</th>
                <th>Kind</th>
                <th>To</th>
              </tr>
            </thead>
            <tbody>
              {g.edges.map((e, i) => (
                <tr key={i}>
                  <td className="mono">{labelById.get(e.from) ?? e.from}</td>
                  <td>
                    <span className={`badge ${e.kind === "exposure" ? "critical" : "info"}`}>
                      {e.kind}
                    </span>
                  </td>
                  <td className="mono">{labelById.get(e.to) ?? e.to}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
