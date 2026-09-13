import { api, type Finding, type Summary } from "@/lib/api";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function pct(n: number, total: number): string {
  return total > 0 ? `${Math.round((n / total) * 100)}%` : "0%";
}

function grade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export default async function Dashboard() {
  let summary: Summary = {
    posture_score: 100,
    total: 0,
    open: 0,
    resolved: 0,
    suppressed: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  };
  let findings: Finding[] = [];
  try {
    summary = await api.summary();
    findings = await api.findings();
  } catch {
    // leave defaults on error
  }

  const g = grade(summary.posture_score);

  return (
    <>
      <h1>Dashboard</h1>

      <div className="stat">
        <div className="card score-card">
          <div className="score-head">
            <div className="value">{summary.posture_score}</div>
            <div className={`grade grade-${g.toLowerCase()}`}>{g}</div>
          </div>
          <div className="label">Posture score</div>
        </div>
        <div className="card">
          <div className="value">{summary.total}</div>
          <div className="label">Total findings</div>
        </div>
        <div className="card">
          <div className="value">{summary.open}</div>
          <div className="label">Open</div>
        </div>
        <div className="card">
          <div className="value">{summary.resolved}</div>
          <div className="label">Resolved</div>
        </div>
      </div>

      <div className="card">
        <h2>Open findings by severity</h2>
        <div className="severity-bars">
          {SEVERITIES.map((s) => (
            <div key={s} className="severity-row">
              <span className={`badge ${s}`}>{s}</span>
              <div className="bar">
                <div
                  className={`fill ${s}`}
                  style={{ width: pct(summary.by_severity[s], summary.open) }}
                />
              </div>
              <span className="count">{summary.by_severity[s]}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2>Recent findings</h2>
        {findings.length === 0 ? (
          <div className="empty">No findings yet. Run a CSPM scan to get started.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Source</th>
                <th>Status</th>
                <th>Detected</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 10).map((f) => (
                <tr key={f.id}>
                  <td>
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                  </td>
                  <td>{f.title}</td>
                  <td>{f.source}</td>
                  <td>{f.status}</td>
                  <td>{new Date(f.detected_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
