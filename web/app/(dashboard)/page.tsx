import { api, type Asset, type Finding, type Summary, type TrendPoint } from "@/lib/api";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#9ca3af",
};
const PROVIDER_COLORS: Record<string, string> = {
  aws: "#f97316",
  gcp: "#eab308",
  azure: "#0ea5e9",
};

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

function scoreColor(score: number): string {
  if (score >= 90) return "#22c55e";
  if (score >= 75) return "#84cc16";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

function riskLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score > 0) return "low";
  return "info";
}

function polar(cx: number, cy: number, r: number, deg: number) {
  const a = ((deg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
}

function sectorPath(cx: number, cy: number, r: number, startDeg: number, endDeg: number) {
  const s = polar(cx, cy, r, endDeg);
  const e = polar(cx, cy, r, startDeg);
  const largeArc = endDeg - startDeg > 180 ? 1 : 0;
  return `M ${cx} ${cy} L ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y} Z`;
}

function RingGauge({ value, color }: { value: number; color: string }) {
  const R = 56;
  const C = 2 * Math.PI * R;
  const frac = Math.max(0, Math.min(100, value)) / 100;
  return (
    <svg viewBox="0 0 140 140" width="140" height="140" role="img" aria-label="Posture score">
      <circle cx="70" cy="70" r={R} fill="none" stroke="var(--border)" strokeWidth="14" />
      <circle
        cx="70"
        cy="70"
        r={R}
        fill="none"
        stroke={color}
        strokeWidth="14"
        strokeLinecap="round"
        strokeDasharray={`${frac * C} ${C}`}
        transform="rotate(-90 70 70)"
      />
      <text x="70" y="64" textAnchor="middle" fill="var(--text-strong)" fontSize="34" fontWeight="700">
        {value}
      </text>
      <text x="70" y="86" textAnchor="middle" fill="var(--text-muted)" fontSize="12">
        / 100
      </text>
    </svg>
  );
}

function Donut({ data }: { data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const cx = 80;
  const cy = 80;
  const r = 60;
  let angle = 0;
  return (
    <svg viewBox="0 0 160 160" width="140" height="140" role="img" aria-label="Severity distribution">
      {total === 0 ? (
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border)" strokeWidth="20" />
      ) : (
        data.map((d) => {
          if (d.value <= 0) return null;
          const sweep = (d.value / total) * 360;
          const seg = <path key={d.label} d={sectorPath(cx, cy, r, angle, angle + sweep)} fill={d.color} />;
          angle += sweep;
          return seg;
        })
      )}
      <circle cx={cx} cy={cy} r={40} fill="var(--surface)" />
      <text x={cx} y={cy - 6} textAnchor="middle" fill="var(--text-strong)" fontSize="24" fontWeight="700">
        {total}
      </text>
      <text x={cx} y={cy + 16} textAnchor="middle" fill="var(--text-muted)" fontSize="11">
        findings
      </text>
    </svg>
  );
}

function AreaChart({ data }: { data: TrendPoint[] }) {
  const w = 760;
  const h = 150;
  const padL = 34;
  const padR = 12;
  const padT = 14;
  const padB = 30;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const max = Math.max(1, ...data.map((d) => d.count));
  const step = data.length > 1 ? plotW / (data.length - 1) : plotW;
  const x = (i: number) => padL + i * step;
  const y = (v: number) => padT + plotH - (v / max) * plotH;

  if (data.length < 2) {
    return <div className="empty">Not enough data yet.</div>;
  }

  const line = data.map((d, i) => `${i === 0 ? "M" : "L"} ${x(i)} ${y(d.count)}`).join(" ");
  const area = `${line} L ${x(data.length - 1)} ${padT + plotH} L ${x(0)} ${padT + plotH} Z`;

  const tickFractions = [0, 0.25, 0.5, 0.75, 1];
  const labelStep = Math.max(1, Math.ceil(data.length / 6));

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Findings detected over time">
      {tickFractions.map((f) => {
        const yy = padT + plotH - f * plotH;
        const val = Math.round(f * max);
        return (
          <g key={f}>
            <line x1={padL} y1={yy} x2={w - padR} y2={yy} stroke="var(--border)" strokeWidth="1" />
            <text x={padL - 6} y={yy + 4} textAnchor="end" fill="var(--text-muted)" fontSize="11">
              {val}
            </text>
          </g>
        );
      })}
      <path d={area} fill="var(--accent)" fillOpacity="0.12" />
      <path d={line} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      {data.map((d, i) =>
        i % labelStep === 0 ? (
          <text key={d.date} x={x(i)} y={h - 10} textAnchor="middle" fill="var(--text-muted)" fontSize="11">
            {d.date.slice(5)}
          </text>
        ) : null,
      )}
    </svg>
  );
}

function HBarList({ rows }: { rows: { label: string; value: number; color: string; max: number }[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {rows.map((r) => (
        <div key={r.label}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 4 }}>
            <span className="mono" style={{ color: "var(--text-muted)" }}>{r.label}</span>
            <span style={{ color: "var(--text-strong)", fontWeight: 600 }}>{r.value}</span>
          </div>
          <div style={{ height: 10, background: "var(--border)", borderRadius: 5, overflow: "hidden" }}>
            <div style={{ width: pct(r.value, r.max), height: "100%", background: r.color, borderRadius: 5 }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export default async function Dashboard() {
  let summary: Summary = {
    posture_score: 0,
    total: 0,
    open: 0,
    resolved: 0,
    suppressed: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  };
  let findings: Finding[] = [];
  let trend: TrendPoint[] = [];
  let assets: Asset[] = [];
  let loaded = false;

  try {
    [summary, findings, trend, assets] = await Promise.all([
      api.summary(),
      api.findings(),
      api.trend(30),
      api.assets(),
    ]);
    loaded = true;
  } catch {
    // leave defaults on error
  }

  const g = grade(summary.posture_score);
  const color = scoreColor(summary.posture_score);

  const severityData = SEVERITIES.map((s) => ({
    label: s,
    value: summary.by_severity[s],
    color: SEVERITY_COLORS[s],
  }));

  const providerCounts: Record<string, number> = {};
  for (const a of assets) {
    providerCounts[a.provider] = (providerCounts[a.provider] ?? 0) + 1;
  }
  const providerRows = Object.entries(providerCounts).map(([label, value]) => ({
    label: label.toUpperCase(),
    value,
    color: PROVIDER_COLORS[label] ?? "var(--accent)",
    max: assets.length,
  }));

  const riskyAssets = [...assets].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);

  return (
    <>
      <h1>Dashboard</h1>

      {loaded && summary.total === 0 && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16 }}>
            <div>
              <h2 style={{ margin: 0 }}>Welcome to CastraCloud</h2>
              <p className="subtext" style={{ marginTop: 6 }}>
                Connect a cloud account and run a scan to start discovering security findings.
              </p>
            </div>
            <a className="btn" href="/connectors" style={{ textDecoration: "none", whiteSpace: "nowrap" }}>
              Connect cloud account
            </a>
          </div>
        </div>
      )}

      <div className="stat">
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
        <div className="card">
          <div className="value">{summary.suppressed}</div>
          <div className="label">Suppressed</div>
        </div>
        <div className="card">
          <div className="value">{assets.length}</div>
          <div className="label">Assets</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <div className="card" style={{ flex: 1, minWidth: 280, display: "flex", flexDirection: "column", alignItems: "center" }}>
          <h2 style={{ alignSelf: "flex-start", width: "100%" }}>Security posture</h2>
          <RingGauge value={loaded ? summary.posture_score : 0} color={color} />
          <div style={{ marginTop: 8, textAlign: "center" }}>
            <span className={`grade grade-${g.toLowerCase()}`} style={{ fontSize: 14, padding: "2px 12px" }}>
              Grade {loaded ? g : "—"}
            </span>
          </div>
        </div>

        <div className="card" style={{ flex: 1, minWidth: 280 }}>
          <h2>Findings by severity</h2>
          <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 16 }}>
            <Donut data={severityData} />
            <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 13 }}>
              {severityData.map((d) => (
                <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 3, background: d.color, display: "inline-block" }} />
                  <span style={{ color: "var(--text-muted)", textTransform: "capitalize" }}>{d.label}</span>
                  <span style={{ color: "var(--text-strong)", fontWeight: 600 }}>{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2>Findings detected — last 30 days</h2>
        <AreaChart data={trend} />
      </div>

      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <div className="card" style={{ flex: 1, minWidth: 280 }}>
          <h2>Assets by provider</h2>
          {providerRows.length === 0 ? (
            <div className="empty">No assets discovered yet.</div>
          ) : (
            <HBarList rows={providerRows} />
          )}
        </div>

        <div className="card" style={{ flex: 1, minWidth: 280 }}>
          <h2>Top risky assets</h2>
          {riskyAssets.length === 0 ? (
            <div className="empty">No assets discovered yet.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {riskyAssets.map((a) => {
                const level = riskLevel(a.risk_score);
                return (
                  <div key={a.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-strong)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {a.name || a.external_id}
                      </div>
                      <div className="subtext">{a.asset_type} · {a.provider.toUpperCase()}</div>
                    </div>
                    <span className={`badge ${level}`}>{a.risk_score}</span>
                  </div>
                );
              })}
            </div>
          )}
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
