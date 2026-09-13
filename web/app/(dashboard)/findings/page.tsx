import { api, type Finding } from "@/lib/api";
import Filters from "./filters";
import StatusActions from "./status-actions";

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: { severity?: string; status?: string };
}) {
  const severity = searchParams.severity ?? "";
  const status = searchParams.status ?? "";

  let findings: Finding[] = [];
  try {
    findings = await api.findings(severity, status);
  } catch {
    findings = [];
  }

  return (
    <>
      <h1>Findings</h1>
      <Filters severity={severity} status={status} />
      <div className="card">
        {findings.length === 0 ? (
          <div className="empty">No findings match.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Title</th>
                <th>Status</th>
                <th>Detected</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                  </td>
                  <td className="mono">{f.rule_id}</td>
                  <td>
                    <div>{f.title}</div>
                    {f.description && <div className="subtext">{f.description}</div>}
                    {f.remediation && (
                      <div className="remediation">Fix: {f.remediation}</div>
                    )}
                  </td>
                  <td>{f.status}</td>
                  <td>{new Date(f.detected_at).toLocaleString()}</td>
                  <td>
                    <StatusActions id={f.id} status={f.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
