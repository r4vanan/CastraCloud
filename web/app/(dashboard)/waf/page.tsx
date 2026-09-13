import { api, type WAFRule } from "@/lib/api";
import WAFClient, { DeleteRuleButton } from "./waf-client";

export default async function WAFPage() {
  let rules: WAFRule[] = [];
  try {
    rules = await api.wafRules();
  } catch {
    rules = [];
  }

  return (
    <>
      <h1>WAF Rules</h1>

      <WAFClient />

      <div className="card">
        {rules.length === 0 ? (
          <div className="empty">No WAF rules configured.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Phase</th>
                <th>Action</th>
                <th>Match</th>
                <th>Priority</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>{r.phase}</td>
                  <td>{r.action}</td>
                  <td className="mono">{r.match}</td>
                  <td>{r.priority}</td>
                  <td>{r.enabled ? "yes" : "no"}</td>
                  <td>
                    <DeleteRuleButton id={r.id} />
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
