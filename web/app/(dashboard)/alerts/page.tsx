import { api, type AlertChannel } from "@/lib/api";
import AlertsClient, { DeleteAlertButton } from "./alerts-client";

export default async function AlertsPage() {
  let channels: AlertChannel[] = [];
  try {
    channels = await api.alerts();
  } catch {
    channels = [];
  }

  return (
    <>
      <h1>Alerts</h1>

      <AlertsClient />

      <div className="card">
        <h2>Alert channels</h2>
        {channels.length === 0 ? (
          <div className="empty">No alert channels configured yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Enabled</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.type}</td>
                  <td>{c.enabled ? "yes" : "no"}</td>
                  <td>{new Date(c.created_at).toLocaleString()}</td>
                  <td>
                    <DeleteAlertButton id={c.id} />
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
