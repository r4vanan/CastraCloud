"use client";

import { useState, useTransition } from "react";
import { type CloudConnector } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { createCloudConnector, deleteCloudConnector, runCloudScan } from "./actions";

export function ConnectorsClient({ initialConnectors }: { initialConnectors: CloudConnector[] }) {
  const [pending, startTransition] = useTransition();
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleCreate(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const form = e.currentTarget;
    const fd = new FormData(form);
    startTransition(() => {
      createCloudConnector(fd)
        .then(() => form.reset())
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function handleDelete(id: string) {
    setError(null);
    startTransition(() => {
      deleteCloudConnector(id).catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function handleScan(id: string) {
    setError(null);
    setScanMessage(null);
    setScanningId(id);
    startTransition(() => {
      runCloudScan(id)
        .then((res) => {
          setScanMessage(`Scan complete for ${res.provider}! Found ${res.scanned} misconfigurations.`);
          setScanningId(null);
        })
        .catch((err) => {
          setError(String(err?.message ?? err));
          setScanningId(null);
        });
    });
  }

  return (
    <>
      <div className="card">
        <h2>Connect Cloud Provider Account</h2>
        <form onSubmit={handleCreate} style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input name="name" placeholder="Account Name (e.g. AWS Production)" required style={{ flex: 2 }} />
          <select name="provider" required style={{ flex: 1 }}>
            <option value="aws">AWS (Amazon Web Services)</option>
            <option value="gcp">GCP (Google Cloud Platform)</option>
            <option value="azure">Microsoft Azure</option>
          </select>
          <input name="region" placeholder="Region (e.g. us-east-1)" defaultValue="us-east-1" style={{ flex: 1 }} />
          <textarea
            name="credentials"
            placeholder="Credential JSON (optional when using workload identity)"
            rows={2}
            style={{ flexBasis: "100%", minHeight: 60 }}
          />
          <button className="btn" type="submit" disabled={pending}>
            {pending ? "Connecting..." : "Add Integration"}
          </button>
        </form>
      </div>

      {error && <div className="card"><div className="login-error">{error}</div></div>}
      {scanMessage && <div className="card"><div style={{ color: "var(--success)", fontWeight: 600 }}>{scanMessage}</div></div>}

      <div className="card">
        <h2>Connected Cloud Accounts ({initialConnectors.length})</h2>
        {initialConnectors.length === 0 ? (
          <div className="empty">No cloud accounts connected yet. Add your AWS, GCP, or Azure integration above.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Account Name</th>
                <th>Provider</th>
                <th>Region</th>
                <th>Status</th>
                <th>Last Scanned</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {initialConnectors.map((c) => (
                <tr key={c.id}>
                  <td><strong>{c.name}</strong></td>
                  <td>
                    <span className={`badge ${c.provider === "aws" ? "high" : c.provider === "gcp" ? "info" : "medium"}`}>
                      {c.provider.toUpperCase()}
                    </span>
                  </td>
                  <td>{c.region}</td>
                  <td>
                    <span className="badge low">{c.status}</span>
                  </td>
                  <td>{formatDateTime(c.last_scanned_at)}</td>
                  <td>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        className="btn"
                        disabled={pending || scanningId === c.id}
                        onClick={() => handleScan(c.id)}
                        style={{ borderColor: "var(--accent-2)", color: "var(--accent-2)" }}
                      >
                        {scanningId === c.id ? "Scanning..." : "Run Scan Now"}
                      </button>
                      <button
                        className="btn"
                        disabled={pending}
                        onClick={() => handleDelete(c.id)}
                        style={{ color: "var(--danger)" }}
                      >
                        Remove
                      </button>
                    </div>
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
