"use client";

import { useState, useTransition } from "react";
import { scanPackages, type ScanResponse } from "./actions";

function severityBadge(s: string) {
  const sev = s.toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(sev)) return sev;
  return "medium";
}

export default function VulnsClient() {
  const [pending, startTransition] = useTransition();
  const [input, setInput] = useState("");
  const [resource, setResource] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState("");

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const packages = input
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const idx = l.lastIndexOf("@");
        if (idx <= 0) return { name: l, version: "" };
        return { name: l.slice(0, idx), version: l.slice(idx + 1) };
      })
      .filter((p) => p.name);
    setError("");
    startTransition(() => {
      scanPackages(packages, resource, "container")
        .then(setResult)
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  return (
    <>
      <form className="card" onSubmit={onSubmit}>
        <h2>Scan workload packages</h2>
        <input
          placeholder="Workload name (optional)"
          value={resource}
          onChange={(e) => setResource(e.target.value)}
          style={{ width: "100%", marginBottom: 8 }}
        />
        <textarea
          placeholder={"log4j-core@2.14.1\nopenssl@1.0.1f\nlodash@4.17.15"}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={5}
          style={{ width: "100%", marginBottom: 8 }}
        />
        <button className="btn" type="submit" disabled={pending}>
          {pending ? "Scanning..." : "Scan"}
        </button>
        {error && <div className="login-error">{error}</div>}
      </form>

      {result && (
        <div className="card">
          <h2>
            Results: {result.vulnerabilities} vulnerable of {result.scanned}{" "}
            scanned
          </h2>
          {result.results.length === 0 ? (
            <div className="empty">No known vulnerabilities found.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Package</th>
                  <th>Installed</th>
                  <th>Fixed</th>
                  <th>Severity</th>
                  <th>Title</th>
                </tr>
              </thead>
              <tbody>
                {result.results.map((r, i) => (
                  <tr key={i}>
                    <td className="mono">{r.cve}</td>
                    <td>{r.package}</td>
                    <td>{r.installed}</td>
                    <td>{r.fixed}</td>
                    <td>
                      <span className={`badge ${severityBadge(r.severity)}`}>
                        {r.severity}
                      </span>
                    </td>
                    <td>{r.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </>
  );
}
