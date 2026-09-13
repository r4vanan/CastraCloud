"use client";

import { useRouter } from "next/navigation";

export default function Filters({
  severity,
  status,
}: {
  severity: string;
  status: string;
}) {
  const router = useRouter();

  function go(sev: string, st: string) {
    const next = new URLSearchParams();
    if (sev) next.set("severity", sev);
    if (st) next.set("status", st);
    router.push(next.size ? `/findings?${next.toString()}` : "/findings");
  }

  return (
    <div className="filters">
      <select value={severity} onChange={(e) => go(e.target.value, status)}>
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select value={status} onChange={(e) => go(severity, e.target.value)}>
        <option value="">All statuses</option>
        <option value="open">Open</option>
        <option value="resolved">Resolved</option>
        <option value="suppressed">Suppressed</option>
      </select>
      {(severity || status) && (
        <a className="clear" href="/findings">
          Clear
        </a>
      )}
    </div>
  );
}
