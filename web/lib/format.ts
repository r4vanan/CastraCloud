// Deterministic date formatting for values rendered in client components.
// `toLocaleString()` differs between server and browser timezones, which causes
// React hydration mismatches. ISO/UTC output is identical in both environments.

export function formatDateTime(iso?: string | null): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Never";
  return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}
