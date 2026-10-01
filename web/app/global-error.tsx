"use client";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html>
      <body style={{ fontFamily: "sans-serif", background: "var(--bg)", padding: 40, display: "flex", justifyContent: "center" }}>
        <div style={{ background: "var(--surface)", padding: 32, borderRadius: 12, border: "1px solid var(--border)", maxWidth: 480, textAlign: "center" }}>
          <h2 style={{ color: "var(--text-strong)", margin: "0 0 12px" }}>Application Error</h2>
          <p style={{ color: "var(--text-muted)", fontSize: 14, marginBottom: 20 }}>
            {error.message || "A critical error occurred."}
          </p>
          <button
            onClick={() => reset()}
            style={{ background: "var(--accent)", color: "var(--accent-fg)", border: "none", padding: "10px 16px", borderRadius: 8, cursor: "pointer" }}
          >
            Reload application
          </button>
        </div>
      </body>
    </html>
  );
}
