"use client";

import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Dashboard error:", error);
  }, [error]);

  return (
    <div className="card" style={{ maxWidth: 500, margin: "40px auto", textAlign: "center" }}>
      <h2>Something went wrong</h2>
      <p className="subtext" style={{ marginBottom: 16 }}>
        {error.message || "An unexpected error occurred while loading this page."}
      </p>
      <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
        <button className="btn" onClick={() => reset()}>
          Try again
        </button>
        <button className="btn" onClick={() => (window.location.href = "/")}>
          Go to Dashboard
        </button>
      </div>
    </div>
  );
}
