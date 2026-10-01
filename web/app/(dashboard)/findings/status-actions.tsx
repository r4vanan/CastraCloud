"use client";

import { useState, useTransition } from "react";
import { updateFindingStatus, analyzeFindingWithAI } from "./actions";
import { loadAIConfig } from "@/lib/ai-config";

function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="prose" style={{ marginTop: 8, padding: 12, background: "var(--surface-2)", borderRadius: 8 }}>
      {lines.map((line, i) => {
        const t = line.trim();
        if (t.startsWith("## ")) return <h3 key={i} style={{ marginTop: 8 }}>{t.slice(3)}</h3>;
        if (t.startsWith("### ")) return <h4 key={i} style={{ marginTop: 6 }}>{t.slice(4)}</h4>;
        if (t.startsWith("- ")) return <div key={i} className="prose-li">• {t.slice(2)}</div>;
        if (t === "") return <div key={i} style={{ height: 4 }} />;
        return <p key={i} style={{ margin: "2px 0" }}>{line}</p>;
      })}
    </div>
  );
}

export default function StatusActions({
  id,
  status,
}: {
  id: string;
  status: string;
}) {
  const [pending, startTransition] = useTransition();
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function act(s: "resolved" | "suppressed" | "open") {
    startTransition(() => {
      updateFindingStatus(id, s).catch(() => {});
    });
  }

  function analyze() {
    if (analysis) {
      setAnalysis(null);
      return;
    }
    setError(null);
    startTransition(() => {
      analyzeFindingWithAI(id, loadAIConfig())
        .then((res) => setAnalysis(res))
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  return (
    <div>
      <span className="actions">
        <button className="btn" disabled={pending} onClick={analyze} style={{ borderColor: "var(--accent-2)", color: "var(--accent-2)" }}>
          {pending ? "Analyzing..." : analysis ? "Hide AI" : "AI Analyze"}
        </button>
        {status !== "resolved" && (
          <button className="btn" disabled={pending} onClick={() => act("resolved")}>
            Resolve
          </button>
        )}
        {status !== "suppressed" && (
          <button className="btn" disabled={pending} onClick={() => act("suppressed")}>
            Suppress
          </button>
        )}
        {status !== "open" && (
          <button className="btn" disabled={pending} onClick={() => act("open")}>
            Reopen
          </button>
        )}
      </span>
      {error && <div className="login-error" style={{ marginTop: 4 }}>{error}</div>}
      {analysis && <Markdown text={analysis} />}
    </div>
  );
}
