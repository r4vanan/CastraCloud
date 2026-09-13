"use client";

import { useTransition } from "react";
import { updateFindingStatus } from "./actions";

export default function StatusActions({
  id,
  status,
}: {
  id: string;
  status: string;
}) {
  const [pending, startTransition] = useTransition();

  function act(s: "resolved" | "suppressed" | "open") {
    startTransition(() => {
      updateFindingStatus(id, s).catch(() => {});
    });
  }

  return (
    <span className="actions">
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
  );
}
