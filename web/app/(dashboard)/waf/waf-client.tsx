"use client";

import { useTransition } from "react";
import { createWAFRule, deleteWAFRule } from "./actions";

export default function WAFClient() {
  const [pending, startTransition] = useTransition();

  return (
    <form
      className="card"
      action={(fd) =>
        startTransition(() => {
          createWAFRule(fd).catch(() => {});
        })
      }
    >
      <h2>New rule</h2>
      <div className="filters">
        <input name="name" placeholder="Rule name" required />
        <select name="phase" defaultValue="request">
          <option value="request">request</option>
          <option value="response">response</option>
        </select>
        <select name="action" defaultValue="block">
          <option value="block">block</option>
          <option value="allow">allow</option>
          <option value="log">log</option>
          <option value="challenge">challenge</option>
        </select>
        <input name="priority" type="number" defaultValue={10} placeholder="Priority" style={{ width: 90 }} />
      </div>
      <input
        name="match"
        placeholder='match (e.g. uri:regex:(?i)union\s+select)'
        style={{ width: "100%", marginBottom: 12 }}
      />
      <button className="btn" type="submit" disabled={pending}>
        {pending ? "Saving..." : "Add rule"}
      </button>
    </form>
  );
}

export function DeleteRuleButton({ id }: { id: string }) {
  const [pending, startTransition] = useTransition();

  function del() {
    startTransition(() => {
      deleteWAFRule(id).catch(() => {});
    });
  }

  return (
    <button className="btn" disabled={pending} onClick={del}>
      Delete
    </button>
  );
}
