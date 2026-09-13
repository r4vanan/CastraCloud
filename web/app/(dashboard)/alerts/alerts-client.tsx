"use client";

import { useState, useTransition } from "react";
import { createAlertChannel, deleteAlertChannel } from "./actions";

const CHANNEL_TYPES = [
  { value: "slack", label: "Slack", placeholder: '{"url": "https://hooks.slack.com/services/..."}' },
  { value: "teams", label: "Microsoft Teams", placeholder: '{"url": "https://outlook.office.com/webhook/..."}' },
  { value: "webhook", label: "Webhook", placeholder: '{"url": "https://example.com/hook"}' },
  { value: "email", label: "Email", placeholder: '{"host": "smtp.example.com", "port": 587, "from": "a@b.c", "to": ["x@y.z"]}' },
  { value: "syslog", label: "Syslog / Wazuh", placeholder: '{"host": "10.0.0.5", "port": 514}' },
];

export default function AlertsClient() {
  const [pending, startTransition] = useTransition();
  const [type, setType] = useState("slack");
  const placeholder = CHANNEL_TYPES.find((c) => c.value === type)?.placeholder ?? "";

  return (
    <form
      className="card"
      action={(fd) =>
        startTransition(() => {
          createAlertChannel(fd).catch(() => {});
        })
      }
    >
      <h2>New alert channel</h2>
      <div className="filters">
        <input name="name" placeholder="Name" required />
        <select name="type" value={type} onChange={(e) => setType(e.target.value)}>
          {CHANNEL_TYPES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
      </div>
      <input
        name="config"
        placeholder={placeholder}
        style={{ width: "100%", marginBottom: 12 }}
      />
      <button className="btn" type="submit" disabled={pending}>
        {pending ? "Saving..." : "Add channel"}
      </button>
    </form>
  );
}

export function DeleteAlertButton({ id }: { id: string }) {
  const [pending, startTransition] = useTransition();

  function del() {
    startTransition(() => {
      deleteAlertChannel(id).catch(() => {});
    });
  }

  return (
    <button className="btn" disabled={pending} onClick={del}>
      Delete
    </button>
  );
}
