"use client";

import { useTransition } from "react";
import {
  createDomain,
  createDNSRecord,
  enumerateSubdomains,
  scanDomain,
} from "./actions";

export function AddDomainForm() {
  const [pending, startTransition] = useTransition();

  return (
    <form
      className="card"
      action={(fd) =>
        startTransition(() => {
          createDomain(fd).catch(() => {});
        })
      }
    >
      <h2>Add domain</h2>
      <div className="filters">
        <input name="name" placeholder="example.com" required />
        <select name="provider" defaultValue="route53">
          <option value="route53">route53</option>
          <option value="cloudflare">cloudflare</option>
          <option value="gcp">gcp</option>
          <option value="azure">azure</option>
          <option value="manual">manual</option>
        </select>
        <button className="btn" type="submit" disabled={pending}>
          {pending ? "Adding..." : "Add"}
        </button>
      </div>
    </form>
  );
}

export function AddRecordForm({ domainId }: { domainId: string }) {
  const [pending, startTransition] = useTransition();

  return (
    <form
      className="filters"
      action={(fd) =>
        startTransition(() => {
          createDNSRecord(domainId, fd).catch(() => {});
        })
      }
    >
      <select name="type" defaultValue="A">
        <option value="A">A</option>
        <option value="AAAA">AAAA</option>
        <option value="CNAME">CNAME</option>
        <option value="TXT">TXT</option>
        <option value="MX">MX</option>
      </select>
      <input name="name" placeholder="name (blank = apex)" />
      <input name="value" placeholder="value" required />
      <input name="ttl" type="number" defaultValue={300} style={{ width: 90 }} />
      <button className="btn" type="submit" disabled={pending}>
        {pending ? "Adding..." : "Add record"}
      </button>
    </form>
  );
}

export function DomainActions({ domainId }: { domainId: string }) {
  const [pending, startTransition] = useTransition();

  function run(fn: (id: string) => Promise<void>) {
    startTransition(() => {
      fn(domainId).catch(() => {});
    });
  }

  return (
    <span className="actions">
      <button
        className="btn"
        disabled={pending}
        onClick={() => run(enumerateSubdomains)}
      >
        Enumerate
      </button>
      <button className="btn" disabled={pending} onClick={() => run(scanDomain)}>
        Scan
      </button>
    </span>
  );
}
