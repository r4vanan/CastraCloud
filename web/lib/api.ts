// Server-side client for the CastraCloud control-plane API.
// Reads the auth token from the httpOnly cookie and forwards it as a Bearer token.
import { cookies } from "next/headers";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export type Finding = {
  id: string;
  tenant_id: string;
  asset_id?: string;
  source: string;
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "resolved" | "suppressed";
  description: string;
  remediation: string;
  detected_at: string;
  resolved_at?: string;
};

export type Summary = {
  posture_score: number;
  total: number;
  open: number;
  resolved: number;
  suppressed: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};

export type WAFRule = {
  id: string;
  name: string;
  phase: string;
  action: string;
  match: string;
  enabled: boolean;
  priority: number;
};

export type Domain = {
  id: string;
  name: string;
  provider: string;
  cert_expires_at?: string;
};

export type DNSRecord = {
  id: string;
  domain_id: string;
  type: string;
  name: string;
  value: string;
  ttl: number;
};

export type Subdomain = {
  id: string;
  domain_id: string;
  name: string;
  source: string;
  first_seen: string;
  last_seen: string;
};

export type AlertChannel = {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
};

export type Framework = {
  id: string;
  tenant_id: string;
  name: string;
  version: string;
  created_at: string;
};

export type Control = {
  id: string;
  framework_id: string;
  control_id: string;
  title: string;
  description: string;
};

export type AttackNode = {
  id: string;
  label: string;
  kind: string;
  type?: string;
  risk: number;
};

export type AttackEdge = {
  from: string;
  to: string;
  kind: string;
};

export type AttackPath = {
  target: string;
  label: string;
  nodes: string[];
  hops: number;
  risk: number;
};

export type AttackGraph = {
  nodes: AttackNode[];
  edges: AttackEdge[];
  paths: AttackPath[];
};

export class AuthError extends Error {}

function token(): string | undefined {
  return cookies().get("castra_token")?.value;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (res.status === 401) throw new AuthError("unauthorized");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  summary: () => request<Summary>(`/v1/summary`),
  findings: (severity = "", status = "") => {
    const qs = new URLSearchParams();
    if (severity) qs.set("severity", severity);
    if (status) qs.set("status", status);
    return request<Finding[]>(`/v1/findings?${qs.toString()}`);
  },
  wafRules: () => request<WAFRule[]>(`/v1/waf/rules`),
  domains: () => request<Domain[]>(`/v1/domains`),
  dnsRecords: (domainId: string) =>
    request<DNSRecord[]>(`/v1/domains/${domainId}/records`),
  subdomains: (domainId: string) =>
    request<Subdomain[]>(`/v1/domains/${domainId}/subdomains`),
  alerts: () => request<AlertChannel[]>(`/v1/alerts`),
  frameworks: () => request<Framework[]>(`/v1/compliance/frameworks`),
  controls: (frameworkId: string) =>
    request<Control[]>(`/v1/compliance/frameworks/${frameworkId}/controls`),
  attackPath: () => request<AttackGraph>(`/v1/attack-path`),
};
