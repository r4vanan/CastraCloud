"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

const API_BASE = process.env.API_URL || "http://localhost:8080";

function authHeaders(token?: string): HeadersInit {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

export async function createDomain(formData: FormData) {
  const token = cookies().get("castra_token")?.value;
  const name = String(formData.get("name") ?? "").trim();
  const provider = String(formData.get("provider") ?? "route53").trim();

  const res = await fetch(`${API_BASE}/v1/domains`, {
    method: "POST",
    cache: "no-store",
    headers: authHeaders(token),
    body: JSON.stringify({ name, provider }),
  });
  if (!res.ok) throw new Error(`failed to create domain: ${res.status}`);
  revalidatePath("/domains");
}

export async function createDNSRecord(domainId: string, formData: FormData) {
  const token = cookies().get("castra_token")?.value;
  const type = String(formData.get("type") ?? "").trim();
  const name = String(formData.get("name") ?? "").trim();
  const value = String(formData.get("value") ?? "").trim();
  const ttl = Number(formData.get("ttl") ?? 300) || 300;

  const res = await fetch(`${API_BASE}/v1/domains/${domainId}/records`, {
    method: "POST",
    cache: "no-store",
    headers: authHeaders(token),
    body: JSON.stringify({ type, name, value, ttl }),
  });
  if (!res.ok) throw new Error(`failed to add record: ${res.status}`);
  revalidatePath("/domains");
}

export async function enumerateSubdomains(domainId: string) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/domains/${domainId}/enumerate`, {
    method: "POST",
    cache: "no-store",
    headers: authHeaders(token),
  });
  if (!res.ok) throw new Error(`failed to enumerate subdomains: ${res.status}`);
  revalidatePath("/domains");
}

export async function scanDomain(domainId: string) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/domains/${domainId}/scan`, {
    method: "POST",
    cache: "no-store",
    headers: authHeaders(token),
  });
  if (!res.ok) throw new Error(`failed to scan domain: ${res.status}`);
  revalidatePath("/domains");
  revalidatePath("/");
  revalidatePath("/findings");
}
