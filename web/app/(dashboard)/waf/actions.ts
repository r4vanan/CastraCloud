"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function createWAFRule(formData: FormData) {
  const token = cookies().get("castra_token")?.value;
  const name = String(formData.get("name") ?? "").trim();
  const phase = String(formData.get("phase") ?? "request").trim();
  const action = String(formData.get("action") ?? "block").trim();
  const match = String(formData.get("match") ?? "").trim();
  const priority = Number(formData.get("priority") ?? 10) || 10;

  const res = await fetch(`${API_BASE}/v1/waf/rules`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ name, phase, action, match, priority, enabled: true }),
  });
  if (!res.ok) throw new Error(`failed to create WAF rule: ${res.status}`);
  revalidatePath("/waf");
}

export async function deleteWAFRule(id: string) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/waf/rules/${id}`, {
    method: "DELETE",
    cache: "no-store",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`failed to delete WAF rule: ${res.status}`);
  revalidatePath("/waf");
}
