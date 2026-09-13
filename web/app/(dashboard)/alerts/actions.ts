"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function createAlertChannel(formData: FormData) {
  const token = cookies().get("castra_token")?.value;
  const name = String(formData.get("name") ?? "").trim();
  const type = String(formData.get("type") ?? "").trim();
  const configRaw = String(formData.get("config") ?? "").trim();

  let config: Record<string, unknown> = {};
  if (configRaw) {
    try {
      config = JSON.parse(configRaw);
    } catch {
      throw new Error("config must be valid JSON");
    }
  }

  const res = await fetch(`${API_BASE}/v1/alerts`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ name, type, config, enabled: true }),
  });
  if (!res.ok) throw new Error(`failed to create alert channel: ${res.status}`);
  revalidatePath("/alerts");
}

export async function deleteAlertChannel(id: string) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/alerts/${id}`, {
    method: "DELETE",
    cache: "no-store",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`failed to delete alert channel: ${res.status}`);
  revalidatePath("/alerts");
}
