"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { type AIConfig } from "@/lib/ai-config";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function updateFindingStatus(
  id: string,
  status: "resolved" | "suppressed" | "open",
) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/findings/${id}`, {
    method: "PATCH",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error(`failed to update finding: ${res.status}`);
  revalidatePath("/findings");
  revalidatePath("/");
}

export async function analyzeFindingWithAI(id: string, config?: AIConfig) {
  const token = cookies().get("castra_token")?.value;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
  if (config?.apiKey) headers["X-AI-API-Key"] = config.apiKey;
  if (config?.baseURL) headers["X-AI-Base-URL"] = config.baseURL;
  if (config?.model) headers["X-AI-Model"] = config.model;
  if (config?.provider) headers["X-AI-Provider"] = config.provider;

  const res = await fetch(`${API_BASE}/v1/ai/analyze`, {
    method: "POST",
    cache: "no-store",
    headers,
    body: JSON.stringify({ finding_id: id }),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    let msg = errText;
    try {
      const parsed = JSON.parse(errText);
      if (parsed.error) msg = parsed.error;
    } catch {
      // use raw text
    }
    throw new Error(`AI analysis failed (${res.status}): ${msg}`);
  }
  const data = await res.json();
  return data.analysis as string;
}
