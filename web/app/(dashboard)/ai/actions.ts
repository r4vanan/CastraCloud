"use server";

import { cookies } from "next/headers";
import { type AIConfig } from "@/lib/ai-config";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

async function post<T>(path: string, body: unknown, config?: AIConfig): Promise<T> {
  const token = cookies().get("castra_token")?.value;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
  if (config?.apiKey) headers["X-AI-API-Key"] = config.apiKey;
  if (config?.baseURL) headers["X-AI-Base-URL"] = config.baseURL;
  if (config?.model) headers["X-AI-Model"] = config.model;
  if (config?.provider) headers["X-AI-Provider"] = config.provider;

  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    cache: "no-store",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try {
      const parsed = JSON.parse(text);
      if (parsed.error) msg = parsed.error;
    } catch {
      // use raw text
    }
    throw new Error(`AI request failed (${res.status}): ${msg}`);
  }
  return res.json();
}

export async function sendChat(
  messages: ChatMessage[],
  config?: AIConfig,
): Promise<{ reply: string }> {
  return post("/v1/ai/chat", { messages }, config);
}
