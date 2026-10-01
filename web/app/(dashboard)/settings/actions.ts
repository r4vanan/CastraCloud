"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export type User = {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  full_name: string;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at: string;
};

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
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
    throw new Error(msg || `request failed: ${res.status}`);
  }
  return res.json();
}

function refresh() {
  revalidatePath("/settings");
}

// --- MFA ---

export async function enrollMFA(): Promise<{ secret: string; otpauth_uri: string }> {
  return request("POST", "/v1/auth/mfa/enroll");
}

export async function verifyMFA(code: string): Promise<{ recovery_codes: string[] }> {
  const data = await request<{ recovery_codes: string[] }>("POST", "/v1/auth/mfa/verify", { code });
  refresh();
  return data;
}

export async function disableMFA(): Promise<{ enabled: boolean }> {
  const data = await request<{ enabled: boolean }>("POST", "/v1/auth/mfa/disable");
  refresh();
  return data;
}

export async function regenerateCodes(): Promise<{ recovery_codes: string[] }> {
  return request("POST", "/v1/auth/mfa/recovery-codes");
}

// --- Users ---

export async function listUsers(): Promise<User[]> {
  return request("GET", "/v1/users");
}

export async function createUser(input: {
  email: string;
  full_name: string;
  role: string;
  password?: string;
}): Promise<{ user: User; temp_password?: string }> {
  const data = await request<{ user: User; temp_password?: string }>("POST", "/v1/users", input);
  refresh();
  return data;
}

export async function updateUser(
  id: string,
  patch: { role?: string; is_active?: boolean },
): Promise<User> {
  const data = await request<User>("PATCH", `/v1/users/${id}`, patch);
  refresh();
  return data;
}

export async function deactivateUser(id: string): Promise<{ deactivated: boolean }> {
  const data = await request<{ deactivated: boolean }>("DELETE", `/v1/users/${id}`);
  refresh();
  return data;
}
