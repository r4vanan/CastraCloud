"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function createCloudConnector(formData: FormData) {
  const token = cookies().get("castra_token")?.value;
  const name = String(formData.get("name") ?? "");
  const provider = String(formData.get("provider") ?? "aws");
  const region = String(formData.get("region") ?? "us-east-1");
  const credentialsText = String(formData.get("credentials") ?? "").trim();
  let credentials: Record<string, unknown> | undefined;
  if (credentialsText) {
    try {
      credentials = JSON.parse(credentialsText);
    } catch {
      throw new Error("Credential JSON is invalid.");
    }
  }

  const res = await fetch(`${API_BASE}/v1/connectors`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ name, provider, region, credentials }),
  });

  if (!res.ok) throw new Error(`failed to create connector: ${res.status}`);
  revalidatePath("/connectors");
  revalidatePath("/");
}

export async function deleteCloudConnector(id: string) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/connectors/${id}`, {
    method: "DELETE",
    cache: "no-store",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) throw new Error(`failed to delete connector: ${res.status}`);
  revalidatePath("/connectors");
}

export async function runCloudScan(id: string) {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/connectors/${id}/scan`, {
    method: "POST",
    cache: "no-store",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) throw new Error(`scan failed: ${res.status}`);
  const data = await res.json();
  revalidatePath("/connectors");
  revalidatePath("/findings");
  revalidatePath("/");
  return data;
}
