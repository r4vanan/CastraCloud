"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

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
