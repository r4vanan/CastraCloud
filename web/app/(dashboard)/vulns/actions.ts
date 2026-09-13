"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export type VulnResult = {
  package: string;
  installed: string;
  fixed: string;
  cve: string;
  severity: string;
  title: string;
};

export type ScanResponse = {
  scanned: number;
  vulnerabilities: number;
  results: VulnResult[];
};

export async function scanPackages(
  packages: { name: string; version: string }[],
  resourceName: string,
  resourceType: string,
): Promise<ScanResponse> {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/vulns/scan`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      packages,
      resource_name: resourceName,
      resource_type: resourceType,
    }),
  });
  if (!res.ok) throw new Error(`scan failed: ${res.status}`);
  revalidatePath("/vulns");
  revalidatePath("/");
  revalidatePath("/findings");
  return res.json();
}
