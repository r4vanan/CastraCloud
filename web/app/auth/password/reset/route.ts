import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function POST(req: Request) {
  const { email } = await req.json();
  const res = await fetch(`${API_BASE}/v1/auth/password/reset`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.ok ? 200 : res.status });
}
