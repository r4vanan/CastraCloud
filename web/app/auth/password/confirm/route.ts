import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function POST(req: Request) {
  const { token, password } = await req.json();
  const res = await fetch(`${API_BASE}/v1/auth/password/reset/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, password }),
  });
  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.ok ? 200 : res.status });
}
