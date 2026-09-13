import { NextResponse } from "next/server";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function POST(req: Request) {
  const { email, password } = await req.json();

  const res = await fetch(`${API_BASE}/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    return NextResponse.json(
      { error: "Invalid email or password" },
      { status: 401 },
    );
  }

  const data = await res.json();
  const response = NextResponse.json({ ok: true });
  response.cookies.set("castra_token", data.access_token, {
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    maxAge: data.expires_in ?? 3600,
  });
  return response;
}
