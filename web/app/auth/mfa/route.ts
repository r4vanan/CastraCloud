import { NextResponse } from "next/server";
import { cookies } from "next/headers";

export const dynamic = "force-dynamic";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function POST(req: Request) {
  const { code, recovery_code } = await req.json();
  const mfaToken = cookies().get("castra_mfa")?.value ?? "";

  const res = await fetch(`${API_BASE}/v1/auth/mfa/verify-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      mfa_token: mfaToken,
      code,
      recovery_code,
    }),
  });

  if (!res.ok) {
    return NextResponse.json({ ok: false, error: "Invalid verification code" }, { status: 401 });
  }

  const data = await res.json();
  const response = NextResponse.json({ ok: true });
  response.cookies.set("castra_token", data.access_token, {
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    maxAge: data.expires_in ?? 86400,
  });
  response.cookies.delete("castra_mfa");
  return response;
}
