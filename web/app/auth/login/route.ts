import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function POST(req: Request) {
  const { email, password } = await req.json();

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
  } catch {
    return NextResponse.json({ ok: false, error: "Authentication service unavailable" }, { status: 503 });
  }

  if (res.ok) {
    const data = await res.json();

    // Second factor required: stash the short-lived MFA token and let the
    // client render the TOTP entry step.
    if (data.mfa_required) {
      const response = NextResponse.json({ ok: true, mfa_required: true });
      response.cookies.set("castra_mfa", data.mfa_token, {
        httpOnly: true,
        path: "/",
        sameSite: "lax",
        maxAge: 300,
      });
      return response;
    }

    const response = NextResponse.json({ ok: true });
    response.cookies.set("castra_token", data.access_token, {
      httpOnly: true,
      path: "/",
      sameSite: "lax",
      maxAge: data.expires_in ?? 86400,
    });
    return response;
  }

  return NextResponse.json({ ok: false, error: "Invalid email or password" }, { status: 401 });
}

