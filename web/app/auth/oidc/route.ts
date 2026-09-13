import { NextResponse } from "next/server";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function GET() {
  return NextResponse.redirect(`${API_BASE}/v1/auth/oidc/start`);
}
