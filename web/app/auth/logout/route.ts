import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const response = NextResponse.redirect(new URL("/login", req.url));
  response.cookies.set("castra_token", "", {
    httpOnly: true,
    path: "/",
    maxAge: 0,
  });
  return response;
}
