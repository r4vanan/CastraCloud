import { NextResponse } from "next/server";

export async function GET(req: Request) {
  const response = NextResponse.redirect(new URL("/login", req.url));
  response.cookies.set("castra_token", "", {
    httpOnly: true,
    path: "/",
    maxAge: 0,
  });
  return response;
}
