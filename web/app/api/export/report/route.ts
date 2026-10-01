import { cookies } from "next/headers";

export const dynamic = "force-dynamic";

const API_BASE = process.env.API_URL || "http://localhost:8080";

export async function GET() {
  const token = cookies().get("castra_token")?.value;
  const res = await fetch(`${API_BASE}/v1/export/report.pdf`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    return new Response("Export failed", { status: res.status });
  }
  const body = await res.arrayBuffer();
  return new Response(body, {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": 'attachment; filename="castracloud-report.pdf"',
    },
  });
}
