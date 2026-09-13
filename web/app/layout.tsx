import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CastraCloud Console",
  description: "Cloud Security Posture Management and Web Application Firewall",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
