export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">CastraCloud</div>
        <a href="/">Dashboard</a>
        <a href="/findings">Findings</a>
        <a href="/attack-path">Attack Paths</a>
        <a href="/vulns">Vulnerabilities</a>
        <a href="/waf">WAF Rules</a>
        <a href="/domains">Domains</a>
        <a href="/compliance">Compliance</a>
        <a href="/alerts">Alerts</a>
        <div className="spacer" />
        <a href="/auth/logout">Sign out</a>
      </nav>
      <main className="content">{children}</main>
    </div>
  );
}
