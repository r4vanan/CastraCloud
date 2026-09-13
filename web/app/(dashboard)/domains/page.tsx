import { api, type DNSRecord, type Domain, type Subdomain } from "@/lib/api";
import { AddDomainForm, AddRecordForm, DomainActions } from "./domains-client";

export default async function DomainsPage() {
  let domains: Domain[] = [];
  try {
    domains = await api.domains();
  } catch {
    domains = [];
  }

  const detail = await Promise.all(
    domains.map(async (d) => {
      let records: DNSRecord[] = [];
      let subs: Subdomain[] = [];
      try {
        [records, subs] = await Promise.all([
          api.dnsRecords(d.id),
          api.subdomains(d.id),
        ]);
      } catch {
        // leave empty
      }
      return { domain: d, records, subs };
    }),
  );

  return (
    <>
      <h1>Domains</h1>

      <AddDomainForm />

      {detail.length === 0 ? (
        <div className="card">
          <div className="empty">No domains yet. Add one above to get started.</div>
        </div>
      ) : (
        detail.map(({ domain, records, subs }) => (
          <div className="card" key={domain.id}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <h2 style={{ margin: 0 }}>
                {domain.name}{" "}
                <span className="subtext">{domain.provider}</span>
              </h2>
              <DomainActions domainId={domain.id} />
            </div>

            {domain.cert_expires_at && (
              <div className="subtext" style={{ marginBottom: 12 }}>
                Cert expires {new Date(domain.cert_expires_at).toLocaleString()}
              </div>
            )}

            <h3 className="subtext" style={{ margin: "16px 0 8px" }}>
              DNS records
            </h3>
            <AddRecordForm domainId={domain.id} />
            {records.length === 0 ? (
              <div className="empty">No records.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Name</th>
                    <th>Value</th>
                    <th>TTL</th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((r) => (
                    <tr key={r.id}>
                      <td>{r.type}</td>
                      <td>{r.name}</td>
                      <td className="mono">{r.value}</td>
                      <td>{r.ttl}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <h3 className="subtext" style={{ margin: "16px 0 8px" }}>
              Subdomains ({subs.length})
            </h3>
            {subs.length === 0 ? (
              <div className="empty">
                None discovered. Click &quot;Enumerate&quot; to query crt.sh.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Source</th>
                    <th>First seen</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {subs.map((s) => (
                    <tr key={s.id}>
                      <td className="mono">{s.name}</td>
                      <td>{s.source}</td>
                      <td>{new Date(s.first_seen).toLocaleString()}</td>
                      <td>{new Date(s.last_seen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        ))
      )}
    </>
  );
}
