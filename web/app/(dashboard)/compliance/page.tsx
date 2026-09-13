import { api, type Control, type Framework } from "@/lib/api";

async function frameworkControls(
  frameworkId: string,
): Promise<Control[]> {
  try {
    return await api.controls(frameworkId);
  } catch {
    return [];
  }
}

export default async function CompliancePage() {
  let frameworks: Framework[] = [];
  try {
    frameworks = await api.frameworks();
  } catch {
    frameworks = [];
  }

  const withControls = await Promise.all(
    frameworks.map(async (f) => ({
      framework: f,
      controls: await frameworkControls(f.id),
    })),
  );

  return (
    <>
      <h1>Compliance</h1>

      {withControls.length === 0 ? (
        <div className="card">
          <div className="empty">No compliance frameworks available.</div>
        </div>
      ) : (
        withControls.map(({ framework, controls }) => (
          <div className="card" key={framework.id}>
            <h2>
              {framework.name} <span className="subtext">v{framework.version}</span>
            </h2>
            {controls.length === 0 ? (
              <div className="empty">No controls defined.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 120 }}>Control</th>
                    <th>Title</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {controls.map((c) => (
                    <tr key={c.id}>
                      <td className="mono">{c.control_id}</td>
                      <td>{c.title}</td>
                      <td className="subtext">{c.description}</td>
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
