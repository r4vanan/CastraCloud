"use client";

import { useEffect, useState, useTransition } from "react";
import { listUsers, createUser, updateUser, deactivateUser, type User } from "./actions";

const ROLES = [
  { value: "owner", label: "Owner" },
  { value: "admin", label: "Admin" },
  { value: "analyst", label: "Analyst" },
  { value: "viewer", label: "Viewer" },
];

export function UsersPanel({ currentUserId }: { currentUserId?: string }) {
  const [pending, startTransition] = useTransition();
  const [users, setUsers] = useState<User[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  function load() {
    startTransition(() => {
      listUsers()
        .then((res) => setUsers(res))
        .catch((err) => setError(String(err?.message ?? err)))
        .finally(() => setLoaded(true));
    });
  }

  useEffect(() => {
    load();
  }, []);

  function handleCreate(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setTempPassword(null);
    const fd = new FormData(e.currentTarget);
    startTransition(() => {
      createUser({
        email: String(fd.get("email") ?? ""),
        full_name: String(fd.get("full_name") ?? ""),
        role: String(fd.get("role") ?? "viewer"),
        password: String(fd.get("password") ?? ""),
      })
        .then((res) => {
          e.currentTarget.reset();
          setUsers((prev) => [...prev, res.user]);
          if (res.temp_password) {
            setTempPassword(res.temp_password);
            setNotice("User created. Share the temporary password below (shown only once).");
          } else {
            setNotice("User created.");
          }
        })
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function changeRole(id: string, role: string) {
    setError(null);
    startTransition(() => {
      updateUser(id, { role })
        .then((updated) => setUsers((prev) => prev.map((u) => (u.id === id ? updated : u))))
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function toggleActive(id: string, isActive: boolean) {
    setError(null);
    startTransition(() => {
      updateUser(id, { is_active: isActive })
        .then((updated) => setUsers((prev) => prev.map((u) => (u.id === id ? updated : u))))
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function handleRemove(id: string) {
    setError(null);
    startTransition(() => {
      deactivateUser(id)
        .then(() => setUsers((prev) => prev.map((u) => (u.id === id ? { ...u, is_active: false } : u))))
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  return (
    <>
      {error && <div className="card"><div className="login-error">{error}</div></div>}
      {notice && (
        <div className="card">
          <div style={{ color: "var(--success)", fontWeight: 600 }}>{notice}</div>
          {tempPassword && (
            <div className="mono" style={{ marginTop: 8, fontSize: 14 }}>
              Temporary password: <strong>{tempPassword}</strong>
            </div>
          )}
        </div>
      )}

      <div className="card">
        <h2>Add user</h2>
        <form onSubmit={handleCreate} style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input name="full_name" placeholder="Full name" style={{ flex: 1, minWidth: 160 }} />
          <input name="email" type="email" placeholder="Email" required style={{ flex: 2, minWidth: 200 }} />
          <select name="role" defaultValue="viewer" style={{ flex: 1, minWidth: 120 }}>
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
          <input name="password" type="password" placeholder="Password (blank = generate)" style={{ flex: 1, minWidth: 160 }} />
          <button className="btn" type="submit" disabled={pending}>
            {pending ? "Adding..." : "Add user"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Users ({users.length})</h2>
        {!loaded ? (
          <div className="empty">Loading users…</div>
        ) : users.length === 0 ? (
          <div className="empty">No users found.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === currentUserId;
                return (
                  <tr key={u.id}>
                    <td>
                      <strong>{u.full_name || "—"}</strong>
                      <div className="subtext">{u.email}</div>
                    </td>
                    <td>
                      {isSelf ? (
                        <span className="badge info">{u.role}</span>
                      ) : (
                        <select value={u.role} onChange={(e) => changeRole(u.id, e.target.value)} disabled={pending}>
                          {ROLES.map((r) => (
                            <option key={r.value} value={r.value}>
                              {r.label}
                            </option>
                          ))}
                        </select>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${u.is_active ? "low" : "critical"}`}>
                        {u.is_active ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${u.mfa_enabled ? "low" : "info"}`}>
                        {u.mfa_enabled ? "Enabled" : "Off"}
                      </span>
                    </td>
                    <td className="mono">{u.created_at ? u.created_at.slice(0, 10) : ""}</td>
                    <td>
                      <div className="actions">
                        {!isSelf && (
                          <>
                            <button className="btn" disabled={pending} onClick={() => toggleActive(u.id, !u.is_active)}>
                              {u.is_active ? "Deactivate" : "Activate"}
                            </button>
                            <button className="btn" disabled={pending} onClick={() => handleRemove(u.id)} style={{ color: "var(--danger)" }}>
                              Remove
                            </button>
                          </>
                        )}
                        {isSelf && <span className="subtext">You</span>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
