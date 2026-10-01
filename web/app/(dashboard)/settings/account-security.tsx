"use client";

import { useState, useTransition } from "react";
import { type User } from "@/lib/api";
import { enrollMFA, verifyMFA, disableMFA, regenerateCodes } from "./actions";

export function AccountSecurity({ initialUser }: { initialUser: User | null }) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [enrolled, setEnrolled] = useState(Boolean(initialUser?.mfa_enabled));
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  function run(fn: () => Promise<unknown>) {
    setError(null);
    setNotice(null);
    startTransition(() => {
      fn().catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function handleEnroll() {
    run(() =>
      enrollMFA().then((res) => {
        setSecret(res.secret);
        setOtpauthUri(res.otpauth_uri);
        setCode("");
        setRecoveryCodes(null);
      }),
    );
  }

  function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    run(() =>
      verifyMFA(code).then((res) => {
        setEnrolled(true);
        setSecret(null);
        setOtpauthUri(null);
        setCode("");
        setRecoveryCodes(res.recovery_codes);
        setNotice("Two-factor authentication is now enabled.");
      }),
    );
  }

  function handleDisable() {
    run(() =>
      disableMFA().then(() => {
        setEnrolled(false);
        setRecoveryCodes(null);
        setNotice("Two-factor authentication has been disabled.");
      }),
    );
  }

  function handleRegenerate() {
    run(() =>
      regenerateCodes().then((res) => {
        setRecoveryCodes(res.recovery_codes);
        setNotice("New recovery codes generated.");
      }),
    );
  }

  return (
    <>
      {error && <div className="card"><div className="login-error">{error}</div></div>}
      {notice && <div className="card"><div style={{ color: "var(--success)", fontWeight: 600 }}>{notice}</div></div>}

      <div className="card">
        <h2>Two-factor authentication</h2>
        {enrolled ? (
          <>
            <p className="subtext">
              MFA is <strong style={{ color: "var(--success)" }}>enabled</strong> on your account. You will be
              prompted for a verification code at sign in.
            </p>
            <div className="actions" style={{ marginTop: 12 }}>
              <button className="btn" onClick={handleRegenerate} disabled={pending}>
                Regenerate recovery codes
              </button>
              <button className="btn" onClick={handleDisable} disabled={pending} style={{ color: "var(--danger)" }}>
                Disable MFA
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="subtext">
              Add an extra layer of security by requiring a time-based one-time password
              (TOTP) from an authenticator app such as Google Authenticator or 1Password.
            </p>
            <button className="btn" onClick={handleEnroll} disabled={pending} style={{ marginTop: 12 }}>
              {pending ? "Preparing..." : "Set up MFA"}
            </button>
          </>
        )}
      </div>

      {secret && otpauthUri && !enrolled && (
        <div className="card">
          <h2>Scan with your authenticator app</h2>
          <p className="subtext">Open your authenticator app and scan the QR code or enter the secret manually.</p>
          <div className="mono" style={{ wordBreak: "break-all", margin: "12px 0" }}>{secret}</div>
          <a className="btn" href={otpauthUri} style={{ textDecoration: "none", display: "inline-block" }}>
            Open in authenticator app
          </a>
          <form onSubmit={handleVerify} style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center" }}>
            <input
              placeholder="6-digit code"
              inputMode="numeric"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              style={{ flex: 1 }}
            />
            <button className="btn" type="submit" disabled={pending || code.length < 6}>
              {pending ? "Verifying..." : "Verify & enable"}
            </button>
          </form>
        </div>
      )}

      {recoveryCodes && enrolled && (
        <div className="card">
          <h2>Recovery codes</h2>
          <p className="subtext">
            Store these single-use codes somewhere safe. Each can be used once to sign in if you
            lose access to your authenticator app.
          </p>
          <div className="mono" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 8, marginTop: 12 }}>
            {recoveryCodes.map((c) => (
              <div key={c} style={{ border: "1px solid var(--border)", borderRadius: 6, padding: "6px 10px" }}>
                {c}
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
