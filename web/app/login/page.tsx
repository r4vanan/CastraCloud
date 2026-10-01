"use client";

import { useState } from "react";

type Step = "credentials" | "mfa" | "forgot" | "reset";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<Step>("credentials");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);

  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");

  async function loginWith(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setLoading(true);
    setError("");
    const res = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.mfa_required) {
      setStep("mfa");
      setLoading(false);
      return;
    }
    if (res.ok) {
      window.location.href = "/";
    } else {
      setError("Invalid email or password");
      setLoading(false);
    }
  }

  async function verifyMfa(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setLoading(true);
    setError("");
    const res = await fetch("/auth/mfa", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    if (res.ok) {
      window.location.href = "/";
    } else {
      setError("Invalid verification code");
      setLoading(false);
    }
  }

  async function requestReset(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setLoading(true);
    setError("");
    const res = await fetch("/auth/password/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const data = await res.json().catch(() => ({}));
    setLoading(false);
    if (res.ok && data.reset_token) {
      setResetToken(data.reset_token);
      setNewPassword("");
      setStep("reset");
    } else {
      setError(data.error || "Unable to request a password reset.");
    }
  }

  async function confirmReset(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setLoading(true);
    setError("");
    const res = await fetch("/auth/password/reset/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: resetToken, password: newPassword }),
    });
    const data = await res.json().catch(() => ({}));
    setLoading(false);
    if (res.ok) {
      setStep("credentials");
      setPassword("");
      setNotice("Password updated. Sign in with your new password.");
    } else {
      setError(data.error || "Password reset failed. The token may be invalid or expired.");
    }
  }

  if (step === "mfa") {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={verifyMfa}>
          <div className="brand">CastraCloud</div>
          <h1>Two-factor verification</h1>
          <p className="subtext" style={{ marginBottom: 8 }}>
            Enter the six-digit code from your authenticator app.
          </p>
          <label htmlFor="code">Verification code</label>
          <input
            id="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            autoFocus
          />
          {error && <div className="login-error">{error}</div>}
          <button type="submit" disabled={loading || code.length < 6}>
            {loading ? "Verifying..." : "Verify & sign in"}
          </button>
          <button type="button" className="btn" onClick={() => { setStep("credentials"); setError(""); }} disabled={loading}
            style={{ marginTop: 8, padding: 10, width: "100%", textAlign: "center" }}>
            Back to sign in
          </button>
        </form>
      </div>
    );
  }

  if (step === "forgot") {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={requestReset}>
          <div className="brand">CastraCloud</div>
          <h1>Reset password</h1>
          <p className="subtext" style={{ marginBottom: 8 }}>
            Enter your account email to receive a reset token.
          </p>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
          />
          {error && <div className="login-error">{error}</div>}
          <button type="submit" disabled={loading}>
            {loading ? "Sending..." : "Send reset token"}
          </button>
          <button type="button" className="btn" onClick={() => { setStep("credentials"); setError(""); }} disabled={loading}
            style={{ marginTop: 8, padding: 10, width: "100%", textAlign: "center" }}>
            Back to sign in
          </button>
        </form>
      </div>
    );
  }

  if (step === "reset") {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={confirmReset}>
          <div className="brand">CastraCloud</div>
          <h1>Set new password</h1>
          <p className="subtext" style={{ marginBottom: 8 }}>
            Enter a new password (12+ characters with upper, lower, and number).
          </p>
          <label>Reset token</label>
          <input value={resetToken} readOnly className="mono" style={{ fontSize: 12 }} />
          <label htmlFor="newPassword">New password</label>
          <input
            id="newPassword"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            autoComplete="new-password"
            autoFocus
          />
          {error && <div className="login-error">{error}</div>}
          <button type="submit" disabled={loading || newPassword.length < 12}>
            {loading ? "Updating..." : "Update password"}
          </button>
          <button type="button" className="btn" onClick={() => { setStep("credentials"); setError(""); }} disabled={loading}
            style={{ marginTop: 8, padding: 10, width: "100%", textAlign: "center" }}>
            Back to sign in
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={(e) => loginWith(e)}>
        <div className="brand">CastraCloud</div>
        <h1>Sign in</h1>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="username"
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
        />
        {error && <div className="login-error">{error}</div>}
        {notice && <div className="subtext" style={{ color: "var(--success)" }}>{notice}</div>}
        <button type="submit" disabled={loading}>
          {loading ? "Signing in..." : "Sign in"}
        </button>
        <button type="button" className="btn" onClick={() => { setStep("forgot"); setError(""); setNotice(""); }} disabled={loading}
          style={{ marginTop: 8, padding: 10, width: "100%", textAlign: "center" }}>
          Forgot password?
        </button>
        {process.env.NEXT_PUBLIC_OIDC_ENABLED === "true" && (
          <a className="sso-link" href="/auth/oidc">
            Continue with SSO
          </a>
        )}
      </form>
    </div>
  );
}
