import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { tokenStore } from '../api/client';
import { beginAuthorization } from '../auth/oidc';

export function LoginPage() {
  const existing = tokenStore().get();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (existing) return <Navigate to="/findings" replace />;

  const onSignIn = async () => {
    setError(null);
    setBusy(true);
    try {
      // Redirect to compose Keycloak. This client has no password field and
      // never sends an org id — the issued JWT carries org_id.
      await beginAuthorization({
        origin: window.location.origin,
        assign: (url) => {
          window.location.assign(url);
        },
      });
    } catch (err) {
      setBusy(false);
      setError(err instanceof Error ? err.message : 'Could not start Keycloak login.');
    }
  };

  return (
    <div className="login">
      <div className="card login-card">
        <h1>Sign in</h1>
        <p className="muted">
          Redirects to the compose Keycloak <code>ctem</code> realm. The organization is read from
          the issued JWT — this client never sends an org id, header, or query.
        </p>
        {error ? <p className="error">{error}</p> : null}
        <button type="button" onClick={onSignIn} disabled={busy}>
          {busy ? 'Redirecting…' : 'Sign in with Keycloak'}
        </button>
      </div>
    </div>
  );
}
