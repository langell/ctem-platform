import { FormEvent, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { gatewayFetch, GatewayError, tokenStore } from '../api/client';
import type { Session } from '../api/types';

export function LoginPage() {
  const navigate = useNavigate();
  const existing = tokenStore().get();
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (existing) return <Navigate to="/findings" replace />;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const value = token.trim();
    if (!value) {
      setError('Paste a JWT (or PAT) issued for your organization.');
      return;
    }
    setBusy(true);
    tokenStore().set(value);
    try {
      // Session is minted from the bearer token. This form has no org field.
      await gatewayFetch<Session>('/v1/session', { token: value });
      navigate('/findings', { replace: true });
    } catch (err) {
      tokenStore().clear();
      setError(
        err instanceof GatewayError
          ? err.message
          : 'Could not verify the token against the gateway.',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="card login-card" onSubmit={onSubmit}>
        <h1>Sign in</h1>
        <p className="muted">
          Present a bearer JWT from the IdP. The organization is read from the token —
          this client never sends an org id, header, or query.
        </p>
        <label>
          JWT
          <textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            rows={6}
            placeholder="eyJ…"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        {error ? <p className="error">{error}</p> : null}
        <button type="submit" disabled={busy}>
          {busy ? 'Verifying…' : 'Continue'}
        </button>
      </form>
    </div>
  );
}
