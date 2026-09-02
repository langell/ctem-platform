import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { gatewayFetch, GatewayError, tokenStore } from '../api/client';
import type { Session } from '../api/types';
import { completeAuthorization } from '../auth/oidc';

/**
 * OIDC redirect target. Stores the issued access-token JWT and confirms the
 * gateway session. Org still comes from that JWT.
 */
export function CallbackPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const jwt = await completeAuthorization({
          search: window.location.search,
          origin: window.location.origin,
        });
        // Session is minted from the bearer JWT. This callback has no org field.
        await gatewayFetch<Session>('/v1/session', { token: jwt });
        if (!cancelled) navigate('/findings', { replace: true });
      } catch (err) {
        tokenStore().clear();
        if (cancelled) return;
        setError(
          err instanceof GatewayError
            ? err.message
            : err instanceof Error
              ? err.message
              : 'Could not complete Keycloak login.',
        );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  return (
    <div className="login">
      <div className="card login-card">
        <h1>Sign in</h1>
        {error ? (
          <>
            <p className="error">{error}</p>
            <Link to="/login">Try again</Link>
          </>
        ) : (
          <p className="muted">Completing Keycloak login…</p>
        )}
      </div>
    </div>
  );
}
