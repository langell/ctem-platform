import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { gatewayFetch, GatewayError, tokenStore } from '../api/client';
import type { Session } from '../api/types';
import { completeAuthorization, keepSessionAfterCallbackError } from '../auth/oidc';

/**
 * OIDC redirect target. Stores the issued access-token JWT and confirms the
 * gateway session. Org still comes from that JWT.
 *
 * React Strict Mode remounts this page. The authorization code is taken once
 * (and stripped from the URL) so the second mount cannot POST it again or
 * wipe a JWT the first mount already stored.
 */
export function CallbackPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const search = window.location.search;
    (async () => {
      try {
        // Claim the one-shot exchange before stripping the code so a Strict Mode
        // remount joins inflight (or sees the stored JWT) instead of POSTing again.
        const jwtPromise = completeAuthorization({
          search,
          origin: window.location.origin,
        });
        if (search) {
          window.history.replaceState(window.history.state, '', window.location.pathname);
        }
        const jwt = await jwtPromise;
        // Session is minted from the bearer JWT. This callback has no org field.
        await gatewayFetch<Session>('/v1/session', { token: jwt });
        if (!cancelled) navigate('/findings', { replace: true });
      } catch (err) {
        if (cancelled) return;
        if (keepSessionAfterCallbackError()) {
          navigate('/findings', { replace: true });
          return;
        }
        tokenStore().clear();
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
        {error ? (
          <>
            <p>Could not complete sign-in.</p>
            <p className="error">{error}</p>
            <Link to="/login">Try again</Link>
          </>
        ) : (
          <>
            <p className="muted">Completing sign-in…</p>
            <div className="progress" />
          </>
        )}
      </div>
    </div>
  );
}
