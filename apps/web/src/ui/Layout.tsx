import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { gatewayFetch, GatewayError, tokenStore } from '../api/client';
import type { Session } from '../api/types';

export function Layout() {
  const navigate = useNavigate();
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    gatewayFetch<Session>('/v1/session')
      .then((s) => {
        if (!cancelled) setSession(s);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof GatewayError && (err.status === 401 || err.status === 403)) {
          tokenStore().clear();
          navigate('/login', { replace: true });
          return;
        }
        setError(err instanceof Error ? err.message : 'Failed to load session');
      });
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  const logout = () => {
    tokenStore().clear();
    navigate('/login', { replace: true });
  };

  return (
    <div className="app">
      <aside className="dock">
        <strong className="brand">CTEM</strong>
        <nav aria-label="Primary">
          <div className="nav-group" role="group" aria-labelledby="nav-ops">
            <div id="nav-ops" className="nav-group-label">
              Ops
            </div>
            <NavLink to="/assets">Assets</NavLink>
            <NavLink to="/findings">Findings</NavLink>
            <NavLink to="/scans">Scan</NavLink>
          </div>
          <div className="nav-group nav-group-admin" role="group" aria-labelledby="nav-admin">
            <div id="nav-admin" className="nav-group-label">
              Admin
            </div>
            <NavLink to="/policies">Policies</NavLink>
            <NavLink to="/members">Members</NavLink>
          </div>
        </nav>
        <div className="session">
          {session ? (
            <span title={session.orgId}>{session.role}</span>
          ) : (
            <span className="muted">…</span>
          )}
          <button type="button" className="link" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="bleed">
        {error ? <p className="banner error">{error}</p> : null}
        <Outlet />
      </main>
    </div>
  );
}
