import { FormEvent, useEffect, useRef, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { gatewayFetch, GatewayError, isNoOrganizationError, tokenStore } from '../api/client';
import type { CreatedOrg, Session } from '../api/types';

/**
 * Shown when a signed-in human has no organization. Name and slug only —
 * the gateway assigns the owner from the verified JWT subject.
 */
export function CreateOrgPage() {
  const navigate = useNavigate();
  const token = tokenStore().get();
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const submitting = useRef(false);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    gatewayFetch<Session>('/v1/session')
      .then(() => {
        if (!cancelled) navigate('/findings', { replace: true });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (isNoOrganizationError(err)) {
          setReady(true);
          return;
        }
        if (err instanceof GatewayError && err.status === 401) {
          tokenStore().clear();
          navigate('/login', { replace: true });
          return;
        }
        setError(err instanceof GatewayError ? err.message : 'Could not check your session.');
        setReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, [navigate, token]);

  if (!token) return <Navigate to="/login" replace />;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch<CreatedOrg>('/v1/orgs', {
        method: 'POST',
        body: { name: name.trim(), slug: slug.trim().toLowerCase() },
      });
      navigate('/findings', { replace: true });
    } catch (err) {
      if (err instanceof GatewayError && err.status === 409) {
        try {
          await gatewayFetch<Session>('/v1/session');
          navigate('/findings', { replace: true });
          return;
        } catch {
          setError(err.message);
        }
      } else {
        setError(err instanceof GatewayError ? err.message : 'Could not create the organization.');
      }
      setBusy(false);
      submitting.current = false;
    }
  };

  return (
    <div className="login">
      <div className="card login-card">
        <h1 className="login-brand">CTEM</h1>
        <p className="muted lede">Create your organization</p>
        {ready ? (
          <form onSubmit={(event) => void onSubmit(event)}>
            <label>
              Name
              <input
                name="name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
                maxLength={80}
                autoComplete="organization"
              />
            </label>
            <label>
              Slug
              <input
                name="slug"
                value={slug}
                onChange={(event) => setSlug(event.target.value.toLowerCase())}
                required
                minLength={3}
                maxLength={40}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <p className="muted small">Lowercase letters, numbers, and hyphens. 3–40 characters.</p>
            {error ? <p className="error">{error}</p> : null}
            <button type="submit" className="cta-loud" disabled={busy}>
              {busy ? 'Creating…' : 'Create organization'}
            </button>
          </form>
        ) : (
          <>
            <p className="muted">{error ?? 'Checking your session…'}</p>
            {error ? null : <div className="progress" />}
          </>
        )}
      </div>
    </div>
  );
}
