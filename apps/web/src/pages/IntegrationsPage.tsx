import { FormEvent, useEffect, useState } from 'react';
import { gatewayFetch, GatewayError } from '../api/client';
import type { GitHubIntegration, Session } from '../api/types';

function syncLabel(row: GitHubIntegration): string {
  if (row.lastSyncError) return 'Sync failed';
  if (row.lastSyncAt) return 'Synced';
  return 'Not synced';
}

export function IntegrationsPage() {
  const [session, setSession] = useState<Session | null>(null);
  const [items, setItems] = useState<GitHubIntegration[]>([]);
  const [owner, setOwner] = useState('');
  const [ownerType, setOwnerType] = useState<'user' | 'org'>('org');
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const canManage = session?.permissions.includes('integration:manage') ?? false;

  const reload = async () => {
    const [me, listed] = await Promise.all([
      gatewayFetch<Session>('/v1/session'),
      gatewayFetch<GitHubIntegration[]>('/v1/integrations'),
    ]);
    setSession(me);
    setItems(listed);
  };

  useEffect(() => {
    let cancelled = false;
    gatewayFetch<Session>('/v1/session')
      .then(async (me) => {
        if (cancelled) return;
        setSession(me);
        if (!me.permissions.includes('integration:manage')) return;
        const listed = await gatewayFetch<GitHubIntegration[]>('/v1/integrations');
        if (!cancelled) setItems(listed);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof GatewayError ? err.message : 'Failed to load integrations');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const onConnect = async (event: FormEvent) => {
    event.preventDefault();
    const submitted = token;
    setToken('');
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch<GitHubIntegration>('/v1/integrations/github', {
        method: 'POST',
        body: { owner: owner.trim(), ownerType, token: submitted },
      });
      setOwner('');
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Could not connect GitHub');
    } finally {
      setBusy(false);
    }
  };

  const onDisconnect = async (id: string) => {
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch(`/v1/integrations/${id}`, { method: 'DELETE' });
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Could not disconnect GitHub');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h1 className="page-title">Connect GitHub</h1>
      {error ? <p className="banner error">{error}</p> : null}
      {loading ? <p className="muted">Loading integrations…</p> : null}
      {!loading && session && !canManage ? (
        <p className="muted">You need permission to connect GitHub for this organization.</p>
      ) : null}
      {!loading && canManage ? (
        <form className="card" onSubmit={(event) => void onConnect(event)}>
          <label>
            Owner
            <input
              name="owner"
              value={owner}
              onChange={(event) => setOwner(event.target.value)}
              required
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label>
            Account type
            <select
              name="ownerType"
              value={ownerType}
              onChange={(event) => setOwnerType(event.target.value === 'user' ? 'user' : 'org')}
            >
              <option value="user">User</option>
              <option value="org">Organization</option>
            </select>
          </label>
          <label>
            Token
            <input
              name="token"
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              required
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button type="submit" className="cta-loud" disabled={busy}>
            {busy ? 'Connecting…' : 'Connect GitHub'}
          </button>
        </form>
      ) : null}
      {!loading && canManage ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Owner</th>
              <th>Account</th>
              <th>Sync</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <td>
                  <strong>{row.displayName}</strong>
                </td>
                <td>{row.owner}</td>
                <td>{row.ownerType === 'org' ? 'Organization' : 'User'}</td>
                <td>
                  {syncLabel(row)}
                  {row.lastSyncError ? (
                    <div className="muted small">{row.lastSyncError}</div>
                  ) : null}
                </td>
                <td>
                  <button
                    type="button"
                    className="link"
                    disabled={busy}
                    onClick={() => void onDisconnect(row.id)}
                  >
                    Disconnect
                  </button>
                </td>
              </tr>
            ))}
            {items.length === 0 ? (
              <tr>
                <td colSpan={5}>
                  <div className="empty-title">No GitHub integrations</div>
                  <p className="muted empty-copy">Paste a token to inventory repositories.</p>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
