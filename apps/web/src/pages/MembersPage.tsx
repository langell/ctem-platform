import { FormEvent, useEffect, useRef, useState } from 'react';
import { gatewayFetch, GatewayError } from '../api/client';
import { ROLES, type Member, type Session } from '../api/types';
import { humanize } from '../ui/display';
import { SkeletonRows } from '../ui/SkeletonRows';

function roleBadgeClass(role: string): string {
  switch (role) {
    case 'owner':
      return 'badge badge-accent badge-signal';
    case 'admin':
      return 'badge badge-info badge-signal';
    default:
      return 'badge badge-muted badge-signal';
  }
}

function statusBadgeClass(disabled: boolean): string {
  return disabled ? 'badge badge-muted badge-signal' : 'badge badge-ok badge-signal';
}

export function MembersPage() {
  const [items, setItems] = useState<Member[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<string>('developer');
  const [draftRoles, setDraftRoles] = useState<Record<string, string>>({});
  const [pendingDisable, setPendingDisable] = useState<Member | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);

  const canManage = session?.permissions.includes('member:manage') ?? false;

  const reload = async () => {
    const [listed, me] = await Promise.all([
      gatewayFetch<Member[]>('/v1/org/members'),
      gatewayFetch<Session>('/v1/session'),
    ]);
    setItems(listed);
    setSession(me);
    setDraftRoles({});
  };

  useEffect(() => {
    reload()
      .catch((err: unknown) =>
        setError(err instanceof GatewayError ? err.message : 'Failed to load members'),
      )
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (pendingDisable) {
      if (!dialog.open) dialog.showModal();
    } else if (dialog.open) {
      dialog.close();
    }
  }, [pendingDisable]);

  const onInvite = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch('/v1/org/members', {
        method: 'POST',
        body: { email: inviteEmail.trim(), role: inviteRole },
      });
      setInviteEmail('');
      setInviteRole('developer');
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Failed to invite member');
    } finally {
      setBusy(false);
    }
  };

  const onSaveRole = async (member: Member) => {
    const role = draftRoles[member.userId] ?? member.role;
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch(`/v1/org/members/${member.userId}/role`, {
        method: 'PATCH',
        body: { role },
      });
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Failed to change role');
    } finally {
      setBusy(false);
    }
  };

  const onConfirmDisable = async () => {
    if (!pendingDisable) return;
    const target = pendingDisable;
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch(`/v1/org/members/${target.userId}`, { method: 'DELETE' });
      setPendingDisable(null);
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Failed to disable member');
      setPendingDisable(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h1 className="page-title">Members</h1>
      <p className="lede">People in this organization. Roles come from membership, not the IdP.</p>
      {!loading && !error ? <p className="muted count">{items.length} members</p> : null}
      {error ? <p className="banner error">{error}</p> : null}

      <table>
        <thead>
          <tr>
            <th>Member</th>
            <th>Role</th>
            <th>Status</th>
            {canManage ? <th>Actions</th> : null}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <SkeletonRows columns={canManage ? 4 : 3} />
          ) : (
            items.map((m) => {
              const draft = draftRoles[m.userId] ?? m.role;
              const disabled = m.disabledAt !== null;
              return (
                <tr key={m.userId}>
                  <td>
                    <strong>{m.name || m.email}</strong>
                    <div className="muted small">{m.email}</div>
                  </td>
                  <td>
                    <span className={roleBadgeClass(m.role)}>{humanize(m.role)}</span>
                  </td>
                  <td>
                    <span className={statusBadgeClass(disabled)}>
                      {disabled ? 'Disabled' : 'Active'}
                    </span>
                  </td>
                  {canManage ? (
                    <td>
                      <div className="member-actions">
                        <select
                          aria-label={`Role for ${m.email}`}
                          value={draft}
                          disabled={busy}
                          onChange={(e) =>
                            setDraftRoles((current) => ({
                              ...current,
                              [m.userId]: e.target.value,
                            }))
                          }
                        >
                          {ROLES.map((role) => (
                            <option key={role} value={role}>
                              {humanize(role)}
                            </option>
                          ))}
                        </select>
                        <button
                          type="button"
                          disabled={busy || draft === m.role}
                          onClick={() => void onSaveRole(m)}
                        >
                          Save
                        </button>
                        {disabled ? null : (
                          <button
                            type="button"
                            className="link"
                            disabled={busy}
                            onClick={() => setPendingDisable(m)}
                          >
                            Disable
                          </button>
                        )}
                      </div>
                    </td>
                  ) : null}
                </tr>
              );
            })
          )}
          {!loading && items.length === 0 && !error ? (
            <tr>
              <td colSpan={canManage ? 4 : 3}>
                <div className="empty-title">No members in this organization</div>
                <p className="muted empty-copy">Invite someone to join this organization.</p>
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>

      {canManage ? (
        <form className="card" onSubmit={(e) => void onInvite(e)}>
          <h2>Invite</h2>
          <label>
            Email
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              required
              autoComplete="off"
            />
          </label>
          <label>
            Role
            <select
              aria-label="Invite role"
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
            >
              {ROLES.map((role) => (
                <option key={role} value={role}>
                  {humanize(role)}
                </option>
              ))}
            </select>
          </label>
          <div className="form-actions">
            <button type="submit" className="cta-loud" disabled={busy}>
              {busy ? 'Inviting…' : 'Invite'}
            </button>
          </div>
        </form>
      ) : (
        <p className="muted">This role can read members. Managing requires member:manage.</p>
      )}

      <dialog ref={dialogRef} className="confirm-dialog" onClose={() => setPendingDisable(null)}>
        <h2>Disable member?</h2>
        <p>
          {pendingDisable ? `${pendingDisable.email} will lose access on the next request.` : null}
        </p>
        <div className="form-actions">
          <button type="button" className="link" onClick={() => setPendingDisable(null)}>
            Cancel
          </button>
          <button
            type="button"
            className="cta-loud"
            disabled={busy}
            onClick={() => void onConfirmDisable()}
          >
            {busy ? 'Disabling…' : 'Disable member'}
          </button>
        </div>
      </dialog>
    </section>
  );
}
