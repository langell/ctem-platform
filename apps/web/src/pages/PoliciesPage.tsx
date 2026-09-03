import { FormEvent, useEffect, useState } from 'react';
import { gatewayFetch, GatewayError } from '../api/client';
import { SEVERITIES, type Policy, type PolicyWrite, type Session } from '../api/types';
import { SkeletonRows } from '../ui/SkeletonRows';
import { actionSelectValue, actionsFromSelect, editorActionsFromPolicy } from './policy-actions';

const emptyDraft = (): PolicyWrite => ({
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  condition: {},
  actions: ['notify'],
  slaHours: null,
});

function conditionSummary(condition: Policy['condition']): string {
  const parts: string[] = [];
  if (condition.severityAtLeast) parts.push(`severity ≥ ${condition.severityAtLeast}`);
  if (condition.kevOnly) parts.push('KEV');
  if (condition.minRiskScore !== undefined) parts.push(`risk ≥ ${condition.minRiskScore}`);
  if (condition.minEpss !== undefined) parts.push(`EPSS ≥ ${condition.minEpss}`);
  if (condition.requireFixAvailable) parts.push('fix available');
  if (condition.exposure?.length) parts.push(condition.exposure.join(', '));
  return parts.join(' · ') || 'any finding';
}

function toDraft(policy: Policy): PolicyWrite {
  return {
    name: policy.name,
    description: policy.description,
    enabled: policy.enabled,
    priority: policy.priority,
    condition: { ...policy.condition },
    actions: editorActionsFromPolicy(policy.actions),
    slaHours: policy.slaHours,
  };
}

export function PoliciesPage() {
  const [items, setItems] = useState<Policy[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<PolicyWrite>(emptyDraft);
  const [busy, setBusy] = useState(false);

  const canWrite = session?.permissions.includes('policy:write') ?? false;

  const reload = async () => {
    const [listed, me] = await Promise.all([
      gatewayFetch<Policy[]>('/v1/policies'),
      gatewayFetch<Session>('/v1/session'),
    ]);
    setItems([...listed].sort((a, b) => a.priority - b.priority));
    setSession(me);
  };

  useEffect(() => {
    reload()
      .catch((err: unknown) =>
        setError(err instanceof GatewayError ? err.message : 'Failed to load policies'),
      )
      .finally(() => setLoading(false));
  }, []);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (editingId) {
        await gatewayFetch<Policy>(`/v1/policies/${editingId}`, {
          method: 'PATCH',
          body: draft,
        });
      } else {
        await gatewayFetch<Policy>('/v1/policies', { method: 'POST', body: draft });
      }
      setDraft(emptyDraft());
      setEditingId(null);
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Failed to save policy');
    } finally {
      setBusy(false);
    }
  };

  const move = async (policy: Policy, direction: -1 | 1) => {
    const index = items.findIndex((p) => p.id === policy.id);
    const neighbor = items[index + direction];
    if (!neighbor) return;
    setError(null);
    setBusy(true);
    try {
      await gatewayFetch<Policy>(`/v1/policies/${policy.id}`, {
        method: 'PATCH',
        body: { priority: neighbor.priority },
      });
      await gatewayFetch<Policy>(`/v1/policies/${neighbor.id}`, {
        method: 'PATCH',
        body: { priority: policy.priority },
      });
      await reload();
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Failed to reorder');
    } finally {
      setBusy(false);
    }
  };

  const setCondition = (patch: Policy['condition']) => {
    setDraft((current) => ({ ...current, condition: { ...current.condition, ...patch } }));
  };

  return (
    <section>
      <h1>Policies</h1>
      <p className="muted">
        Ordered notify, ticket, or fail-build rules for the organization on the token.
        Lower priority runs first; the first match wins. Notify goes to Slack; ticket
        goes to Jira; fail-build is the CI scan conclusion on GET — not a GitHub Check.
        This client never sends an org id, a webhook/Jira URL, or a scan conclusion.
      </p>
      {error ? <p className="banner error">{error}</p> : null}

      <table>
        <thead>
          <tr>
            <th>Priority</th>
            <th>Name</th>
            <th>When</th>
            <th>Enabled</th>
            <th>Action</th>
            {canWrite ? <th /> : null}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <SkeletonRows columns={canWrite ? 6 : 5} />
          ) : (
            items.map((p, index) => (
              <tr key={p.id}>
                <td>{p.priority}</td>
                <td>
                  <strong>{p.name}</strong>
                  {p.description ? <div className="muted small">{p.description}</div> : null}
                </td>
                <td>{conditionSummary(p.condition)}</td>
                <td>{p.enabled ? 'yes' : 'no'}</td>
                <td>{p.actions.join(', ')}</td>
                {canWrite ? (
                  <td>
                    <button type="button" className="link" disabled={busy || index === 0} onClick={() => void move(p, -1)}>
                      Up
                    </button>{' '}
                    <button
                      type="button"
                      className="link"
                      disabled={busy || index === items.length - 1}
                      onClick={() => void move(p, 1)}
                    >
                      Down
                    </button>{' '}
                    <button
                      type="button"
                      className="link"
                      onClick={() => {
                        setEditingId(p.id);
                        setDraft(toDraft(p));
                      }}
                    >
                      Edit
                    </button>
                  </td>
                ) : null}
              </tr>
            ))
          )}
          {!loading && items.length === 0 && !error ? (
            <tr>
              <td colSpan={canWrite ? 6 : 5} className="muted">
                No policies in this organization.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>

      {canWrite ? (
        <form className="card" onSubmit={(e) => void onSubmit(e)}>
          <h2>{editingId ? 'Update rule' : 'Create rule'}</h2>
          <label>
            Name
            <input
              value={draft.name}
              onChange={(e) => setDraft((c) => ({ ...c, name: e.target.value }))}
              required
            />
          </label>
          <label>
            Description
            <input
              value={draft.description}
              onChange={(e) => setDraft((c) => ({ ...c, description: e.target.value }))}
            />
          </label>
          <label>
            Priority (lower runs first)
            <input
              type="number"
              value={draft.priority}
              onChange={(e) => setDraft((c) => ({ ...c, priority: Number(e.target.value) }))}
              required
            />
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) => setDraft((c) => ({ ...c, enabled: e.target.checked }))}
            />
            Enabled
          </label>
          <label>
            Severity at least
            <select
              value={draft.condition.severityAtLeast ?? ''}
              onChange={(e) =>
                setCondition({
                  severityAtLeast: (e.target.value || undefined) as Policy['condition']['severityAtLeast'],
                })
              }
            >
              <option value="">Any</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label>
            Minimum risk score
            <input
              type="number"
              min={0}
              max={100}
              value={draft.condition.minRiskScore ?? ''}
              onChange={(e) =>
                setCondition({
                  minRiskScore: e.target.value === '' ? undefined : Number(e.target.value),
                })
              }
            />
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={draft.condition.kevOnly === true}
              onChange={(e) => setCondition({ kevOnly: e.target.checked ? true : undefined })}
            />
            KEV only
          </label>
          <label>
            Action
            <select
              value={actionSelectValue(draft.actions)}
              onChange={(e) => setDraft((c) => ({ ...c, actions: actionsFromSelect(e.target.value) }))}
            >
              <option value="notify">Notify (Slack)</option>
              <option value="ticket">Ticket (Jira)</option>
              <option value="fail_build">Fail build (CI GET)</option>
              <option value="notify,ticket">Notify and ticket</option>
              <option value="notify,fail_build">Notify and fail build</option>
              <option value="ticket,fail_build">Ticket and fail build</option>
              <option value="notify,ticket,fail_build">Notify, ticket, and fail build</option>
            </select>
          </label>
          <p className="muted small">
            block-deploy and tenant webhook/Jira URLs are out of this slice. Slack still cannot
            ticket. CI reads conclusion from GET /v1/scans/:id — this form cannot POST it.
          </p>
          {editingId ? (
            <button
              type="button"
              className="link"
              onClick={() => {
                setEditingId(null);
                setDraft(emptyDraft());
              }}
            >
              Cancel edit
            </button>
          ) : null}
          <button type="submit" disabled={busy}>
            {busy ? 'Saving…' : editingId ? 'Update rule' : 'Create rule'}
          </button>
        </form>
      ) : (
        <p className="muted">This role can read policies. Writing requires policy:write.</p>
      )}
    </section>
  );
}
