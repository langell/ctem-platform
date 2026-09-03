import { useEffect, useState } from 'react';
import { gatewayFetch, GatewayError } from '../api/client';
import type { Asset, Page } from '../api/types';
import { exposureBadgeClass, humanize, severityBadgeClass } from '../ui/display';
import { SkeletonRows } from '../ui/SkeletonRows';

export function AssetsPage() {
  const [items, setItems] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    gatewayFetch<Page<Asset>>('/v1/assets')
      .then((page) => setItems(page.items ?? []))
      .catch((err: unknown) =>
        setError(err instanceof GatewayError ? err.message : 'Failed to load assets'),
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <section>
      <h1>Assets</h1>
      {!loading && !error ? <p className="muted count">{items.length} assets</p> : null}
      {error ? <p className="banner error">{error}</p> : null}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Kind</th>
            <th>Source</th>
            <th>Exposure</th>
            <th>Criticality</th>
            <th>Owner</th>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <SkeletonRows columns={6} />
          ) : (
            items.map((a) => (
              <tr key={a.id}>
                <td>
                  <strong>{a.name}</strong>
                  <div className="muted small">{a.externalKey}</div>
                </td>
                <td>{humanize(a.kind)}</td>
                <td>{humanize(a.source)}</td>
                <td>
                  <span className={exposureBadgeClass(a.exposure)}>{humanize(a.exposure)}</span>
                </td>
                <td>
                  <span className={severityBadgeClass(a.criticality)}>
                    {humanize(a.criticality)}
                  </span>
                </td>
                <td>{a.ownerTeam ?? '—'}</td>
              </tr>
            ))
          )}
          {!loading && !error && items.length === 0 ? (
            <tr>
              <td colSpan={6}>
                <div className="empty-title">No assets in this organization</div>
                <p className="muted empty-copy">Discovery connectors fill this list.</p>
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </section>
  );
}
