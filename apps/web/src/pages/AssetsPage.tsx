import { useEffect, useState } from 'react';
import { gatewayFetch, GatewayError } from '../api/client';
import type { Asset, Page } from '../api/types';

export function AssetsPage() {
  const [items, setItems] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    gatewayFetch<Page<Asset>>('/v1/assets')
      .then((page) => setItems(page.items ?? []))
      .catch((err: unknown) =>
        setError(err instanceof GatewayError ? err.message : 'Failed to load assets'),
      );
  }, []);

  return (
    <section>
      <h1>Assets</h1>
      {error ? <p className="error">{error}</p> : null}
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
          {items.map((a) => (
            <tr key={a.id}>
              <td>
                <strong>{a.name}</strong>
                <div className="muted small">{a.externalKey}</div>
              </td>
              <td>{a.kind}</td>
              <td>{a.source}</td>
              <td>{a.exposure}</td>
              <td>{a.criticality}</td>
              <td>{a.ownerTeam ?? '—'}</td>
            </tr>
          ))}
          {items.length === 0 && !error ? (
            <tr>
              <td colSpan={6} className="muted">
                No assets in this organization.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </section>
  );
}
