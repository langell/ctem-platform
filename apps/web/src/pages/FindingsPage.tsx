import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { gatewayFetch, GatewayError } from '../api/client';
import type { Finding, Page } from '../api/types';

export function FindingsPage() {
  const [items, setItems] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    gatewayFetch<Page<Finding>>('/v1/findings')
      .then((page) => setItems(page.items ?? []))
      .catch((err: unknown) =>
        setError(err instanceof GatewayError ? err.message : 'Failed to load findings'),
      );
  }, []);

  return (
    <section>
      <h1>Findings</h1>
      {error ? <p className="error">{error}</p> : null}
      <table>
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>Risk</th>
            <th>State</th>
            <th>Validation</th>
            <th>Scanner</th>
          </tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <tr key={f.id}>
              <td>
                <Link to={`/findings/${f.id}`}>{f.title}</Link>
              </td>
              <td>{f.severity}</td>
              <td>{f.riskScore}</td>
              <td>{f.state}</td>
              <td>{f.validation}</td>
              <td>{f.scannerType}</td>
            </tr>
          ))}
          {items.length === 0 && !error ? (
            <tr>
              <td colSpan={6} className="muted">
                No findings in this organization.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </section>
  );
}
