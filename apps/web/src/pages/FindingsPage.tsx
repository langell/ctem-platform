import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { gatewayFetch, GatewayError } from '../api/client';
import type { Finding, Page } from '../api/types';
import {
  humanize,
  riskBandClass,
  scoreClass,
  severityBadgeClass,
  severityRailClass,
  validationBadgeClass,
} from '../ui/display';
import { SkeletonRows } from '../ui/SkeletonRows';

export function FindingsPage() {
  const navigate = useNavigate();
  const [items, setItems] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    gatewayFetch<Page<Finding>>('/v1/findings')
      .then((page) => setItems(page.items ?? []))
      .catch((err: unknown) =>
        setError(err instanceof GatewayError ? err.message : 'Failed to load findings'),
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <section>
      <h1>Findings</h1>
      {!loading && !error ? <p className="muted count">{items.length} findings</p> : null}
      {error ? <p className="banner error">{error}</p> : null}
      <table>
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th className="num">Risk</th>
            <th>State</th>
            <th>Validation</th>
            <th>Scanner</th>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <SkeletonRows columns={6} />
          ) : (
            items.map((f) => (
              <tr
                key={f.id}
                className={`clickable ${severityRailClass(f.severity)}`}
                onClick={() => navigate(`/findings/${f.id}`)}
              >
                <td>
                  <Link className="finding-title" to={`/findings/${f.id}`}>
                    {f.title}
                  </Link>
                </td>
                <td>
                  <span className={severityBadgeClass(f.severity)}>{humanize(f.severity)}</span>
                </td>
                <td className="num risk-cell">
                  <div className={`${scoreClass(f.riskScore)} ${riskBandClass(f.riskScore)}`}>
                    {f.riskScore}
                  </div>
                </td>
                <td className={f.state === 'resolved' || f.state === 'healthy' ? 'ok' : undefined}>
                  {humanize(f.state)}
                </td>
                <td>
                  <span className={validationBadgeClass(f.validation)}>{humanize(f.validation)}</span>
                </td>
                <td>{humanize(f.scannerType)}</td>
              </tr>
            ))
          )}
          {!loading && !error && items.length === 0 ? (
            <tr>
              <td colSpan={6}>
                <div className="empty-title">No findings yet</div>
                <p className="muted empty-copy">
                  Run a scan from Scan, or wait for the next scheduled job.
                </p>
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </section>
  );
}
