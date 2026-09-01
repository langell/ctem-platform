import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { gatewayFetch, GatewayError } from '../api/client';
import type { AssetGraph, Finding, RiskExplanation } from '../api/types';

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [risk, setRisk] = useState<RiskExplanation | null>(null);
  const [graph, setGraph] = useState<AssetGraph | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setError(null);

    (async () => {
      try {
        const detail = await gatewayFetch<Finding>(`/v1/findings/${id}`);
        if (cancelled) return;
        setFinding(detail);
        const [riskBody, graphBody] = await Promise.all([
          gatewayFetch<RiskExplanation>(`/v1/findings/${id}/risk`),
          detail.assetId
            ? gatewayFetch<AssetGraph>(`/v1/assets/${detail.assetId}/graph`, {
                query: { depth: 2 },
              }).catch(() => null)
            : Promise.resolve(null),
        ]);
        if (cancelled) return;
        setRisk(riskBody);
        setGraph(graphBody);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof GatewayError ? err.message : 'Failed to load finding');
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) {
    return (
      <section>
        <p>
          <Link to="/findings">← Findings</Link>
        </p>
        <p className="error">{error}</p>
      </section>
    );
  }

  if (!finding) return <p className="muted">Loading…</p>;

  const reachability =
    (finding.evidence?.reachability as string | undefined) ?? finding.validation ?? 'unknown';
  const dependencyPath = finding.evidence?.dependencyPath ?? [];
  const internetFacing = graph?.nodes.filter((n) => n.exposure === 'internet_facing') ?? [];

  return (
    <section>
      <p>
        <Link to="/findings">← Findings</Link>
      </p>
      <h1>{finding.title}</h1>
      <p className="muted">{finding.description}</p>

      <dl className="meta">
        <div>
          <dt>Severity</dt>
          <dd>{finding.severity}</dd>
        </div>
        <div>
          <dt>State</dt>
          <dd>{finding.state}</dd>
        </div>
        <div>
          <dt>Validation</dt>
          <dd>{finding.validation}</dd>
        </div>
        <div>
          <dt>Scanner</dt>
          <dd>{finding.scannerType}</dd>
        </div>
        {finding.fixedVersion ? (
          <div>
            <dt>Fix</dt>
            <dd>{finding.fixedVersion}</dd>
          </div>
        ) : null}
      </dl>

      <div className="grid">
        <article className="card">
          <h2>Risk</h2>
          {risk ? (
            <>
              <p className="score">{risk.score}</p>
              <table>
                <thead>
                  <tr>
                    <th>Factor</th>
                    <th>Weight</th>
                    <th>Raw</th>
                    <th>Contribution</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {risk.factors.map((f) => (
                    <tr key={f.name}>
                      <td>{f.name}</td>
                      <td>{f.weight}</td>
                      <td>{f.rawValue}</td>
                      <td>{f.contribution.toFixed(3)}</td>
                      <td className="muted">{f.note ?? ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {risk.matchedPolicies.length ? (
                <p className="muted">Policies: {risk.matchedPolicies.join(', ')}</p>
              ) : null}
            </>
          ) : (
            <p className="muted">No risk explanation.</p>
          )}
        </article>

        <article className="card">
          <h2>Reachability</h2>
          <p>
            Code: <strong>{reachability}</strong>
          </p>
          {dependencyPath.length ? (
            <p>
              Dependency path: <code>{dependencyPath.join(' → ')}</code>
            </p>
          ) : null}
          {finding.asset ? (
            <p className="muted">
              Asset {finding.asset.name} · {finding.asset.exposure} · {finding.asset.criticality}
            </p>
          ) : null}
          {graph ? (
            <>
              <h3>Asset graph</h3>
              <ul className="plain">
                {graph.nodes.map((n) => (
                  <li key={n.id}>
                    {n.name}{' '}
                    <span className="muted">
                      {n.kind} · {n.exposure}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="muted">
                {internetFacing.length
                  ? `${internetFacing.length} internet-facing node(s) in the neighborhood.`
                  : 'No internet-facing node in the neighborhood.'}
              </p>
            </>
          ) : null}
        </article>
      </div>
    </section>
  );
}
