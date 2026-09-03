import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { gatewayFetch, GatewayError } from '../api/client';
import type { AssetGraph, Finding, RiskExplanation } from '../api/types';
import {
  contributionBarWidth,
  exposureBadgeClass,
  formatContribution,
  humanize,
  scoreClass,
  severityBadgeClass,
  validationBadgeClass,
} from '../ui/display';

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
        const [riskBody, graphBody] = await Promise.all([
          gatewayFetch<RiskExplanation>(`/v1/findings/${id}/risk`),
          detail.assetId
            ? gatewayFetch<AssetGraph>(`/v1/assets/${detail.assetId}/graph`, {
                query: { depth: 2 },
              }).catch(() => null)
            : Promise.resolve(null),
        ]);
        if (cancelled) return;
        setFinding(detail);
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
          <Link to="/findings">Findings</Link>
        </p>
        <p className="banner error">{error}</p>
      </section>
    );
  }

  if (!finding) {
    return (
      <section>
        <p>
          <Link to="/findings">Findings</Link>
        </p>
        <div className="skeleton skeleton-title" />
        <div className="grid">
          <article className="card skeleton skeleton-card" />
          <article className="card skeleton skeleton-card" />
        </div>
      </section>
    );
  }

  const reachability =
    (finding.evidence?.reachability as string | undefined) ?? finding.validation ?? 'unknown';
  const dependencyPath = finding.evidence?.dependencyPath ?? [];
  const internetFacing = graph?.nodes.filter((n) => n.exposure === 'internet_facing') ?? [];

  return (
    <section>
      <p>
        <Link to="/findings">Findings</Link>
      </p>
      <h1>{finding.title}</h1>
      <p className="lede">{finding.description}</p>

      <div className="chips">
        <span className={severityBadgeClass(finding.severity)}>{humanize(finding.severity)}</span>
        <span className={finding.state === 'resolved' || finding.state === 'healthy' ? 'badge badge-ok' : 'badge badge-muted'}>
          {humanize(finding.state)}
        </span>
        <span className={validationBadgeClass(finding.validation)}>{humanize(finding.validation)}</span>
        <span className="badge badge-muted">{humanize(finding.scannerType)}</span>
        {finding.fixedVersion ? <span className="badge badge-muted">Fix {finding.fixedVersion}</span> : null}
      </div>

      <div className="grid">
        <article className="card">
          <h2>Risk</h2>
          {risk ? (
            <>
              <p className={`score ${scoreClass(risk.score)}`}>{risk.score}</p>
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
                      <td>{humanize(f.name)}</td>
                      <td>{f.weight}</td>
                      <td>{f.rawValue}</td>
                      <td>
                        <div className="contrib">
                          <div className="contrib-track">
                            <span className="contrib-bar" style={{ width: contributionBarWidth(f.contribution) }} />
                          </div>
                          <span className="muted">{formatContribution(f.contribution)}</span>
                        </div>
                      </td>
                      <td className="muted">{f.note ? humanize(f.note) : ''}</td>
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
          <ul className="plain">
            <li>
              Code: <strong>{humanize(String(reachability))}</strong>
            </li>
            {dependencyPath.length ? (
              <li>
                Dependency path: <code>{dependencyPath.join(' → ')}</code>
              </li>
            ) : null}
            {finding.asset ? (
              <li className="muted">
                Asset {finding.asset.name} · {humanize(finding.asset.exposure)} ·{' '}
                {humanize(finding.asset.criticality)}
              </li>
            ) : null}
            {graph
              ? graph.nodes.map((n) => (
                  <li key={n.id}>
                    {n.name} <span className="muted">{humanize(n.kind)}</span>
                    {n.exposure === 'internet_facing' ? (
                      <>
                        {' '}
                        <span className={exposureBadgeClass(n.exposure)}>{humanize(n.exposure)}</span>
                      </>
                    ) : (
                      <span className="muted"> · {humanize(n.exposure)}</span>
                    )}
                  </li>
                ))
              : null}
          </ul>
          {graph ? (
            <p className="muted">
              {internetFacing.length
                ? `${internetFacing.length} internet-facing node(s) in the neighborhood.`
                : 'No internet-facing node in the neighborhood.'}
            </p>
          ) : null}
        </article>
      </div>
    </section>
  );
}
