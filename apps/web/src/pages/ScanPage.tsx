import { FormEvent, useState } from 'react';
import { gatewayFetch, GatewayError } from '../api/client';
import { SCANNER_TYPES, type Scan, type ScannerType } from '../api/types';
import { humanize } from '../ui/display';

export function ScanPage() {
  const [scannerType, setScannerType] = useState<ScannerType>('sca');
  const [assetIds, setAssetIds] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Scan | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setResult(null);
    const ids = assetIds
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    setBusy(true);
    try {
      const scan = await gatewayFetch<Scan>('/v1/scans', {
        method: 'POST',
        body: {
          scannerType,
          assetSelector: ids.length ? { assetIds: ids } : {},
          options: {},
        },
      });
      setResult(scan);
    } catch (err) {
      setError(err instanceof GatewayError ? err.message : 'Failed to start scan');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h1>Scan</h1>
      <p className="lede">
        Start a scan for this organization. Leave asset IDs empty to include every in-scope asset.
      </p>
      <form className="card" onSubmit={onSubmit}>
        <label>
          Scanner
          <select
            value={scannerType}
            onChange={(e) => setScannerType(e.target.value as ScannerType)}
          >
            {SCANNER_TYPES.map((t) => (
              <option key={t} value={t}>
                {humanize(t)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Asset IDs (optional, comma-separated)
          <input
            value={assetIds}
            onChange={(e) => setAssetIds(e.target.value)}
            placeholder="uuid, uuid"
          />
        </label>
        {error ? <p className="banner error">{error}</p> : null}
        <button type="submit" disabled={busy}>
          {busy ? 'Starting…' : 'Start scan'}
        </button>
      </form>
      {result ? (
        <article className="card">
          <h2>{humanize(result.status)}</h2>
          <p>
            <span className="badge badge-muted">{humanize(result.scannerType)}</span>{' '}
            <span className="badge badge-muted">{humanize(result.status)}</span>
          </p>
          <p className="small muted">
            <code>{result.id}</code>
          </p>
        </article>
      ) : null}
    </section>
  );
}
