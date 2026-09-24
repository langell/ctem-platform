import { afterEach, describe, expect, it, vi } from 'vitest';
import { PRINCIPAL_HEADER, PRINCIPAL_SIGNATURE_HEADER } from '@ctem/auth';
import { ServiceProxy } from '../proxy/service-proxy';
import { ScansProxyController } from './scans.controller';

describe('scan create proxy', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('forwards Idempotency-Key and does not invent a meter body', async () => {
    const proxy = { forward: vi.fn(async () => ({ id: 'scan-1' })) };
    const ctrl = new ScansProxyController(proxy as unknown as ServiceProxy);
    const body = { scannerType: 'sca' as const, assetSelector: {}, options: {} };

    await ctrl.create({} as never, '  kick-1  ', body);
    expect(proxy.forward).toHaveBeenCalledWith('orchestrator', 'POST', '/internal/scans', {}, {
      body,
      headers: { 'idempotency-key': 'kick-1' },
    });

    await ctrl.ingestSbom({} as never, undefined, {
      assetExternalKey: 'github:acme/api',
      format: 'cyclonedx-json' as const,
      document: { bomFormat: 'CycloneDX' },
    });
    expect(proxy.forward).toHaveBeenLastCalledWith('orchestrator', 'POST', '/internal/scans/sbom', {}, {
      body: {
        assetExternalKey: 'github:acme/api',
        format: 'cyclonedx-json' as const,
        document: { bomFormat: 'CycloneDX' },
      },
      headers: undefined,
    });
  });

  it('keeps the signed principal ahead of a forwarded idempotency header', async () => {
    const fetchMock = vi.fn(async (_url: unknown, init?: { headers?: Record<string, string> }) => {
      void init;
      return new Response(JSON.stringify({ id: '1' }), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const proxy = new ServiceProxy();
    await proxy.forward(
      'orchestrator',
      'POST',
      '/internal/scans',
      { principalHeaders: { value: 'principal', signature: 'sig' } },
      { body: { scannerType: 'sca' }, headers: { 'idempotency-key': 'kick-1', [PRINCIPAL_HEADER]: 'forged' } },
    );
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.headers?.['idempotency-key']).toBe('kick-1');
    expect(init?.headers?.[PRINCIPAL_HEADER]).toBe('principal');
    expect(init?.headers?.[PRINCIPAL_SIGNATURE_HEADER]).toBe('sig');
  });
});
