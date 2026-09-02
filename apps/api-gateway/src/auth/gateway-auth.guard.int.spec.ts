import 'reflect-metadata';
import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Controller, Get, type INestApplication } from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { AuthModule, CurrentUser, JwtVerifier, RequirePermissions } from '@ctem/auth';
import type { Principal } from '@ctem/contracts';
import { TestIdp, applyTestEnv } from '@ctem/testing';
import { GatewayAuthGuard } from './gateway-auth.guard';

const KNOWN_PAT = 'ctem_pat_known-integration-token';
const PAT_NO_ORG = 'ctem_pat_missing-org-record';
const PAT_DROP = 'ctem_pat_identity-unreachable';

@Controller('probe')
class ProbeController {
  @Get('read')
  @RequirePermissions('finding:read')
  read(@CurrentUser() principal: Principal) {
    return principal;
  }

  @Get('triage')
  @RequirePermissions('finding:triage')
  triage() {
    return { ok: true };
  }
}

/**
 * Boots a minimal Nest app with the real guard, a real JWKS-backed IdP and a
 * stub identity-service, then talks to it over real HTTP. Covers both token
 * paths end to end: OIDC JWTs and machine PATs.
 */
describe('GatewayAuthGuard (integration)', () => {
  let idp: TestIdp;
  let strangerIdp: TestIdp;
  let identityStub: Server;
  let app: INestApplication;
  let base: string;
  const orgId = '4a6f9f4e-1111-4222-8333-444455556666';

  beforeAll(async () => {
    idp = await TestIdp.start();
    strangerIdp = await TestIdp.start();

    identityStub = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        const presented = (() => {
          try {
            return (JSON.parse(body) as { token?: string }).token;
          } catch {
            return undefined;
          }
        })();
        // Fail-closed: identity never answers for this PAT.
        if (presented === PAT_DROP) {
          req.socket.destroy();
          return;
        }
        res.setHeader('content-type', 'application/json');
        if (req.url === '/internal/tokens/verify' && presented === KNOWN_PAT) {
          res.end(
            JSON.stringify({
              orgId,
              tokenId: 'tok-1',
              name: 'ci-bot',
              scopes: ['scan:run', 'finding:read', 'not-a-real-permission'],
            }),
          );
        } else if (req.url === '/internal/tokens/verify' && presented === PAT_NO_ORG) {
          // 200 without an org — gateway must not invent a tenant from the client.
          res.end(JSON.stringify({ tokenId: 'tok-x', name: 'ci-bot', scopes: ['finding:read'] }));
        } else {
          res.statusCode = 401;
          res.end(JSON.stringify({ message: 'Invalid token' }));
        }
      });
    });
    await new Promise<void>((resolve) => identityStub.listen(0, '127.0.0.1', resolve));
    const stubPort = (identityStub.address() as AddressInfo).port;

    applyTestEnv({
      OIDC_ISSUER: idp.issuer,
      IDENTITY_SERVICE_URL: `http://127.0.0.1:${stubPort}`,
    });

    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      controllers: [ProbeController],
      providers: [
        {
          provide: APP_GUARD,
          // Explicit inject list: vitest's transform does not emit decorator
          // metadata, so constructor injection must be spelled out here.
          useFactory: (reflector: Reflector, jwt: JwtVerifier) =>
            new GatewayAuthGuard(reflector, jwt),
          inject: [Reflector, JwtVerifier],
        },
      ],
    }).compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0);
    base = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await app?.close();
    await idp?.stop();
    await strangerIdp?.stop();
    await new Promise<void>((resolve) => identityStub.close(() => resolve()));
  });

  const get = (path: string, token?: string) =>
    fetch(`${base}${path}`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });

  it('rejects requests without a bearer token', async () => {
    expect((await get('/probe/read')).status).toBe(401);
  });

  it('rejects a JWT signed by an unknown issuer', async () => {
    const forged = await strangerIdp.issueToken({ orgId, roles: ['owner'] });
    expect((await get('/probe/read', forged)).status).toBe(401);
  });

  it('mints a principal from a valid JWT', async () => {
    const jwt = await idp.issueToken({ sub: 'idp|alice', orgId, roles: ['security_analyst'] });
    const res = await get('/probe/read', jwt);
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal).toMatchObject({
      userId: 'idp|alice',
      orgId,
      role: 'security_analyst',
      serviceAccount: null,
    });
    expect(principal.permissions).toContain('finding:triage');
  });

  it('rejects an expired JWT', async () => {
    const jwt = await idp.issueToken({ orgId, roles: ['owner'], expiresIn: -60 });
    expect((await get('/probe/read', jwt)).status).toBe(401);
  });

  it('rejects a JWT without an organization', async () => {
    const jwt = await idp.issueToken({ orgId: null, roles: ['owner'] });
    expect((await get('/probe/read', jwt)).status).toBe(403);
  });

  it('ignores a client-supplied x-ctem-org that disagrees with the JWT', async () => {
    const otherOrg = 'bbbbbbbb-2222-4333-8444-555566667777';
    const jwt = await idp.issueToken({ sub: 'idp|alice', orgId, roles: ['owner'] });
    const res = await fetch(`${base}/probe/read`, {
      headers: { authorization: `Bearer ${jwt}`, 'x-ctem-org': otherOrg },
    });
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal.orgId).toBe(orgId);
    expect(principal.orgId).not.toBe(otherOrg);
  });

  it('rejects a JWT with an unknown role', async () => {
    const jwt = await idp.issueToken({ orgId, roles: ['superuser'] });
    expect((await get('/probe/read', jwt)).status).toBe(403);
  });

  it('denies a role that lacks the route permission', async () => {
    const jwt = await idp.issueToken({ orgId, roles: ['auditor'] });
    expect((await get('/probe/read', jwt)).status).toBe(200);
    expect((await get('/probe/triage', jwt)).status).toBe(403);
  });

  it('mints a service-account principal from a valid PAT, keeping only real permissions', async () => {
    const res = await get('/probe/read', KNOWN_PAT);
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal).toMatchObject({ orgId, userId: 'tok-1', serviceAccount: 'ci-bot' });
    expect(principal.permissions.sort()).toEqual(['finding:read', 'scan:run']);
  });

  it('takes PAT org from the token record, ignoring a client-supplied org', async () => {
    const otherOrg = 'bbbbbbbb-2222-4333-8444-555566667777';
    const res = await fetch(`${base}/probe/read?orgId=${otherOrg}`, {
      headers: {
        authorization: `Bearer ${KNOWN_PAT}`,
        'x-ctem-org': otherOrg,
        'x-org-id': otherOrg,
      },
    });
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal.orgId).toBe(orgId);
    expect(principal.orgId).not.toBe(otherOrg);
    expect(principal.serviceAccount).toBe('ci-bot');
  });

  it('rejects an unknown PAT', async () => {
    expect((await get('/probe/read', 'ctem_pat_bogus')).status).toBe(401);
  });

  it('rejects a missing PAT (no bearer) fail-closed', async () => {
    expect((await get('/probe/read')).status).toBe(401);
    expect((await get('/probe/read', '')).status).toBe(401);
  });

  it('rejects a PAT whose identity record has no org', async () => {
    expect((await get('/probe/read', PAT_NO_ORG)).status).toBe(401);
  });

  it('fail-closes when identity-service is unreachable for a PAT', async () => {
    expect((await get('/probe/read', PAT_DROP)).status).toBe(401);
  });

  it('denies a PAT whose scopes lack the route permission', async () => {
    expect((await get('/probe/triage', KNOWN_PAT)).status).toBe(403);
  });
});
