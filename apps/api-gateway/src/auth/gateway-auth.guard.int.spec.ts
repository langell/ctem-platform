import 'reflect-metadata';
import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Controller, Get, type INestApplication } from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { AuthModule, CurrentUser, JwtVerifier, RequirePermissions } from '@ctem/auth';
import type { Principal } from '@ctem/contracts';
import { ProblemDetailsFilter } from '@ctem/service-kit';
import { TestIdp, applyTestEnv, stubUserIdFromSubject } from '@ctem/testing';
import { GatewayAuthGuard } from './gateway-auth.guard';
import { OrgsProxyController } from '../routes/orgs.controller';

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
  const otherOrg = 'bbbbbbbb-2222-4333-8444-555566667777';
  const createdOrgId = 'cccccccc-3333-4333-8333-444455556666';
  const createdBySub = new Map<string, string>();
  let orgCreateCalls = 0;

  beforeAll(async () => {
    idp = await TestIdp.start();
    strangerIdp = await TestIdp.start();

    identityStub = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        const json = (() => {
          try {
            return JSON.parse(body) as {
              token?: string;
              sub?: string;
              orgId?: string;
              name?: string;
              slug?: string;
            };
          } catch {
            return {} as { token?: string; sub?: string; orgId?: string };
          }
        })();
        // Fail-closed: identity never answers for this PAT.
        if (json.token === PAT_DROP) {
          req.socket.destroy();
          return;
        }
        res.setHeader('content-type', 'application/json');
        if (req.url === '/internal/auth/memberships') {
          const sub = json.sub ?? '';
          if (sub.includes('|drop')) {
            req.socket.destroy();
            return;
          }
          if (sub.includes('|multi')) {
            res.end(
              JSON.stringify({
                userId: stubUserIdFromSubject(sub),
                memberships: [
                  { orgId, role: 'owner' },
                  { orgId: otherOrg, role: 'admin' },
                ],
              }),
            );
            return;
          }
          if (sub.includes('|one')) {
            res.end(
              JSON.stringify({
                userId: stubUserIdFromSubject(sub),
                memberships: [{ orgId, role: 'security_analyst' }],
              }),
            );
            return;
          }
          const created = createdBySub.get(sub);
          res.end(
            JSON.stringify({
              userId: stubUserIdFromSubject(sub || 'test|user'),
              memberships: created ? [{ orgId: created, role: 'owner' }] : [],
            }),
          );
          return;
        }
        if (req.url === '/internal/orgs') {
          orgCreateCalls += 1;
          const sub = json.sub ?? '';
          if (
            !json.name ||
            !json.slug ||
            !sub ||
            json.orgId ||
            'userId' in json ||
            'role' in json
          ) {
            res.statusCode = 400;
            res.end(JSON.stringify({ title: 'Validation failed', status: 400 }));
            return;
          }
          createdBySub.set(sub, createdOrgId);
          res.statusCode = 201;
          res.end(
            JSON.stringify({
              id: createdOrgId,
              name: json.name,
              slug: json.slug,
              plan: 'trial',
            }),
          );
          return;
        }
        if (req.url === '/internal/auth/resolve') {
          const sub = json.sub ?? '';
          if (sub.includes('|nomember')) {
            res.statusCode = 403;
            res.end(JSON.stringify({ message: 'No organization membership' }));
            return;
          }
          if (sub === 'idp|raw-sub') {
            // Identity must never echo an IdP sub as userId; gateway fail-closes.
            res.end(JSON.stringify({ userId: sub, orgId: json.orgId, role: 'owner' }));
            return;
          }
          const role = sub.includes('|auditor') ? 'auditor' : 'owner';
          res.end(
            JSON.stringify({
              userId: stubUserIdFromSubject(sub || 'test|user'),
              orgId: json.orgId,
              role,
            }),
          );
          return;
        }
        if (req.url === '/internal/tokens/verify' && json.token === KNOWN_PAT) {
          res.end(
            JSON.stringify({
              orgId,
              tokenId: 'tok-1',
              name: 'ci-bot',
              scopes: ['scan:run', 'finding:read', 'not-a-real-permission'],
            }),
          );
        } else if (req.url === '/internal/tokens/verify' && json.token === PAT_NO_ORG) {
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
      controllers: [ProbeController, OrgsProxyController],
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
    app.useGlobalFilters(new ProblemDetailsFilter());
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

  const postOrg = (
    token: string | undefined,
    body: unknown,
    headers: Record<string, string> = {},
  ) =>
    fetch(`${base}/v1/orgs`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: JSON.stringify(body),
    });

  it('rejects requests without a bearer token', async () => {
    expect((await get('/probe/read')).status).toBe(401);
  });

  it('rejects a JWT signed by an unknown issuer', async () => {
    const forged = await strangerIdp.issueToken({ orgId, roles: ['owner'] });
    expect((await get('/probe/read', forged)).status).toBe(401);
  });

  it('mints a principal from Membership, not the IdP sub or JWT roles', async () => {
    const jwt = await idp.issueToken({
      sub: 'idp|alice',
      orgId,
      roles: ['security_analyst'],
      email: 'alice@test.local',
    });
    const res = await get('/probe/read', jwt);
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal).toMatchObject({
      userId: stubUserIdFromSubject('idp|alice'),
      orgId,
      role: 'owner',
      serviceAccount: null,
    });
    expect(principal.userId).not.toBe('idp|alice');
    expect(principal.permissions).toContain('finding:triage');
  });

  it('rejects an expired JWT', async () => {
    const jwt = await idp.issueToken({ orgId, roles: ['owner'], expiresIn: -60 });
    expect((await get('/probe/read', jwt)).status).toBe(401);
  });

  it('rejects a JWT without an organization', async () => {
    const jwt = await idp.issueToken({ orgId: null, roles: ['owner'] });
    const res = await get('/probe/read', jwt);
    expect(res.status).toBe(403);
    expect((await res.json()).title).toBe('No organization');
  });

  it('scopes a JWT with no org_id to the single membership and ignores a client org', async () => {
    const jwt = await idp.issueToken({
      sub: 'idp|one',
      orgId: null,
      roles: ['owner'],
      email: 'one@test.local',
    });
    const res = await fetch(`${base}/probe/read?orgId=${otherOrg}`, {
      headers: { authorization: `Bearer ${jwt}`, 'x-ctem-org': otherOrg },
    });
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal.orgId).toBe(orgId);
    expect(principal.orgId).not.toBe(otherOrg);
    expect(principal.role).toBe('security_analyst');
    expect(principal.userId).toBe(stubUserIdFromSubject('idp|one'));
  });

  it('rejects multiple active memberships with 409 and does not create an org', async () => {
    const before = orgCreateCalls;
    const jwt = await idp.issueToken({ sub: 'idp|multi', orgId: null, roles: ['owner'] });
    const res = await get('/probe/read', jwt);
    expect(res.status).toBe(409);
    expect((await res.json()).title).toBe('multiple organizations');
    const created = await postOrg(jwt, { name: 'Multi', slug: 'multi-org' });
    expect(created.status).toBe(409);
    expect((await created.json()).title).toBe('multiple organizations');
    expect(orgCreateCalls).toBe(before);
  });

  it('allows POST /v1/orgs for a zero-membership JWT, then scopes the next request to that org', async () => {
    const before = orgCreateCalls;
    const jwt = await idp.issueToken({
      sub: 'idp|fresh-owner',
      orgId: null,
      roles: ['owner'],
      email: 'fresh@test.local',
    });
    const blocked = await get('/probe/read', jwt);
    expect(blocked.status).toBe(403);
    expect((await blocked.json()).title).toBe('No organization');

    const created = await postOrg(
      jwt,
      { name: 'Fresh', slug: 'fresh-org' },
      { 'x-ctem-org': otherOrg },
    );
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({
      id: createdOrgId,
      name: 'Fresh',
      slug: 'fresh-org',
      plan: 'trial',
    });
    expect(orgCreateCalls).toBe(before + 1);

    const session = await fetch(`${base}/probe/read?orgId=${otherOrg}`, {
      headers: { authorization: `Bearer ${jwt}`, 'x-ctem-org': otherOrg },
    });
    expect(session.status).toBe(200);
    const principal = (await session.json()) as Principal;
    expect(principal.orgId).toBe(createdOrgId);
    expect(principal.role).toBe('owner');
    expect(principal.orgId).not.toBe(otherOrg);
  });

  it('rejects client-supplied org, role, and owner on POST /v1/orgs', async () => {
    const jwt = await idp.issueToken({
      sub: 'idp|fresh-extra',
      orgId: null,
      email: 'extra@test.local',
    });
    const res = await postOrg(jwt, {
      name: 'Fresh',
      slug: 'fresh-extra',
      orgId,
      role: 'owner',
      userId: stubUserIdFromSubject('idp|someone'),
      plan: 'enterprise',
    });
    expect(res.status).toBe(400);
  });

  it('does not create an org when the token names an org the user is not in', async () => {
    const before = orgCreateCalls;
    const jwt = await idp.issueToken({
      sub: 'idp|nomember',
      orgId,
      roles: ['owner'],
      email: 'nobody@test.local',
    });
    const res = await postOrg(jwt, { name: 'Other', slug: 'other-org' });
    expect(res.status).toBe(403);
    expect((await res.json()).title).toBe('No organization membership');
    expect(orgCreateCalls).toBe(before);
  });

  it('rejects a PAT and a missing bearer on POST /v1/orgs', async () => {
    const before = orgCreateCalls;
    expect((await postOrg(undefined, { name: 'X', slug: 'xxxx' })).status).toBe(401);
    expect((await postOrg(KNOWN_PAT, { name: 'X', slug: 'xxxx' })).status).toBe(401);
    expect(orgCreateCalls).toBe(before);
  });

  it('fail-closes org create when identity is unreachable and does not invent an org', async () => {
    const before = orgCreateCalls;
    const jwt = await idp.issueToken({ sub: 'idp|drop', orgId: null, email: 'drop@test.local' });
    const res = await postOrg(jwt, { name: 'Drop', slug: 'drop-org' });
    expect(res.status).toBe(401);
    expect(orgCreateCalls).toBe(before);
  });

  it('rejects a present but invalid org_id without falling through to signup', async () => {
    const before = orgCreateCalls;
    const jwt = await idp.issueToken({ orgId: 'not-a-uuid', roles: ['owner'] });
    const res = await postOrg(jwt, { name: 'Nope', slug: 'nope-org' });
    expect(res.status).toBe(403);
    expect((await res.json()).title).toBe('No organization selected');
    expect(orgCreateCalls).toBe(before);
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

  it('rejects a JWT with no Membership (403), ignoring JWT roles', async () => {
    const jwt = await idp.issueToken({
      sub: 'idp|nomember',
      orgId,
      roles: ['owner'],
      email: 'nobody@test.local',
    });
    expect((await get('/probe/read', jwt)).status).toBe(403);
  });

  it('does not write an IdP-shaped sub as Principal.userId', async () => {
    const jwt = await idp.issueToken({ sub: 'idp|raw-sub', orgId, roles: ['owner'] });
    expect((await get('/probe/read', jwt)).status).toBe(401);
  });

  it('takes permissions from Membership when JWT roles disagree', async () => {
    const jwt = await idp.issueToken({
      sub: 'idp|auditor',
      orgId,
      roles: ['owner'],
      email: 'auditor@test.local',
    });
    const res = await get('/probe/read', jwt);
    expect(res.status).toBe(200);
    const principal = (await res.json()) as Principal;
    expect(principal.role).toBe('auditor');
    expect(principal.permissions).not.toContain('finding:triage');
    expect((await get('/probe/triage', jwt)).status).toBe(403);
  });

  it('ignores unknown JWT role claims when Membership exists', async () => {
    const jwt = await idp.issueToken({ orgId, roles: ['superuser'] });
    expect((await get('/probe/read', jwt)).status).toBe(200);
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
