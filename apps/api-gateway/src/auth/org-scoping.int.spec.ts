import 'reflect-metadata';
import { type AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  Controller,
  Get,
  NotFoundException,
  Param,
  type INestApplication,
} from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { AuthModule, CurrentUser, JwtVerifier, RequirePermissions } from '@ctem/auth';
import type { Principal } from '@ctem/contracts';
import { TestIdp, applyTestEnv } from '@ctem/testing';
import { GatewayAuthGuard } from './gateway-auth.guard';
import { SessionController } from '../routes/session.controller';

const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const ORG_B = 'bbbbbbbb-2222-4333-8444-555566667777';
const FINDING_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const FINDING_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

@Controller('v1/findings')
class FindingsProbeController {
  @Get()
  @RequirePermissions('finding:read')
  list(@CurrentUser() principal: Principal) {
    const id = principal.orgId === ORG_A ? FINDING_A : FINDING_B;
    return {
      items: [{ id, orgId: principal.orgId, title: `finding-of-${principal.orgId}` }],
      nextCursor: null,
    };
  }

  @Get(':id/risk')
  @RequirePermissions('finding:read')
  risk(@CurrentUser() principal: Principal, @Param('id') id: string) {
    const owned = principal.orgId === ORG_A ? FINDING_A : FINDING_B;
    if (id !== owned) throw new NotFoundException(`Finding ${id} not found`);
    return { findingId: id, score: 91, factors: [], matchedPolicies: [] };
  }

  @Get(':id')
  @RequirePermissions('finding:read')
  get(@CurrentUser() principal: Principal, @Param('id') id: string) {
    const owned = principal.orgId === ORG_A ? FINDING_A : FINDING_B;
    if (id !== owned) throw new NotFoundException(`Finding ${id} not found`);
    return { id, orgId: principal.orgId, title: `finding-of-${principal.orgId}` };
  }
}

/**
 * JWT/org scoping + findings isolation at the gateway.
 *
 * The UI is a client of these endpoints. A client-supplied org id (header or
 * query) must not change the tenant, and a JWT for org A must not see org B
 * findings — even when the caller asks for them by id.
 */
describe('JWT org scoping and findings tenancy (integration)', () => {
  let idp: TestIdp;
  let app: INestApplication;
  let base: string;

  beforeAll(async () => {
    idp = await TestIdp.start();
    applyTestEnv({ OIDC_ISSUER: idp.issuer });

    const moduleRef = await Test.createTestingModule({
      imports: [AuthModule],
      controllers: [SessionController, FindingsProbeController],
      providers: [
        {
          provide: APP_GUARD,
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
  });

  async function call(
    path: string,
    token: string,
    extra: { headers?: Record<string, string> } = {},
  ) {
    return fetch(`${base}${path}`, {
      headers: { authorization: `Bearer ${token}`, ...extra.headers },
    });
  }

  it('session.orgId comes from the JWT, not x-ctem-org or ?orgId=', async () => {
    const jwt = await idp.issueToken({ sub: 'idp|alice', orgId: ORG_A, roles: ['security_analyst'] });
    const res = await call(`/v1/session?orgId=${ORG_B}`, jwt, {
      headers: { 'x-ctem-org': ORG_B, 'x-org-id': ORG_B },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { orgId: string; userId: string };
    expect(body.orgId).toBe(ORG_A);
    expect(body.userId).toBe('idp|alice');
  });

  it('a JWT without org_id is rejected even when the client supplies an org header', async () => {
    const jwt = await idp.issueToken({ orgId: null, roles: ['owner'] });
    const res = await call('/v1/session', jwt, { headers: { 'x-ctem-org': ORG_A } });
    expect(res.status).toBe(403);
  });

  it('lists only findings for the JWT org when the client sends another org', async () => {
    const jwt = await idp.issueToken({ orgId: ORG_A, roles: ['security_analyst'] });
    const res = await call(`/v1/findings?orgId=${ORG_B}&limit=50`, jwt, {
      headers: { 'x-ctem-org': ORG_B },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { items: Array<{ id: string; orgId: string; title: string }> };
    expect(body.items).toHaveLength(1);
    expect(body.items[0]?.orgId).toBe(ORG_A);
    expect(body.items[0]?.id).toBe(FINDING_A);
    expect(body.items.some((f) => f.orgId === ORG_B || f.id === FINDING_B)).toBe(false);
  });

  it('does not leak an org-B finding (detail or risk) to an org-A JWT', async () => {
    const jwt = await idp.issueToken({ orgId: ORG_A, roles: ['security_analyst'] });
    const detail = await call(`/v1/findings/${FINDING_B}`, jwt, {
      headers: { 'x-ctem-org': ORG_B },
    });
    expect(detail.status).toBe(404);

    const risk = await call(`/v1/findings/${FINDING_B}/risk`, jwt, {
      headers: { 'x-ctem-org': ORG_B },
    });
    expect(risk.status).toBe(404);
  });

  it('returns org-A finding detail and risk only for an org-A JWT', async () => {
    const jwtA = await idp.issueToken({ orgId: ORG_A, roles: ['security_analyst'] });
    const jwtB = await idp.issueToken({ orgId: ORG_B, roles: ['security_analyst'] });

    const a = await call(`/v1/findings/${FINDING_A}`, jwtA);
    expect(a.status).toBe(200);
    expect(((await a.json()) as { orgId: string }).orgId).toBe(ORG_A);

    const bList = await call('/v1/findings', jwtB);
    expect(bList.status).toBe(200);
    const items = ((await bList.json()) as { items: Array<{ id: string }> }).items;
    expect(items.map((i) => i.id)).toEqual([FINDING_B]);

    const crossed = await call(`/v1/findings/${FINDING_A}/risk`, jwtB);
    expect(crossed.status).toBe(404);
  });
});
