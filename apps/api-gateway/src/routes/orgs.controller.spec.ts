import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const controller = readFileSync(resolve('apps/api-gateway/src/routes/orgs.controller.ts'), 'utf8');
const app = readFileSync(resolve('apps/api-gateway/src/app.module.ts'), 'utf8');
const guard = readFileSync(resolve('apps/api-gateway/src/auth/gateway-auth.guard.ts'), 'utf8');

describe('create-org gateway route', () => {
  it('posts name and slug to identity and takes the owner from the verified sub', () => {
    expect(controller).toMatch(/@Controller\('v1\/orgs'\)/);
    expect(controller).toMatch(/@Post\(\)/);
    expect(controller).toMatch(/ZodBody\(CreateOrgRequest\)/);
    expect(controller).toMatch(/req\.verifiedSub/);
    expect(controller).toMatch(/\/internal\/orgs/);
    expect(controller).toMatch(/InternalCreateOrgRequest\.parse/);
    expect(controller).not.toMatch(/body\.userId/);
    expect(controller).not.toMatch(/body\.orgId/);
    expect(controller).not.toMatch(/body\.role/);
    expect(app).toMatch(/OrgsProxyController/);
    expect(guard).toMatch(/multiple organizations/);
    expect(guard).toMatch(/No organization'/);
    expect(guard).toMatch(/path === '\/v1\/orgs'/);
    expect(guard).not.toMatch(/optionalOrg/);
  });
});
