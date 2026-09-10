import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const controller = readFileSync(
  resolve('apps/api-gateway/src/routes/org-members.controller.ts'),
  'utf8',
);
const app = readFileSync(resolve('apps/api-gateway/src/app.module.ts'), 'utf8');

describe('org members gateway proxy', () => {
  it('exposes GET/POST/PATCH role/DELETE on /v1/org/members via identity', () => {
    expect(controller).toMatch(/@Controller\('v1\/org\/members'\)/);
    expect(controller).toMatch(/@Get\(\)/);
    expect(controller).toMatch(/@Post\(\)/);
    expect(controller).toMatch(/@Patch\(':userId\/role'\)/);
    expect(controller).toMatch(/@Delete\(':userId'\)/);
    expect(controller).toMatch(/@RequirePermissions\('org:read'\)/);
    expect(controller).toMatch(/@RequirePermissions\('member:manage'\)/);
    expect(controller).toMatch(/forward\('identity', 'GET', '\/internal\/org\/members'/);
    expect(controller).toMatch(/forward\('identity', 'POST', '\/internal\/org\/members'/);
    expect(controller).toMatch(
      /forward\(\s*'identity',\s*'PATCH',\s*`\/internal\/org\/members\/\$\{userId\}\/role`/,
    );
    expect(controller).toMatch(
      /forward\('identity', 'DELETE', `\/internal\/org\/members\/\$\{userId\}`/,
    );
    expect(controller).toMatch(/no Keycloak Admin API/);
    expect(controller).not.toMatch(/orgId/);
    expect(app).toMatch(/OrgMembersProxyController/);
  });
});
