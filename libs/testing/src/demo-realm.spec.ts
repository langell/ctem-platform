import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEMO_DEVELOPER_EMAIL,
  DEMO_DEVELOPER_IDP_SUBJECT,
  DEMO_IDP_SUBJECT,
  DEMO_USER_EMAIL,
} from './factories';

type RealmUser = {
  id?: string;
  email?: string;
  emailVerified?: boolean;
  attributes?: Record<string, string[]>;
};
type ProtocolMapper = { name?: string; protocolMapper?: string; config?: Record<string, string> };
type RealmClient = {
  clientId?: string;
  publicClient?: boolean;
  secret?: string;
  standardFlowEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  directAccessGrantsEnabled?: boolean;
  attributes?: Record<string, string>;
  redirectUris?: string[];
  protocolMappers?: ProtocolMapper[];
};

function mapperClaims(client: RealmClient | undefined) {
  return Object.fromEntries((client?.protocolMappers ?? []).map((m) => [m.name, m]));
}

/**
 * Compose Keycloak and `make db-seed` must agree: JWT sub = idpSubject.
 * Org comes from the single active membership, not an org_id claim.
 */
describe('compose Keycloak ctem realm', () => {
  const realm = JSON.parse(readFileSync(resolve('deploy/keycloak/ctem-realm.json'), 'utf8')) as {
    realm: string;
    registrationAllowed?: boolean;
    verifyEmail?: boolean;
    identityProviders?: unknown[];
    clients: RealmClient[];
    users: RealmUser[];
  };

  it('imports realm ctem with a demo analyst whose subject matches the seed', () => {
    expect(realm.realm).toBe('ctem');
    const user = realm.users.find((u) => u.email === DEMO_USER_EMAIL);
    expect(user?.id).toBe(DEMO_IDP_SUBJECT);
    expect(user?.attributes?.org_id).toBeUndefined();
    expect(user?.attributes).toBeUndefined();
    const developer = realm.users.find((u) => u.email === DEMO_DEVELOPER_EMAIL);
    expect(developer?.id).toBe(DEMO_DEVELOPER_IDP_SUBJECT);
    expect(developer?.emailVerified).toBe(true);
    expect(developer?.attributes).toBeUndefined();
    expect(DEMO_IDP_SUBJECT).toBe('demo|analyst');
    expect(DEMO_DEVELOPER_IDP_SUBJECT).toBe('demo|developer');
    const seed = readFileSync(resolve('libs/testing/src/factories.ts'), 'utf8');
    expect(seed).toMatch(/idpSubject: DEMO_IDP_SUBJECT/);
    expect(seed).toMatch(/role: 'owner', disabledAt: null/);
  });

  it('maps email_verified and does not map org_id, role, or sub', () => {
    expect(realm.registrationAllowed).toBe(true);
    expect(realm.verifyEmail).not.toBe(true);
    expect(realm.identityProviders).toBeUndefined();
    const api = realm.clients.find((c) => c.clientId === 'ctem-api');
    const web = realm.clients.find((c) => c.clientId === 'ctem-web');
    expect(api).toBeDefined();
    expect(web).toBeDefined();
    for (const client of [api, web]) {
      const byName = mapperClaims(client);
      expect(byName.org_id).toBeUndefined();
      expect(byName.email_verified?.protocolMapper).toBe('oidc-usermodel-property-mapper');
      expect(byName.email_verified?.config?.['user.attribute']).toBe('emailVerified');
      expect(byName.email_verified?.config?.['claim.name']).toBe('email_verified');
      expect(byName.email_verified?.config?.['jsonType.label']).toBe('boolean');
      expect(byName.email_verified?.config?.['access.token.claim']).toBe('true');
      expect(byName.roles).toBeUndefined();
      expect(byName.sub).toBeUndefined();
      expect(byName.email?.config?.['claim.name']).toBe('email');
      expect(byName.email?.config?.['access.token.claim']).toBe('true');
      expect(
        client?.protocolMappers?.some((m) => m.protocolMapper === 'oidc-hardcoded-claim-mapper'),
      ).toBe(false);
      expect(byName['audience-ctem-api']?.protocolMapper).toBe('oidc-audience-mapper');
      expect(byName['audience-ctem-api']?.config?.['included.custom.audience']).toBe('ctem-api');
    }
  });

  it('registers apps/web as a public OIDC client with PKCE', () => {
    const web = realm.clients.find((c) => c.clientId === 'ctem-web');
    expect(web?.publicClient).toBe(true);
    expect(web?.secret).toBeFalsy();
    expect(web?.standardFlowEnabled).toBe(true);
    expect(web?.implicitFlowEnabled).toBe(false);
    expect(web?.directAccessGrantsEnabled).toBe(false);
    expect(web?.attributes?.['pkce.code.challenge.method']).toBe('S256');
    expect(web?.redirectUris).toEqual(
      expect.arrayContaining([
        'http://localhost:3000/login/callback',
        'http://localhost:4200/login/callback',
      ]),
    );
  });

  it('keeps confidential ctem-api for password-grant demo-token, not the browser', () => {
    const api = realm.clients.find((c) => c.clientId === 'ctem-api');
    expect(api?.publicClient).toBe(false);
    expect(api?.directAccessGrantsEnabled).toBe(true);
    expect(api?.standardFlowEnabled).toBe(false);
  });
});
