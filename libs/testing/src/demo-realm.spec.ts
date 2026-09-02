import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEMO_IDP_SUBJECT, DEMO_ORG_ID, DEMO_USER_EMAIL } from './factories';

type RealmUser = { id?: string; email?: string };
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
 * Compose Keycloak and `make db-seed` must agree: JWT sub = idpSubject,
 * org_id = the demo org primary key the gateway reads after verify.
 */
describe('compose Keycloak ctem realm', () => {
  const realm = JSON.parse(readFileSync(resolve('deploy/keycloak/ctem-realm.json'), 'utf8')) as {
    realm: string;
    clients: RealmClient[];
    users: RealmUser[];
  };

  it('imports realm ctem with a demo analyst whose subject matches the seed', () => {
    expect(realm.realm).toBe('ctem');
    const user = realm.users.find((u) => u.email === DEMO_USER_EMAIL);
    expect(user?.id).toBe(DEMO_IDP_SUBJECT);
  });

  it('issues org_id, roles, audience and sub the gateway JWT path accepts', () => {
    const api = realm.clients.find((c) => c.clientId === 'ctem-api');
    const web = realm.clients.find((c) => c.clientId === 'ctem-web');
    expect(api).toBeDefined();
    expect(web).toBeDefined();
    for (const client of [api, web]) {
      const byName = mapperClaims(client);
      expect(byName.org_id?.config?.['claim.value']).toBe(DEMO_ORG_ID);
      expect(byName.roles?.config?.['claim.value']).toBe('["owner"]');
      expect(byName.sub?.config?.['claim.value']).toBe(DEMO_IDP_SUBJECT);
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
