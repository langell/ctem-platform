/**
 * Dev-only Keycloak user for invite QA.
 *
 *   pnpm kc:user -- --email invitee@example.test --verified true --password demo
 *
 * Uses the compose bootstrap admin (docker-compose.yml keycloak service).
 * Refuses to run when NODE_ENV is production or OIDC_ISSUER is not localhost.
 * No new environment variables: OIDC_ISSUER is the existing issuer.
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const DEV_ADMIN_USER = 'admin';
const DEV_ADMIN_PASSWORD = 'admin';

export interface CreateKeycloakUserInput {
  email: string;
  verified: boolean;
  password: string;
}

function readEnvKey(file: string, key: string): string | undefined {
  if (!existsSync(file)) return undefined;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) continue;
    if (trimmed.slice(0, eq).trim() !== key) continue;
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    return value;
  }
  return undefined;
}

function issuerFromEnv(): string {
  if (!process.env.OIDC_ISSUER) {
    const roots = [
      process.cwd(),
      resolve(process.cwd(), '..'),
      resolve(process.cwd(), '../..'),
      resolve(process.cwd(), '../../..'),
    ];
    for (const root of roots) {
      const value = readEnvKey(resolve(root, '.env'), 'OIDC_ISSUER');
      if (value) {
        process.env.OIDC_ISSUER = value;
        break;
      }
    }
  }
  return process.env.OIDC_ISSUER ?? 'http://localhost:8080/realms/ctem';
}

function assertDevIssuer(): { origin: string; realm: string } {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('kc:user refuses to run when NODE_ENV is production');
  }
  const issuer = issuerFromEnv();
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new Error('OIDC_ISSUER is not a URL');
  }
  if (url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new Error('kc:user refuses OIDC_ISSUER hosts other than localhost or 127.0.0.1');
  }
  const parts = url.pathname.split('/').filter(Boolean);
  const realmAt = parts.indexOf('realms');
  const realm = realmAt >= 0 ? parts[realmAt + 1] : undefined;
  if (!realm) throw new Error('OIDC_ISSUER must include /realms/<realm>');
  return { origin: url.origin, realm };
}

async function adminToken(origin: string): Promise<string> {
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: 'admin-cli',
    username: DEV_ADMIN_USER,
    password: DEV_ADMIN_PASSWORD,
  });
  const res = await fetch(`${origin}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) throw new Error(`Keycloak admin login failed (${res.status})`);
  const json = (await res.json()) as { access_token?: string };
  if (!json.access_token) throw new Error('Keycloak admin login returned no token');
  return json.access_token;
}

async function findUserId(origin: string, realm: string, token: string, email: string) {
  const url = new URL(`${origin}/admin/realms/${realm}/users`);
  url.searchParams.set('email', email);
  url.searchParams.set('exact', 'true');
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`Keycloak user search failed (${res.status})`);
  const rows = (await res.json()) as Array<{ id?: string }>;
  return rows.find((row) => row.id)?.id;
}

export async function createKeycloakUser(
  input: CreateKeycloakUserInput,
): Promise<{ id: string }> {
  const email = input.email.trim().toLowerCase();
  if (!email.includes('@')) throw new Error('kc:user requires an email address');
  if (!input.password) throw new Error('kc:user requires a password');
  const { origin, realm } = assertDevIssuer();
  const token = await adminToken(origin);
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  };
  const created = await fetch(`${origin}/admin/realms/${realm}/users`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      username: email,
      email,
      emailVerified: input.verified,
      enabled: true,
      firstName: 'Invite',
      lastName: 'User',
      credentials: [{ type: 'password', value: input.password, temporary: false }],
    }),
  });
  if (created.status === 201) {
    const location = created.headers.get('location') ?? '';
    const id = location.split('/').filter(Boolean).pop();
    if (!id) throw new Error('Keycloak created the user without an id');
    return { id };
  }
  if (created.status !== 409) {
    throw new Error(`Keycloak user create failed (${created.status})`);
  }
  const id = await findUserId(origin, realm, token, email);
  if (!id) throw new Error('Keycloak reported a conflict but the user was not found');
  const updated = await fetch(`${origin}/admin/realms/${realm}/users/${id}`, {
    method: 'PUT',
    headers,
    body: JSON.stringify({
      email,
      username: email,
      emailVerified: input.verified,
      enabled: true,
    }),
  });
  if (!updated.ok) throw new Error(`Keycloak user update failed (${updated.status})`);
  const reset = await fetch(`${origin}/admin/realms/${realm}/users/${id}/reset-password`, {
    method: 'PUT',
    headers,
    body: JSON.stringify({ type: 'password', value: input.password, temporary: false }),
  });
  if (!reset.ok) throw new Error(`Keycloak password reset failed (${reset.status})`);
  return { id };
}

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  return process.argv[index + 1];
}

function invokedAsCli(): boolean {
  const entry = process.argv[1]?.replace(/\\/g, '/');
  return Boolean(entry && entry.includes('tools/keycloak/create-user'));
}

async function main(): Promise<void> {
  const email = flag('email');
  const verified = flag('verified');
  const password = flag('password');
  if (!email || (verified !== 'true' && verified !== 'false') || !password) {
    throw new Error('usage: pnpm kc:user -- --email X --verified true|false --password P');
  }
  const user = await createKeycloakUser({ email, verified: verified === 'true', password });
  process.stdout.write(`${email} ${user.id} verified=${verified}\n`);
}

if (invokedAsCli()) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : 'kc:user failed'}\n`);
    process.exitCode = 1;
  });
}
