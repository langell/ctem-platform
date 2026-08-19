import { createHmac, timingSafeEqual } from 'node:crypto';
import { Principal, ROLE_PERMISSIONS, Role } from '@ctem/contracts';
import { loadEnv } from '@ctem/config';

export const PRINCIPAL_HEADER = 'x-ctem-principal';
export const PRINCIPAL_SIGNATURE_HEADER = 'x-ctem-principal-signature';

/**
 * Only the gateway talks to the IdP. Downstream services trust a compact,
 * HMAC-signed principal header instead of re-verifying the user's JWT, which
 * keeps the IdP off the hot path and lets internal services stay stateless.
 * In production this is paired with mTLS so the header cannot be injected from
 * outside the mesh.
 */
export function encodePrincipal(principal: Principal): { value: string; signature: string } {
  const value = Buffer.from(JSON.stringify(principal)).toString('base64url');
  return { value, signature: sign(value) };
}

export function decodePrincipal(value: string, signature: string): Principal {
  const expected = sign(value);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new Error('Principal signature mismatch');
  }
  return Principal.parse(JSON.parse(Buffer.from(value, 'base64url').toString('utf8')));
}

function sign(value: string): string {
  return createHmac('sha256', loadEnv().INTERNAL_TOKEN_SECRET).update(value).digest('base64url');
}

export function permissionsForRole(role: Role): string[] {
  return ROLE_PERMISSIONS[role] ?? [];
}
