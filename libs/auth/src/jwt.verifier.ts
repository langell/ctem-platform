import { Injectable } from '@nestjs/common';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { loadEnv } from '@ctem/config';

export interface VerifiedToken extends JWTPayload {
  sub: string;
  email?: string;
  /** Org selected for this session; a user may belong to several. */
  org_id?: string;
  roles?: string[];
}

/**
 * Verifies OIDC access tokens against the issuer's JWKS. jose caches and rotates
 * keys internally, so a key roll does not require a redeploy.
 */
@Injectable()
export class JwtVerifier {
  private jwks?: ReturnType<typeof createRemoteJWKSet>;

  private keySet(): ReturnType<typeof createRemoteJWKSet> {
    if (!this.jwks) {
      const env = loadEnv();
      this.jwks = createRemoteJWKSet(new URL(`${env.OIDC_ISSUER}/protocol/openid-connect/certs`), {
        cooldownDuration: 30_000,
        cacheMaxAge: 10 * 60_000,
      });
    }
    return this.jwks;
  }

  async verify(token: string): Promise<VerifiedToken> {
    const env = loadEnv();
    const { payload } = await jwtVerify(token, this.keySet(), {
      issuer: env.OIDC_ISSUER,
      audience: env.OIDC_AUDIENCE,
      clockTolerance: 5,
    });
    if (!payload.sub) throw new Error('Token has no subject claim');
    return payload as VerifiedToken;
  }
}
