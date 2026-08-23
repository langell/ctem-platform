import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { SignJWT, exportJWK, generateKeyPair, type JWK, type KeyLike } from 'jose';

export interface TestTokenClaims {
  sub?: string;
  orgId?: string | null;
  roles?: string[];
  audience?: string;
  /** Seconds until expiry; negative values produce an already-expired token. */
  expiresIn?: number;
}

/**
 * A miniature OIDC issuer for tests: one RSA key, a real HTTP endpoint serving
 * the JWKS on the Keycloak path `JwtVerifier` expects, and a token mint.
 *
 * Usage:
 *   const idp = await TestIdp.start();
 *   applyTestEnv({ OIDC_ISSUER: idp.issuer });
 *   const jwt = await idp.issueToken({ orgId, roles: ['security_analyst'] });
 */
export class TestIdp {
  private constructor(
    private readonly server: Server,
    private readonly privateKey: KeyLike,
    private readonly kid: string,
    readonly issuer: string,
  ) {}

  static async start(): Promise<TestIdp> {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };

    const server = createServer((req, res) => {
      if (req.url?.endsWith('/protocol/openid-connect/certs')) {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ keys: [jwk] }));
      } else {
        res.statusCode = 404;
        res.end();
      }
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    const issuer = `http://127.0.0.1:${port}/realms/ctem-test`;
    return new TestIdp(server, privateKey, 'test-key', issuer);
  }

  async issueToken(claims: TestTokenClaims = {}): Promise<string> {
    const { sub = 'test|user', orgId = 'org-unset', roles = ['developer'], audience = 'ctem-api', expiresIn = 300 } = claims;
    const jwt = new SignJWT({
      ...(orgId === null ? {} : { org_id: orgId }),
      roles,
    })
      .setProtectedHeader({ alg: 'RS256', kid: this.kid })
      .setSubject(sub)
      .setIssuer(this.issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + expiresIn);
    return jwt.sign(this.privateKey);
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) =>
      this.server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}
