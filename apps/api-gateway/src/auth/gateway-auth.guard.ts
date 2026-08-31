import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  JwtVerifier,
  PERMISSIONS_KEY,
  PUBLIC_KEY,
  encodePrincipal,
  permissionsForRole,
} from '@ctem/auth';
import { loadEnv } from '@ctem/config';
import { Principal, Role, Permission } from '@ctem/contracts';
import { currentTraceId, getContext, rootLogger } from '@ctem/observability';

const PAT_PREFIX = 'ctem_pat_';

/**
 * The only place a user-facing token is verified. Everything downstream trusts
 * the signed principal this guard produces.
 *
 * Two paths:
 *   1. **JWT** — verified against the IdP's JWKS (human users).
 *   2. **PAT** — forwarded to identity-service for SHA-256 lookup (CI/connectors).
 */
@Injectable()
export class GatewayAuthGuard implements CanActivate {
  private readonly log = rootLogger.child({ component: 'gateway-auth' });

  constructor(
    private readonly reflector: Reflector,
    private readonly jwt: JwtVerifier,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest();
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) throw new UnauthorizedException('Missing bearer token');

    const token = header.slice('Bearer '.length);

    let principal: Principal;

    if (token.startsWith(PAT_PREFIX)) {
      principal = await this.verifyPat(token);
    } else {
      principal = await this.verifyJwt(token);
    }

    const required =
      this.reflector.getAllAndOverride<Permission[]>(PERMISSIONS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    const missing = required.filter((p) => !principal.permissions.includes(p));
    if (missing.length) throw new ForbiddenException(`Missing permission(s): ${missing.join(', ')}`);

    req.principal = principal;
    req.principalHeaders = encodePrincipal(principal);

    const ctx = getContext();
    if (ctx) {
      ctx.orgId = principal.orgId;
      ctx.userId = principal.userId;
    }
    return true;
  }

  // ---------------------------------------------------------------------------
  // JWT path (human users via OIDC)
  // ---------------------------------------------------------------------------

  private async verifyJwt(token: string): Promise<Principal> {
    let claims;
    try {
      claims = await this.jwt.verify(token);
    } catch {
      throw new UnauthorizedException('Invalid token');
    }

    // Tenant is taken from the verified JWT only. A client-supplied org id
    // (x-ctem-org, query, body) must never select the organization — that is
    // how findings leak across tenants.
    const orgId = claims.org_id;
    if (!orgId) throw new ForbiddenException('No organization selected');

    const role = Role.safeParse(claims.roles?.[0] ?? 'developer');
    if (!role.success) throw new ForbiddenException('Unknown role');

    return {
      userId: claims.sub,
      orgId,
      role: role.data,
      permissions: permissionsForRole(role.data) as Permission[],
      serviceAccount: null,
      traceId: currentTraceId(),
    };
  }

  // ---------------------------------------------------------------------------
  // PAT path (CI / connectors / machine callers)
  // ---------------------------------------------------------------------------

  /**
   * PATs are verified by the identity-service, which stores only the SHA-256
   * hash. The response gives us (orgId, scopes, name). We map scopes to the
   * closest role's permission set, and mark the principal as a service account.
   */
  private async verifyPat(token: string): Promise<Principal> {
    const env = loadEnv();
    const url = `${env.IDENTITY_SERVICE_URL}/internal/tokens/verify`;

    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token }),
        signal: AbortSignal.timeout(5_000),
      });
    } catch (err) {
      this.log.error({ err }, 'identity-service unreachable for PAT verification');
      throw new UnauthorizedException('Token verification failed');
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new UnauthorizedException((body as { message?: string }).message ?? 'Invalid token');
    }

    const verified = (await res.json()) as {
      orgId: string;
      tokenId: string;
      scopes: string[];
      name: string;
    };

    // Map token scopes directly to permissions. Scopes are issued using the
    // same Permission enum values (e.g. "scan:run", "finding:read").
    const permissions = verified.scopes.filter((s): s is Permission =>
      Permission.options.includes(s as Permission),
    );

    return {
      userId: verified.tokenId,
      orgId: verified.orgId,
      role: 'developer', // PATs have no concept of role; permissions are explicit.
      permissions,
      serviceAccount: verified.name,
      traceId: currentTraceId(),
    };
  }
}
