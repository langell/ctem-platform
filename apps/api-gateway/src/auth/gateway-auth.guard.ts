import {
  CanActivate,
  ConflictException,
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
import {
  OrgId,
  Principal,
  Permission,
  ResolveJwtRequest,
  ResolveJwtResponse,
  ResolveMembershipsRequest,
  ResolveMembershipsResponse,
} from '@ctem/contracts';
import { currentTraceId, getContext, rootLogger } from '@ctem/observability';

const PAT_PREFIX = 'ctem_pat_';

interface GatewayRequest {
  headers: { authorization?: string };
  method?: string;
  path?: string;
  originalUrl?: string;
  url?: string;
  principal?: Principal;
  principalHeaders?: { value: string; signature: string };
  /** Verified JWT `sub`. Set only after the signature check. Never taken from the body. */
  verifiedSub?: string;
}

/** The two routes a zero-membership human may call. Not a general optional-org flag. */
function isCreateOrgRequest(req: GatewayRequest): boolean {
  if ((req.method ?? '').toUpperCase() !== 'POST') return false;
  return [req.path, req.originalUrl, req.url].some((value) => {
    if (!value) return false;
    const path = value.split('?')[0]?.replace(/\/+$/, '') || '/';
    return path === '/v1/orgs' || path === '/v1/invites/accept';
  });
}

/**
 * The only place a user-facing token is verified. Everything downstream trusts
 * the signed principal this guard produces.
 *
 * Two paths:
 *   1. **JWT** — verified against the IdP's JWKS, then Membership loaded from
 *      identity-service. Role/permissions come from Membership, never JWT roles.
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

    const req = context.switchToHttp().getRequest<GatewayRequest>();
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) throw new UnauthorizedException('Missing bearer token');

    const token = header.slice('Bearer '.length);
    const createOrg = isCreateOrgRequest(req);

    let principal: Principal;

    if (token.startsWith(PAT_PREFIX)) {
      // A machine token has no human subject to own a new org or accept an invite.
      if (createOrg) throw new UnauthorizedException('Invalid token');
      principal = await this.verifyPat(token);
    } else {
      const resolved = await this.verifyJwt(token, req);
      if (resolved === 'signup') return true;
      principal = resolved;
    }

    const required =
      this.reflector.getAllAndOverride<Permission[]>(PERMISSIONS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    const missing = required.filter((p) => !principal.permissions.includes(p));
    if (missing.length)
      throw new ForbiddenException(`Missing permission(s): ${missing.join(', ')}`);

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

  private async verifyJwt(token: string, req: GatewayRequest): Promise<Principal | 'signup'> {
    let claims;
    try {
      claims = await this.jwt.verify(token);
    } catch {
      throw new UnauthorizedException('Invalid token');
    }

    req.verifiedSub = claims.sub;

    // A present org_id stays authoritative, including when it is not a valid
    // OrgId. Do not fall through to signup or to the single-membership lookup.
    if (claims.org_id != null) {
      const membership = await this.resolveMembership(
        claims.sub,
        claims.org_id,
        claims.email,
        claims.name,
      );
      return this.principalFromMembership(membership.userId, claims.org_id, membership.role);
    }

    const resolved = await this.resolveActiveMemberships(
      claims.sub,
      claims.email,
      claims.name,
      claims.email_verified === true,
    );
    if (resolved.memberships.length > 1) {
      throw new ConflictException('multiple organizations');
    }
    if (resolved.memberships.length === 1) {
      const membership = resolved.memberships[0]!;
      return this.principalFromMembership(resolved.userId, membership.orgId, membership.role);
    }

    if (isCreateOrgRequest(req)) return 'signup';
    throw new ForbiddenException('No organization');
  }

  private principalFromMembership(
    userId: string,
    orgId: string,
    role: Principal['role'],
  ): Principal {
    return {
      userId,
      orgId,
      role,
      permissions: permissionsForRole(role) as Permission[],
      serviceAccount: null,
      traceId: currentTraceId(),
    };
  }

  /**
   * Map IdP `sub` → `users.id` and load Membership. JWT `roles` / realm roles
   * are ignored. A missing membership is 403; identity down is fail-closed 401.
   * Raw IdP `sub` is never used as Principal.userId.
   */
  private async resolveMembership(
    sub: string,
    orgId: string,
    email: string | undefined,
    name: string | undefined,
  ): Promise<ResolveJwtResponse> {
    const tenant = OrgId.safeParse(orgId);
    if (!tenant.success) throw new ForbiddenException('No organization selected');

    // Invalid email/name must not 500 or block a valid membership resolve.
    const emailParsed =
      typeof email === 'string' ? ResolveJwtRequest.shape.email.safeParse(email) : undefined;
    const nameParsed =
      typeof name === 'string' && name.trim()
        ? ResolveJwtRequest.shape.name.safeParse(name.trim())
        : undefined;

    const body: ResolveJwtRequest = {
      sub,
      orgId: tenant.data,
      ...(emailParsed?.success ? { email: emailParsed.data } : {}),
      ...(nameParsed?.success ? { name: nameParsed.data } : {}),
    };

    const env = loadEnv();
    const url = `${env.IDENTITY_SERVICE_URL}/internal/auth/resolve`;

    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5_000),
      });
    } catch (err) {
      this.log.error({ err }, 'identity-service unreachable for JWT membership resolve');
      throw new UnauthorizedException('Token verification failed');
    }

    if (res.status === 403) throw new ForbiddenException('No organization membership');
    if (!res.ok) throw new UnauthorizedException('Token verification failed');

    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new UnauthorizedException('Token verification failed');
    }

    const parsed = ResolveJwtResponse.safeParse(json);
    if (!parsed.success) throw new UnauthorizedException('Token verification failed');
    if (parsed.data.orgId !== orgId) throw new UnauthorizedException('Token verification failed');
    return parsed.data;
  }

  /**
   * No org_id on the token. Identity returns this user's active memberships.
   * Unreachable identity is 401 — never an anonymous org.
   */
  private async resolveActiveMemberships(
    sub: string,
    email: string | undefined,
    name: string | undefined,
    emailVerified: boolean,
  ): Promise<ResolveMembershipsResponse> {
    const emailParsed =
      typeof email === 'string'
        ? ResolveMembershipsRequest.shape.email.safeParse(email)
        : undefined;
    const nameParsed =
      typeof name === 'string' && name.trim()
        ? ResolveMembershipsRequest.shape.name.safeParse(name.trim())
        : undefined;

    const body: ResolveMembershipsRequest = {
      sub,
      ...(emailParsed?.success ? { email: emailParsed.data } : {}),
      ...(nameParsed?.success ? { name: nameParsed.data } : {}),
      emailVerified,
    };

    const env = loadEnv();
    const url = `${env.IDENTITY_SERVICE_URL}/internal/auth/memberships`;

    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5_000),
      });
    } catch (err) {
      this.log.error({ err }, 'identity-service unreachable for membership lookup');
      throw new UnauthorizedException('Token verification failed');
    }

    if (res.status === 403) throw new ForbiddenException('No organization membership');
    if (!res.ok) throw new UnauthorizedException('Token verification failed');

    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new UnauthorizedException('Token verification failed');
    }

    const parsed = ResolveMembershipsResponse.safeParse(json);
    if (!parsed.success) throw new UnauthorizedException('Token verification failed');
    return parsed.data;
  }

  // ---------------------------------------------------------------------------
  // PAT path (CI / connectors / machine callers)
  // ---------------------------------------------------------------------------

  /**
   * PATs are verified by identity-service, which stores only the SHA-256 hash.
   * The gateway never hashes, never trusts a client org, and fail-closes if
   * identity is unreachable or the record has no org.
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

    // Any non-success is unauthenticated. Do not leak identity's error body.
    if (!res.ok) throw new UnauthorizedException('Invalid token');

    let verified: { orgId?: string; tokenId?: string; scopes?: string[]; name?: string };
    try {
      verified = (await res.json()) as typeof verified;
    } catch {
      throw new UnauthorizedException('Invalid token');
    }

    // Tenant is taken from the PAT record only. A client-supplied org id
    // (x-ctem-org, query, body) must never select the organization.
    if (!verified?.orgId || !verified.tokenId) throw new UnauthorizedException('Invalid token');

    // Map token scopes directly to permissions. Scopes are issued using the
    // same Permission enum values (e.g. "scan:run", "finding:read").
    const permissions = (verified.scopes ?? []).filter((s): s is Permission =>
      Permission.options.includes(s as Permission),
    );

    return {
      userId: verified.tokenId,
      orgId: verified.orgId,
      role: 'developer', // PATs have no concept of role; permissions are explicit.
      permissions,
      serviceAccount: verified.name ?? null,
      traceId: currentTraceId(),
    };
  }
}
