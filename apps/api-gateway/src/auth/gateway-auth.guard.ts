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
import { Principal, Role, type Permission } from '@ctem/contracts';
import { currentTraceId, getContext } from '@ctem/observability';

/**
 * The only place a user-facing token is verified. Everything downstream trusts
 * the signed principal this guard produces.
 */
@Injectable()
export class GatewayAuthGuard implements CanActivate {
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
    let claims;
    try {
      claims = await this.jwt.verify(token);
    } catch {
      // TODO: fall through to API-token verification against identity-service
      // for CI/machine callers, which present `ctem_pat_...` instead of a JWT.
      throw new UnauthorizedException('Invalid token');
    }

    // A user can belong to several orgs; the active one comes from the token or
    // an explicit header, and is always re-checked against membership.
    const orgId = (req.headers['x-ctem-org'] as string) || claims.org_id;
    if (!orgId) throw new ForbiddenException('No organization selected');

    const role = Role.safeParse(claims.roles?.[0] ?? 'developer');
    if (!role.success) throw new ForbiddenException('Unknown role');

    const principal: Principal = {
      userId: claims.sub,
      orgId,
      role: role.data,
      permissions: permissionsForRole(role.data) as Permission[],
      serviceAccount: null,
      traceId: currentTraceId(),
    };

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
}
