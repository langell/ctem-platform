import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Permission, Principal } from '@ctem/contracts';
import { getContext } from '@ctem/observability';
import { PERMISSIONS_KEY, PUBLIC_KEY } from './decorators';
import { PRINCIPAL_HEADER, PRINCIPAL_SIGNATURE_HEADER, decodePrincipal } from './principal';

/**
 * Guard for internal services: the principal has already been established by the
 * gateway, so this verifies the signature and checks permissions. The gateway
 * itself uses JwtVerifier plus its own guard to mint the principal.
 */
@Injectable()
export class InternalAuthGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest();
    const raw = req.headers[PRINCIPAL_HEADER];
    const signature = req.headers[PRINCIPAL_SIGNATURE_HEADER];
    if (!raw || !signature) throw new UnauthorizedException('Missing principal');

    let principal: Principal;
    try {
      principal = decodePrincipal(String(raw), String(signature));
    } catch {
      throw new UnauthorizedException('Invalid principal');
    }

    const required =
      this.reflector.getAllAndOverride<Permission[]>(PERMISSIONS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    const missing = required.filter((p) => !principal.permissions.includes(p));
    if (missing.length) {
      throw new ForbiddenException(`Missing permission(s): ${missing.join(', ')}`);
    }

    req.principal = principal;
    // Bind the tenant onto the ambient context so the db layer can scope queries.
    const ctx = getContext();
    if (ctx) {
      ctx.orgId = principal.orgId;
      ctx.userId = principal.userId;
    }
    return true;
  }
}
