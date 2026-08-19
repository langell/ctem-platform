import { SetMetadata, createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Permission, Principal } from '@ctem/contracts';

export const PERMISSIONS_KEY = 'ctem:permissions';
export const PUBLIC_KEY = 'ctem:public';

/** Declares what a route requires; the guard denies anything not listed. */
export const RequirePermissions = (...permissions: Permission[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);

/** Health and metrics endpoints only. */
export const Public = () => SetMetadata(PUBLIC_KEY, true);

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Principal => {
    return ctx.switchToHttp().getRequest().principal as Principal;
  },
);

export const CurrentOrg = createParamDecorator((_data: unknown, ctx: ExecutionContext): string => {
  return (ctx.switchToHttp().getRequest().principal as Principal).orgId;
});
