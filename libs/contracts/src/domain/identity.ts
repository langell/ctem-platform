import { z } from 'zod';
import { AuditMeta, OrgId, UserId } from '../common';

export const Role = z.enum(['owner', 'admin', 'security_analyst', 'developer', 'auditor']);
export type Role = z.infer<typeof Role>;

/**
 * Permissions are checked, roles are assigned. Keeping the mapping in one place
 * means the gateway and every service agree on what a role can do.
 */
export const Permission = z.enum([
  'org:read',
  'org:write',
  'member:manage',
  'asset:read',
  'asset:write',
  'scan:read',
  'scan:run',
  'finding:read',
  'finding:triage',
  'policy:read',
  'policy:write',
  'exception:approve',
  'report:read',
  'integration:manage',
]);
export type Permission = z.infer<typeof Permission>;

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  owner: Permission.options.slice(),
  admin: Permission.options.filter((p) => p !== 'org:write'),
  security_analyst: [
    'org:read',
    'asset:read',
    'asset:write',
    'scan:read',
    'scan:run',
    'finding:read',
    'finding:triage',
    'policy:read',
    'exception:approve',
    'report:read',
  ],
  developer: ['org:read', 'asset:read', 'scan:read', 'scan:run', 'finding:read', 'finding:triage', 'report:read'],
  auditor: ['org:read', 'asset:read', 'scan:read', 'finding:read', 'policy:read', 'report:read'],
};

export const Organization = z
  .object({
    id: OrgId,
    name: z.string().min(1),
    slug: z.string().regex(/^[a-z0-9-]+$/),
    plan: z.enum(['trial', 'team', 'enterprise']).default('trial'),
    /** Enterprise buyers want their own key; default is the platform key. */
    dataResidency: z.enum(['us', 'eu', 'ap']).default('us'),
  })
  .merge(AuditMeta);
export type Organization = z.infer<typeof Organization>;

export const User = z
  .object({
    id: UserId,
    email: z.string().email(),
    name: z.string(),
    /** Subject claim from the upstream IdP; local passwords are not stored. */
    idpSubject: z.string(),
    disabledAt: z.coerce.date().nullable().default(null),
  })
  .merge(AuditMeta);
export type User = z.infer<typeof User>;

export const Membership = z.object({
  orgId: OrgId,
  userId: UserId,
  role: Role,
  disabledAt: z.coerce.date().nullable().default(null),
});
export type Membership = z.infer<typeof Membership>;

/** CTEM-side invite. Membership is created on first login (email match). */
export const InviteMemberRequest = z.object({
  email: z.string().email(),
  role: Role,
});
export type InviteMemberRequest = z.infer<typeof InviteMemberRequest>;

export const SetMemberRoleRequest = z.object({
  role: Role,
});
export type SetMemberRoleRequest = z.infer<typeof SetMemberRoleRequest>;

/** Gateway → identity after JWT verify. Role claims are intentionally absent. */
export const ResolveJwtRequest = z.object({
  sub: z.string().min(1),
  orgId: OrgId,
  email: z.string().email().optional(),
  name: z.string().min(1).optional(),
});
export type ResolveJwtRequest = z.infer<typeof ResolveJwtRequest>;

export const ResolveJwtResponse = z.object({
  userId: UserId,
  orgId: OrgId,
  role: Role,
});
export type ResolveJwtResponse = z.infer<typeof ResolveJwtResponse>;

/**
 * The request-scoped identity every service receives. For humans it is derived
 * from a verified JWT plus CTEM Membership (never JWT role claims) and
 * forwarded as a signed internal header.
 */
export const Principal = z.object({
  userId: z.string(),
  orgId: z.string(),
  role: Role,
  permissions: z.array(Permission),
  /** Set when the caller is a machine token (CI, connector) rather than a human. */
  serviceAccount: z.string().nullable().default(null),
  traceId: z.string(),
});
export type Principal = z.infer<typeof Principal>;
