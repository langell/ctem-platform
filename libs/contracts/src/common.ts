import { z } from 'zod';

/**
 * Every persisted row and every event payload is scoped to exactly one
 * organization. Kept as a plain uuid rather than a branded type: these ids cross
 * the HTTP and event boundaries constantly, and branding buys compile-time
 * safety at the cost of a cast at every one of those edges.
 */
export const OrgId = z.string().uuid();
export type OrgId = z.infer<typeof OrgId>;

export const UserId = z.string().uuid();
export type UserId = z.infer<typeof UserId>;

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof Severity>;

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** CTEM lifecycle stages (Gartner): scoping -> discovery -> prioritization -> validation -> mobilization. */
export const CtemStage = z.enum([
  'scoping',
  'discovery',
  'prioritization',
  'validation',
  'mobilization',
]);
export type CtemStage = z.infer<typeof CtemStage>;

export const PageQuery = z.object({
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
export type PageQuery = z.infer<typeof PageQuery>;

export function pageOf<T extends z.ZodTypeAny>(item: T) {
  return z.object({
    items: z.array(item),
    nextCursor: z.string().nullable(),
    total: z.number().int().nonnegative().optional(),
  });
}

export const AuditMeta = z.object({
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
});

export const ProblemDetails = z.object({
  type: z.string().default('about:blank'),
  title: z.string(),
  status: z.number().int(),
  detail: z.string().optional(),
  instance: z.string().optional(),
  traceId: z.string().optional(),
});
export type ProblemDetails = z.infer<typeof ProblemDetails>;
