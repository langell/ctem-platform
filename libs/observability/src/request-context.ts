import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

export interface RequestContext {
  traceId: string;
  orgId: string | null;
  userId: string | null;
}

const storage = new AsyncLocalStorage<RequestContext>();

/**
 * Tenancy travels implicitly through async context so that no repository call
 * can forget to pass orgId. The db lib reads from here to set the RLS GUC.
 */
export function runWithContext<T>(ctx: Partial<RequestContext>, fn: () => T): T {
  return storage.run(
    { traceId: ctx.traceId ?? randomUUID(), orgId: ctx.orgId ?? null, userId: ctx.userId ?? null },
    fn,
  );
}

export function getContext(): RequestContext | undefined {
  return storage.getStore();
}

export function requireOrgId(): string {
  const orgId = storage.getStore()?.orgId;
  if (!orgId) {
    throw new Error('No organization in request context — refusing to run an unscoped query');
  }
  return orgId;
}

export function currentTraceId(): string {
  return storage.getStore()?.traceId ?? randomUUID();
}
