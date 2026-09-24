import { BadRequestException } from '@nestjs/common';
import { SCAN_KICK_IDEMPOTENCY_KEY_MAX, type ScanKickSource } from '@ctem/contracts';

export type ScanKickTrigger = 'manual' | 'scheduled' | 'webhook' | 'ci';

/** Orchestrator trigger `scheduled` is the architecture source `schedule`. */
export function scanKickSource(trigger: ScanKickTrigger): ScanKickSource {
  return trigger === 'scheduled' ? 'schedule' : trigger;
}

/**
 * One dedupe slot per accept: the `Idempotency-Key` header, or CI `externalId`
 * (already aliased from `external_id`). Scoped to orgId by the unique index,
 * not by this function. Empty means "no client key" — each persist is its own kick.
 * Disagreement or an oversized key fails before any scan row is written.
 */
export function resolveScanKickIdempotencyKey(input: {
  header?: string | string[] | null;
  externalId?: string | null;
}): string | null {
  const header = firstHeader(input.header);
  const externalId = clean(input.externalId);
  if (header && externalId && header !== externalId) {
    throw new BadRequestException(
      'Idempotency-Key and externalId disagree — refusing scan create',
    );
  }
  const key = header ?? externalId;
  if (!key) return null;
  if (key.length > SCAN_KICK_IDEMPOTENCY_KEY_MAX) {
    throw new BadRequestException(
      `Idempotency-Key exceeds ${SCAN_KICK_IDEMPOTENCY_KEY_MAX} characters — refusing scan create`,
    );
  }
  return key;
}

/** Postgres unique violation (Prisma P2002). The losing transaction has rolled back. */
export function isPrismaUniqueConflict(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'code' in err && (err as { code: unknown }).code === 'P2002';
}

function firstHeader(value: string | string[] | null | undefined): string | null {
  if (Array.isArray(value)) return clean(value[0]);
  return clean(value ?? null);
}

function clean(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}
