import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { z } from 'zod';

/** Templates other than this one never touch `notification_delivery_claims`. */
export const POLICY_VIOLATED_TEMPLATE = 'policy.violated';

const CLAIM_CHANNELS = ['slack', 'jira'] as const;
export type PolicyDeliveryChannel = (typeof CLAIM_CHANNELS)[number];

const uuid = z.string().uuid();

export interface PolicyDeliveryClaimKey {
  orgId: string;
  findingId: string;
  policyId: string;
  channel: PolicyDeliveryChannel;
}

export interface PolicyDeliveryClaimStore {
  /** Insert the claim. `duplicate` means a successful send already owns it. */
  tryClaim(key: PolicyDeliveryClaimKey): Promise<'claimed' | 'duplicate'>;
  /** Drop the claim so a failed send can be retried. */
  release(key: PolicyDeliveryClaimKey): Promise<void>;
}

/**
 * Claim identity for a `policy.violated` Slack or Jira send.
 * Returns null for every other template, the webhook channel, and payloads
 * that lack UUID `findingId` + `policyId` — those paths must not touch the table.
 *
 * `orgId` is the envelope org. Body fields (`data.orgId`, webhook hosts) are ignored.
 */
export function policyDeliveryClaimKey(message: {
  orgId: string;
  channel: string;
  template: string;
  data: Record<string, unknown>;
}): PolicyDeliveryClaimKey | null {
  if (message.template !== POLICY_VIOLATED_TEMPLATE) return null;
  if (!isClaimChannel(message.channel)) return null;
  const findingId = message.data.findingId;
  const policyId = message.data.policyId;
  if (!isUuid(findingId) || !isUuid(policyId)) return null;
  return {
    orgId: message.orgId,
    findingId,
    policyId,
    channel: message.channel,
  };
}

/**
 * Claim-before-send. A unique conflict skips the send and returns `skipped`
 * so the caller can ack. A send failure releases the claim and rethrows so
 * JetStream naks and the next delivery can claim again.
 */
export async function sendWithDeliveryClaim(
  message: {
    orgId: string;
    channel: string;
    template: string;
    target: string;
    data: Record<string, unknown>;
  },
  send: () => Promise<void>,
  store: PolicyDeliveryClaimStore,
): Promise<'sent' | 'skipped'> {
  const key = policyDeliveryClaimKey(message);
  if (!key) {
    await send();
    return 'sent';
  }

  const outcome = await store.tryClaim(key);
  if (outcome === 'duplicate') return 'skipped';

  try {
    await send();
  } catch (sendErr) {
    try {
      await store.release(key);
    } catch (releaseErr) {
      const sendMessage = sendErr instanceof Error ? sendErr.message : String(sendErr);
      const releaseMessage = releaseErr instanceof Error ? releaseErr.message : String(releaseErr);
      throw new Error(
        `policy delivery send failed (${sendMessage}) and claim rollback failed (${releaseMessage})`,
        { cause: sendErr instanceof Error ? sendErr : undefined },
      );
    }
    throw sendErr;
  }
  return 'sent';
}

/**
 * Postgres claim store. Org scope is the key's org (envelope), applied with
 * `withOrg` so RLS sees `app.current_org_id`. Redis is not consulted.
 */
@Injectable()
export class PrismaPolicyDeliveryClaims implements PolicyDeliveryClaimStore {
  constructor(private readonly prisma: PrismaService) {}

  async tryClaim(key: PolicyDeliveryClaimKey): Promise<'claimed' | 'duplicate'> {
    try {
      await this.prisma.withOrg(key.orgId, (tx) =>
        tx.notificationDeliveryClaim.create({
          data: {
            orgId: key.orgId,
            findingId: key.findingId,
            policyId: key.policyId,
            channel: key.channel,
          },
        }),
      );
      return 'claimed';
    } catch (err) {
      if (isPrismaUniqueConflict(err)) return 'duplicate';
      throw err;
    }
  }

  async release(key: PolicyDeliveryClaimKey): Promise<void> {
    await this.prisma.withOrg(key.orgId, (tx) =>
      tx.notificationDeliveryClaim.deleteMany({
        where: {
          orgId: key.orgId,
          findingId: key.findingId,
          policyId: key.policyId,
          channel: key.channel,
        },
      }),
    );
  }
}

function isClaimChannel(channel: string): channel is PolicyDeliveryChannel {
  return (CLAIM_CHANNELS as readonly string[]).includes(channel);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && uuid.safeParse(value).success;
}

/** Postgres unique violation (Prisma P2002). The losing insert has rolled back. */
function isPrismaUniqueConflict(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === 'P2002'
  );
}
