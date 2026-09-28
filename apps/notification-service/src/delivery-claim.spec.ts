import { describe, expect, it, vi } from 'vitest';
import { PrismaService } from '@ctem/db';
import {
  PrismaPolicyDeliveryClaims,
  policyDeliveryClaimKey,
  sendWithDeliveryClaim,
  type PolicyDeliveryClaimKey,
  type PolicyDeliveryClaimStore,
} from './delivery-claim';

const orgId = '11111111-1111-4111-8111-111111111111';
const otherOrgId = '99999999-9999-4999-8999-999999999999';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = '00000000-0000-4000-8000-00000000c7e1';

function key(
  channel: 'slack' | 'jira',
  overrides: Partial<PolicyDeliveryClaimKey> = {},
): PolicyDeliveryClaimKey {
  return { orgId, findingId, policyId, channel, ...overrides };
}

function memoryStore() {
  const rows = new Set<string>();
  const id = (claim: PolicyDeliveryClaimKey) =>
    `${claim.orgId}|${claim.findingId}|${claim.policyId}|${claim.channel}`;
  const store: PolicyDeliveryClaimStore = {
    async tryClaim(claim) {
      const row = id(claim);
      if (rows.has(row)) return 'duplicate';
      rows.add(row);
      return 'claimed';
    },
    async release(claim) {
      rows.delete(id(claim));
    },
  };
  return { rows, store, id };
}

function message(
  channel: string,
  template = 'policy.violated',
  data: Record<string, unknown> = { findingId, policyId, actions: ['notify', 'ticket'] },
) {
  return { orgId, channel, template, target: channel, data };
}

describe('policyDeliveryClaimKey', () => {
  it('uses the envelope org and ignores body org and host fields', () => {
    expect(
      policyDeliveryClaimKey({
        orgId,
        channel: 'slack',
        template: 'policy.violated',
        data: {
          findingId,
          policyId,
          orgId: otherOrgId,
          webhookUrl: 'https://evil.example/hook',
          jiraUrl: 'https://evil.example/rest/api/3/issue',
        },
      }),
    ).toEqual(key('slack'));
  });

  it('is null unless template, channel, and both ids qualify', () => {
    expect(policyDeliveryClaimKey(message('slack', 'sla.breached'))).toBeNull();
    expect(policyDeliveryClaimKey(message('webhook'))).toBeNull();
    expect(policyDeliveryClaimKey(message('email'))).toBeNull();
    expect(policyDeliveryClaimKey(message('slack', 'policy.violated', {}))).toBeNull();
    expect(
      policyDeliveryClaimKey(
        message('slack', 'policy.violated', { findingId, policyId: 'not-a-uuid' }),
      ),
    ).toBeNull();
    expect(
      policyDeliveryClaimKey(message('jira', 'policy.violated', { findingId: 'nope', policyId })),
    ).toBeNull();
  });
});

describe('sendWithDeliveryClaim', () => {
  it('inserts a slack claim and sends once; redelivery skips the send', async () => {
    const { store } = memoryStore();
    const tryClaim = vi.spyOn(store, 'tryClaim');
    const send = vi.fn(async () => undefined);

    await expect(sendWithDeliveryClaim(message('slack'), send, store)).resolves.toBe('sent');
    await expect(sendWithDeliveryClaim(message('slack'), send, store)).resolves.toBe('skipped');

    expect(send).toHaveBeenCalledTimes(1);
    expect(tryClaim).toHaveBeenCalledTimes(2);
    expect(tryClaim.mock.calls[0][0]).toEqual(key('slack'));
    await expect(tryClaim.mock.results[0]?.value).resolves.toBe('claimed');
    await expect(tryClaim.mock.results[1]?.value).resolves.toBe('duplicate');
  });

  it('keeps a jira claim independent of slack', async () => {
    const { store, rows, id } = memoryStore();
    const slackSend = vi.fn(async () => undefined);
    const jiraSend = vi.fn(async () => undefined);

    await sendWithDeliveryClaim(message('slack'), slackSend, store);
    await sendWithDeliveryClaim(message('jira'), jiraSend, store);
    await sendWithDeliveryClaim(message('slack'), slackSend, store);

    expect(slackSend).toHaveBeenCalledTimes(1);
    expect(jiraSend).toHaveBeenCalledTimes(1);
    expect(rows.has(id(key('slack')))).toBe(true);
    expect(rows.has(id(key('jira')))).toBe(true);
  });

  it('clears the claim when send throws so a retry can claim again', async () => {
    const { store, rows, id } = memoryStore();
    const send = vi.fn(async () => {
      throw new Error('slack down');
    });

    await expect(sendWithDeliveryClaim(message('slack'), send, store)).rejects.toThrow(
      /slack down/,
    );
    expect(rows.has(id(key('slack')))).toBe(false);

    send.mockResolvedValueOnce(undefined);
    await expect(sendWithDeliveryClaim(message('slack'), send, store)).resolves.toBe('sent');
    expect(send).toHaveBeenCalledTimes(2);
    expect(rows.has(id(key('slack')))).toBe(true);
  });

  it('claims only the channel that is actually sent (notify-only / ticket-only)', async () => {
    const notify = memoryStore();
    const ticket = memoryStore();
    const slackSend = vi.fn(async () => undefined);
    const jiraSend = vi.fn(async () => undefined);

    await sendWithDeliveryClaim(
      message('slack', 'policy.violated', { findingId, policyId, actions: ['notify'] }),
      slackSend,
      notify.store,
    );
    await sendWithDeliveryClaim(
      message('jira', 'policy.violated', { findingId, policyId, actions: ['ticket'] }),
      jiraSend,
      ticket.store,
    );

    expect(slackSend).toHaveBeenCalledTimes(1);
    expect(jiraSend).toHaveBeenCalledTimes(1);
    expect([...notify.rows]).toEqual([notify.id(key('slack'))]);
    expect([...ticket.rows]).toEqual([ticket.id(key('jira'))]);
    expect(notify.rows.has(notify.id(key('jira')))).toBe(false);
    expect(ticket.rows.has(ticket.id(key('slack')))).toBe(false);
  });

  it('does not touch the store for other templates, webhook, or non-uuid ids', async () => {
    const { store } = memoryStore();
    const tryClaim = vi.spyOn(store, 'tryClaim');
    const release = vi.spyOn(store, 'release');
    const send = vi.fn(async () => undefined);

    await sendWithDeliveryClaim(message('slack', 'finding.created'), send, store);
    await sendWithDeliveryClaim(message('webhook'), send, store);
    await sendWithDeliveryClaim(
      message('jira', 'policy.violated', { note: 'no ids' }),
      send,
      store,
    );
    await sendWithDeliveryClaim(
      message('slack', 'policy.violated', { findingId, policyId: 'policy-name' }),
      send,
      store,
    );

    expect(send).toHaveBeenCalledTimes(4);
    expect(tryClaim).not.toHaveBeenCalled();
    expect(release).not.toHaveBeenCalled();
  });

  it('still naks when claim rollback fails', async () => {
    const store: PolicyDeliveryClaimStore = {
      tryClaim: async () => 'claimed',
      release: async () => {
        throw new Error('db down');
      },
    };
    await expect(
      sendWithDeliveryClaim(
        message('jira'),
        async () => {
          throw new Error('jira down');
        },
        store,
      ),
    ).rejects.toThrow(/claim rollback failed/);
  });
});

describe('PrismaPolicyDeliveryClaims', () => {
  function harness() {
    const tx = {
      notificationDeliveryClaim: {
        create: vi.fn(async () => ({ id: 'row' })),
        deleteMany: vi.fn(async () => ({ count: 1 })),
      },
    };
    const orgs: string[] = [];
    const prisma = {
      withOrg: vi.fn(async (org: string, fn: (txArg: typeof tx) => Promise<unknown>) => {
        orgs.push(org);
        return fn(tx);
      }),
    };
    return {
      tx,
      orgs,
      claims: new PrismaPolicyDeliveryClaims(prisma as unknown as PrismaService),
    };
  }

  it('inserts under the envelope org', async () => {
    const { claims, tx, orgs } = harness();
    await expect(claims.tryClaim(key('slack'))).resolves.toBe('claimed');
    expect(orgs).toEqual([orgId]);
    expect(tx.notificationDeliveryClaim.create).toHaveBeenCalledWith({
      data: { orgId, findingId, policyId, channel: 'slack' },
    });
  });

  it('treats a unique conflict as a duplicate and does not throw', async () => {
    const { claims, tx } = harness();
    tx.notificationDeliveryClaim.create.mockRejectedValueOnce(
      Object.assign(new Error('unique'), { code: 'P2002' }),
    );
    await expect(claims.tryClaim(key('jira'))).resolves.toBe('duplicate');
  });

  it('rethrows non-unique insert failures', async () => {
    const { claims, tx } = harness();
    tx.notificationDeliveryClaim.create.mockRejectedValueOnce(new Error('connection reset'));
    await expect(claims.tryClaim(key('slack'))).rejects.toThrow(/connection reset/);
  });

  it('deletes the claim on release so a retry can insert again', async () => {
    const { claims, tx, orgs } = harness();
    await claims.release(key('jira'));
    expect(orgs).toEqual([orgId]);
    expect(tx.notificationDeliveryClaim.deleteMany).toHaveBeenCalledWith({
      where: { orgId, findingId, policyId, channel: 'jira' },
    });
  });
});
