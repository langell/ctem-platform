import { describe, expect, it, vi } from 'vitest';
import { NotificationRequestedPayload, SUBJECTS } from '@ctem/contracts';
import type { EventBus } from '@ctem/events';
import { dispatchPolicyViolated, shouldNotify, shouldTicket } from './policy-notify';

const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = '00000000-0000-4000-8000-00000000c7e1';
const causationId = '44444444-4444-4444-8444-444444444444';

function requested(channel: 'slack' | 'jira', actions: string[]) {
  return {
    channel,
    template: 'policy.violated',
    target: channel,
    data: { findingId, policyId, actions },
  };
}

function mockBus(publish = vi.fn(async () => undefined)) {
  return { publish, bus: { publish } as Pick<EventBus, 'publish'> };
}

describe('shouldNotify / shouldTicket', () => {
  it('is true only when actions include notify', () => {
    expect(shouldNotify(['notify'])).toBe(true);
    expect(shouldNotify(['notify', 'ticket'])).toBe(true);
    expect(shouldNotify(['ticket', 'fail_build'])).toBe(false);
    expect(shouldNotify(['block_deploy'])).toBe(false);
    expect(shouldNotify(['notify', 'block_deploy'])).toBe(true);
    expect(shouldNotify([])).toBe(false);
  });

  it('is true only when actions include ticket', () => {
    expect(shouldTicket(['ticket'])).toBe(true);
    expect(shouldTicket(['notify', 'ticket'])).toBe(true);
    expect(shouldTicket(['notify', 'fail_build'])).toBe(false);
    expect(shouldTicket(['block_deploy'])).toBe(false);
    expect(shouldTicket(['ticket', 'block_deploy'])).toBe(true);
    expect(shouldTicket([])).toBe(false);
  });
});

describe('dispatchPolicyViolated', () => {
  it('publishes slack then jira notificationRequested and does not send channels', async () => {
    const actions = ['notify', 'ticket'];
    const { publish, bus } = mockBus();

    await dispatchPolicyViolated(orgId, { findingId, policyId, actions }, bus, { causationId });

    expect(publish).toHaveBeenCalledTimes(2);
    expect(publish.mock.calls[0]).toEqual([
      SUBJECTS.notificationRequested,
      orgId,
      requested('slack', actions),
      { causationId },
    ]);
    expect(publish.mock.calls[1]).toEqual([
      SUBJECTS.notificationRequested,
      orgId,
      requested('jira', actions),
      { causationId },
    ]);
    expect(NotificationRequestedPayload.parse(publish.mock.calls[0][2])).toEqual(
      requested('slack', actions),
    );
    expect(NotificationRequestedPayload.parse(publish.mock.calls[1][2])).toEqual(
      requested('jira', actions),
    );
  });

  it('publishes only slack when actions include notify and omit ticket', async () => {
    const actions = ['notify', 'fail_build'];
    const { publish, bus } = mockBus();

    await dispatchPolicyViolated(orgId, { findingId, policyId, actions }, bus);

    expect(publish).toHaveBeenCalledTimes(1);
    expect(publish.mock.calls[0][0]).toBe(SUBJECTS.notificationRequested);
    expect(publish.mock.calls[0][2]).toEqual(requested('slack', actions));
  });

  it('publishes only jira when actions include ticket and omit notify', async () => {
    const actions = ['ticket', 'block_deploy'];
    const { publish, bus } = mockBus();

    await dispatchPolicyViolated(orgId, { findingId, policyId, actions }, bus);

    expect(publish).toHaveBeenCalledTimes(1);
    expect(publish.mock.calls[0][2]).toEqual(requested('jira', actions));
  });

  it('does not publish when actions omit notify and ticket', async () => {
    for (const actions of [['fail_build'], ['block_deploy'], []] as string[][]) {
      const { publish, bus } = mockBus();
      await dispatchPolicyViolated(orgId, { findingId, policyId, actions }, bus);
      expect(publish).not.toHaveBeenCalled();
    }
  });

  it('throws when slack publish fails and does not enqueue jira', async () => {
    const publish = vi.fn(async () => {
      throw new Error('bus down');
    });
    await expect(
      dispatchPolicyViolated(
        orgId,
        { findingId, policyId, actions: ['notify', 'ticket'] },
        { publish },
      ),
    ).rejects.toThrow(/bus down/);
    expect(publish).toHaveBeenCalledTimes(1);
    expect(publish.mock.calls[0][2]).toMatchObject({ channel: 'slack' });
  });

  it('throws when jira publish fails after slack was enqueued', async () => {
    const publish = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('bus down'));
    await expect(
      dispatchPolicyViolated(
        orgId,
        { findingId, policyId, actions: ['notify', 'ticket'] },
        { publish },
      ),
    ).rejects.toThrow(/bus down/);
    expect(publish).toHaveBeenCalledTimes(2);
    expect(publish.mock.calls.map((call) => call[2].channel)).toEqual(['slack', 'jira']);
  });
});
