import { SUBJECTS } from '@ctem/contracts';
import type { EventBus } from '@ctem/events';

export interface PolicyViolatedNotice {
  findingId: string;
  policyId: string;
  actions: string[];
}

/**
 * Closes `ctem.policy.violated` by enqueueing one `ctem.notification.requested`
 * per channel. Durable `notification-dispatch` performs the Slack (notify) and
 * Jira (ticket) sends, so a Jira failure redelivers only Jira.
 * fail_build is the CI scan conclusion on GET, not a notification channel.
 * block_deploy is the GET deployConclusion gate — alone it does not fan out.
 */
export function shouldNotify(actions: string[]): boolean {
  return actions.includes('notify');
}

export function shouldTicket(actions: string[]): boolean {
  return actions.includes('ticket');
}

/**
 * Publishes per-channel notification requests. Does not call channel.send.
 * A bus publish failure throws so the policy durable consumer naks.
 * `causationId` is the inbound policy envelope's causationId when the handler has it.
 */
export async function dispatchPolicyViolated(
  orgId: string,
  payload: PolicyViolatedNotice,
  bus: Pick<EventBus, 'publish'>,
  opts: { causationId?: string | null } = {},
): Promise<void> {
  const data = {
    findingId: payload.findingId,
    policyId: payload.policyId,
    actions: payload.actions,
  };

  if (shouldNotify(payload.actions)) {
    await bus.publish(
      SUBJECTS.notificationRequested,
      orgId,
      {
        channel: 'slack',
        template: 'policy.violated',
        target: 'slack',
        data,
      },
      opts,
    );
  }

  if (shouldTicket(payload.actions)) {
    await bus.publish(
      SUBJECTS.notificationRequested,
      orgId,
      {
        channel: 'jira',
        template: 'policy.violated',
        target: 'jira',
        data,
      },
      opts,
    );
  }
}
