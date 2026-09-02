import type { NotificationChannel } from './channels/channel.registry';

export interface PolicyViolatedNotice {
  findingId: string;
  policyId: string;
  actions: string[];
}

/**
 * Closes `ctem.policy.violated` → Slack (notify) and Jira (ticket).
 * fail_build / block_deploy stay out of this slice.
 */
export function shouldNotify(actions: string[]): boolean {
  return actions.includes('notify');
}

export function shouldTicket(actions: string[]): boolean {
  return actions.includes('ticket');
}

export async function dispatchPolicyViolated(
  orgId: string,
  payload: PolicyViolatedNotice,
  channels: { slack: NotificationChannel; jira: NotificationChannel },
): Promise<void> {
  const data = {
    findingId: payload.findingId,
    policyId: payload.policyId,
    actions: payload.actions,
  };

  if (shouldNotify(payload.actions)) {
    await channels.slack.send({
      orgId,
      template: 'policy.violated',
      // Target is not the hook URL. SlackChannel resolves env:SLACK_* only.
      target: 'slack',
      data,
    });
  }

  if (shouldTicket(payload.actions)) {
    await channels.jira.send({
      orgId,
      template: 'policy.violated',
      // Target is not the Jira site. JiraChannel resolves env:JIRA_* only.
      target: 'jira',
      data,
    });
  }
}
