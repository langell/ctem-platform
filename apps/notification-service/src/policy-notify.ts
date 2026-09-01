import type { NotificationChannel } from './channels/channel.registry';

export interface PolicyViolatedNotice {
  findingId: string;
  policyId: string;
  actions: string[];
}

/**
 * Closes `ctem.policy.violated` → Slack. Only the `notify` action fans out;
 * ticket / fail_build / block_deploy stay out of this slice.
 */
export function shouldNotify(actions: string[]): boolean {
  return actions.includes('notify');
}

export async function notifyPolicyViolated(
  orgId: string,
  payload: PolicyViolatedNotice,
  slack: NotificationChannel,
): Promise<void> {
  if (!shouldNotify(payload.actions)) return;
  await slack.send({
    orgId,
    template: 'policy.violated',
    // Target is not the hook URL. SlackChannel resolves env:SLACK_* only.
    target: 'slack',
    data: {
      findingId: payload.findingId,
      policyId: payload.policyId,
      actions: payload.actions,
    },
  });
}
