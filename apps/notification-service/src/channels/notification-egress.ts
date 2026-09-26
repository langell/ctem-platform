import { rootLogger } from '@ctem/observability';
import { InternalHttpPolicy, loadCircuitBreakerConfig } from '@ctem/resilience';

/**
 * Shared notification egress policy (`@ctem/resilience` `InternalHttpPolicy`,
 * the same type as the gateway and publishers). Slack, Jira, and tenant
 * webhooks each name their own circuit on this policy.
 *
 * Attempts are always 1. These POSTs are not idempotent (Jira creates an issue
 * per call; a tenant webhook retry would duplicate the delivery), so JetStream
 * redelivery is the only retry. Other platform `CTEM_CB_*` knobs (threshold,
 * window, cooldown) still apply. No new env var.
 */
export function createNotificationEgressPolicy(
  source: NodeJS.ProcessEnv = process.env,
): InternalHttpPolicy {
  return new InternalHttpPolicy(
    { ...loadCircuitBreakerConfig(source), maxAttempts: 1 },
    { log: rootLogger.child({ component: 'notification-egress' }) },
  );
}
