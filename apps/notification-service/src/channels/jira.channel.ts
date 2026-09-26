import { Injectable, Optional } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import { InternalHttpPolicy } from '@ctem/resilience';
import type { NotificationChannel, NotificationMessage } from './channel.registry';
import { PLATFORM_JIRA_CREDENTIAL_REF, requireJiraCredentials } from './credentials';
import { jiraCreateIssueUrl, tenantSuppliedJiraUrls } from './jira.egress';
import { createNotificationEgressPolicy } from './notification-egress';

/**
 * One breaker for every Jira Cloud issue create. Not per org and not per message.
 */
export const EGRESS_JIRA_API = 'egress:jira-api';

/**
 * Jira Cloud issue create. The site URL is platform-operated `env:JIRA_*`
 * only — never `message.target`, tenant config, body, or query.
 *
 * Allowlist checks run before the policy and do not count toward the circuit.
 * The POST keeps its 10s timeout and is not retried inside the policy (one
 * attempt — a retry would create a second issue). An open circuit or a failed
 * send throws so JetStream `notification-dispatch` naks and redelivers.
 */
@Injectable()
export class JiraChannel implements NotificationChannel {
  readonly name = 'jira';
  private readonly log = rootLogger.child({ component: 'jira-channel' });
  private readonly policy: InternalHttpPolicy;

  constructor(@Optional() policy?: InternalHttpPolicy) {
    this.policy = policy ?? createNotificationEgressPolicy();
  }

  async send(message: NotificationMessage): Promise<void> {
    const ignored = tenantSuppliedJiraUrls(message);
    if (ignored.length) {
      this.log.warn(
        { count: ignored.length },
        'ignoring tenant-supplied Jira URL — Jira egress is env:JIRA_* only',
      );
    }

    const creds = requireJiraCredentials(PLATFORM_JIRA_CREDENTIAL_REF);
    const url = jiraCreateIssueUrl(creds.baseUrl);
    const body = JSON.stringify(jiraIssuePayload(message, creds.projectKey, creds.issueType));

    const res = await this.policy.execute(EGRESS_JIRA_API, (_signal) =>
      fetch(url, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          authorization: jiraBasicAuth(creds.email, creds.apiToken),
        },
        body,
        signal: AbortSignal.timeout(10_000),
      }),
    );

    if (!res.ok) {
      throw new Error(`Jira issue create responded ${res.status}`);
    }
    this.log.info({ template: message.template, orgId: message.orgId }, 'jira ticket created');
  }
}

export function jiraBasicAuth(email: string, apiToken: string): string {
  return `Basic ${Buffer.from(`${email}:${apiToken}`, 'utf8').toString('base64')}`;
}

export function jiraIssuePayload(
  message: NotificationMessage,
  projectKey: string,
  issueType: string,
): {
  fields: {
    project: { key: string };
    summary: string;
    issuetype: { name: string };
    description: {
      type: 'doc';
      version: 1;
      content: Array<{ type: 'paragraph'; content: Array<{ type: 'text'; text: string }> }>;
    };
  };
} {
  const findingId = typeof message.data.findingId === 'string' ? message.data.findingId : 'unknown';
  const policyId = typeof message.data.policyId === 'string' ? message.data.policyId : 'unknown';
  const actions = Array.isArray(message.data.actions) ? message.data.actions.join(', ') : 'ticket';
  const summary = `CTEM policy violated — org ${message.orgId} finding ${findingId}`;
  const text = `CTEM policy violated — org ${message.orgId} finding ${findingId} policy ${policyId} actions [${actions}]`;
  return {
    fields: {
      project: { key: projectKey },
      summary,
      issuetype: { name: issueType },
      description: {
        type: 'doc',
        version: 1,
        content: [{ type: 'paragraph', content: [{ type: 'text', text }] }],
      },
    },
  };
}
