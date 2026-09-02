import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import type { NotificationChannel, NotificationMessage } from './channel.registry';
import { PLATFORM_JIRA_CREDENTIAL_REF, requireJiraCredentials } from './credentials';
import { jiraCreateIssueUrl, tenantSuppliedJiraUrls } from './jira.egress';

/**
 * Jira Cloud issue create. The site URL is platform-operated `env:JIRA_*`
 * only — never `message.target`, tenant config, body, or query.
 */
@Injectable()
export class JiraChannel implements NotificationChannel {
  readonly name = 'jira';
  private readonly log = rootLogger.child({ component: 'jira-channel' });

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

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        authorization: jiraBasicAuth(creds.email, creds.apiToken),
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });

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
