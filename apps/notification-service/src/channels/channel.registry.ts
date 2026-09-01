import { Injectable } from '@nestjs/common';

export interface NotificationMessage {
  orgId: string;
  template: string;
  target: string;
  data: Record<string, unknown>;
}

/**
 * Mobilization — the last CTEM stage and the one that decides whether any of
 * this changes anything. A finding nobody is told about is a finding nobody fixes.
 */
export interface NotificationChannel {
  readonly name: string;
  send(message: NotificationMessage): Promise<void>;
}

@Injectable()
export class ChannelRegistry {
  private readonly channels = new Map<string, NotificationChannel>();

  register(channel: NotificationChannel): void {
    this.channels.set(channel.name, channel);
  }

  get(name: string): NotificationChannel | undefined {
    return this.channels.get(name);
  }
}

/**
 * Planned channels:
 *   slack          -> implemented: policy.violated → hooks.slack.com via env:SLACK_*
 *   jira / linear  -> ticket per finding, with dedup on the finding fingerprint
 *   github_issue   -> issue in the repo the finding came from
 *   email          -> digest, not per-finding — nobody reads per-finding email
 *   webhook        -> generic escape hatch, implemented below
 */
