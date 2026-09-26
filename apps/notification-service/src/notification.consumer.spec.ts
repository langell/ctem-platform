import { afterEach, describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import { EventBus } from '@ctem/events';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
} from '@ctem/resilience';
import { ChannelRegistry } from './channels/channel.registry';
import { JiraChannel } from './channels/jira.channel';
import { SlackChannel } from './channels/slack.channel';
import { WebhookChannel } from './channels/webhook.channel';
import { NotificationConsumer } from './notification.consumer';

const orgId = '11111111-1111-4111-8111-111111111111';
const HOOK = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
const SITE = 'https://acme.atlassian.net';

function openOnFirstFailure(): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 1,
      maxAttempts: 1,
      baseDelayMs: 1,
      timeoutMs: 10_000,
    },
    { sleep: async () => undefined, random: () => 0 },
  );
}

function setJiraEnv() {
  process.env.JIRA_API_TOKEN = 'jira-token';
  process.env.JIRA_EMAIL = 'sec@example.com';
  process.env.JIRA_BASE_URL = SITE;
  process.env.JIRA_PROJECT_KEY = 'SEC';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.SLACK_WEBHOOK_URL;
  delete process.env.JIRA_API_TOKEN;
  delete process.env.JIRA_EMAIL;
  delete process.env.JIRA_BASE_URL;
  delete process.env.JIRA_PROJECT_KEY;
});

function jetstreamMessage(payload: unknown) {
  const envelope = {
    id: '22222222-2222-4222-8222-222222222222',
    subject: SUBJECTS.notificationRequested,
    orgId,
    occurredAt: new Date().toISOString(),
    traceId: 'trace-notification',
    causationId: null,
    version: 1,
    producer: 'test',
    payload,
  };
  return {
    data: new TextEncoder().encode(JSON.stringify(envelope)),
    info: { redeliveryCount: 1 },
    ack: vi.fn(),
    nak: vi.fn(),
  };
}

async function dispatch(
  handler: (payload: unknown, envelope: unknown) => Promise<void>,
  msg: ReturnType<typeof jetstreamMessage>,
): Promise<void> {
  const bus = new EventBus({} as never);
  await (
    bus as unknown as {
      handleMessage: (
        subject: string,
        msg: unknown,
        handler: (payload: unknown, envelope: unknown) => Promise<void>,
      ) => Promise<void>;
    }
  ).handleMessage(SUBJECTS.notificationRequested, msg, handler);
}

describe('notification-dispatch consumer', () => {
  it('naks an open Slack circuit and does not ack or fetch', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const policy = openOnFirstFailure();
    const slack = new SlackChannel(policy);
    const fetchFn = vi.fn(async () => new Response('unavailable', { status: 503 }));
    vi.stubGlobal('fetch', fetchFn);
    await expect(
      slack.send({ orgId, template: 'policy.violated', target: 'slack', data: {} }),
    ).rejects.toThrow(/responded 503/);
    fetchFn.mockClear();

    const handlers = new Map<string, (payload: unknown, envelope: unknown) => Promise<void>>();
    const subscribe = vi.fn(
      async (
        _subject: string,
        options: { durable: string; maxDeliver?: number },
        handler: (payload: unknown, envelope: unknown) => Promise<void>,
      ) => {
        handlers.set(options.durable, handler);
      },
    );
    const consumer = new NotificationConsumer(
      { subscribe } as unknown as EventBus,
      new ChannelRegistry(),
      new WebhookChannel(),
      slack,
      new JiraChannel(policy),
    );
    await consumer.onApplicationBootstrap();
    expect(subscribe).toHaveBeenCalledWith(
      SUBJECTS.notificationRequested,
      expect.objectContaining({ durable: 'notification-dispatch', maxDeliver: 6 }),
      expect.any(Function),
    );

    const handler = handlers.get('notification-dispatch');
    expect(handler).toBeTypeOf('function');
    const msg = jetstreamMessage({
      channel: 'slack',
      template: 'policy.violated',
      target: 'slack',
      data: {},
    });
    await dispatch(handler!, msg);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(msg.nak).toHaveBeenCalledTimes(1);
    expect(msg.ack).not.toHaveBeenCalled();
  });

  it('naks an open Jira circuit and does not ack or fetch', async () => {
    setJiraEnv();
    const policy = openOnFirstFailure();
    const jira = new JiraChannel(policy);
    const fetchFn = vi.fn(
      async () => new Response(JSON.stringify({ title: 'down' }), { status: 503 }),
    );
    vi.stubGlobal('fetch', fetchFn);
    await expect(
      jira.send({ orgId, template: 'policy.violated', target: 'jira', data: {} }),
    ).rejects.toThrow(/responded 503/);
    await expect(
      jira.send({ orgId, template: 'policy.violated', target: 'jira', data: {} }),
    ).rejects.toBeInstanceOf(CircuitOpenError);
    fetchFn.mockClear();

    const handlers = new Map<string, (payload: unknown, envelope: unknown) => Promise<void>>();
    const consumer = new NotificationConsumer(
      {
        subscribe: vi.fn(
          async (
            _subject: string,
            options: { durable: string },
            handler: (payload: unknown, envelope: unknown) => Promise<void>,
          ) => {
            handlers.set(options.durable, handler);
          },
        ),
      } as unknown as EventBus,
      new ChannelRegistry(),
      new WebhookChannel(),
      new SlackChannel(policy),
      jira,
    );
    await consumer.onApplicationBootstrap();
    const msg = jetstreamMessage({
      channel: 'jira',
      template: 'policy.violated',
      target: 'jira',
      data: {},
    });
    await dispatch(handlers.get('notification-dispatch')!, msg);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(msg.nak).toHaveBeenCalledTimes(1);
    expect(msg.ack).not.toHaveBeenCalled();
  });

  it('acks a delivered Slack message', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const slack = new SlackChannel(openOnFirstFailure());
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    const handlers = new Map<string, (payload: unknown, envelope: unknown) => Promise<void>>();
    const consumer = new NotificationConsumer(
      {
        subscribe: vi.fn(
          async (
            _subject: string,
            options: { durable: string },
            handler: (payload: unknown, envelope: unknown) => Promise<void>,
          ) => {
            handlers.set(options.durable, handler);
          },
        ),
      } as unknown as EventBus,
      new ChannelRegistry(),
      new WebhookChannel(),
      slack,
      new JiraChannel(),
    );
    await consumer.onApplicationBootstrap();
    const msg = jetstreamMessage({
      channel: 'slack',
      template: 'policy.violated',
      target: 'slack',
      data: {},
    });
    await dispatch(handlers.get('notification-dispatch')!, msg);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(msg.ack).toHaveBeenCalledTimes(1);
    expect(msg.nak).not.toHaveBeenCalled();
  });
});
