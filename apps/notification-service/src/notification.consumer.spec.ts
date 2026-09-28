import { afterEach, describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import { EventBus } from '@ctem/events';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
} from '@ctem/resilience';
import { ChannelRegistry, type NotificationChannel } from './channels/channel.registry';
import { JiraChannel } from './channels/jira.channel';
import { SlackChannel } from './channels/slack.channel';
import { EGRESS_TENANT_WEBHOOK, WebhookChannel } from './channels/webhook.channel';
import {
  PrismaPolicyDeliveryClaims,
  type PolicyDeliveryClaimKey,
  type PolicyDeliveryClaimStore,
} from './delivery-claim';
import { NotificationConsumer } from './notification.consumer';

const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = '00000000-0000-4000-8000-00000000c7e1';
const causationId = '44444444-4444-4444-8444-444444444444';
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

function memoryClaims(): PrismaPolicyDeliveryClaims {
  const held = new Set<string>();
  const id = (claim: PolicyDeliveryClaimKey) =>
    `${claim.orgId}|${claim.findingId}|${claim.policyId}|${claim.channel}`;
  const store: PolicyDeliveryClaimStore = {
    async tryClaim(claim) {
      const row = id(claim);
      if (held.has(row)) return 'duplicate';
      held.add(row);
      return 'claimed';
    },
    async release(claim) {
      held.delete(id(claim));
    },
  };
  return store as unknown as PrismaPolicyDeliveryClaims;
}

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
  subject: string = SUBJECTS.notificationRequested,
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
  ).handleMessage(subject, msg, handler);
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
      memoryClaims(),
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
      memoryClaims(),
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

  it('naks an open tenant-webhook circuit and does not ack or fetch', async () => {
    const policy = openOnFirstFailure();
    const webhook = new WebhookChannel(policy);
    const target = 'https://tenant.example/hooks/ctem';
    const fetchFn = vi.fn(async () => new Response('unavailable', { status: 503 }));
    vi.stubGlobal('fetch', fetchFn);
    await expect(
      webhook.send({ orgId, template: 'policy.violated', target, data: {} }),
    ).rejects.toThrow(`Webhook ${target} responded 503`);
    await expect(
      webhook.send({ orgId, template: 'policy.violated', target, data: {} }),
    ).rejects.toMatchObject({ name: 'CircuitOpenError', circuit: EGRESS_TENANT_WEBHOOK });
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
      webhook,
      new SlackChannel(policy),
      new JiraChannel(policy),
      memoryClaims(),
    );
    await consumer.onApplicationBootstrap();
    const msg = jetstreamMessage({
      channel: 'webhook',
      template: 'policy.violated',
      target,
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
      memoryClaims(),
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

describe('policy fan-out', () => {
  function channel(name: string, send: NotificationChannel['send']): NotificationChannel {
    return { name, send };
  }

  function boot(
    publish: EventBus['publish'],
    slackSend: NotificationChannel['send'],
    jiraSend: NotificationChannel['send'],
  ) {
    const handlers = new Map<string, (payload: unknown, envelope: unknown) => Promise<void>>();
    const consumer = new NotificationConsumer(
      {
        publish,
        subscribe: vi.fn(
          async (
            _subject: string,
            options: { durable: string; maxDeliver?: number },
            handler: (payload: unknown, envelope: unknown) => Promise<void>,
          ) => {
            handlers.set(options.durable, handler);
          },
        ),
      } as unknown as EventBus,
      new ChannelRegistry(),
      new WebhookChannel(),
      channel('slack', slackSend) as SlackChannel,
      channel('jira', jiraSend) as JiraChannel,
      memoryClaims(),
    );
    return { consumer, handlers };
  }

  it('enqueues slack and jira without calling channel.send, and a later jira failure does not re-invoke slack', async () => {
    const published: unknown[] = [];
    const publish = vi.fn(async (_subject: string, _orgId: string, payload: unknown) => {
      published.push(payload);
    });
    const slackSend = vi.fn(async () => undefined);
    const jiraSend = vi.fn(async () => {
      throw new Error('jira down');
    });
    const { consumer, handlers } = boot(publish, slackSend, jiraSend);
    await consumer.onApplicationBootstrap();

    const actions = ['notify', 'ticket'];
    const policyMsg = jetstreamMessage({ findingId, policyId, actions });
    policyMsg.data = new TextEncoder().encode(
      JSON.stringify({
        id: '33333333-3333-4333-8333-333333333333',
        subject: SUBJECTS.policyViolated,
        orgId,
        occurredAt: new Date().toISOString(),
        traceId: 'trace-policy',
        causationId,
        version: 1,
        producer: 'test',
        payload: { findingId, policyId, actions },
      }),
    );

    await dispatch(handlers.get('notification-policy')!, policyMsg, SUBJECTS.policyViolated);

    expect(policyMsg.ack).toHaveBeenCalledTimes(1);
    expect(policyMsg.nak).not.toHaveBeenCalled();
    expect(slackSend).not.toHaveBeenCalled();
    expect(jiraSend).not.toHaveBeenCalled();
    expect(publish).toHaveBeenCalledTimes(2);
    expect(publish.mock.calls[0][0]).toBe(SUBJECTS.notificationRequested);
    expect(publish.mock.calls[0][2]).toMatchObject({
      channel: 'slack',
      template: 'policy.violated',
      target: 'slack',
      data: { findingId, policyId, actions },
    });
    expect(publish.mock.calls[0][3]).toEqual({ causationId });
    expect(publish.mock.calls[1][2]).toMatchObject({ channel: 'jira', target: 'jira' });
    expect(publish.mock.calls[1][3]).toEqual({ causationId });

    const slackMsg = jetstreamMessage(published[0]);
    await dispatch(handlers.get('notification-dispatch')!, slackMsg);
    expect(slackSend).toHaveBeenCalledTimes(1);
    expect(slackMsg.ack).toHaveBeenCalledTimes(1);
    expect(jiraSend).not.toHaveBeenCalled();

    const jiraMsg = jetstreamMessage(published[1]);
    await dispatch(handlers.get('notification-dispatch')!, jiraMsg);
    expect(jiraSend).toHaveBeenCalledTimes(1);
    expect(jiraMsg.nak).toHaveBeenCalledTimes(1);
    expect(jiraMsg.ack).not.toHaveBeenCalled();
    expect(slackSend).toHaveBeenCalledTimes(1);

    const jiraRedelivery = jetstreamMessage(published[1]);
    await dispatch(handlers.get('notification-dispatch')!, jiraRedelivery);
    expect(jiraSend).toHaveBeenCalledTimes(2);
    expect(jiraRedelivery.nak).toHaveBeenCalledTimes(1);
    expect(slackSend).toHaveBeenCalledTimes(1);
  });

  it('naks the policy delivery when notification publish fails and does not send', async () => {
    const publish = vi.fn(async () => {
      throw new Error('bus down');
    });
    const slackSend = vi.fn(async () => undefined);
    const jiraSend = vi.fn(async () => undefined);
    const { consumer, handlers } = boot(publish, slackSend, jiraSend);
    await consumer.onApplicationBootstrap();

    const msg = jetstreamMessage({
      findingId,
      policyId,
      actions: ['notify', 'ticket'],
    });
    await dispatch(handlers.get('notification-policy')!, msg, SUBJECTS.policyViolated);

    expect(msg.nak).toHaveBeenCalledTimes(1);
    expect(msg.ack).not.toHaveBeenCalled();
    expect(slackSend).not.toHaveBeenCalled();
    expect(jiraSend).not.toHaveBeenCalled();
    expect(publish).toHaveBeenCalledTimes(1);
  });
});

describe('policy delivery claims on notification-dispatch', () => {
  const policyData = {
    findingId,
    policyId,
    actions: ['notify', 'ticket'],
    orgId: '99999999-9999-4999-8999-999999999999',
    webhookUrl: 'https://evil.example/hook',
  };

  function handlersFor(
    claims: PrismaPolicyDeliveryClaims,
    channels: {
      slack?: NotificationChannel['send'];
      jira?: NotificationChannel['send'];
      webhook?: NotificationChannel['send'];
    },
  ) {
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
      { name: 'webhook', send: channels.webhook ?? vi.fn(async () => undefined) } as WebhookChannel,
      { name: 'slack', send: channels.slack ?? vi.fn(async () => undefined) } as SlackChannel,
      { name: 'jira', send: channels.jira ?? vi.fn(async () => undefined) } as JiraChannel,
      claims,
    );
    return { consumer, handlers };
  }

  it('acks the first slack send and acks a redelivery without sending again', async () => {
    const claims = memoryClaims();
    const tryClaim = vi.spyOn(claims, 'tryClaim');
    const slack = vi.fn(async () => undefined);
    const { consumer, handlers } = handlersFor(claims, { slack });
    await consumer.onApplicationBootstrap();
    const handler = handlers.get('notification-dispatch')!;
    const payload = {
      channel: 'slack',
      template: 'policy.violated',
      target: 'slack',
      data: policyData,
    };

    const first = jetstreamMessage(payload);
    await dispatch(handler, first);
    const second = jetstreamMessage(payload);
    await dispatch(handler, second);

    expect(slack).toHaveBeenCalledTimes(1);
    expect(slack.mock.calls[0][0].orgId).toBe(orgId);
    expect(tryClaim).toHaveBeenCalledTimes(2);
    expect(tryClaim.mock.calls[0][0]).toMatchObject({
      orgId,
      findingId,
      policyId,
      channel: 'slack',
    });
    expect(first.ack).toHaveBeenCalledTimes(1);
    expect(second.ack).toHaveBeenCalledTimes(1);
    expect(first.nak).not.toHaveBeenCalled();
    expect(second.nak).not.toHaveBeenCalled();
  });

  it('naks a failed slack send after clearing the claim so redelivery can send', async () => {
    const claims = memoryClaims();
    const release = vi.spyOn(claims, 'release');
    const slack = vi.fn(async () => {
      throw new Error('slack down');
    });
    const { consumer, handlers } = handlersFor(claims, { slack });
    await consumer.onApplicationBootstrap();
    const handler = handlers.get('notification-dispatch')!;
    const payload = {
      channel: 'slack',
      template: 'policy.violated',
      target: 'slack',
      data: policyData,
    };

    const failed = jetstreamMessage(payload);
    await dispatch(handler, failed);
    expect(failed.nak).toHaveBeenCalledTimes(1);
    expect(failed.ack).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledTimes(1);
    expect(release.mock.calls[0][0]).toMatchObject({ orgId, channel: 'slack' });

    slack.mockResolvedValueOnce(undefined);
    const retry = jetstreamMessage(payload);
    await dispatch(handler, retry);
    expect(slack).toHaveBeenCalledTimes(2);
    expect(retry.ack).toHaveBeenCalledTimes(1);
    expect(retry.nak).not.toHaveBeenCalled();
  });

  it('does not let a slack claim suppress jira, and notify-only does not claim jira', async () => {
    const claims = memoryClaims();
    const tryClaim = vi.spyOn(claims, 'tryClaim');
    const slack = vi.fn(async () => undefined);
    const jira = vi.fn(async () => undefined);
    const { consumer, handlers } = handlersFor(claims, { slack, jira });
    await consumer.onApplicationBootstrap();
    const handler = handlers.get('notification-dispatch')!;

    await dispatch(
      handler,
      jetstreamMessage({
        channel: 'slack',
        template: 'policy.violated',
        target: 'slack',
        data: { findingId, policyId, actions: ['notify'] },
      }),
    );
    expect(jira).not.toHaveBeenCalled();
    expect(tryClaim.mock.calls.map((call) => call[0].channel)).toEqual(['slack']);

    await dispatch(
      handler,
      jetstreamMessage({
        channel: 'jira',
        template: 'policy.violated',
        target: 'jira',
        data: { findingId, policyId, actions: ['ticket'] },
      }),
    );
    expect(slack).toHaveBeenCalledTimes(1);
    expect(jira).toHaveBeenCalledTimes(1);
    expect(tryClaim.mock.calls.map((call) => call[0].channel)).toEqual(['slack', 'jira']);
  });

  it('does not touch the claim store for other templates or the webhook channel', async () => {
    const claims = memoryClaims();
    const tryClaim = vi.spyOn(claims, 'tryClaim');
    const release = vi.spyOn(claims, 'release');
    const slack = vi.fn(async () => undefined);
    const webhook = vi.fn(async () => undefined);
    const { consumer, handlers } = handlersFor(claims, { slack, webhook });
    await consumer.onApplicationBootstrap();
    const handler = handlers.get('notification-dispatch')!;

    const other = jetstreamMessage({
      channel: 'slack',
      template: 'finding.created',
      target: 'slack',
      data: policyData,
    });
    await dispatch(handler, other);
    const hook = jetstreamMessage({
      channel: 'webhook',
      template: 'policy.violated',
      target: 'https://tenant.example/hooks/ctem',
      data: policyData,
    });
    await dispatch(handler, hook);

    expect(other.ack).toHaveBeenCalledTimes(1);
    expect(hook.ack).toHaveBeenCalledTimes(1);
    expect(slack).toHaveBeenCalledTimes(1);
    expect(webhook).toHaveBeenCalledTimes(1);
    expect(tryClaim).not.toHaveBeenCalled();
    expect(release).not.toHaveBeenCalled();
  });
});
