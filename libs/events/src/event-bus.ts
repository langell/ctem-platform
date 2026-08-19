import { Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { JsMsg, StringCodec, consumerOpts } from 'nats';
import { EVENT_SCHEMAS, EventEnvelope, STREAMS, Subject } from '@ctem/contracts';
import { loadEnv } from '@ctem/config';
import { currentTraceId, rootLogger, runWithContext } from '@ctem/observability';
import { NatsClient } from './nats.client';

const codec = StringCodec();

export interface SubscribeOptions {
  /** Durable name — one per (service, subject) so restarts resume where they left off. */
  durable: string;
  maxDeliver?: number;
  ackWaitMs?: number;
  queueGroup?: string;
}

export type Handler<T> = (payload: T, envelope: EventEnvelope<T>) => Promise<void>;

@Injectable()
export class EventBus {
  private readonly log = rootLogger.child({ component: 'event-bus' });

  constructor(private readonly nats: NatsClient) {}

  /**
   * Publishes a validated envelope. Validation happens on the producer side so a
   * malformed payload never reaches a stream and poisons every consumer.
   */
  async publish<S extends Subject>(
    subject: S,
    orgId: string,
    payload: unknown,
    opts: { causationId?: string | null } = {},
  ): Promise<void> {
    const schema = EVENT_SCHEMAS[subject as keyof typeof EVENT_SCHEMAS];
    const parsed = schema ? schema.parse(payload) : payload;

    const envelope: EventEnvelope = {
      id: randomUUID(),
      subject,
      orgId,
      occurredAt: new Date(),
      traceId: currentTraceId(),
      causationId: opts.causationId ?? null,
      version: 1,
      producer: loadEnv().SERVICE_NAME,
      payload: parsed,
    };

    await this.nats.js().publish(subject, codec.encode(JSON.stringify(envelope)), {
      // De-dup window in JetStream: a retried publish of the same event is dropped.
      msgID: envelope.id,
    });
    this.log.debug({ subject, orgId, eventId: envelope.id }, 'event published');
  }

  /**
   * Pull-based subscription. Each message is handled inside a request context so
   * the tenant id is available to the db layer without threading it manually.
   */
  async subscribe<S extends Subject>(
    subject: S,
    options: SubscribeOptions,
    handler: Handler<unknown>,
  ): Promise<void> {
    const stream = Object.values(STREAMS).find((s) =>
      s.subjects.some((pattern) => subjectMatches(subject, pattern)),
    );
    if (!stream) throw new Error(`No stream configured for subject ${subject}`);

    const opts = consumerOpts();
    opts.durable(options.durable);
    opts.manualAck();
    opts.ackWait(options.ackWaitMs ?? 60_000);
    opts.maxDeliver(options.maxDeliver ?? 5);
    opts.deliverTo(`${options.durable}.inbox`);
    opts.deliverGroup(options.queueGroup ?? options.durable);
    // Explicit ack + deliver-all are implied by manualAck()/deliverAll().
    opts.deliverAll();
    opts.filterSubject(subject);

    const sub = await this.nats.js().subscribe(subject, opts);
    this.log.info({ subject, durable: options.durable }, 'subscribed');

    void (async () => {
      for await (const msg of sub) {
        await this.handleMessage(subject, msg, handler);
      }
    })();
  }

  private async handleMessage<S extends Subject>(
    subject: S,
    msg: JsMsg,
    handler: Handler<unknown>,
  ): Promise<void> {
    let envelope: EventEnvelope | undefined;
    try {
      envelope = JSON.parse(codec.decode(msg.data)) as EventEnvelope;
      const schema = EVENT_SCHEMAS[subject as keyof typeof EVENT_SCHEMAS];
      const payload = schema ? schema.parse(envelope.payload) : envelope.payload;

      await runWithContext({ traceId: envelope.traceId, orgId: envelope.orgId }, () =>
        handler(payload, { ...envelope!, payload }),
      );
      msg.ack();
    } catch (err) {
      const attempt = msg.info.redeliveryCount;
      this.log.error(
        { subject, err, attempt, eventId: envelope?.id },
        'event handler failed, scheduling redelivery',
      );
      // Exponential backoff, capped — after maxDeliver JetStream moves it aside.
      msg.nak(Math.min(2 ** attempt * 1_000, 60_000));
    }
  }
}

function subjectMatches(subject: string, pattern: string): boolean {
  if (pattern.endsWith('>')) return subject.startsWith(pattern.slice(0, -1));
  return subject === pattern;
}
