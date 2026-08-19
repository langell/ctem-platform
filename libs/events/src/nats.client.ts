import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import {
  connect,
  JetStreamClient,
  JetStreamManager,
  NatsConnection,
  RetentionPolicy,
  StorageType,
} from 'nats';
import { STREAMS } from '@ctem/contracts';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';

/**
 * Thin JetStream wrapper. Streams are declared idempotently at boot so a fresh
 * environment comes up correctly without a separate provisioning step.
 */
@Injectable()
export class NatsClient implements OnModuleInit, OnModuleDestroy {
  private connection?: NatsConnection;
  private jetstream?: JetStreamClient;
  private manager?: JetStreamManager;
  private readonly log = rootLogger.child({ component: 'nats' });

  async onModuleInit(): Promise<void> {
    const env = loadEnv();
    this.connection = await connect({
      servers: env.NATS_URL,
      name: env.SERVICE_NAME,
      reconnect: true,
      maxReconnectAttempts: -1,
    });
    this.jetstream = this.connection.jetstream();
    this.manager = await this.connection.jetstreamManager();
    await this.ensureStreams();
    this.log.info({ url: env.NATS_URL }, 'connected to NATS');
  }

  async onModuleDestroy(): Promise<void> {
    await this.connection?.drain();
  }

  private async ensureStreams(): Promise<void> {
    if (!this.manager) return;
    for (const stream of Object.values(STREAMS)) {
      const config = {
        name: stream.name,
        subjects: [...stream.subjects],
        retention: RetentionPolicy.Limits,
        storage: StorageType.File,
        max_age: 14 * 24 * 60 * 60 * 1_000_000_000, // 14 days in ns — enough to replay a bad consumer
        num_replicas: 1,
      };
      try {
        await this.manager.streams.add(config);
        this.log.info({ stream: stream.name }, 'stream created');
      } catch {
        await this.manager.streams.update(stream.name, config).catch(() => undefined);
      }
    }
  }

  js(): JetStreamClient {
    if (!this.jetstream) throw new Error('JetStream not initialized');
    return this.jetstream;
  }

  jsm(): JetStreamManager {
    if (!this.manager) throw new Error('JetStream manager not initialized');
    return this.manager;
  }

  raw(): NatsConnection {
    if (!this.connection) throw new Error('NATS not connected');
    return this.connection;
  }
}
