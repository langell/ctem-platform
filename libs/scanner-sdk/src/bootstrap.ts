import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { INestApplicationContext } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';

/**
 * Workers have no HTTP surface — they are pure consumers. This boots the DI
 * container only, plus graceful shutdown so in-flight jobs get nak'd rather
 * than silently lost on a rolling deploy.
 */
export async function bootstrapScanner(module: unknown): Promise<INestApplicationContext> {
  const env = loadEnv();
  const app = await NestFactory.createApplicationContext(module as never, { bufferLogs: true });
  app.enableShutdownHooks();

  const log = rootLogger.child({ service: env.SERVICE_NAME });
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.on(signal, () => {
      log.info({ signal }, 'shutting down worker');
      void app.close().then(() => process.exit(0));
    });
  }

  log.info({ service: env.SERVICE_NAME }, 'scanner worker started');
  return app;
}
