import 'reflect-metadata';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { ProblemDetailsFilter } from './problem-details.filter';

export interface BootstrapOptions {
  serviceName: string;
  port: number;
  /** Only the gateway publishes docs publicly; internal services keep them on /docs behind the mesh. */
  swagger?: { title: string; description: string; version?: string };
  /** Serve a built SPA. API/docs/health routes always win. Gateway-only. */
  staticDir?: string;
  /** Browser clients on a different origin (Vite) talk only to this process. */
  cors?: boolean;
}

export async function bootstrapService(
  module: unknown,
  options: BootstrapOptions,
): Promise<INestApplication> {
  process.env.SERVICE_NAME = options.serviceName;
  const env = loadEnv();
  const log = rootLogger.child({ service: options.serviceName });

  const app = await NestFactory.create<NestExpressApplication>(module as never, { bufferLogs: true });
  app.useGlobalFilters(new ProblemDetailsFilter());
  app.enableShutdownHooks();

  if (options.cors) {
    app.enableCors({ origin: true });
  }

  if (options.swagger) {
    const config = new DocumentBuilder()
      .setTitle(options.swagger.title)
      .setDescription(options.swagger.description)
      .setVersion(options.swagger.version ?? '0.1.0')
      .addBearerAuth()
      .build();
    SwaggerModule.setup('docs', app, SwaggerModule.createDocument(app, config));
  }

  if (options.staticDir && existsSync(join(options.staticDir, 'index.html'))) {
    app.useStaticAssets(options.staticDir, { index: false });
    app.use((req: { method: string; path: string }, res: { sendFile: (p: string) => void }, next: () => void) => {
      if (req.method !== 'GET' && req.method !== 'HEAD') return next();
      const path = req.path ?? '';
      if (path.startsWith('/v1') || path.startsWith('/docs') || path.startsWith('/health')) {
        return next();
      }
      res.sendFile(join(options.staticDir as string, 'index.html'));
    });
  }

  // env.PORT has a schema default of 3000, so it can only win when the
  // variable is actually set — otherwise every service would bind the same port.
  const port = process.env.PORT ? env.PORT : options.port;
  await app.listen(port, '0.0.0.0');
  log.info({ port }, `${options.serviceName} listening`);
  return app;
}
