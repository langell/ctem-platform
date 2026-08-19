import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { ProblemDetailsFilter } from './problem-details.filter';

export interface BootstrapOptions {
  serviceName: string;
  port: number;
  /** Only the gateway publishes docs publicly; internal services keep them on /docs behind the mesh. */
  swagger?: { title: string; description: string; version?: string };
}

export async function bootstrapService(
  module: unknown,
  options: BootstrapOptions,
): Promise<INestApplication> {
  process.env.SERVICE_NAME = options.serviceName;
  const env = loadEnv();
  const log = rootLogger.child({ service: options.serviceName });

  const app = await NestFactory.create(module as never, { bufferLogs: true });
  app.useGlobalFilters(new ProblemDetailsFilter());
  app.enableShutdownHooks();

  if (options.swagger) {
    const config = new DocumentBuilder()
      .setTitle(options.swagger.title)
      .setDescription(options.swagger.description)
      .setVersion(options.swagger.version ?? '0.1.0')
      .addBearerAuth()
      .build();
    SwaggerModule.setup('docs', app, SwaggerModule.createDocument(app, config));
  }

  const port = env.PORT || options.port;
  await app.listen(port, '0.0.0.0');
  log.info({ port }, `${options.serviceName} listening`);
  return app;
}
