import { Global, Module, NestMiddleware, Injectable, MiddlewareConsumer } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { rootLogger } from './logger';
import { runWithContext } from './request-context';

export const LOGGER = Symbol('CTEM_LOGGER');

@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction): void {
    const traceId = (req.headers['x-trace-id'] as string) || randomUUID();
    res.setHeader('x-trace-id', traceId);
    // orgId is filled in later by the auth guard once the principal is verified.
    runWithContext({ traceId, orgId: null, userId: null }, () => next());
  }
}

@Global()
@Module({
  providers: [{ provide: LOGGER, useValue: rootLogger }, RequestContextMiddleware],
  exports: [LOGGER],
})
export class ObservabilityModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}
