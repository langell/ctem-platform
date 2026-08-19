import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { currentTraceId, rootLogger } from '@ctem/observability';

/**
 * All services speak RFC 7807 so the gateway and the UI have one error shape.
 * Internal error text is never leaked to the client; the traceId is the bridge
 * between what the user sees and what is in the logs.
 */
@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  private readonly log = rootLogger.child({ component: 'http' });

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const traceId = currentTraceId();

    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      res.status(status).json({
        type: 'about:blank',
        title: typeof body === 'string' ? body : ((body as Record<string, unknown>).title ?? exception.message),
        status,
        detail: typeof body === 'object' ? (body as Record<string, unknown>).message : undefined,
        errors: typeof body === 'object' ? (body as Record<string, unknown>).errors : undefined,
        traceId,
      });
      return;
    }

    this.log.error({ err: exception, traceId }, 'unhandled exception');
    res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      type: 'about:blank',
      title: 'Internal Server Error',
      status: 500,
      traceId,
    });
  }
}
