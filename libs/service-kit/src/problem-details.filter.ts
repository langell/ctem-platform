import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { currentTraceId, rootLogger } from '@ctem/observability';

const PROBLEM_TYPE = /^urn:ctem:problem:[a-z0-9-]+$/;

function problemType(body: unknown): string {
  if (typeof body === 'object' && body !== null && 'type' in body) {
    const type = (body as { type?: unknown }).type;
    if (typeof type === 'string' && PROBLEM_TYPE.test(type)) return type;
  }
  return 'about:blank';
}

function problemDetail(body: unknown): unknown {
  if (typeof body !== 'object' || body === null) return undefined;
  const record = body as { detail?: unknown; message?: unknown };
  return record.detail !== undefined ? record.detail : record.message;
}

/**
 * All services speak RFC 7807 so the gateway and the UI have one error shape.
 * Internal error text is never leaked to the client; the traceId is the bridge
 * between what the user sees and what is in the logs.
 * A `urn:ctem:problem:` type on the exception body is passed through.
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
        type: problemType(body),
        title: typeof body === 'string' ? body : ((body as Record<string, unknown>).title ?? exception.message),
        status,
        detail: problemDetail(body),
        errors: typeof body === 'object' && body !== null ? (body as Record<string, unknown>).errors : undefined,
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
