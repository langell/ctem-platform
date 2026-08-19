import pino, { Logger } from 'pino';
import { loadEnv } from '@ctem/config';

/**
 * Structured logs only. `orgId` and `traceId` are bound per request so a single
 * tenant's activity can be pulled out of a shared log stream.
 */
export function createLogger(name?: string): Logger {
  const env = loadEnv();
  return pino({
    name: name ?? env.SERVICE_NAME,
    level: env.LOG_LEVEL,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers["x-ctem-principal"]',
        '*.credentialRef',
        '*.password',
        '*.token',
        '*.secret',
      ],
      censor: '[redacted]',
    },
    formatters: {
      level: (label) => ({ level: label }),
    },
    transport:
      env.NODE_ENV === 'development'
        ? { target: 'pino/file', options: { destination: 1 } }
        : undefined,
  });
}

export const rootLogger = createLogger();
