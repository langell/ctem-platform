import { BadRequestException, PipeTransform } from '@nestjs/common';
import type { ZodSchema } from 'zod';

/**
 * Contracts are zod schemas, so validation reuses them directly instead of
 * maintaining a parallel set of class-validator DTOs.
 * Usage: `@Body(new ZodBody(CreateScanRequest)) body: CreateScanRequest`
 */
export class ZodBody<T> implements PipeTransform {
  constructor(private readonly schema: ZodSchema<T>) {}

  transform(value: unknown): T {
    const result = this.schema.safeParse(value);
    if (!result.success) {
      throw new BadRequestException({
        title: 'Validation failed',
        status: 400,
        errors: result.error.issues.map((i) => ({
          path: i.path.join('.'),
          message: i.message,
          code: i.code,
        })),
      });
    }
    return result.data;
  }
}

export const ZodQuery = ZodBody;
