import { Global, Module } from '@nestjs/common';
import { RedisClient } from './redis.client';

@Global()
@Module({
  providers: [RedisClient],
  exports: [RedisClient],
})
export class CoordinationModule {}
