import { Global, Module } from '@nestjs/common';
import { EventBus } from './event-bus';
import { NatsClient } from './nats.client';

@Global()
@Module({
  providers: [NatsClient, EventBus],
  exports: [NatsClient, EventBus],
})
export class EventsModule {}
