import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { OrgController } from './org/org.controller';
import { AuthResolveController } from './org/auth-resolve.controller';
import { CreateOrgController } from './org/create-org.controller';
import { OrgService } from './org/org.service';
import { ApiTokenService } from './tokens/api-token.service';
import { ApiTokenController } from './tokens/api-token.controller';
import { MailModule } from './mail/mail.module';

@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule, DbModule, MailModule],
  controllers: [
    HealthController,
    OrgController,
    AuthResolveController,
    CreateOrgController,
    ApiTokenController,
  ],
  providers: [OrgService, ApiTokenService, { provide: APP_GUARD, useClass: InternalAuthGuard }],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}
