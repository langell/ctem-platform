import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'notification-service',
  port: 3007,
  swagger: {
    title: 'Notification Service (internal)',
    description: 'Fan-out to Slack, email, webhooks and ticketing systems.',
  },
});
