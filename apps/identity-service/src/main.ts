import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'identity-service',
  port: 3001,
  swagger: {
    title: 'Identity Service (internal)',
    description: 'Organizations, users, memberships, roles and machine tokens.',
  },
});
