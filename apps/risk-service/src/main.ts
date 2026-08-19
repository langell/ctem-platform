import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'risk-service',
  port: 3005,
  swagger: {
    title: 'Risk & Policy Service (internal)',
    description: 'Risk scoring, policy evaluation, SLAs and exceptions.',
  },
});
