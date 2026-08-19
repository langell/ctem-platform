import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'findings-service',
  port: 3004,
  swagger: {
    title: 'Findings Service (internal)',
    description: 'Normalization, deduplication, lifecycle and triage of findings.',
  },
});
