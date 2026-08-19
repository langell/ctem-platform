import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'orchestrator-service',
  port: 3003,
  swagger: {
    title: 'Orchestrator Service (internal)',
    description: 'Scan planning, job dispatch and scan lifecycle.',
  },
});
