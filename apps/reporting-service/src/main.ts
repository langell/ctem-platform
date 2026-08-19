import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'reporting-service',
  port: 3006,
  swagger: {
    title: 'Reporting Service (internal)',
    description: 'Exposure dashboards, SLA compliance, trends and exports.',
  },
});
