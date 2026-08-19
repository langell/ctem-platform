import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'api-gateway',
  port: 3000,
  swagger: {
    title: 'CTEM Platform API',
    description:
      'Continuous Threat Exposure Management — assets, scans, findings, risk and policy.',
  },
});
