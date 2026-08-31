import { join } from 'node:path';
import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'api-gateway',
  port: 3000,
  cors: true,
  // Gateway is the only UI entry — the built Nx web app is served from here.
  staticDir: join(__dirname, '../../web/dist'),
  swagger: {
    title: 'CTEM Platform API',
    description:
      'Continuous Threat Exposure Management — assets, scans, findings, risk and policy.',
  },
});
