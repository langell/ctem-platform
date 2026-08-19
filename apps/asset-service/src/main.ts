import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

void bootstrapService(AppModule, {
  serviceName: 'asset-service',
  port: 3002,
  swagger: { title: 'Asset Service (internal)', description: 'Asset inventory and asset graph.' },
});
