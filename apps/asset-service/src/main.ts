import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { bootstrapService } from '@ctem/service-kit';
import { AppModule } from './app.module';

const env = loadEnv();
rootLogger
  .child({ service: 'asset-service' })
  .info({ githubApiOrigin: new URL(env.GITHUB_API_URL).origin }, 'github api origin');

void bootstrapService(AppModule, {
  serviceName: 'asset-service',
  port: 3002,
  swagger: { title: 'Asset Service (internal)', description: 'Asset inventory and asset graph.' },
});
