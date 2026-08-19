import { bootstrapScanner } from '@ctem/scanner-sdk';
import { AppModule } from './app.module';

process.env.SERVICE_NAME = 'scanner-sca';
void bootstrapScanner(AppModule);
