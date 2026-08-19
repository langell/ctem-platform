import { bootstrapScanner } from '@ctem/scanner-sdk';
import { AppModule } from './app.module';

process.env.SERVICE_NAME = 'scanner-container-iac';
void bootstrapScanner(AppModule);
