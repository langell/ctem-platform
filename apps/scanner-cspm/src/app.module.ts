import { Module } from '@nestjs/common';
import { ScannerModule } from '@ctem/scanner-sdk';
import { CspmScanner } from './cspm.scanner';

@Module({ imports: [ScannerModule.register(CspmScanner)] })
export class AppModule {}
