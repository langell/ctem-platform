import { Module } from '@nestjs/common';
import { ScannerModule } from '@ctem/scanner-sdk';
import { SastScanner } from './sast.scanner';
import { RuleEngine } from './rule-engine';

@Module({ imports: [ScannerModule.register(SastScanner, [RuleEngine])] })
export class AppModule {}
