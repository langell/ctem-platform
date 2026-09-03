import { Module } from '@nestjs/common';
import { GitRepoCheckout, ScannerModule } from '@ctem/scanner-sdk';
import { SastAnalyzer } from './analyzer';
import { SastScanner } from './sast.scanner';
import { RuleEngine } from './rule-engine';

@Module({ imports: [ScannerModule.register(SastScanner, [RuleEngine, GitRepoCheckout, SastAnalyzer])] })
export class AppModule {}
