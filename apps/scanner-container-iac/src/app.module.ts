import { Module } from '@nestjs/common';
import { GitRepoCheckout, ScannerModule } from '@ctem/scanner-sdk';
import { IacAnalyzer } from './analyzer';
import { ContainerScanner } from './container.scanner';
import { IacScanner } from './iac.scanner';
import { MisconfigRules } from './misconfig.rules';

/**
 * Two scanner types, one process. Container and IaC share a deployable but are
 * separated by scanner type on the bus — each `ScannerModule.register` hosts
 * its own worker so `iac` jobs are not swallowed by the container scanner.
 */
@Module({
  imports: [
    ScannerModule.register(IacScanner, [MisconfigRules, GitRepoCheckout, IacAnalyzer]),
    ScannerModule.register(ContainerScanner),
  ],
})
export class AppModule {}
