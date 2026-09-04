import { Module } from '@nestjs/common';
import { GitRepoCheckout, ScannerModule } from '@ctem/scanner-sdk';
import { DbModule } from '@ctem/db';
import { VulnMatcher } from '@ctem/vuln-intel';
import { IacAnalyzer } from './analyzer';
import { ContainerScanner } from './container.scanner';
import { IacScanner } from './iac.scanner';
import { MisconfigRules } from './misconfig.rules';
import { GhcrRegistry } from './oci/registry';

/**
 * Two scanner types, one process. Container and IaC share a deployable but are
 * separated by scanner type on the bus — each `ScannerModule.register` hosts
 * its own worker so `iac` jobs are not swallowed by the container scanner.
 *
 * DbModule gives the container matcher read access to the vulnerability mirror
 * (same path SCA uses).
 */
@Module({
  imports: [
    DbModule,
    ScannerModule.register(IacScanner, [MisconfigRules, GitRepoCheckout, IacAnalyzer]),
    ScannerModule.register(ContainerScanner, [VulnMatcher, GhcrRegistry]),
  ],
})
export class AppModule {}
