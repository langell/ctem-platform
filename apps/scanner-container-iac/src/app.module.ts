import { Module } from '@nestjs/common';
import { ScannerModule } from '@ctem/scanner-sdk';
import { ContainerScanner } from './container.scanner';
import { IacScanner } from './iac.scanner';
import { MisconfigRules } from './misconfig.rules';

/**
 * Two scanner types, one worker. Container and IaC findings almost always share
 * an owner and a fix, and they share the registry/manifest plumbing, so they are
 * deployed together and separated only by scanner type on the bus.
 */
@Module({
  imports: [ScannerModule.register(ContainerScanner, [MisconfigRules, IacScanner])],
})
export class AppModule {}
