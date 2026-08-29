import { Module } from '@nestjs/common';
import { ScannerModule } from '@ctem/scanner-sdk';
import { DbModule } from '@ctem/db';
import { ScaScanner } from './sca.scanner';
import { SbomParser } from './sbom.parser';
import { VulnMatcher } from './vuln.matcher';
import { GitRepoCheckout } from './repo.checkout';

@Module({
  // DbModule gives the matcher read access to the vulnerability mirror; the
  // scanner runs as ctem_app, which can only SELECT the shared intel tables.
  imports: [DbModule, ScannerModule.register(ScaScanner, [SbomParser, VulnMatcher, GitRepoCheckout])],
})
export class AppModule {}
