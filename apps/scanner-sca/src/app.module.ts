import { Module } from '@nestjs/common';
import { ScannerModule } from '@ctem/scanner-sdk';
import { ScaScanner } from './sca.scanner';
import { SbomParser } from './sbom.parser';
import { VulnMatcher } from './vuln.matcher';

@Module({ imports: [ScannerModule.register(ScaScanner, [SbomParser, VulnMatcher])] })
export class AppModule {}
