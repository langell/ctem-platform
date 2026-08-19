import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule } from '@ctem/observability';
import { EventsModule } from '@ctem/events';
import { StorageModule } from '@ctem/storage';
import { BaseScanner, SCANNER } from './base-scanner';
import { ScannerWorker } from './scanner-worker';

@Module({})
export class ScannerModule {
  /**
   * `ScannerModule.register(ScaScanner, [SbomParser, VulnMatcher])` is all a
   * worker app needs — extra providers are the scanner's own collaborators.
   */
  static register(scanner: Type<BaseScanner>, providers: Provider[] = []): DynamicModule {
    return {
      module: ScannerModule,
      imports: [CtemConfigModule, ObservabilityModule, EventsModule, StorageModule],
      providers: [...providers, scanner, { provide: SCANNER, useExisting: scanner }, ScannerWorker],
      exports: [ScannerWorker],
    };
  }
}
