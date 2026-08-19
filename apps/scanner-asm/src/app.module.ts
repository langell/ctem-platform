import { Module } from '@nestjs/common';
import { ScannerModule } from '@ctem/scanner-sdk';
import { AsmScanner } from './asm.scanner';
import { SurfaceProbe } from './surface.probe';

@Module({ imports: [ScannerModule.register(AsmScanner, [SurfaceProbe])] })
export class AppModule {}
