import { Global, Module } from '@nestjs/common';
import { ArtifactStore } from './artifact.store';

@Global()
@Module({
  providers: [ArtifactStore],
  exports: [ArtifactStore],
})
export class StorageModule {}
