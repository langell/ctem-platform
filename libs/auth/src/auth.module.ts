import { Global, Module } from '@nestjs/common';
import { InternalAuthGuard } from './auth.guard';
import { JwtVerifier } from './jwt.verifier';

@Global()
@Module({
  providers: [JwtVerifier, InternalAuthGuard],
  exports: [JwtVerifier, InternalAuthGuard],
})
export class AuthModule {}
