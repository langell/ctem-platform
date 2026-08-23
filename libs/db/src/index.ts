export * from './prisma.service';
export * from './db.module';
// The Prisma client is generated into src/generated/client (see schema.prisma).
// Everything must import it from here — the plain `@prisma/client` package does
// not contain the generated client under pnpm and fails to resolve at runtime.
export { Prisma, PrismaClient } from './generated/client';
