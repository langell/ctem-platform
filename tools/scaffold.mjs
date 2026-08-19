// One-shot scaffolding helper used to generate per-project package.json/tsconfig.
// Kept in-repo so new services can be added consistently: `node tools/scaffold.mjs`
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();

const NEST = {
  '@nestjs/common': '^11.0.0',
  '@types/express': '^5.0.0',
  zod: '^3.24.1',
  '@nestjs/core': '^11.0.0',
  '@nestjs/platform-express': '^11.0.0',
  '@nestjs/swagger': '^11.0.0',
  '@nestjs/terminus': '^11.0.0',
  'reflect-metadata': '^0.2.2',
  rxjs: '^7.8.1',
};

const LIBS = {
  contracts: { deps: { zod: '^3.24.1' }, refs: [] },
  config: { deps: { zod: '^3.24.1', '@nestjs/common': '^11.0.0' }, refs: [] },
  observability: {
    deps: {
      '@nestjs/common': '^11.0.0',
      pino: '^9.6.0',
      'pino-http': '^10.4.0',
      '@types/express': '^5.0.0',
    },
    refs: ['config'],
  },
  events: {
    deps: { '@nestjs/common': '^11.0.0', nats: '^2.29.0', zod: '^3.24.1' },
    refs: ['contracts', 'config', 'observability'],
  },
  db: {
    deps: { '@nestjs/common': '^11.0.0', '@prisma/client': '^6.3.0' },
    refs: ['config', 'observability'],
  },
  auth: {
    deps: {
      '@nestjs/common': '^11.0.0',
      '@nestjs/core': '^11.0.0',
      jose: '^5.9.6',
      zod: '^3.24.1',
    },
    refs: ['config', 'contracts', 'observability'],
  },
  storage: {
    deps: { '@nestjs/common': '^11.0.0', '@aws-sdk/client-s3': '^3.720.0' },
    refs: ['config'],
  },
  'service-kit': {
    deps: {
      ...NEST,
      '@types/express': '^5.0.0',
      zod: '^3.24.1',
    },
    refs: ['contracts', 'config', 'observability', 'auth'],
  },
  'scanner-sdk': {
    deps: { '@nestjs/common': '^11.0.0', '@nestjs/core': '^11.0.0', 'reflect-metadata': '^0.2.2', rxjs: '^7.8.1' },
    refs: ['contracts', 'config', 'observability', 'events', 'storage'],
  },
};

const SERVICES = {
  'api-gateway': { port: 3000, refs: ['contracts', 'config', 'observability', 'auth', 'events'] },
  'identity-service': { port: 3001, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events'] },
  'asset-service': { port: 3002, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events'] },
  'orchestrator-service': { port: 3003, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events', 'storage'] },
  'findings-service': { port: 3004, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events'] },
  'risk-service': { port: 3005, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events'] },
  'reporting-service': { port: 3006, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events', 'storage'] },
  'notification-service': { port: 3007, refs: ['contracts', 'config', 'observability', 'auth', 'db', 'events'] },
};

const WORKERS = {
  'scanner-sca': { port: 3100 },
  'scanner-sast': { port: 3101 },
  'scanner-container-iac': { port: 3102 },
  'scanner-asm': { port: 3103 },
};

const WORKER_REFS = ['contracts', 'config', 'observability', 'events', 'storage', 'scanner-sdk'];

function tsconfig(refs, dir) {
  const prefix = dir === 'libs' ? '../' : '../../libs/';
  return {
    extends: dir === 'libs' ? '../../tsconfig.base.json' : '../../tsconfig.base.json',
    compilerOptions: { rootDir: 'src', outDir: 'dist', tsBuildInfoFile: 'dist/.tsbuildinfo' },
    include: ['src/**/*.ts'],
    exclude: ['src/**/*.spec.ts', 'src/**/*.test.ts'],
    references: refs.map((r) => ({ path: `${prefix}${r}` })),
  };
}

function write(dir, name, pkg, refs) {
  const base = join(ROOT, dir, name);
  mkdirSync(join(base, 'src'), { recursive: true });
  writeFileSync(join(base, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
  writeFileSync(join(base, 'tsconfig.json'), JSON.stringify(tsconfig(refs, dir), null, 2) + '\n');
}

for (const [name, spec] of Object.entries(LIBS)) {
  const deps = { ...spec.deps };
  for (const r of spec.refs) deps[`@ctem/${r}`] = 'workspace:*';
  write('libs', name, {
    name: `@ctem/${name}`,
    version: '0.1.0',
    private: true,
    main: './dist/index.js',
    types: './dist/index.d.ts',
    scripts: { build: 'tsc -b', clean: 'tsc -b --clean' },
    dependencies: deps,
  }, spec.refs);
}

const allApps = {};
for (const [name, spec] of Object.entries(SERVICES)) {
  allApps[name] = { ...spec, refs: [...spec.refs, 'service-kit'] };
}
for (const [name, spec] of Object.entries(WORKERS)) allApps[name] = { ...spec, refs: WORKER_REFS };

for (const [name, spec] of Object.entries(allApps)) {
  const deps = { ...NEST };
  for (const r of spec.refs) deps[`@ctem/${r}`] = 'workspace:*';
  // Services that use @ctem/db consume Prisma's generated types through its
  // .d.ts, so the package has to resolve from the service too.
  if (spec.refs.includes('db')) deps['@prisma/client'] = '^6.3.0';
  write('apps', name, {
    name: `@ctem/${name}`,
    version: '0.1.0',
    private: true,
    main: './dist/main.js',
    scripts: {
      build: 'tsc -b',
      clean: 'tsc -b --clean',
      start: 'node dist/main.js',
      dev: 'tsx watch src/main.ts',
    },
    ctem: { port: spec.port },
    dependencies: deps,
  }, spec.refs);
}

// Root solution tsconfig
writeFileSync(
  join(ROOT, 'tsconfig.build.json'),
  JSON.stringify(
    {
      files: [],
      references: [
        ...Object.keys(LIBS).map((n) => ({ path: `libs/${n}` })),
        ...Object.keys(allApps).map((n) => ({ path: `apps/${n}` })),
      ],
    },
    null,
    2,
  ) + '\n',
);

console.log('scaffold complete');
