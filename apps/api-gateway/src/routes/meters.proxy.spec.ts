import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Test } from '@nestjs/testing';
import { describe, expect, it, vi } from 'vitest';
import {
  InternalAuthGuard,
  PRINCIPAL_HEADER,
  PRINCIPAL_SIGNATURE_HEADER,
  encodePrincipal,
} from '@ctem/auth';
import type { Permission } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';
import { MetersProxyController, scanKickMeterQuery } from './meters.controller';

const ORG_B = '22222222-2222-4222-8222-222222222222';

describe('scan.kick meter gateway proxy', () => {
  it('forwards GET /v1/meters/scan-kicks and drops orgId', async () => {
    const proxy = { forward: vi.fn(async () => ({ event: 'scan.kick', total: 0, items: [] })) };
    const ctrl = new MetersProxyController(proxy as unknown as ServiceProxy);
    const query = {
      from: ' 2026-09-01T00:00:00.000Z ',
      to: '2026-09-10T00:00:00.000Z',
      source: 'ci',
      limit: '10',
      cursor: 'opaque',
      orgId: ORG_B,
      price: '1',
    };

    await ctrl.list({} as never, query);

    expect(proxy.forward).toHaveBeenCalledWith(
      'orchestrator',
      'GET',
      '/internal/meters/scan-kicks',
      {},
      {
        query: {
          from: '2026-09-01T00:00:00.000Z',
          to: '2026-09-10T00:00:00.000Z',
          source: 'ci',
          limit: '10',
          cursor: 'opaque',
        },
      },
    );
    expect(scanKickMeterQuery(query)).not.toHaveProperty('orgId');
    expect(JSON.stringify(proxy.forward.mock.calls)).not.toContain('idempotency-key');
  });

  it('is registered and denies callers without scan:read', () => {
    const app = readFileSync(resolve('apps/api-gateway/src/app.module.ts'), 'utf8');
    const controller = readFileSync(
      resolve('apps/api-gateway/src/routes/meters.controller.ts'),
      'utf8',
    );
    expect(app).toMatch(/MetersProxyController/);
    expect(controller).toMatch(/@Controller\('v1\/meters'\)/);
    expect(controller).toMatch(/@Get\('scan-kicks'\)/);
    expect(controller).toMatch(/@RequirePermissions\('scan:read'\)/);
    expect(controller).not.toMatch(/idempotencyForwardHeaders/);

    const guard = new InternalAuthGuard(new Reflector());
    expect(() => guard.canActivate(contextFor(['org:read']))).toThrow(ForbiddenException);
    expect(guard.canActivate(contextFor(['scan:read']))).toBe(true);
  });

  it('documents inclusive from and exclusive to on the OpenAPI operation', async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [MetersProxyController],
      providers: [{ provide: ServiceProxy, useValue: { forward: async () => ({}) } }],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const doc = SwaggerModule.createDocument(
      app,
      new DocumentBuilder().setTitle('ctem').setVersion('0').build(),
    );
    await app.close();

    const operation = doc.paths['/v1/meters/scan-kicks']?.get;
    const params = operation?.parameters ?? [];
    const description = (name: string) => {
      const param = params.find((entry) => 'name' in entry && entry.name === name);
      return param && 'description' in param ? param.description : undefined;
    };
    expect(operation?.description).toMatch(/occurredAt >= from/);
    expect(operation?.description).toMatch(/occurredAt < to/);
    expect(operation?.description).toMatch(/last 30 days/);
    expect(operation?.description).toMatch(/no price, currency, or remaining-credits/);
    expect(description('from')).toMatch(/Inclusive/);
    expect(description('to')).toMatch(/Exclusive/);
    expect(description('orgId')).toBeUndefined();
  });
});

function contextFor(permissions: Permission[]) {
  const encoded = encodePrincipal({
    userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    orgId: '11111111-1111-4111-8111-111111111111',
    role: 'auditor',
    permissions,
    serviceAccount: null,
    traceId: 'trace-meter',
  });
  return {
    getHandler: () => MetersProxyController.prototype.list,
    getClass: () => MetersProxyController,
    switchToHttp: () => ({
      getRequest: () => ({
        headers: {
          [PRINCIPAL_HEADER]: encoded.value,
          [PRINCIPAL_SIGNATURE_HEADER]: encoded.signature,
        },
      }),
    }),
  } as never;
}
