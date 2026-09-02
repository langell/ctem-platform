import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const CHECKS = /check-runs|check-suites|github\.checks|checks\.create|\/repos\/[^/]+\/[^/]+\/check/i;

describe('fail-build does not use the GitHub Checks API', () => {
  const files = [
    'apps/orchestrator-service/src/scans/scans.controller.ts',
    'apps/api-gateway/src/routes/scans.controller.ts',
    'apps/risk-service/src/policy/policy-engine.service.ts',
    'apps/web/src/pages/policy-actions.ts',
    'libs/contracts/src/domain/scan.ts',
    'libs/contracts/src/domain/scan-conclusion.ts',
  ];

  it('scan conclusion and CI GET never call check-runs / check-suites', () => {
    for (const rel of files) {
      const src = readFileSync(resolve(rel), 'utf8');
      expect(src, rel).not.toMatch(CHECKS);
      expect(src, rel).not.toMatch(/api\.github\.com\/repos/);
    }
  });
});
