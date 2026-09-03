import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('session chrome', () => {
  const layout = readFileSync(resolve('apps/web/src/ui/Layout.tsx'), 'utf8');

  it('shows role only and keeps org id in the tooltip', () => {
    expect(layout).toMatch(/title=\{session\.orgId\}/);
    expect(layout).toMatch(/\{session\.role\}/);
    expect(layout).not.toMatch(/orgId\.slice/);
    expect(layout).not.toMatch(/org \{session\.orgId/);
    expect(layout).toMatch(/className="brand">CTEM/);
  });
});
