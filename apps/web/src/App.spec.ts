import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const app = readFileSync(resolve('apps/web/src/App.tsx'), 'utf8');

describe('existing routes only', () => {
  it('does not add asset detail, scan history, dashboards, or filters', () => {
    expect(app).toMatch(/path="\/login"/);
    expect(app).toMatch(/path="\/login\/callback"/);
    expect(app).toMatch(/path="\/assets"/);
    expect(app).toMatch(/path="\/findings"/);
    expect(app).toMatch(/path="\/findings\/:id"/);
    expect(app).toMatch(/path="\/scans"/);
    expect(app).toMatch(/path="\/policies"/);
    expect(app).not.toMatch(/path="\/assets\//);
    expect(app).not.toMatch(/path="\/scans\//);
    expect(app).not.toMatch(/path="\/policies\//);
    expect(app).not.toMatch(/dashboard/i);
    expect(app).not.toMatch(/history/i);
    expect(app).not.toMatch(/filter/i);
    expect(app.match(/path="/g)?.length).toBe(9);
  });
});
