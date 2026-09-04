import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const css = readFileSync(resolve('apps/web/src/styles.css'), 'utf8');
const html = readFileSync(resolve('apps/web/index.html'), 'utf8');

describe("Designer's first-pass UI tokens", () => {
  it('declares the spec palette, type, and interaction classes', () => {
    expect(css).toMatch(/--bg:\s*#0B1016/);
    expect(css).toMatch(/--panel:\s*#141B24/);
    expect(css).toMatch(/--panel-2:\s*#1A2330/);
    expect(css).toMatch(/--line:\s*#2A3542/);
    expect(css).toMatch(/--text:\s*#E8EEF4/);
    expect(css).toMatch(/--muted:\s*#8B9AAB/);
    expect(css).toMatch(/--accent:\s*#6CB6FF/);
    expect(css).toMatch(/--accent-pressed:\s*#4A9AE8/);
    expect(css).toMatch(/--danger:\s*#F07178/);
    expect(css).toMatch(/--warn:\s*#E6C07B/);
    expect(css).toMatch(/--ok:\s*#9CCC65/);
    expect(css).toMatch(/--info:\s*#7AA2C4/);
    expect(css).toMatch(/--focus:\s*#6CB6FF/);
    expect(css).not.toMatch(/#1d4f7a/i);
    expect(css).toMatch(/\.badge\s*\{/);
    expect(css).toMatch(/\.skeleton\s*\{/);
    expect(css).toMatch(/\.score-high\s*\{/);
    expect(css).toMatch(/\.score-mid\s*\{/);
    expect(css).toMatch(/\.score-low\s*\{/);
    expect(css).toMatch(/max-width:\s*1120px/);
    expect(css).toMatch(/margin:\s*0 auto/);
    expect(css).toMatch(/:focus-visible\s*\{/);
    expect(css).toMatch(/tbody tr:hover\s*\{/);
    expect(css).toMatch(/position:\s*sticky/);
    expect(css).toMatch(/font-size:\s*36px/);
    expect(css).toMatch(/font-size:\s*24px/);
    expect(css).toMatch(/font-size:\s*16px/);
    expect(css).toMatch(/font-size:\s*14px/);
    expect(css).toMatch(/font-size:\s*13px/);
    expect(css).toMatch(/font-size:\s*11px/);
    expect(css).toMatch(/\.badge-ok\s*\{/);
    expect(css).toMatch(/\.form-actions\s*\{/);
    expect(css).toMatch(/tr\.editing/);
    expect(css).toMatch(/inset 2px 0 0 var\(--accent\)/);
  });

  it('loads IBM Plex Sans instead of naming a missing font', () => {
    expect(css).toMatch(/IBM Plex Sans/);
    expect(html).toMatch(/IBM\+Plex\+Sans/);
  });
});

describe("Designer's Findings Score Rail", () => {
  it('declares inset rails and 12% risk-band fills without retinting pass-1 tokens', () => {
    expect(css).toMatch(/\.rail-danger\s*,[\s\S]*inset 3px 0 0 0 var\(--danger\)/);
    expect(css).toMatch(/\.rail-warn\s*,[\s\S]*inset 3px 0 0 0 var\(--warn\)/);
    expect(css).toMatch(/\.rail-accent\s*,[\s\S]*inset 3px 0 0 0 var\(--accent\)/);
    expect(css).toMatch(/\.rail-info\s*,[\s\S]*inset 3px 0 0 0 var\(--info\)/);
    expect(css).toMatch(/\.rail-muted\s*,[\s\S]*inset 3px 0 0 0 var\(--muted\)/);
    expect(css).toMatch(
      /\.risk-band-high\s*\{[\s\S]*color-mix\(in srgb, var\(--danger\) 12%, transparent\)/,
    );
    expect(css).toMatch(
      /\.risk-band-mid\s*\{[\s\S]*color-mix\(in srgb, var\(--warn\) 12%, transparent\)/,
    );
    expect(css).toMatch(
      /\.risk-band-low\s*\{[\s\S]*color-mix\(in srgb, var\(--ok\) 12%, transparent\)/,
    );
    expect(css).toMatch(/font-size:\s*22px/);
    expect(css).toMatch(/font-weight:\s*700/);
    expect(css).toMatch(/a\.finding-title\s*\{[\s\S]*font-weight:\s*600/);
    expect(css).toMatch(/a\.finding-title:hover\s*\{[\s\S]*color:\s*var\(--accent\)/);
    expect(css).toMatch(/tbody tr:hover\s*\{[\s\S]*background:\s*var\(--panel-2\)/);
    expect(css).toMatch(/position:\s*sticky/);
    expect(css).toMatch(/--danger:\s*#F07178/);
    expect(css).toMatch(/--warn:\s*#E6C07B/);
    expect(css).toMatch(/--ok:\s*#9CCC65/);
  });
});
