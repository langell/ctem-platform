import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { ReachabilityAnalyzer } from './analyze';
import { extractJsImports, npmPackageName } from './javascript';
import { extractPyImports } from './python';
import { extractGoImports } from './golang';
import {
  emptyReachabilityGraph,
  isReachabilityGraph,
  ReachabilityAnalysisError,
  verdictForComponent,
  type ReachabilityGraph,
} from './types';

const analyzer = new ReachabilityAnalyzer();

async function repo(
  files: Record<string, string>,
): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ctem-reach-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    await mkdir(join(abs, '..'), { recursive: true });
    await writeFile(abs, content);
  }
  return dir;
}

function graphWith(partial: {
  languages?: ReachabilityGraph['languages'];
  imported?: ReachabilityGraph['imported'];
  ambiguous?: ReachabilityGraph['ambiguous'];
  truncated?: boolean;
}): ReachabilityGraph {
  return {
    ...emptyReachabilityGraph(),
    ...partial,
  };
}

describe('verdictForComponent', () => {
  it('does not treat lockfile presence as reachable', () => {
    const graph = graphWith({ languages: new Set() });
    expect(
      verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph),
    ).toBe('unknown');
    expect(
      verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph),
    ).not.toBe('reachable');
  });

  it('marks reachable only when the import graph names the package', () => {
    const graph = graphWith({
      languages: new Set(['javascript']),
      imported: new Map([['javascript', new Set(['express'])]]),
    });
    expect(verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'qs', ecosystem: 'npm' }, graph)).toBe('not_reachable');
  });

  it('leaves unknown when the graph cannot prove a verdict', () => {
    const uncovered = graphWith({ languages: new Set(['javascript']) });
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, uncovered)).toBe('unknown');

    const ambiguous = graphWith({
      languages: new Set(['javascript']),
      imported: new Map([['javascript', new Set(['express'])]]),
      ambiguous: new Set(['javascript']),
    });
    expect(verdictForComponent({ name: 'express', ecosystem: 'npm' }, ambiguous)).toBe('reachable');
    expect(verdictForComponent({ name: 'qs', ecosystem: 'npm' }, ambiguous)).toBe('unknown');

    const truncated = graphWith({
      languages: new Set(['javascript']),
      truncated: true,
    });
    expect(verdictForComponent({ name: 'lodash', ecosystem: 'npm' }, truncated)).toBe('unknown');
  });
});

describe('ReachabilityAnalyzer', () => {
  it('does not mark a lockfile-only hit reachable', async () => {
    const workDir = await repo({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { express: '4.17.1' } },
          'node_modules/express': { version: '4.17.1' },
        },
      }),
    });
    const graph = await analyzer.analyze(workDir);
    expect(isReachabilityGraph(graph)).toBe(true);
    expect(verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph)).toBe('unknown');
    expect(verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph)).not.toBe('reachable');
  });

  it('marks imported packages reachable and unused same-language packages not_reachable', async () => {
    const workDir = await repo({
      'package-lock.json': '{}',
      'src/index.ts': `import express from 'express';\nexport const app = express();\n`,
      'node_modules/qs/index.js': `module.exports = require('qs');\n`,
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'qs', ecosystem: 'npm' }, graph)).toBe('not_reachable');
  });

  it('walks first-party files and ignores commented-out imports', async () => {
    const workDir = await repo({
      'app.js': `
        // import lodash from 'lodash';
        /* import hidden from 'hidden-dep'; */
        const unused = "import faker from 'faker'";
        import axios from 'axios';
      `,
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.imported.get('javascript')).toEqual(new Set(['axios']));
    expect(verdictForComponent({ name: 'lodash', ecosystem: 'npm' }, graph)).toBe('not_reachable');
    expect(verdictForComponent({ name: 'faker', ecosystem: 'npm' }, graph)).toBe('not_reachable');
  });

  it('resolves Python and Go imports against lockfile names', async () => {
    const workDir = await repo({
      'svc/app.py': 'import requests\nfrom flask import Flask\n',
      'cmd/server.go': `
        package main
        import (
          "fmt"
          "github.com/pkg/errors"
        )
      `,
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'requests', ecosystem: 'PyPI' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'Flask', ecosystem: 'PyPI' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'django', ecosystem: 'PyPI' }, graph)).toBe('not_reachable');
    expect(verdictForComponent({ name: 'github.com/pkg/errors', ecosystem: 'Go' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'github.com/kr/pretty', ecosystem: 'Go' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('treats dynamic imports as unknown for packages the graph did not name', async () => {
    const workDir = await repo({
      'load.js': `
        import express from 'express';
        require(process.env.PLUGIN);
      `,
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'express', ecosystem: 'npm' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'qs', ecosystem: 'npm' }, graph)).toBe('unknown');
  });

  it('fails the job when the workDir cannot be read', async () => {
    await expect(analyzer.analyze('/no/such/ctem-reach-workDir')).rejects.toThrow(
      ReachabilityAnalysisError,
    );
  });

  it('fails the job when the deadline expires before a graph is produced', async () => {
    const workDir = await repo({ 'app.js': "import express from 'express';\n" });
    await expect(analyzer.analyze(workDir, () => false)).rejects.toThrow(/deadline/);
  });

  it('fails when every source file is unreadable rather than returning an empty graph', async () => {
    const workDir = await repo({ 'app.js': "import express from 'express';\n" });
    await chmod(join(workDir, 'app.js'), 0);
    try {
      await expect(analyzer.analyze(workDir)).rejects.toThrow(ReachabilityAnalysisError);
    } finally {
      await chmod(join(workDir, 'app.js'), 0o644);
    }
  });
});

describe('language extractors', () => {
  it('maps JS specifiers to package names', () => {
    expect(npmPackageName('lodash/fp')).toBe('lodash');
    expect(npmPackageName('@scope/name/sub')).toBe('@scope/name');
    expect(npmPackageName('./local')).toBeUndefined();
    expect(npmPackageName('node:fs')).toBeUndefined();
  });

  it('extracts require and scoped imports', () => {
    const found = extractJsImports(`
      const x = require('left-pad');
      import foo from '@babel/core';
      export { bar } from 'ms';
    `);
    expect(found.packages.sort()).toEqual(['@babel/core', 'left-pad', 'ms']);
    expect(found.dynamic).toBe(false);
  });

  it('extracts Python imports without relative modules', () => {
    const found = extractPyImports('from .local import x\nimport urllib3 as u\n');
    expect(found.packages).toEqual(['urllib3']);
  });

  it('extracts third-party Go imports and skips stdlib', () => {
    const found = extractGoImports(`
      import (
        "fmt"
        "net/http"
        gin "github.com/gin-gonic/gin"
      )
      import "github.com/pkg/errors"
    `);
    expect(found.packages.sort()).toEqual(['github.com/gin-gonic/gin', 'github.com/pkg/errors']);
  });
});
