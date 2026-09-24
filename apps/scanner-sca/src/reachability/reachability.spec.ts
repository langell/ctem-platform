import { chmod, mkdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { MAX_SOURCE_BYTES, ReachabilityAnalyzer } from './analyze';
import { extractJsImports, npmPackageName } from './javascript';
import { extractPyImports } from './python';
import { extractGoImports } from './golang';
import {
  cargoTomlDeclaresDependencyRename,
  extractRustImports,
  isRustBuildOrVendoredPath,
  isRustSource,
} from './rust';
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

describe('Rust reachability', () => {
  it('marks serde reachable from use and serde_json from a path with no use', async () => {
    const workDir = await repo({
      'src/main.rs': `
        use serde::Deserialize;

        fn parse(input: &str) -> Result<serde_json::Value, serde_json::Error> {
            serde_json::from_str(input)
        }
      `,
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.languages.has('rust')).toBe(true);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'serde_json', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'serde-json', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('does not count a crate named only inside a comment or string literal', async () => {
    const workDir = await repo({
      'src/lib.rs': `
        // use serde::Deserialize;
        /* extern crate tokio; */
        /// reqwest::Client
        /*! hyper::Client */
        fn main() {
            let _ = "tracing::info";
            let _ = r#"bytes::Bytes"#;
            let _ = r##"include!("generated.rs") and axum::Router"##;
            let _ = b"clap::Parser";
        }
      `,
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.ambiguous.has('rust')).toBe(false);
    expect([...(graph.imported.get('rust') ?? [])].sort()).toEqual([]);
    for (const name of ['serde', 'tokio', 'reqwest', 'hyper', 'tracing', 'bytes', 'axum', 'clap']) {
      expect(verdictForComponent({ name, ecosystem: 'crates.io' }, graph)).toBe('not_reachable');
    }
  });

  it('counts the real ident of extern crate, not the alias', async () => {
    const workDir = await repo({
      'src/lib.rs': 'extern crate foo as bar;\nfn main() {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'foo', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'bar', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('does not treat std, crate, or super path roots as crates', async () => {
    const workDir = await repo({
      'src/lib.rs': `
        use std::collections::HashMap;
        use crate::local::Thing;
        use super::sibling::Other;

        fn demo() {
            let _ = core::mem::size_of::<u8>();
            let _ = alloc::vec![1, 2];
            let _ = self::demo();
            let _ = Self::demo();
        }
      `,
    });
    const graph = await analyzer.analyze(workDir);
    const imported = [...(graph.imported.get('rust') ?? [])];
    for (const name of ['std', 'core', 'alloc', 'crate', 'self', 'super', 'Self']) {
      expect(imported).not.toContain(name);
    }
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('marks Rust ambiguous when Cargo.toml renames a dependency with package =', async () => {
    const workDir = await repo({
      'Cargo.toml': `
        [package]
        name = "app"
        version = "0.1.0"
        description = "package = \\"not-a-rename\\""

        [dependencies]
        serde = "1"
        renamed = { version = "1.0", package = "actual-crate" }
      `,
      'src/main.rs': 'use serde::Deserialize;\nfn main() {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.ambiguous.has('rust')).toBe(true);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe('unknown');
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).not.toBe(
      'not_reachable',
    );
  });

  it('does not treat a Cargo.toml dependency list as reachability', async () => {
    const workDir = await repo({
      'Cargo.toml': `
        [package]
        name = "app"
        version = "0.1.0"

        [dependencies]
        serde = "1"
        tokio = "1"
      `,
      'src/main.rs': 'fn main() {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.ambiguous.has('rust')).toBe(false);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('marks Rust ambiguous when source include! pulls in code we do not parse', async () => {
    const workDir = await repo({
      'src/lib.rs': `
        use serde::Deserialize;
        include!(concat!(env!("OUT_DIR"), "/generated.rs"));
        fn main() {}
      `,
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.ambiguous.has('rust')).toBe(true);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe('unknown');
  });

  it('ignores .rs files under target/ and vendor/', async () => {
    const workDir = await repo({
      'src/lib.rs': 'fn main() {}\n',
      'target/debug/build/out.rs': 'use serde::Deserialize;\nserde_json::from_str("");\n',
      'vendor/tokio-1.0.0/src/lib.rs': 'use tokio::io;\n',
      'not_target/used.rs': 'use bytes::Bytes;\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'bytes', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
    expect(verdictForComponent({ name: 'serde_json', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('sets truncated when a Rust source file exceeds the size cap', async () => {
    const workDir = await repo({
      'src/lib.rs': 'use serde::Deserialize;\n',
      'src/huge.rs': `fn main() {}\n${'x'.repeat(MAX_SOURCE_BYTES)}\n`,
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.truncated).toBe(true);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe('unknown');
  });

  it('throws when every Rust source file fails to parse', async () => {
    const workDir = await repo({ 'src/lib.rs': 'fn main() {}\n' });
    await chmod(join(workDir, 'src/lib.rs'), 0);
    try {
      await expect(analyzer.analyze(workDir)).rejects.toThrow(ReachabilityAnalysisError);
      await expect(analyzer.analyze(workDir)).rejects.toThrow(/parsed none/);
    } finally {
      await chmod(join(workDir, 'src/lib.rs'), 0o644);
    }
  });

  it('parses src/bin even though the shared walk skips bin directories', async () => {
    const workDir = await repo({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'src/bin/cli.rs': 'use clap::Parser;\nfn main() {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'clap', ecosystem: 'crates.io' }, graph)).toBe('reachable');
  });

  it('skips src/**/target and vendor on the crate src walk', async () => {
    const workDir = await repo({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'src/lib.rs': 'fn lib() {}\n',
      'src/nested/target/hidden.rs': 'use serde::Deserialize;\n',
      'src/vendor/leaf.rs': 'use tokio::io;\n',
      'vendor/dep/src/lib.rs': 'use anyhow::Error;\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
    expect(verdictForComponent({ name: 'anyhow', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('marks anyhow reachable from a return type path after ->', async () => {
    const workDir = await repo({
      'src/lib.rs': 'fn main() -> ::anyhow::Result<()> { Ok(()) }\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'anyhow', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect([...(graph.imported.get('rust') ?? [])]).not.toContain('fn');
  });

  it('marks serde reachable from impl ::serde and does not record impl', async () => {
    const workDir = await repo({
      'src/lib.rs': 'impl ::serde::Serialize for F {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect([...(graph.imported.get('rust') ?? [])]).not.toContain('impl');
  });

  it('marks crate roots after as, return, dyn, mut, and pub', async () => {
    const workDir = await repo({
      'src/lib.rs': `
        fn demo(x: &dyn ::bytes::Buf) {
            return ::tracing::info("x");
            let _ = x as ::http::StatusCode;
            let mut ::log::Level::Error;
            pub ::regex::Regex::new("");
        }
      `,
    });
    const graph = await analyzer.analyze(workDir);
    for (const name of ['bytes', 'tracing', 'http', 'log', 'regex']) {
      expect(verdictForComponent({ name, ecosystem: 'crates.io' }, graph)).toBe('reachable');
    }
    const imported = [...(graph.imported.get('rust') ?? [])];
    for (const keyword of ['dyn', 'return', 'as', 'mut', 'pub']) {
      expect(imported).not.toContain(keyword);
    }
  });

  it('marks tokio reachable from a path after a closing brace', async () => {
    const workDir = await repo({
      'src/lib.rs': 'fn branch() { if c { } ::tokio::spawn(x); }\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe('reachable');
  });

  it('marks Rust ambiguous for include! brace and bracket forms', async () => {
    const braceDir = await repo({
      'src/lib.rs': 'fn main() { include! { "generated.rs" } }\n',
    });
    const brace = await analyzer.analyze(braceDir);
    expect(brace.ambiguous.has('rust')).toBe(true);
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, brace)).toBe('unknown');

    const bracketDir = await repo({
      'src/lib.rs': 'fn main() { include!["generated.rs"]; }\n',
    });
    const bracket = await analyzer.analyze(bracketDir);
    expect(bracket.ambiguous.has('rust')).toBe(true);
    expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, bracket)).toBe('unknown');
  });

  it('maps use xml::reader to the xml-rs package', async () => {
    const workDir = await repo({
      'src/lib.rs': 'use xml::reader::EventReader;\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'xml-rs', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('resolves the fixed lib-name aliases and leaves other mismatched names unknown', () => {
    const graph = graphWith({
      languages: new Set(['rust']),
      imported: new Map([['rust', new Set(['xml', 'md5', 'sha1', 'crypto', 'ini', 's3'])]]),
    });
    expect(verdictForComponent({ name: 'xml-rs', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'md-5', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'sha-1', ecosystem: 'crates.io' }, graph)).toBe('reachable');
    expect(verdictForComponent({ name: 'rust-crypto', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'rust-ini', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'rust-s3', ecosystem: 'crates.io' }, graph)).toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'foo-rs', ecosystem: 'crates.io' }, graph)).toBe('unknown');
    expect(verdictForComponent({ name: 'rust-other', ecosystem: 'crates.io' }, graph)).toBe(
      'unknown',
    );
    expect(verdictForComponent({ name: 'bar-2', ecosystem: 'crates.io' }, graph)).toBe('unknown');
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('does not mark an unaliased foo-rs package not_reachable', async () => {
    const workDir = await repo({
      'src/lib.rs': 'fn main() {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(verdictForComponent({ name: 'foo-rs', ecosystem: 'crates.io' }, graph)).toBe('unknown');
    expect(verdictForComponent({ name: 'foo-rs', ecosystem: 'crates.io' }, graph)).not.toBe(
      'not_reachable',
    );
    expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
      'not_reachable',
    );
  });

  it('does not claim not_reachable when one Rust file fails and another parses', async () => {
    const workDir = await repo({
      'src/lib.rs': 'use serde::Deserialize;\n',
      'src/secret.rs': 'fn hidden() {}\n',
    });
    await chmod(join(workDir, 'src/secret.rs'), 0);
    try {
      const graph = await analyzer.analyze(workDir);
      expect(graph.truncated).toBe(true);
      expect(graph.ambiguous.has('rust')).toBe(true);
      expect(verdictForComponent({ name: 'serde', ecosystem: 'crates.io' }, graph)).toBe(
        'reachable',
      );
      expect(verdictForComponent({ name: 'tokio', ecosystem: 'crates.io' }, graph)).toBe('unknown');
    } finally {
      await chmod(join(workDir, 'src/secret.rs'), 0o644);
    }
  });

  it('does not follow a symlinked crate src directory', async () => {
    const workDir = await repo({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'app.rs': 'fn main() {}\n',
    });
    const outside = join(dirname(workDir), `${basename(workDir)}-outside`);
    await mkdir(outside);
    await writeFile(join(outside, 'lib.rs'), 'use leaked::X;\n');
    await symlink(relative(workDir, outside), join(workDir, 'src'));
    const graph = await analyzer.analyze(workDir);
    expect(graph.truncated).toBe(true);
    expect([...(graph.imported.get('rust') ?? [])]).not.toContain('leaked');
    expect(verdictForComponent({ name: 'leaked', ecosystem: 'crates.io' }, graph)).not.toBe(
      'reachable',
    );
  });

  it('does not follow a symlinked src/lib.rs file', async () => {
    const workDir = await repo({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'src/main.rs': 'fn main() {}\n',
    });
    const outside = join(dirname(workDir), `${basename(workDir)}-outside`);
    await mkdir(outside);
    await writeFile(join(outside, 'lib.rs'), 'use leaked::X;\n');
    await symlink(
      relative(join(workDir, 'src'), join(outside, 'lib.rs')),
      join(workDir, 'src/lib.rs'),
    );
    const graph = await analyzer.analyze(workDir);
    expect(graph.truncated).toBe(true);
    expect([...(graph.imported.get('rust') ?? [])]).not.toContain('leaked');
    expect(verdictForComponent({ name: 'leaked', ecosystem: 'crates.io' }, graph)).not.toBe(
      'reachable',
    );
  });

  it('does not follow a symlinked src subdirectory', async () => {
    const workDir = await repo({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'src/lib.rs': 'fn lib() {}\n',
    });
    const outside = join(dirname(workDir), `${basename(workDir)}-outside`);
    await mkdir(outside);
    await writeFile(join(outside, 'mod.rs'), 'use leaked::X;\n');
    await symlink(relative(join(workDir, 'src'), outside), join(workDir, 'src/util'));
    const graph = await analyzer.analyze(workDir);
    expect(graph.truncated).toBe(true);
    expect([...(graph.imported.get('rust') ?? [])]).not.toContain('leaked');
    expect(verdictForComponent({ name: 'leaked', ecosystem: 'crates.io' }, graph)).not.toBe(
      'reachable',
    );
  });

  it('does not mark a workspace member under bin/ not_reachable', async () => {
    const workDir = await repo({
      'Cargo.toml': '[workspace]\nmembers = ["bin/cli"]\n',
      'Cargo.lock': '# clap\nname = "clap"\n',
      'src/lib.rs': 'fn lib() {}\n',
      'bin/cli/Cargo.toml': '[package]\nname = "cli"\nversion = "0.1.0"\n',
      'bin/cli/src/main.rs': 'use clap::Parser;\nfn main() {}\n',
    });
    const graph = await analyzer.analyze(workDir);
    expect(graph.ambiguous.has('rust')).toBe(true);
    expect(verdictForComponent({ name: 'clap', ecosystem: 'crates.io' }, graph)).not.toBe(
      'not_reachable',
    );
  });

  it('does not follow a symlink inside an ignored directory', async () => {
    const workDir = await repo({
      'Cargo.toml': '[workspace]\nmembers = ["bin/cli"]\n',
      'src/lib.rs': 'fn lib() {}\n',
      'bin/cli/Cargo.toml': '[package]\nname = "cli"\nversion = "0.1.0"\n',
      'bin/cli/src/main.rs': 'use clap::Parser;\nfn main() {}\n',
    });
    const outside = join(dirname(workDir), `${basename(workDir)}-outside`);
    await mkdir(outside);
    await writeFile(join(outside, 'sneak.rs'), 'use leaked::X;\n');
    await symlink(
      relative(join(workDir, 'bin/cli'), join(outside, 'sneak.rs')),
      join(workDir, 'bin/cli/sneak.rs'),
    );
    const graph = await analyzer.analyze(workDir);
    expect(graph.truncated).toBe(true);
    expect([...(graph.imported.get('rust') ?? [])]).not.toContain('leaked');
    expect(verdictForComponent({ name: 'leaked', ecosystem: 'crates.io' }, graph)).not.toBe(
      'reachable',
    );
    expect(verdictForComponent({ name: 'clap', ecosystem: 'crates.io' }, graph)).not.toBe(
      'not_reachable',
    );
  });
});

describe('Rust extractors', () => {
  it('recognizes .rs sources and skips build or vendored path segments', () => {
    expect(isRustSource('lib.rs')).toBe(true);
    expect(isRustSource('lib.rs.txt')).toBe(false);
    expect(isRustBuildOrVendoredPath('src/lib.rs')).toBe(false);
    expect(isRustBuildOrVendoredPath('target.rs')).toBe(false);
    expect(isRustBuildOrVendoredPath('src/target/debug/out.rs')).toBe(true);
    expect(isRustBuildOrVendoredPath('vendor/serde/src/lib.rs')).toBe(true);
    expect(isRustBuildOrVendoredPath('not_target/lib.rs')).toBe(false);
  });

  it('collects use roots, path roots, extern crate idents, and attribute paths', () => {
    const found = extractRustImports(`
      use serde::Deserialize;
      use serde_json;
      use ::bytes::Bytes;
      use {tracing, tokio::io};
      extern crate foo as bar;
      #[tokio::main]
      #[derive(serde::Deserialize)]
      fn main() {
          let _ = hyper::Client::new();
      }
    `);
    expect(found.dynamic).toBe(false);
    expect(found.packages.sort()).toEqual(
      ['bytes', 'foo', 'hyper', 'serde', 'serde_json', 'tokio', 'tracing'].sort(),
    );
  });

  it('sets dynamic only for include!, not include_str! or a commented include!', () => {
    expect(extractRustImports('include!("generated.rs");\n').dynamic).toBe(true);
    expect(extractRustImports('include ! ( "generated.rs" );\n').dynamic).toBe(true);
    expect(extractRustImports('let s = include_str!("Cargo.toml");\n').dynamic).toBe(false);
    expect(extractRustImports('let b = include_bytes!("blob.bin");\n').dynamic).toBe(false);
    expect(extractRustImports('// include!("generated.rs")\nfn main() {}\n').dynamic).toBe(false);
  });

  it('detects Cargo dependency renames and ignores comments and the package table', () => {
    expect(
      cargoTomlDeclaresDependencyRename(`
        [dependencies]
        foo = { version = "1", package = "bar" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [dependencies.serde]
        version = "1"
        package = "serde"
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [dev-dependencies]
        tempfile = { version = "3", package = "tempfile" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [build-dependencies]
        cc = { version = "1", package = "cc" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [target.'cfg(unix)'.dependencies]
        nix = { version = "0.27", package = "nix" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [target.'cfg(windows)'.dev-dependencies]
        win = { version = "0.1", package = "windows" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [target.x86_64-pc-windows-msvc.dependencies.windows]
        version = "0.52"
        package = "windows"
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [workspace.dependencies]
        tokio = { version = "1", package = "tokio" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        dependencies.foo = { version = "1", package = "bar" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [package]
        name = "app"
        version = "0.1.0"
        description = "package = \\"nope\\""

        [dependencies]
        # package = "commented-out"
        serde = "1"
      `),
    ).toBe(false);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [dependencies]
        renamed = { version = "1", "package" = "actual-crate" }
      `),
    ).toBe(true);
    expect(
      cargoTomlDeclaresDependencyRename(`
        [dependencies.foo]
        version = "1"
        'package' = 'actual-crate'
      `),
    ).toBe(true);
  });

  it('treats a leading :: path after ->, }, and keywords as the crate root', () => {
    const anyhow = extractRustImports('fn main() -> ::anyhow::Result<()> {}\n');
    expect(anyhow.packages).toContain('anyhow');
    expect(anyhow.packages).not.toContain('fn');

    const serialize = extractRustImports('impl ::serde::Serialize for F {}\n');
    expect(serialize.packages).toContain('serde');
    expect(serialize.packages).not.toContain('impl');

    const afterKeywords = extractRustImports(`
      fn demo(x: &dyn ::bytes::Buf) {
          return ::tracing::info("x");
          let _ = x as ::http::StatusCode;
          let mut ::log::Level::Error;
          pub ::regex::Regex::new("");
      }
    `);
    expect(afterKeywords.packages).toEqual(
      expect.arrayContaining(['bytes', 'tracing', 'http', 'log', 'regex']),
    );
    for (const keyword of ['dyn', 'return', 'as', 'mut', 'pub', 'fn', 'let']) {
      expect(afterKeywords.packages).not.toContain(keyword);
    }

    const afterBrace = extractRustImports('fn branch() { if c { } ::tokio::spawn(x); }\n');
    expect(afterBrace.packages).toContain('tokio');
    expect(afterBrace.packages).not.toContain('if');
  });

  it("marks serde reachable after a lifetime in impl<'de>", () => {
    const found = extractRustImports("impl<'de> ::serde::Deserialize<'de> for Foo {}\n");
    expect(found.packages).toContain('serde');
    expect(found.packages).not.toContain('de');
  });

  it('marks bincode reachable after a generic closer', () => {
    const found = extractRustImports('impl<T> ::bincode::Encode for W<T> {}\n');
    expect(found.packages).toContain('bincode');
    expect(found.packages).not.toContain('impl');
  });

  it('marks tracing reachable after a match arm =>', () => {
    const found = extractRustImports('match x { 1 => ::tracing::info!("ok") }\n');
    expect(found.packages).toContain('tracing');
  });

  it('marks serde_json reachable after a lifetime and does not record the lifetime', () => {
    const found = extractRustImports("let v: &'a ::serde_json::Value = x;\n");
    expect(found.packages).toContain('serde_json');
    expect(found.packages).not.toContain('a');
  });

  it("marks tower reachable after for<'a>", () => {
    const found = extractRustImports("fn bound<S: for<'a> ::tower::Service>() {}\n");
    expect(found.packages).toContain('tower');
    expect(found.packages).not.toContain('a');
    expect(found.packages).not.toContain('for');
  });

  it('keeps as-trait bounds, turbofish, and Vec<::crate> paths', () => {
    const found = extractRustImports(`
      fn keep() {
          let _ = <T as serde::Deserialize>::deserialize(x);
          let _ = Vec::<u8>::new();
          let _ = Vec<::serde_json::Value>::new();
      }
    `);
    expect(found.packages).toContain('serde');
    expect(found.packages).toContain('serde_json');
    expect(found.packages).not.toContain('as');
  });
});
