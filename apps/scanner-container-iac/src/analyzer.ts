import { readdir, readFile, stat } from 'node:fs/promises';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import { classifyParsedDoc, helmChartRoots, kindFromName, sniffYamlKind, type IacKind } from './detect';
import {
  evaluableFromCfn,
  evaluableFromDockerfile,
  evaluableFromHcl,
  evaluableFromK8s,
  evaluateResource,
  type EvaluableResource,
  type IacMatch,
} from './evaluate';
import { MisconfigRules } from './misconfig.rules';
import { parseDockerfile } from './parse/dockerfile';
import { parseYamlDocumentsOrThrow, parseYamlOrJsonDocuments, stripHelmMustaches, YamlParseError } from './parse/docs';
import { parseHclResources, parseTfJsonResources, HclParseError } from './parse/hcl';
import { listRepoFiles, MAX_WALK_FILES, type RepoFile } from './walk';

const log = rootLogger.child({ component: 'iac-analyzer' });

export const MAX_IAC_BYTES = 1 * 1024 * 1024;

export class IacAnalysisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IacAnalysisError';
  }
}

export interface IacAnalysis {
  matches: IacMatch[];
  files: string[];
  truncated: boolean;
  detected: number;
  parsed: number;
}

export interface IacAnalyzerPort {
  analyze(workDir: string, checkDeadline?: () => boolean): Promise<IacAnalysis>;
}

/**
 * Walks a checked-out workDir, parses IaC files in-process, and evaluates the
 * built-in MisconfigRules pack. Crash, timeout, empty workDir, or any
 * detected IaC file that fails to parse must throw — never a partial success
 * that findings-service could auto-resolve from. A repo with no IaC files is
 * a legitimate empty success after the walk.
 */
@Injectable()
export class IacAnalyzer implements IacAnalyzerPort {
  constructor(private readonly rules: MisconfigRules) {}

  async analyze(workDir: string, checkDeadline: () => boolean = () => true): Promise<IacAnalysis> {
    await assertAnalyzableWorkDir(workDir);
    if (!checkDeadline()) {
      throw new IacAnalysisError('Job deadline exceeded during IaC analysis');
    }

    const files = await listRepoFiles(workDir);
    const chartRoots = helmChartRoots(files);
    const truncated = files.length >= MAX_WALK_FILES;
    const matches: IacMatch[] = [];
    const parsedFiles: string[] = [];
    const parseFailures: string[] = [];
    let detected = 0;
    let parsed = 0;

    for (const file of files) {
      if (!checkDeadline()) {
        throw new IacAnalysisError('Job deadline exceeded during IaC analysis');
      }
      const namedKind = kindFromName(file, chartRoots);
      const candidate = namedKind !== null || looksLikeYamlJson(file.fileName);
      if (!candidate) continue;

      let content: string;
      try {
        const size = (await stat(file.absPath)).size;
        if (size > MAX_IAC_BYTES) {
          if (namedKind) {
            throw new IacAnalysisError(
              `IaC analyzer failed to parse '${file.relPath}' (${size} bytes over cap) — refusing incomplete success`,
            );
          }
          continue;
        }
        content = await readFile(file.absPath, 'utf8');
      } catch (err) {
        if (err instanceof IacAnalysisError) throw err;
        if (namedKind) {
          throw new IacAnalysisError(
            `IaC analyzer failed to parse '${file.relPath}': ${err instanceof Error ? err.message : String(err)} — refusing incomplete success`,
          );
        }
        continue;
      }

      const result = parseIacFile(file, content, namedKind);
      if (!result) continue;
      detected += 1;
      if (!result.ok) {
        log.warn({ file: file.relPath, error: result.error }, 'IaC parse failed');
        parseFailures.push(file.relPath);
        continue;
      }
      parsed += 1;
      parsedFiles.push(file.relPath);
      for (const resource of result.resources) {
        matches.push(...evaluateResource(resource, this.rules.forTarget(resource.kind)));
      }
    }

    if (parseFailures.length) {
      if (parsed === 0) {
        throw new IacAnalysisError(
          `IaC analyzer parsed none of ${detected} detected IaC files (${parseFailures.join(', ')}) — refusing empty success`,
        );
      }
      throw new IacAnalysisError(
        `IaC analyzer failed to parse ${parseFailures.map((p) => `'${p}'`).join(', ')} after ${parsed} parsed file(s) — refusing incomplete success`,
      );
    }

    return { matches, files: parsedFiles, truncated, detected, parsed };
  }
}

function looksLikeYamlJson(fileName: string): boolean {
  return /\.(ya?ml|json)$/i.test(fileName);
}

function parseIacFile(
  file: RepoFile,
  content: string,
  namedKind: IacKind | null,
): { ok: true; resources: EvaluableResource[] } | { ok: false; error: string } | null {
  try {
    if (namedKind === 'terraform') {
      const resources = file.fileName.endsWith('.tf.json')
        ? parseTfJsonResources(content)
        : parseHclResources(content);
      return { ok: true, resources: resources.map((r) => evaluableFromHcl(file.relPath, r, content)) };
    }
    if (namedKind === 'dockerfile') {
      return { ok: true, resources: [evaluableFromDockerfile(file.relPath, parseDockerfile(content), content)] };
    }
    if (namedKind === 'helm' && (file.fileName === 'Chart.yaml' || file.fileName === 'Chart.yml')) {
      parseYamlStrictOrThrow(content);
      return { ok: true, resources: [] };
    }
    if (namedKind === 'helm') {
      const stripped = stripHelmMustaches(content);
      const docs = parseYamlDocumentsOrThrow(stripped);
      return { ok: true, resources: docs.flatMap((doc) => k8sResources(file.relPath, 'helm', doc, content)) };
    }

    // YAML/JSON: only IaC if the document classifies as k8s or CloudFormation.
    const docs = tryParseDocs(file, content);
    if (docs === 'unparsed') {
      const sniffed = sniffYamlKind(content);
      if (!sniffed) return null;
      return { ok: false, error: 'YAML/JSON parse failed' };
    }
    const resources: EvaluableResource[] = [];
    let classified = false;
    for (const doc of docs) {
      const kind = classifyParsedDoc(doc);
      if (!kind) continue;
      classified = true;
      if (kind === 'cloudformation') {
        resources.push(...cfnResources(file.relPath, doc, content));
      } else if (kind === 'kubernetes' || kind === 'helm') {
        resources.push(...k8sResources(file.relPath, kind, doc, content));
      }
    }
    if (!classified) return null;
    return { ok: true, resources };
  } catch (err) {
    if (err instanceof HclParseError || err instanceof YamlParseError) {
      return { ok: false, error: err.message };
    }
    if (namedKind) return { ok: false, error: err instanceof Error ? err.message : String(err) };
    const sniffed = sniffYamlKind(content);
    if (!sniffed) return null;
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function tryParseDocs(file: RepoFile, content: string): unknown[] | 'unparsed' {
  try {
    if (file.fileName.endsWith('.json')) {
      return parseYamlOrJsonDocuments(content, file.fileName);
    }
    return parseYamlDocumentsOrThrow(content);
  } catch {
    return 'unparsed';
  }
}

function parseYamlStrictOrThrow(content: string): void {
  parseYamlDocumentsOrThrow(content);
}

function cfnResources(path: string, doc: unknown, source: string) {
  if (!doc || typeof doc !== 'object') return [];
  const resources = (doc as Record<string, unknown>).Resources;
  if (!resources || typeof resources !== 'object' || Array.isArray(resources)) return [];
  const out = [];
  for (const [logicalId, body] of Object.entries(resources as Record<string, unknown>)) {
    if (!body || typeof body !== 'object') continue;
    const rec = body as Record<string, unknown>;
    const type = String(rec.Type ?? '');
    const properties =
      rec.Properties && typeof rec.Properties === 'object' && !Array.isArray(rec.Properties)
        ? (rec.Properties as Record<string, unknown>)
        : {};
    const startLine = lineOf(source, logicalId) ?? 1;
    out.push(evaluableFromCfn(path, logicalId, type, properties, startLine, source));
  }
  return out;
}

function k8sResources(path: string, kind: IacKind, doc: unknown, source: string) {
  if (!doc || typeof doc !== 'object') return [];
  const rec = doc as Record<string, unknown>;
  const resourceKind = String(rec.kind ?? 'Unknown');
  const metadata = rec.metadata && typeof rec.metadata === 'object' ? (rec.metadata as Record<string, unknown>) : {};
  const name = String(metadata.name ?? '');
  const startLine = lineOf(source, `kind:${resourceKind}`) ?? lineOf(source, resourceKind) ?? 1;
  return [evaluableFromK8s(path, kind, resourceKind, name, rec, startLine, source)];
}

function lineOf(source: string, token: string): number | null {
  const lines = source.split('\n');
  const idx = lines.findIndex((line) => line.includes(token));
  return idx === -1 ? null : idx + 1;
}

async function assertAnalyzableWorkDir(workDir: string): Promise<void> {
  try {
    const info = await stat(workDir);
    if (!info.isDirectory()) {
      throw new IacAnalysisError(`IaC workDir is not a directory: ${workDir}`);
    }
    const entries = await readdir(workDir);
    if (entries.length === 0) {
      throw new IacAnalysisError('IaC workDir is empty — refusing success without a checkout');
    }
  } catch (err) {
    if (err instanceof IacAnalysisError) throw err;
    throw new IacAnalysisError(
      `IaC analyzer could not read workDir ${workDir}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
