import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const gradleParser: EcosystemParser = {
  id: 'gradle',
  ecosystem: ECOSYSTEM.maven,
  group: 'java',
  priority: 20,
  matches: (fileName) => fileName === 'gradle.lockfile',
  parse: (input) => parseGradleLockfile(input.content, input.relPath),
};

export const pomParser: EcosystemParser = {
  id: 'maven-pom',
  ecosystem: ECOSYSTEM.maven,
  group: 'java',
  priority: 10,
  matches: (fileName) => fileName === 'pom.xml',
  parse: (input) => parsePomXml(input.content, input.relPath),
};

/**
 * Gradle lockfiles are a flat `group:artifact:version=configurations` list.
 * Limitation: no graph, so every coordinate is `direct: false` with an empty
 * dependencyPath — we cannot tell which were declared vs pulled in.
 */
export function parseGradleLockfile(content: string, manifestPath: string) {
  const seen = new Map<string, string>();
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('empty=')) continue;
    const coord = line.split('=')[0];
    const parts = coord.split(':');
    if (parts.length < 3) continue;
    const [group, artifact, version] = parts;
    if (!group || !artifact || !version) continue;
    const name = `${group}:${artifact}`;
    if (!seen.has(name)) seen.set(name, version);
  }

  return [...seen.entries()].map(([name, version]) =>
    makeComponent({
      name,
      version,
      ecosystem: ECOSYSTEM.maven,
      purl: purlFor(ECOSYSTEM.maven, name, version),
      direct: false,
      dependencyPath: [],
      manifestPath,
    }),
  );
}

/**
 * pom.xml is a manifest. We only emit dependencies whose version is a concrete
 * value after `${property}` substitution (including managed versions from
 * `dependencyManagement`). Ranges and unresolved properties are skipped.
 *
 * Limitation: only direct dependencies; Maven's transitive graph requires the
 * resolver, which we do not shell out to.
 */
export function parsePomXml(content: string, manifestPath: string) {
  const xml = stripXmlComments(content);
  const properties = parsePomProperties(xml);
  const managed = parseDependencies(extractTagInner(xml, 'dependencyManagement') ?? '', properties);
  const managedVersion = new Map(managed.map((d) => [d.name, d.version]));
  // Plugin classpath deps live under <build>/<reporting>/<pluginManagement>
  // and are not product coordinates.
  const deps = parseDependencies(productDependencyXml(xml), properties);

  const seen = new Map<string, string>();
  for (const dep of deps) {
    const version = dep.version || managedVersion.get(dep.name) || '';
    if (!isConcreteVersion(version)) continue;
    if (!seen.has(dep.name)) seen.set(dep.name, version);
  }

  return [...seen.entries()].map(([name, version]) =>
    makeComponent({
      name,
      version,
      ecosystem: ECOSYSTEM.maven,
      purl: purlFor(ECOSYSTEM.maven, name, version),
      direct: true,
      dependencyPath: [name],
      manifestPath,
    }),
  );
}

function parsePomProperties(xml: string): Record<string, string> {
  const props: Record<string, string> = {};
  const parentInner = extractTagInner(xml, 'parent');
  const header = projectHeader(xml);
  // Direct project children only — the first <version> in a POM is often the
  // parent's and must not become ${project.version}.
  const version = extractTagInner(header, 'version');
  if (version) {
    props['project.version'] = version;
    props['pom.version'] = version;
  }
  const parentVersion = parentInner ? extractTagInner(parentInner, 'version') : null;
  if (parentVersion) props['project.parent.version'] = parentVersion;
  const groupId = extractTagInner(header, 'groupId') ?? (parentInner ? extractTagInner(parentInner, 'groupId') : null);
  const artifactId = extractTagInner(header, 'artifactId');
  if (groupId) props['project.groupId'] = groupId;
  if (artifactId) props['project.artifactId'] = artifactId;

  const propInner = extractTagInner(xml, 'properties') ?? '';
  for (const m of propInner.matchAll(/<([A-Za-z0-9_.-]+)>([^<]*)<\/\1>/g)) {
    props[m[1]] = m[2].trim();
  }
  return props;
}

/** Project (and profile) product deps — strip plugin-bearing sections first. */
function productDependencyXml(xml: string): string {
  let product = xml;
  for (const tag of ['dependencyManagement', 'build', 'reporting', 'pluginManagement']) {
    product = product.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?</${tag}>`, 'gi'), '');
  }
  return product;
}

function parseDependencies(
  xml: string,
  properties: Record<string, string>,
): Array<{ name: string; version: string }> {
  const out: Array<{ name: string; version: string }> = [];
  for (const block of xml.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi)) {
    const inner = block[1];
    const groupId = resolveProps(extractTagInner(inner, 'groupId') ?? '', properties);
    const artifactId = resolveProps(extractTagInner(inner, 'artifactId') ?? '', properties);
    const version = resolveProps(extractTagInner(inner, 'version') ?? '', properties);
    if (!groupId || !artifactId) continue;
    out.push({ name: `${groupId}:${artifactId}`, version });
  }
  return out;
}

/** Project-level coords: strip parent/deps/build so the first <version> is the child's. */
function projectHeader(xml: string): string {
  let header = xml;
  for (const tag of [
    'parent',
    'properties',
    'dependencyManagement',
    'dependencies',
    'build',
    'profiles',
    'reporting',
    'repositories',
    'pluginRepositories',
  ]) {
    header = header.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?</${tag}>`, 'gi'), '');
  }
  return header;
}

function extractTagInner(xml: string, tag: string): string | null {
  const m = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, 'i').exec(xml);
  return m ? m[1].trim() : null;
}

function resolveProps(value: string, properties: Record<string, string>): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, key: string) => properties[key] ?? `\${${key}}`);
}

function isConcreteVersion(version: string): boolean {
  if (!version || version.includes('${')) return false;
  if (/[[(,*\]]/.test(version)) return false;
  return true;
}

function stripXmlComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?-->/g, '');
}
