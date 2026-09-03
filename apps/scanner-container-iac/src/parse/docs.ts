import { parseAllDocuments } from 'yaml';

export class YamlParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'YamlParseError';
  }
}

/** Strip Helm `{{ ... }}` so templates can be YAML-parsed without helm CLI. */
export function stripHelmMustaches(content: string): string {
  return content.replace(/\{\{[\s\S]*?\}\}/g, ' ');
}

export function parseYamlOrJsonDocuments(content: string, fileName: string): unknown[] {
  const trimmed = content.trim();
  if (!trimmed) return [];
  if (fileName.toLowerCase().endsWith('.json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const doc = JSON.parse(trimmed) as unknown;
      return Array.isArray(doc) ? doc : [doc];
    } catch (err) {
      throw new YamlParseError(`Invalid JSON: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  try {
    return parseAllDocuments(content)
      .filter((doc) => !doc.errors.length)
      .map((doc) => doc.toJSON() as unknown)
      .filter((doc) => doc !== null && doc !== undefined);
  } catch (err) {
    throw new YamlParseError(`Invalid YAML: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * YAML parse that fails closed on *any* document error. Multi-doc files with a
 * single broken document are unparsed — leftover truncated is not inventory.
 */
export function parseYamlDocumentsOrThrow(content: string): unknown[] {
  const docs = parseAllDocuments(content);
  const errors = docs.flatMap((d) => d.errors);
  if (errors.length) {
    throw new YamlParseError(errors.map((e) => e.message).join('; '));
  }
  return docs.map((d) => d.toJSON() as unknown).filter((doc) => doc !== null && doc !== undefined);
}
