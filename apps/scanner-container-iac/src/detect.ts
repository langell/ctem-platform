import { posixDir, type RepoFile } from './walk';

export type IacKind = 'terraform' | 'cloudformation' | 'kubernetes' | 'helm' | 'dockerfile';

export function isDockerfileName(fileName: string): boolean {
  return (
    fileName === 'Dockerfile' ||
    fileName.startsWith('Dockerfile.') ||
    fileName.toLowerCase().endsWith('.dockerfile')
  );
}

export function isTerraformName(fileName: string): boolean {
  return fileName.endsWith('.tf') || fileName.endsWith('.tf.json');
}

export function isChartYaml(fileName: string): boolean {
  return fileName === 'Chart.yaml' || fileName === 'Chart.yml';
}

export function isYamlOrJsonName(fileName: string): boolean {
  return /\.(ya?ml|json)$/i.test(fileName);
}

export function helmChartRoots(files: RepoFile[]): string[] {
  return files.filter((file) => isChartYaml(file.fileName)).map((file) => posixDir(file.relPath));
}

export function isHelmTemplatePath(relPath: string, chartRoots: string[]): boolean {
  return chartRoots.some((root) => {
    const prefix = root ? `${root}/templates/` : 'templates/';
    return relPath.startsWith(prefix) && isYamlOrJsonName(relPath.slice(relPath.lastIndexOf('/') + 1));
  });
}

/**
 * Filename/path detection that does not require a successful parse. `*.tf`,
 * Dockerfiles, Chart.yaml, and Helm templates are IaC even when unreadable.
 * Other YAML/JSON is classified after a parse (or a raw-text sniff on failure).
 */
export function kindFromName(file: RepoFile, chartRoots: string[]): IacKind | null {
  if (isTerraformName(file.fileName)) return 'terraform';
  if (isDockerfileName(file.fileName)) return 'dockerfile';
  if (isChartYaml(file.fileName)) return 'helm';
  if (isHelmTemplatePath(file.relPath, chartRoots)) return 'helm';
  return null;
}

/** Last-resort sniff when YAML/JSON parse fails — do not fetch, just look at bytes. */
export function sniffYamlKind(content: string): IacKind | null {
  if (/AWSTemplateFormatVersion\s*:/i.test(content) || /["']AWS::[A-Za-z0-9]+::[A-Za-z0-9]+["']/.test(content)) {
    return 'cloudformation';
  }
  if (/\bapiVersion\s*:/.test(content) && /\bkind\s*:/.test(content)) {
    return 'kubernetes';
  }
  return null;
}

export function classifyParsedDoc(doc: unknown): IacKind | null {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const rec = doc as Record<string, unknown>;
  if (typeof rec.AWSTemplateFormatVersion === 'string' || isCloudFormationResources(rec.Resources)) {
    return 'cloudformation';
  }
  if (typeof rec.apiVersion === 'string' && typeof rec.kind === 'string') {
    return rec.kind === 'Chart' ? 'helm' : 'kubernetes';
  }
  // Helm Chart.yaml: apiVersion + name, no k8s kind.
  if (typeof rec.apiVersion === 'string' && typeof rec.name === 'string' && rec.kind === undefined) {
    return 'helm';
  }
  return null;
}

function isCloudFormationResources(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.values(value as Record<string, unknown>).some((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
    const type = (entry as Record<string, unknown>).Type;
    return typeof type === 'string' && type.startsWith('AWS::');
  });
}
