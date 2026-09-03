export interface DockerfileResource {
  user: string | null;
  implicitRoot: boolean;
  startLine: number;
}

/**
 * Parse Dockerfile instructions in-process. Does not pull the image, talk to a
 * registry, or invoke the docker CLI. Only the final stage's USER matters.
 */
export function parseDockerfile(content: string): DockerfileResource {
  const lines = content.split('\n');
  let lastFromLine = 1;
  let lastUser: { value: string; line: number } | null = null;

  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = stripDockerfileComment(lines[i] ?? '').trim();
    if (!trimmed) continue;
    const from = /^FROM\s+(\S+)/i.exec(trimmed);
    if (from) {
      lastFromLine = i + 1;
      lastUser = null;
      continue;
    }
    const user = /^USER\s+(\S+)/i.exec(trimmed);
    if (user) {
      lastUser = { value: user[1] ?? '', line: i + 1 };
    }
  }

  return {
    user: lastUser?.value ?? null,
    implicitRoot: lastUser === null,
    startLine: lastUser?.line ?? lastFromLine,
  };
}

export function dockerfileRunsAsRoot(resource: DockerfileResource): boolean {
  if (resource.implicitRoot || resource.user === null) return true;
  const user = resource.user.split(':')[0]?.trim() ?? '';
  return user === '' || user === 'root' || user === '0';
}

function stripDockerfileComment(line: string): string {
  let inQuote: string | null = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inQuote) {
      if (ch === inQuote && line[i - 1] !== '\\') inQuote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inQuote = ch;
      continue;
    }
    if (ch === '#') return line.slice(0, i);
  }
  return line;
}
