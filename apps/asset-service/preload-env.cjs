/**
 * Fill unset environment variables from the workspace `.env` before the
 * service module graph calls `loadEnv()`.
 *
 * Nx can unload `.env` keys from a `dev` task when they match the file and
 * `NX_LOAD_DOT_ENV_FILES` is not set on that process. The UI smoke job points
 * `GITHUB_API_URL` at the local stub by editing `.env`; this preload is what
 * makes that file reach asset-service. Already-set variables win, so a
 * production process that exports `GITHUB_API_URL` is unchanged. This file is
 * only on the `dev` script, not the production `start` command.
 */
const { existsSync, readFileSync } = require('node:fs');
const { dirname, join } = require('node:path');

function findWorkspaceEnv(start) {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, '.env')) && existsSync(join(dir, 'nx.json'))) {
      return join(dir, '.env');
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

const file = findWorkspaceEnv(process.cwd());
if (file) {
  for (const raw of readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (process.env[key]) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!value) continue;
    process.env[key] = value;
  }
}
