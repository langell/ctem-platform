/**
 * Local GitHub REST stand-in for QA and Playwright.
 *
 *   pnpm nx run @ctem/github-stub:serve
 *   docker compose --profile e2e up -d github-stub
 *
 * Point a non-production CTEM_GITHUB_API_URL at http://127.0.0.1:4019.
 * Does not log Authorization headers or token values.
 */
import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 4019);

const repos = [
  {
    name: 'payments-api',
    full_name: 'acme/payments-api',
    private: true,
    archived: false,
    fork: false,
    html_url: 'https://github.com/acme/payments-api',
    default_branch: 'main',
    language: 'TypeScript',
    owner: { login: 'acme' },
  },
  {
    name: 'web',
    full_name: 'acme/web',
    private: false,
    archived: false,
    fork: false,
    html_url: 'https://github.com/acme/web',
    default_branch: 'main',
    language: 'TypeScript',
    owner: { login: 'acme' },
  },
];

// E2E smoke inventories this public repo with no token (GET /users/langell/repos).
const scanTarget = {
  name: 'ctem-scan-target',
  full_name: 'langell/ctem-scan-target',
  private: false,
  archived: false,
  fork: false,
  html_url: 'https://github.com/langell/ctem-scan-target',
  default_branch: 'main',
  language: 'JavaScript',
  owner: { login: 'langell' },
};

const seen = [];

function send(req, res, status, body) {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
  const method = req.method ?? 'GET';
  seen.push({ method, path: url.pathname, status });
  if (seen.length > 500) seen.shift();
  process.stdout.write(`${method} ${url.pathname} ${status}\n`);
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function authed(req) {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length).trim();
  return token.length > 0 && !token.startsWith('invalid');
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
  if (req.method === 'GET' && url.pathname === '/health') {
    send(req, res, 200, { ok: true });
    return;
  }
  if (req.method === 'GET' && url.pathname === '/__requests') {
    send(req, res, 200, { requests: seen.slice() });
    return;
  }
  if (req.method !== 'GET') {
    send(req, res, 404, { message: 'Not Found' });
    return;
  }
  if (url.pathname === '/user') {
    if (!authed(req)) {
      send(req, res, 401, { message: 'Bad credentials' });
      return;
    }
    send(req, res, 200, { login: 'acme' });
    return;
  }
  const org = url.pathname.match(/^\/orgs\/([^/]+)$/);
  if (org) {
    if (!authed(req)) {
      send(req, res, 401, { message: 'Bad credentials' });
      return;
    }
    if (decodeURIComponent(org[1]) !== 'acme') {
      send(req, res, 404, { message: 'Not Found' });
      return;
    }
    send(req, res, 200, { login: 'acme' });
    return;
  }
  if (
    url.pathname === '/orgs/acme/repos' ||
    url.pathname === '/user/repos' ||
    url.pathname === '/users/acme/repos'
  ) {
    if (url.pathname !== '/users/acme/repos' && !authed(req)) {
      send(req, res, 401, { message: 'Bad credentials' });
      return;
    }
    send(req, res, 200, repos);
    return;
  }
  if (url.pathname === '/users/langell/repos') {
    send(req, res, 200, [scanTarget]);
    return;
  }
  send(req, res, 404, { message: 'Not Found' });
});

server.listen(port, '0.0.0.0', () => {
  process.stdout.write(`github stub listening on ${port}\n`);
});
