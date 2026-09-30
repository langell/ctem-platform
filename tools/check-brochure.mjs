// Confirms the six brochure pages exist and that internal links stay on
// this static site. Not a product-feature test.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(process.argv[2] ?? path.join(here, '../site'));

const expected = [
  'index.html',
  'sdk/index.html',
  'contact/index.html',
  'support/index.html',
  'privacy/index.html',
  'terms/index.html',
];

const failures = [];
let links = 0;

function posix(file) {
  return file.split(path.sep).join('/');
}

function htmlFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...htmlFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.html')) {
      found.push(posix(path.relative(root, full)));
    }
  }
  return found.sort();
}

function inside(target) {
  const rel = path.relative(root, target);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function resolveFile(fromFile, hrefPath) {
  const target = hrefPath.startsWith('/')
    ? path.resolve(root, hrefPath.replace(/^\/+/, ''))
    : path.resolve(path.dirname(fromFile), hrefPath);
  if (!inside(target)) return { error: `escapes the brochure (${hrefPath})` };
  if (existsSync(target) && statSync(target).isDirectory()) {
    const index = path.join(target, 'index.html');
    if (existsSync(index)) return { file: index };
    return { error: `directory has no index.html (${hrefPath})` };
  }
  if (existsSync(target) && statSync(target).isFile()) return { file: target };
  const index = path.join(target, 'index.html');
  if (existsSync(index)) return { file: index };
  return { error: `unresolved (${hrefPath})` };
}

function pageHasId(file, id) {
  return readFileSync(file, 'utf8').includes(`id="${id}"`);
}

if (!existsSync(root)) {
  console.error(`missing brochure directory ${root}`);
  process.exit(1);
}

const found = htmlFiles(root);
const want = expected.slice().sort();
if (found.join('\n') !== want.join('\n')) {
  failures.push(`expected pages:\n${want.join('\n')}\nfound:\n${found.join('\n') || '(none)'}`);
}

for (const rel of want) {
  const file = path.join(root, rel);
  if (!existsSync(file)) continue;
  const html = readFileSync(file, 'utf8');
  if (!html.includes('href="mailto:lonny.angell@gmail.com"')) {
    failures.push(`${rel}: missing mailto:lonny.angell@gmail.com`);
  }
  if (html.includes('libs/scanner-sdk')) {
    failures.push(`${rel}: documents libs/scanner-sdk`);
  }
  const hrefs = [...html.matchAll(/\b(?:href|src)="([^"]*)"/g)].map((match) => match[1]);
  for (const href of hrefs) {
    links += 1;
    if (href.startsWith('mailto:')) {
      if (href !== 'mailto:lonny.angell@gmail.com') {
        failures.push(`${rel}: unexpected mailto ${href}`);
      }
      continue;
    }
    if (href.startsWith('https://') || href.startsWith('http://')) continue;
    if (href.startsWith('//') || href.startsWith('javascript:')) {
      failures.push(`${rel}: link leaves the site (${href})`);
      continue;
    }
    const hashAt = href.indexOf('#');
    const beforeHash = hashAt === -1 ? href : href.slice(0, hashAt);
    const hash = hashAt === -1 ? '' : href.slice(hashAt + 1);
    const pathOnly = beforeHash.split('?')[0];
    let dest = file;
    if (pathOnly !== '') {
      const resolved = resolveFile(file, pathOnly);
      if (resolved.error) {
        failures.push(`${rel}: ${resolved.error}`);
        continue;
      }
      dest = resolved.file;
    }
    if (hash && !pageHasId(dest, hash)) {
      failures.push(`${rel}: missing #${hash}`);
    }
  }
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`ok: ${want.length} pages, ${links} links under ${root}`);
