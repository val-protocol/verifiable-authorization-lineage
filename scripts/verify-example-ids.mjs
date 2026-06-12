#!/usr/bin/env node
// verify-example-ids.mjs — publish-surface leak gate.
//
// Every real-shape UUID in this repository must be registered in
// example-uuid-registry.json (repo root). The repo is entirely public and its
// packages publish to npm, so ANY unregistered UUID is treated as a potential
// leaked operator-substrate identifier and fails the build. Registration
// discipline lives in the registry's __doc header.
//
// Scans git-visible files (tracked + new unignored), so a fresh example file is
// caught before it is ever committed. Zero dependencies; wired into CI and into
// every package's prepublishOnly.
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const registry = JSON.parse(readFileSync(join(ROOT, 'example-uuid-registry.json'), 'utf8'));
const allowed = new Set(Object.keys(registry.ids).map((k) => k.toLowerCase()));
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
const PLACEHOLDER_RE = /^(00000000-0000|deadbeef-|cafecafe-)/;
const SKIP = /(package-lock\.json|\.map|\.png|\.jpg|\.ico|\.svg|\.woff2?)$/;

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
  cwd: ROOT,
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
})
  .split('\n')
  .filter((f) => f.length > 0 && !SKIP.test(f));

const violations = [];
let scanned = 0;
for (const rel of files) {
  const abs = join(ROOT, rel);
  if (!existsSync(abs)) continue;
  scanned += 1;
  const content = readFileSync(abs, 'utf8').toLowerCase();
  for (const m of content.matchAll(UUID_RE)) {
    const id = m[0];
    if (allowed.has(id) || PLACEHOLDER_RE.test(id)) continue;
    const line = content.slice(0, m.index).split('\n').length;
    violations.push(`${rel}:${line} — ${id} not in example-uuid-registry.json`);
  }
}

if (violations.length > 0) {
  console.error(`FAIL verify-example-ids — ${violations.length} unregistered real-shape UUID(s):`);
  for (const v of [...new Set(violations)].slice(0, 20)) console.error('  ' + v);
  console.error('Replace a leaked identifier (mint random, register) or register a legitimate new example.');
  process.exit(1);
}
console.log(`verify-example-ids: OK — every real-shape UUID across ${scanned} git-visible files is registry-listed (${allowed.size} registered)`);
