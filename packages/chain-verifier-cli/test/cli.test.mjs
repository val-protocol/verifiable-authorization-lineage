// val-verify subprocess smoke — file mode against a synthetic chain built with the
// same preimage construction the verifier library specifies (§4.3).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { reconstructChainHash } from '@val-protocol/chain-verifier';

const SCOPE = 's-cli-smoke';
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;

async function mkRow(seq, prev, eventType, details) {
  const canonical_details = JSON.stringify(details);
  const chain_hash = await reconstructChainHash({
    scopeKey: SCOPE,
    sequenceNumber: seq,
    eventType,
    canonicalDetails: canonical_details,
    previousHash: prev,
  });
  return { scope_key: SCOPE, sequence_number: seq, event_type: eventType, canonical_details, previous_hash: prev, chain_hash };
}

function chainFile(rows) {
  const dir = mkdtempSync(join(tmpdir(), 'val-verify-'));
  const p = join(dir, 'chain.ndjson');
  writeFileSync(p, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return p;
}

const a = await mkRow(1, null, 'genesis', { v: 1 });
const b = await mkRow(2, a.chain_hash, 'event.two', { v: 1, n: 2 });

test('clean chain => exit 0, all PASS', () => {
  const out = execFileSync(process.execPath, [CLI, `--export=${chainFile([a, b])}`], { encoding: 'utf8' });
  assert.match(out, /2\/2 PASS, 0 FAIL/);
});

test('tampered chain_hash => exit 1 with mismatch diagnostics', () => {
  const bad = { ...b, chain_hash: 'f'.repeat(64) };
  try {
    execFileSync(process.execPath, [CLI, `--export=${chainFile([a, bad])}`], { encoding: 'utf8' });
    assert.fail('expected exit 1');
  } catch (e) {
    assert.equal(e.status, 1);
    assert.match(e.stdout, /chain_hash mismatch/);
  }
});

test('missing args => exit 2 with usage', () => {
  try {
    execFileSync(process.execPath, [CLI], { encoding: 'utf8' });
    assert.fail('expected exit 2');
  } catch (e) {
    assert.equal(e.status, 2);
    assert.match(e.stdout, /val-verify/);
  }
});

// ── 0.5.0 --html: self-verifying report smoke. A human-rooted chain with one in-scope
// action → exit 0, §7.3 summary printed, single-file HTML written embedding the chain
// bytes, the verifier source, and the in-browser driver. ──
test('--html => full VAL summary + self-verifying report file', async () => {
  const root = await mkRow(1, null, 'assign', {
    v: 1,
    block_type: 'ASSIGNMENT',
    scope: { act: ['read'], res: { in_workspace: 'w' } },
    human_attestation: { method: 'session', subject_user_hash: 'sha256:t' },
  });
  const act = await mkRow(2, root.chain_hash, 'read', {
    v: 1,
    block_type: 'ACCESS',
    parent_assignment_hash: root.chain_hash,
    action: 'read',
    principal: 'agent:t',
    resource: { resource_id: 'doc-1', in_workspace: 'w' },
  });
  const dir = mkdtempSync(join(tmpdir(), 'val-verify-html-'));
  const htmlPath = join(dir, 'report.html');
  const out = execFileSync(
    process.execPath,
    [CLI, `--export=${chainFile([root, act])}`, `--html=${htmlPath}`],
    { encoding: 'utf8' },
  );
  assert.match(out, /2\/2 PASS, 0 FAIL/);
  assert.match(out, /VAL verification/);
  assert.match(out, /integrity\s+green/);
  assert.match(out, /lineage\s+green/);
  assert.match(out, /profile \(floor\)\s+A/);
  const html = readFileSync(htmlPath, 'utf8');
  assert.match(html, /<!doctype html>/);
  assert.match(html, /id="val-payload"/); // embedded chain + verifier payload
  assert.match(html, /data:text\/javascript;base64,/); // in-browser verifier import
  assert.match(html, /Download embedded chain/);
  // the embedded NDJSON round-trips to the exact chain bytes
  const payload = JSON.parse(html.match(/<script type="application\/json" id="val-payload">(.*?)<\/script>/s)[1]);
  const ndjson = Buffer.from(payload.ndjsonB64, 'base64').toString('utf8');
  assert.match(ndjson, new RegExp(root.chain_hash));
  assert.match(ndjson, new RegExp(act.chain_hash));
});

test('--html on a red chain => exit 1, failure surfaced in summary', async () => {
  const orphan = await mkRow(1, null, 'read', {
    v: 1,
    block_type: 'ACCESS',
    parent_assignment_hash: 'a'.repeat(64),
    action: 'read',
    principal: 'agent:t',
    resource: { resource_id: 'doc-1' },
  });
  const dir = mkdtempSync(join(tmpdir(), 'val-verify-html-red-'));
  try {
    execFileSync(process.execPath, [CLI, `--export=${chainFile([orphan])}`, `--html=${join(dir, 'r.html')}`], {
      encoding: 'utf8',
    });
    assert.fail('expected exit 1');
  } catch (e) {
    assert.equal(e.status, 1);
    assert.match(e.stdout, /lineage\s+red/);
  }
});
