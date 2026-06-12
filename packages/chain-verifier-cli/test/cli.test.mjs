// val-verify subprocess smoke — file mode against a synthetic chain built with the
// same preimage construction the verifier library specifies (§4.3).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { reconstructChainHash } from '@val-protocol/chain-verifier';

const SCOPE = 's-cli-smoke';
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;

function mkRow(seq, prev, eventType, details) {
  const canonical_details = JSON.stringify(details);
  const chain_hash = reconstructChainHash({
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

const a = mkRow(1, null, 'genesis', { v: 1 });
const b = mkRow(2, a.chain_hash, 'event.two', { v: 1, n: 2 });

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
