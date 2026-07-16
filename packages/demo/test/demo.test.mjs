// val-demo subprocess smoke — the demo asserts its own expectations internally
// (every act's verdict), so exit 0 IS the assertion. We additionally check the
// artifacts (--out NDJSON verifies; --html report embeds the payload).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyValChain } from '@val-protocol/chain-verifier';

const BIN = new URL('../dist/demo.js', import.meta.url).pathname;

test('val-demo runs all acts, exit 0, every internal expectation holds', () => {
  const out = execFileSync(process.execPath, [BIN], { encoding: 'utf8' });
  assert.match(out, /Act 0 —/);
  assert.match(out, /Act 4 —/);
  assert.match(out, /All acts behaved exactly as the protocol specifies\./);
  assert.doesNotMatch(out, /EXPECTATION FAILED/);
});

test('val-demo --out chain verifies independently; --html report embeds chain + verifier', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'val-demo-'));
  const ndjsonPath = join(dir, 'chain.ndjson');
  const htmlPath = join(dir, 'report.html');
  execFileSync(process.execPath, [BIN, `--out=${ndjsonPath}`, `--html=${htmlPath}`], { encoding: 'utf8' });

  const rows = readFileSync(ndjsonPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const r = await verifyValChain(rows, {
    delegatorAuthorityPolicy: { org_verified_representative: ['read', 'record.append', 'sign'] },
  });
  assert.equal(r.integrity, 'green');
  assert.equal(r.lineage, 'green');
  assert.equal(r.scope, 'green');
  assert.equal(r.grounding, 'green');
  assert.equal(r.signature, 'green');
  assert.equal(r.conformanceProfile, 'B');

  const html = readFileSync(htmlPath, 'utf8');
  assert.match(html, /id="val-payload"/);
  assert.match(html, /data:text\/javascript;base64,/);
});
