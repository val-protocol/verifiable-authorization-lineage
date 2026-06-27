// Pass 4 — external anchor (§8). An ANCHOR block binds an RFC 3161 TimeStampToken to a
// `val.checkpoint-merkle.v1` root over an in-band block range. These tests use REAL tokens fetched
// from two independent TSAs (DigiCert + FreeTSA) over the fixture chain's root, so the CMS
// `signedAttributes` + `messageImprint` verification is exercised against production tokens — a
// single-TSA test would hide the signedAttrs gotcha (review §2.1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyValChain, reconstructChainHash, computeCheckpointMerkleRoot } from '../dist/esm/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(join(HERE, 'fixtures', 'anchor-fixtures.json'), 'utf8'));
const parity = JSON.parse(readFileSync(join(HERE, 'fixtures', 'tsa-merkle-parity-vectors.json'), 'utf8'));

// RFC 8785-ish canonical JSON (sorted keys) — mirrors the producer's ValBlockFactory.forAnchor.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

function anchorCanonical({ merkleRoot, fromSeq, toSeq, tst, timestampLocal }) {
  return canonical({
    v: 1,
    block_type: 'ANCHOR',
    merkle_root: merkleRoot,
    merkle_alg: 'val.checkpoint-merkle.v1',
    covered_range: { from_sequence: fromSeq, to_sequence: toSeq },
    tst,
    timestamp_local: timestampLocal,
  });
}

// Build the full chain: the fixture data rows + one ANCHOR row, with a valid §4.3 chain_hash.
async function buildChain({ merkleRoot, fromSeq, toSeq, tst }) {
  const rows = fx.chain.dataRows.map((r) => ({ ...r }));
  const anchorSeq = fx.chain.lastSeq + 1;
  const canonical_details = anchorCanonical({ merkleRoot, fromSeq, toSeq, tst, timestampLocal: 1700000000000 });
  const chain_hash = await reconstructChainHash({
    scopeKey: fx.chain.scopeKey,
    sequenceNumber: anchorSeq,
    eventType: 'dataroom.anchored',
    canonicalDetails: canonical_details,
    previousHash: fx.chain.lastChainHash,
  });
  rows.push({
    scope_key: fx.chain.scopeKey,
    sequence_number: anchorSeq,
    event_type: 'dataroom.anchored',
    canonical_details,
    previous_hash: fx.chain.lastChainHash,
    chain_hash,
  });
  return { rows, anchorSeq };
}

// ── Merkle parity vector — the verifier's port reproduces the frozen producer roots ──────────────
test('val.checkpoint-merkle.v1 — verifier port reproduces every frozen producer vector', async () => {
  assert.equal(parity.algorithm, 'val.checkpoint-merkle.v1');
  for (const v of parity.vectors) {
    const root = await computeCheckpointMerkleRoot(v.rows);
    assert.equal(root, v.expectedRoot, `n=${v.n}: verifier port != producer root`);
  }
});

// ── Real-TSA happy paths (≥2 independent TSAs) ───────────────────────────────────────────────────
for (const tsa of fx.tsas) {
  test(`Pass 4 — verified against real ${tsa.name} token`, async () => {
    const { rows, anchorSeq } = await buildChain({
      merkleRoot: fx.chain.merkleRoot,
      fromSeq: fx.chain.coveredFrom,
      toSeq: fx.chain.coveredTo,
      tst: tsa.tstBase64,
    });
    const res = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: tsa.spkis } });
    assert.equal(res.integrity, 'green', 'integrity must hold');
    assert.equal(res.anchorBinding, 'verified', `anchorBinding should be verified (first: ${JSON.stringify(res.firstAnchorViolation)})`);
    assert.equal(res.firstAnchorViolation, null);
    assert.equal(res.anchors.length, 1);
    assert.equal(res.anchors[0].sequenceNumber, String(anchorSeq));
    assert.deepEqual(res.anchors[0].covered_range, { from_sequence: fx.chain.coveredFrom, to_sequence: fx.chain.coveredTo });
    assert.match(res.anchors[0].genTime, /^\d{4}-\d{2}-\d{2}T/); // ISO genTime surfaced
  });
}

// ── not_evaluated: no trust anchor supplied (additive, never fails) ──────────────────────────────
test('Pass 4 — not_evaluated when no anchorTrust supplied', async () => {
  const { rows } = await buildChain({ merkleRoot: fx.chain.merkleRoot, fromSeq: fx.chain.coveredFrom, toSeq: fx.chain.coveredTo, tst: fx.tsas[0].tstBase64 });
  const res = await verifyValChain(rows); // no options
  assert.equal(res.integrity, 'green');
  assert.equal(res.anchorBinding, 'not_evaluated');
  assert.equal(res.anchors.length, 0);
});

// ── not_evaluated: chain has no ANCHOR block ─────────────────────────────────────────────────────
test('Pass 4 — not_evaluated when chain carries no ANCHOR block', async () => {
  const rows = fx.chain.dataRows.map((r) => ({ ...r }));
  const res = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: fx.tsas[0].spkis } });
  assert.equal(res.anchorBinding, 'not_evaluated');
});

// ── mismatch: wrong cert (token signed by a TSA, but a non-matching SPKI is pinned) ──────────────
test('Pass 4 — mismatch when the pinned trust anchor is the wrong certificate', async () => {
  const { rows } = await buildChain({ merkleRoot: fx.chain.merkleRoot, fromSeq: fx.chain.coveredFrom, toSeq: fx.chain.coveredTo, tst: fx.tsas[0].tstBase64 });
  const res = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: [fx.wrongSpki] } });
  assert.equal(res.anchorBinding, 'mismatch');
  assert.ok(res.firstAnchorViolation);
});

// ── mismatch: tampered covered range (root recompute no longer equals the timestamped root) ──────
test('Pass 4 — mismatch when covered_range is tampered', async () => {
  // ANCHOR claims the token's root but a shorter range — recompute over [1..coveredTo-1] differs.
  const { rows } = await buildChain({ merkleRoot: fx.chain.merkleRoot, fromSeq: fx.chain.coveredFrom, toSeq: fx.chain.coveredTo - 1, tst: fx.tsas[0].tstBase64 });
  const res = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: fx.tsas[0].spkis } });
  assert.equal(res.anchorBinding, 'mismatch');
  assert.match(res.firstAnchorViolation.reason, /recomputed checkpoint root/);
});

// ── mismatch: messageImprint binding (§2.2) — token is valid but timestamps a DIFFERENT digest ───
// Recompute passes (claimed root == real range root), so this isolates the messageImprint check:
// the token (a real DigiCert token over `otherDigest`) does NOT cover this chain's root.
test('Pass 4 — mismatch when the token messageImprint binds a different digest', async () => {
  const { rows } = await buildChain({
    merkleRoot: fx.chain.merkleRoot, // == recompute over [1..8], so the Merkle step passes
    fromSeq: fx.chain.coveredFrom,
    toSeq: fx.chain.coveredTo,
    tst: fx.tokenOverOtherDigest, // but the token timestamps otherDigest, not this root
  });
  const res = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: fx.tsas[0].spkis } });
  assert.equal(res.anchorBinding, 'mismatch');
  assert.match(res.firstAnchorViolation.reason, /messageImprint/);
});

// ── mismatch: corrupted token bytes (malformed / signature fails) ────────────────────────────────
test('Pass 4 — mismatch when the RFC 3161 token is corrupted', async () => {
  const good = fx.tsas[0].tstBase64;
  const raw = Buffer.from(good, 'base64');
  raw[raw.length - 10] ^= 0xff; // flip a byte inside the trailing signature value
  const badTst = raw.toString('base64');
  const { rows } = await buildChain({ merkleRoot: fx.chain.merkleRoot, fromSeq: fx.chain.coveredFrom, toSeq: fx.chain.coveredTo, tst: badTst });
  const res = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: fx.tsas[0].spkis } });
  assert.equal(res.anchorBinding, 'mismatch');
  assert.ok(res.firstAnchorViolation);
});
