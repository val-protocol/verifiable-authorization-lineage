// Pass 6 — bytes-binding (ADR 0061). A MUTATION's hiding `bytes_commitment` is
// re-derived ONLY at evidence time from a disclosed { bytes, nonce }. The verifier
// hashes the bytes itself; absence never fails the verdict.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { verifyValChain, reconstructChainHash } from '../dist/esm/index.js';

const SCOPE = 's-bytes';

// Producer-side commitment (must match recomputeBytesCommitment in src):
//   value = SHA-256( "val.bytes-commitment.v1" ‖ 0x00 ‖ nonce(32B) ‖ sha256(bytes)(32B) )
function commit(bytes, nonce) {
  const inner = createHash('sha256').update(bytes).digest();
  const tag = Buffer.from('val.bytes-commitment.v1', 'utf8');
  const pre = Buffer.concat([tag, Buffer.from([0x00]), nonce, inner]);
  return createHash('sha256').update(pre).digest('hex');
}

async function mkRow(seq, prev, eventType, body) {
  const canonical_details = JSON.stringify(body);
  const chain_hash = await reconstructChainHash({
    scopeKey: SCOPE, sequenceNumber: seq, eventType, canonicalDetails: canonical_details, previousHash: prev,
  });
  return { scope_key: SCOPE, sequence_number: seq, event_type: eventType, canonical_details, previous_hash: prev, chain_hash };
}

const ASSIGNMENT = { v: 1, block_type: 'ASSIGNMENT', scope: { act: ['read', 'write'], res: {} }, human_attestation: { method: 'session' } };

// ASSIGNMENT → MUTATION(resource_id='r2') carrying bytes_commitment (or not).
async function chain({ withCommitment }) {
  const a = await mkRow(1, null, 'assign', ASSIGNMENT);
  const body = {
    v: 1, block_type: 'MUTATION', parent_assignment_hash: a.chain_hash, action: 'write',
    principal: 'P', resource: { content_hash: 'outhash', resource_id: 'r2', in_workspace: 'w' },
  };
  if (withCommitment) body.bytes_commitment = { alg: 'sha256-nonce.v1', value: COMMIT };
  const mut = await mkRow(2, a.chain_hash, 'mutate', body);
  return [a, mut];
}

const BYTES = Buffer.from('hello VAL bytes-binding — the document a court holds');
const NONCE = randomBytes(32);
const COMMIT = commit(BYTES, NONCE);
const disc = (bytes, nonce) => [{ resourceId: 'r2', documentBytesBase64: bytes.toString('base64'), nonceHex: nonce.toString('hex') }];

test('correct bytes + nonce => bytesBinding bound; other passes stay green', async () => {
  const r = await verifyValChain(await chain({ withCommitment: true }), { bytesDisclosures: disc(BYTES, NONCE) });
  assert.equal(r.integrity, 'green');
  assert.equal(r.lineage, 'green');
  assert.equal(r.bytesBinding, 'bound', r.firstBytesBindingViolation?.reason);
  assert.equal(r.firstBytesBindingViolation, null);
});

test('wrong bytes => bytesBinding mismatch (binding fails, integrity untouched)', async () => {
  const r = await verifyValChain(await chain({ withCommitment: true }), { bytesDisclosures: disc(Buffer.from('a different file'), NONCE) });
  assert.equal(r.integrity, 'green');
  assert.equal(r.bytesBinding, 'mismatch');
  assert.ok(r.firstBytesBindingViolation);
});

test('wrong nonce => bytesBinding mismatch (commitment is hiding)', async () => {
  const r = await verifyValChain(await chain({ withCommitment: true }), { bytesDisclosures: disc(BYTES, randomBytes(32)) });
  assert.equal(r.bytesBinding, 'mismatch');
});

test('commitment present but NO disclosure => not_evaluated (never fails)', async () => {
  const r = await verifyValChain(await chain({ withCommitment: true }));
  assert.equal(r.bytesBinding, 'not_evaluated');
  assert.equal(r.integrity, 'green');
});

test('no commitment on block + a disclosure => not_evaluated (additive, ignored)', async () => {
  const r = await verifyValChain(await chain({ withCommitment: false }), { bytesDisclosures: disc(BYTES, NONCE) });
  assert.equal(r.bytesBinding, 'not_evaluated');
});
