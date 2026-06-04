// §7.5 grounding (read-before-derive) — domain-neutral, no Q&A vocabulary.
// A MUTATION citing grounded_document_hashes must cite content the same principal
// read via a prior ACCESS in the same chain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyValChain, reconstructChainHash } from '../dist/esm/index.js';

const SCOPE = 's-grounding';
const C = 'c0ffeecontenthash'; // a content hash the principal reads

function mkRow(seq, prev, eventType, body) {
  const canonical_details = JSON.stringify(body);
  const chain_hash = reconstructChainHash({
    scopeKey: SCOPE,
    sequenceNumber: seq,
    eventType,
    canonicalDetails: canonical_details,
    previousHash: prev,
  });
  return { scope_key: SCOPE, sequence_number: seq, event_type: eventType, canonical_details, previous_hash: prev, chain_hash };
}

const ASSIGNMENT = {
  v: 1,
  block_type: 'ASSIGNMENT',
  scope: { act: ['read', 'write'], res: {} },
  human_attestation: { method: 'session' },
};

// ASSIGNMENT → [ACCESS by P of C] → MUTATION by P citing `cited`.
function chain(cited, includeAccess) {
  const a = mkRow(1, null, 'assign', ASSIGNMENT);
  const rows = [a];
  let seq = 2;
  let prev = a.chain_hash;
  if (includeAccess) {
    const acc = mkRow(seq, prev, 'access', {
      v: 1, block_type: 'ACCESS', parent_assignment_hash: a.chain_hash, action: 'read',
      principal: 'P', resource: { content_hash: C, resource_id: 'r', in_workspace: 'w' },
    });
    rows.push(acc); seq++; prev = acc.chain_hash;
  }
  const mut = mkRow(seq, prev, 'mutate', {
    v: 1, block_type: 'MUTATION', parent_assignment_hash: a.chain_hash, action: 'write',
    principal: 'P', resource: { content_hash: 'outhash', resource_id: 'r2', in_workspace: 'w' },
    grounded_document_hashes: cited,
  });
  rows.push(mut);
  return rows;
}

test('grounded MUTATION citing content read by same principal => grounding green', () => {
  const r = verifyValChain(chain([C], true));
  assert.equal(r.integrity, 'green');
  assert.equal(r.lineage, 'green');
  assert.equal(r.scope, 'green');
  assert.equal(r.grounding, 'green', r.firstGroundingViolation?.reason);
});

test('grounded MUTATION citing content never read => grounding red', () => {
  const r = verifyValChain(chain(['neverreadhash'], true));
  assert.equal(r.grounding, 'red');
});

test('grounded MUTATION with no prior ACCESS at all => grounding red', () => {
  const r = verifyValChain(chain([C], false));
  assert.equal(r.grounding, 'red');
});

test('MUTATION with empty grounded_document_hashes => grounding green (not content-derived)', () => {
  const r = verifyValChain(chain([], true));
  assert.equal(r.grounding, 'green');
});
