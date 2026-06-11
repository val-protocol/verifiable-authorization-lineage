// §7.2 Pass 5 (delegator authority) — every ASSIGNMENT's delegated scope checked
// against its delegator's declared authority. Carrier REQUIRED on v2 bodies;
// scope.act ⊆ policy[capability] when the §7.1(d) policy is supplied; v1 bodies
// without the carrier are pre-carrier legacy (tolerated, counted).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyValChain, reconstructChainHash } from '../dist/esm/index.js';

const SCOPE = 's-authority';
const POLICY = { user: ['read', 'create'], read_only: ['read'] };

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

const assignment = (extra = {}) => ({
  v: 2,
  block_type: 'ASSIGNMENT',
  scope: { act: ['read'], res: { in_workspace: 'w' } },
  human_attestation: {
    method: 'session',
    delegator_authority: { basis: 'op_role', capability: 'user', scope_ref: 'w' },
  },
  ...extra,
});

test('v2 ASSIGNMENT with conformant carrier => authority green', () => {
  const a = mkRow(1, null, 'assign', assignment());
  const r = verifyValChain([a], { delegatorAuthorityPolicy: POLICY });
  assert.equal(r.authority, 'green');
  assert.equal(r.firstAuthorityViolation, null);
  assert.equal(r.legacyPreAuthorityAssignmentCount, 0);
});

test('v2 ASSIGNMENT without the carrier => authority red (required as of v2)', () => {
  const a = mkRow(1, null, 'assign', assignment({ human_attestation: { method: 'session' } }));
  const r = verifyValChain([a]);
  assert.equal(r.authority, 'red');
  assert.match(r.firstAuthorityViolation.reason, /required as of v2/);
});

test('scope.act exceeding the delegator capability => authority red (escalation)', () => {
  const a = mkRow(1, null, 'assign', assignment({
    scope: { act: ['read', 'create'], res: { in_workspace: 'w' } },
    human_attestation: {
      method: 'session',
      delegator_authority: { basis: 'op_role', capability: 'read_only', scope_ref: 'w' },
    },
  }));
  const r = verifyValChain([a], { delegatorAuthorityPolicy: POLICY });
  assert.equal(r.authority, 'red');
  assert.match(r.firstAuthorityViolation.reason, /authority escalation/);
});

test('unknown delegator capability => authority red (not evaluable)', () => {
  const a = mkRow(1, null, 'assign', assignment({
    human_attestation: {
      method: 'session',
      delegator_authority: { basis: 'op_role', capability: 'made_up', scope_ref: 'w' },
    },
  }));
  const r = verifyValChain([a], { delegatorAuthorityPolicy: POLICY });
  assert.equal(r.authority, 'red');
  assert.match(r.firstAuthorityViolation.reason, /unknown delegator capability/);
});

test('v1 ASSIGNMENT without the carrier => legacy tolerated + counted, authority stays none', () => {
  const a = mkRow(1, null, 'assign', assignment({ v: 1, human_attestation: { method: 'session' } }));
  const r = verifyValChain([a]);
  assert.equal(r.authority, 'none');
  assert.equal(r.legacyPreAuthorityAssignmentCount, 1);
  assert.equal(r.firstAuthorityViolation, null);
});

test('no policy supplied => presence still enforced, subset check skipped', () => {
  // read_only delegating 'create' would be red WITH the policy; without it, presence-only.
  const a = mkRow(1, null, 'assign', assignment({
    scope: { act: ['read', 'create'], res: { in_workspace: 'w' } },
    human_attestation: {
      method: 'session',
      delegator_authority: { basis: 'op_role', capability: 'read_only', scope_ref: 'w' },
    },
  }));
  const r = verifyValChain([a]);
  assert.equal(r.authority, 'green');
});

test('options param is additive — legacy call shape still verifies passes 1-3', () => {
  const a = mkRow(1, null, 'assign', assignment({ v: 1, human_attestation: { method: 'session' } }));
  const b = mkRow(2, a.chain_hash, 'access', {
    v: 1, block_type: 'ACCESS', parent_assignment_hash: a.chain_hash, action: 'read',
    principal: 'P', resource: { content_hash: 'c', resource_id: 'r', in_workspace: 'w' },
  });
  const r = verifyValChain([a, b]);
  assert.equal(r.integrity, 'green');
  assert.equal(r.lineage, 'green');
  assert.equal(r.scope, 'green');
});
