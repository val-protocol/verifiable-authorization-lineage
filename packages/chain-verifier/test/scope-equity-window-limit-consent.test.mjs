// In-package regression coverage for the five verdict-affecting checks added at 0.5.0:
// agent-equity (principal == grantee), §6.6 temporal window (`win`, fail-closed), §6.6 count
// limit (`lim.max_count`), §6.7 transitive effective scope (intersection back to root), and the
// §4.3 CONSENT per-action signature. Each: a chain that should pass → green, and the violating
// variant → red. The logic is integration-proven in the operator e2e; this file proves the
// verdicts IN THE PUBLISHED ARTIFACT so a third party running the verifier standalone gets the
// same guarantees (transcription guard: fail-closed window, over-count, principal≠grantee,
// out-of-scope act, CONSENT signature over the wrong document).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, createSign, randomBytes } from 'node:crypto';
import { verifyValChain, reconstructChainHash } from '../dist/esm/index.js';

const SCOPE = 's-units';

async function mkRow(seq, prev, eventType, body) {
  const canonical_details = JSON.stringify(body);
  const chain_hash = await reconstructChainHash({
    scopeKey: SCOPE,
    sequenceNumber: seq,
    eventType,
    canonicalDetails: canonical_details,
    previousHash: prev,
  });
  return { scope_key: SCOPE, sequence_number: seq, event_type: eventType, canonical_details, previous_hash: prev, chain_hash };
}

const access = (parentHash, principal, extra = {}) => ({
  v: 1,
  block_type: 'ACCESS',
  parent_assignment_hash: parentHash,
  action: 'read',
  principal,
  resource: { content_hash: 'c', resource_id: 'r', in_workspace: 'w' },
  ...extra,
});

// ─────────────────────────────────────────────────────────────────────────────
// 1) Agent-equity — every action rooting in a v≥3 ASSIGNMENT must carry
//    principal == grantee ("it's THIS actor's own mandate").
// ─────────────────────────────────────────────────────────────────────────────
const equityAssignment = (grantee) => ({
  v: 3,
  block_type: 'ASSIGNMENT',
  grantee,
  scope: { act: ['read'], res: { in_workspace: 'w' } },
  human_attestation: { method: 'session', delegator_authority: { basis: 'op_role', capability: 'user', scope_ref: 'w' } },
});

test('agent-equity: v3 action principal == grantee => authority green', async () => {
  const a = await mkRow(1, null, 'assign', equityAssignment('agent:sa-1'));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1'));
  const r = await verifyValChain([a, b], { delegatorAuthorityPolicy: { user: ['read'] } });
  assert.equal(r.lineage, 'green');
  assert.equal(r.scope, 'green');
  assert.equal(r.authority, 'green');
  assert.equal(r.firstAuthorityViolation, null);
});

test('agent-equity: v3 action principal != grantee => authority red', async () => {
  const a = await mkRow(1, null, 'assign', equityAssignment('agent:sa-1'));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:intruder-9'));
  const r = await verifyValChain([a, b], { delegatorAuthorityPolicy: { user: ['read'] } });
  assert.equal(r.authority, 'red');
  assert.match(r.firstAuthorityViolation.reason, /agent-equity/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) §6.6 temporal window — not_before ≤ timestamp_local ≤ not_after, FAIL-CLOSED
//    when the scope is windowed but the action carries no timestamp_local.
// ─────────────────────────────────────────────────────────────────────────────
const winAssignment = (win) => ({
  v: 1,
  block_type: 'ASSIGNMENT',
  scope: { act: ['read'], res: { in_workspace: 'w' }, win },
  human_attestation: { method: 'session' },
});

test('§6.6 win: timestamp_local within the window => scope green', async () => {
  const a = await mkRow(1, null, 'assign', winAssignment({ not_before: 1000, not_after: 2000 }));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1', { timestamp_local: 1500 }));
  const r = await verifyValChain([a, b]);
  assert.equal(r.scope, 'green');
});

test('§6.6 win: timestamp_local after not_after => scope red', async () => {
  const a = await mkRow(1, null, 'assign', winAssignment({ not_before: 1000, not_after: 2000 }));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1', { timestamp_local: 3000 }));
  const r = await verifyValChain([a, b]);
  assert.equal(r.scope, 'red');
  assert.match(r.firstScopeViolation.reason, /after win\.not_after/);
});

test('§6.6 win: windowed scope but action has no timestamp_local => scope red (fail-closed)', async () => {
  const a = await mkRow(1, null, 'assign', winAssignment({ not_before: 1000, not_after: 2000 }));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1')); // no timestamp_local
  const r = await verifyValChain([a, b]);
  assert.equal(r.scope, 'red');
  assert.match(r.firstScopeViolation.reason, /no timestamp_local/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) §6.6 lim.max_count — the (max_count+1)-th action rooting in a grant is the violation.
// ─────────────────────────────────────────────────────────────────────────────
const limAssignment = (max_count) => ({
  v: 1,
  block_type: 'ASSIGNMENT',
  scope: { act: ['read'], res: { in_workspace: 'w' }, lim: { max_count } },
  human_attestation: { method: 'session' },
});

test('§6.6 lim.max_count: actions within the limit => scope green', async () => {
  const a = await mkRow(1, null, 'assign', limAssignment(2));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1'));
  const c = await mkRow(3, b.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1'));
  const r = await verifyValChain([a, b, c]);
  assert.equal(r.scope, 'green');
});

test('§6.6 lim.max_count: the (max_count+1)-th action => scope red', async () => {
  const a = await mkRow(1, null, 'assign', limAssignment(2));
  const b = await mkRow(2, a.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1'));
  const c = await mkRow(3, b.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1'));
  const d = await mkRow(4, c.chain_hash, 'access', access(a.chain_hash, 'agent:sa-1'));
  const r = await verifyValChain([a, b, c, d]);
  assert.equal(r.scope, 'red');
  assert.match(r.firstScopeViolation.reason, /lim\.max_count 2 exceeded/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4) §6.7 transitive effective scope — a leaf is evaluated against EVERY ancestor scope;
//    a sub-assignment cannot grant more than its parent had.
// ─────────────────────────────────────────────────────────────────────────────
const rootAssignment = () => ({
  v: 1,
  block_type: 'ASSIGNMENT',
  scope: { act: ['read'], res: { in_workspace: 'w' } },
  human_attestation: { method: 'session' },
});
const subAssignment = (parentHash) => ({
  v: 1,
  block_type: 'ASSIGNMENT',
  parent_assignment_hash: parentHash,
  scope: { act: ['read', 'create'], res: { in_workspace: 'w' } }, // broadens act beyond the root
  human_attestation: { method: 'session' },
});

test('§6.7 transitive: leaf action within BOTH child and root scope => scope green', async () => {
  const root = await mkRow(1, null, 'assign', rootAssignment());
  const sub = await mkRow(2, root.chain_hash, 'assign', subAssignment(root.chain_hash));
  const act = await mkRow(3, sub.chain_hash, 'access', access(sub.chain_hash, 'agent:sa-1', { action: 'read' }));
  const r = await verifyValChain([root, sub, act]);
  assert.equal(r.lineage, 'green');
  assert.equal(r.scope, 'green');
});

test('§6.7 transitive: sub-assignment broadens act beyond root => scope red (intersection back to root)', async () => {
  const root = await mkRow(1, null, 'assign', rootAssignment());
  const sub = await mkRow(2, root.chain_hash, 'assign', subAssignment(root.chain_hash));
  const act = await mkRow(3, sub.chain_hash, 'access', access(sub.chain_hash, 'agent:sa-1', { action: 'create' }));
  const r = await verifyValChain([root, sub, act]);
  assert.equal(r.scope, 'red');
  assert.match(r.firstScopeViolation.reason, /not in scope\.act \[read\]/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5) §4.3 CONSENT per-action signature — the embedded WebAuthn assertion's challenge MUST
//    equal sha256(jcs({document_hash, parent_assignment_hash, principal})); a signature over a
//    different document → red.
// ─────────────────────────────────────────────────────────────────────────────
const b64 = (b) => b.toString('base64');
const spkiB64 = (pub) => b64(pub.export({ format: 'der', type: 'spki' }));
const newKey = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });

/** Build a WebAuthn-shaped ES256 assertion over `challenge` (mirrors the operator's signer). */
function signAssertion(challenge, priv, pub) {
  const clientDataJson = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://x', crossOrigin: false }), 'utf8');
  const authenticatorData = randomBytes(37);
  const signedBytes = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJson).digest()]);
  const s = createSign('sha256'); s.update(signedBytes); s.end();
  return { alg: 'webauthn', credential_id: 'c', public_key: spkiB64(pub), authenticator_data: b64(authenticatorData), client_data_json: b64(clientDataJson), signature: b64(s.sign({ key: priv, dsaEncoding: 'der' })) };
}

/** Replicates the verifier's jcs (RFC 8785: sorted keys, JSON.stringify scalars). */
function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
}

/** The exact per-action consent challenge the verifier recomputes (b64url, no padding). */
const consentChallenge = (document_hash, parent_assignment_hash, principal) =>
  createHash('sha256').update(Buffer.from(jcs({ document_hash, parent_assignment_hash, principal }), 'utf8')).digest('base64url');

const consentParent = () => ({
  v: 1,
  block_type: 'ASSIGNMENT',
  scope: { act: ['sign'], res: { in_workspace: 'w' } },
  human_attestation: { method: 'session' },
});

test('CONSENT: per-action signature over the bound document => signature green', async () => {
  const k = newKey();
  const a = await mkRow(1, null, 'assign', consentParent());
  const principal = 'user:u-1';
  const document_hash = 'doc-abc';
  const consent = {
    v: 1, block_type: 'CONSENT', parent_assignment_hash: a.chain_hash, action: 'sign',
    principal, document_hash, resource: { content_hash: 'doc-abc', resource_id: 'r', in_workspace: 'w' },
    signature: signAssertion(consentChallenge(document_hash, a.chain_hash, principal), k.privateKey, k.publicKey),
  };
  const b = await mkRow(2, a.chain_hash, 'consent', consent);
  const r = await verifyValChain([a, b]);
  assert.equal(r.scope, 'green');
  assert.equal(r.signature, 'green');
  assert.equal(r.firstSignatureViolation, null);
});

test('CONSENT: signature over a DIFFERENT document => signature red', async () => {
  const k = newKey();
  const a = await mkRow(1, null, 'assign', consentParent());
  const principal = 'user:u-1';
  // The signature commits to 'doc-OTHER' but the block binds 'doc-abc' → challenge mismatch.
  const consent = {
    v: 1, block_type: 'CONSENT', parent_assignment_hash: a.chain_hash, action: 'sign',
    principal, document_hash: 'doc-abc', resource: { content_hash: 'doc-abc', resource_id: 'r', in_workspace: 'w' },
    signature: signAssertion(consentChallenge('doc-OTHER', a.chain_hash, principal), k.privateKey, k.publicKey),
  };
  const b = await mkRow(2, a.chain_hash, 'consent', consent);
  const r = await verifyValChain([a, b]);
  assert.equal(r.signature, 'red');
  assert.match(r.firstSignatureViolation.reason, /CONSENT per-action signature invalid/);
});

test('CONSENT: block carries no per-action signature => signature red', async () => {
  const a = await mkRow(1, null, 'assign', consentParent());
  const consent = {
    v: 1, block_type: 'CONSENT', parent_assignment_hash: a.chain_hash, action: 'sign',
    principal: 'user:u-1', document_hash: 'doc-abc', resource: { content_hash: 'doc-abc', resource_id: 'r', in_workspace: 'w' },
  };
  const b = await mkRow(2, a.chain_hash, 'consent', consent);
  const r = await verifyValChain([a, b]);
  assert.equal(r.signature, 'red');
  assert.match(r.firstSignatureViolation.reason, /no per-action signature/);
});
