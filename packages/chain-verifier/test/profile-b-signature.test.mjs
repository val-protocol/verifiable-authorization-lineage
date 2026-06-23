// §5.2 Profile B/C — a present delegation signature is verified offline and must chain to
// the enrolled, self-attested org-root key. Profile B (webauthn) is cryptographically
// verified here; Profile C (qualified) is classified (QTSP-anchored verification is a future
// trust-anchor input). device_bound vs syncable is surfaced verbatim, never rounded up.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, createSign, randomBytes } from 'node:crypto';
import { verifyValChain, reconstructChainHash, orgRootBindingChallenge } from '../dist/esm/index.js';

const SCOPE = 's-profile-b';
const b64 = (b) => b.toString('base64');
const spkiB64 = (pub) => b64(pub.export({ format: 'der', type: 'spki' }));
const newKey = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });

/** Build a WebAuthn-shaped ES256 assertion over `challenge` with `priv`/`pub` (Node-side, sync). */
function signAssertion(challenge, priv, pub) {
  const clientDataJson = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://x', crossOrigin: false }), 'utf8');
  const authenticatorData = randomBytes(37);
  const signedBytes = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJson).digest()]);
  const s = createSign('sha256'); s.update(signedBytes); s.end();
  return { alg: 'webauthn', credential_id: 'c', public_key: spkiB64(pub), authenticator_data: b64(authenticatorData), client_data_json: b64(clientDataJson), signature: b64(s.sign({ key: priv, dsaEncoding: 'der' })) };
}

/** Build a self-attested org-root + a delegation signed by the same key. keyBinding chosen. */
async function makeSignedAssignment({ keyBinding = 'device_bound', delegationKey, relabelBinding } = {}) {
  const root = newKey();
  const rootSpki = spkiB64(root.publicKey);
  const assurance = { source: 'self_asserted', subject_claim: 'Maître Dupont, notaire' };
  const orgRootBase = { org_id: 'org-1', signatory_identity_hash: 'sha256:sig', public_key: rootSpki, identity_assurance: assurance, key_binding: keyBinding };
  const selfSig = signAssertion(await orgRootBindingChallenge(orgRootBase), root.privateKey, root.publicKey);
  // relabelBinding: stamp a DIFFERENT key_binding than what was signed (tamper).
  const org_root = { ...orgRootBase, key_binding: relabelBinding ?? keyBinding, self_signature: selfSig };
  const dk = delegationKey ?? root; // by default the delegation is signed by the org-root key.
  const signature = signAssertion('Z3JhbnQ', dk.privateKey, dk.publicKey);
  return {
    v: 2, block_type: 'ASSIGNMENT', scope: { act: ['read'], res: { in_workspace: 'w' } },
    human_attestation: { method: 'webauthn', subject_user_hash: 'sha256:sig', delegator_authority: { basis: 'org_verified_representative', capability: 'org_verified_representative', scope_ref: 'w', signature, org_root } },
  };
}

async function mkRow(body) {
  const canonical_details = JSON.stringify(body);
  const chain_hash = await reconstructChainHash({ scopeKey: SCOPE, sequenceNumber: 1, eventType: 'assign', canonicalDetails: canonical_details, previousHash: null });
  return [{ scope_key: SCOPE, sequence_number: 1, event_type: 'assign', canonical_details, previous_hash: null, chain_hash }];
}

test('Profile B device-bound: signature verified + linked => conformance B, signature green, keyBinding device_bound', async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({ keyBinding: 'device_bound' })));
  assert.equal(r.conformanceProfile, 'B');
  assert.equal(r.signature, 'green');
  assert.equal(r.keyBinding, 'device_bound');
  assert.equal(r.firstSignatureViolation, null);
});

test('Profile B syncable: surfaced verbatim, never rounded to device_bound', async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({ keyBinding: 'syncable' })));
  assert.equal(r.conformanceProfile, 'B');
  assert.equal(r.signature, 'green');
  assert.equal(r.keyBinding, 'syncable');
});

test('tampered delegation signature => signature red', async () => {
  const a = await makeSignedAssignment({});
  const buf = Buffer.from(a.human_attestation.delegator_authority.signature.signature, 'base64'); buf[10] ^= 0xff;
  a.human_attestation.delegator_authority.signature.signature = buf.toString('base64');
  const r = await verifyValChain(await mkRow(a));
  assert.equal(r.signature, 'red');
});

test('delegation signed by a key that is NOT the enrolled org-root => signature red (linkage)', async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({ delegationKey: newKey() })));
  assert.equal(r.signature, 'red');
  assert.match(r.firstSignatureViolation.reason, /not the enrolled org-root key/);
});

test('relabel key_binding (device_bound→syncable) without re-signing org-root => signature red (tamper-evident)', async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({ keyBinding: 'device_bound', relabelBinding: 'syncable' })));
  assert.equal(r.signature, 'red');
});

test('Profile C (qualified alg) => conformance C, classified but not crypto-verified', async () => {
  const a = await makeSignedAssignment({});
  a.human_attestation.delegator_authority.signature.alg = 'qes';
  const r = await verifyValChain(await mkRow(a));
  assert.equal(r.conformanceProfile, 'C');
  assert.equal(r.signature, 'none'); // qualified_unverified — not green, not red
});

test('Profile A (no signature) => conformance A, signature none', async () => {
  const a = await makeSignedAssignment({});
  delete a.human_attestation.delegator_authority.signature;
  delete a.human_attestation.delegator_authority.org_root;
  const r = await verifyValChain(await mkRow(a));
  assert.equal(r.conformanceProfile, 'A');
  assert.equal(r.signature, 'none');
});

// 0.6.0 — rootSubject surfaces the root human's DECLARED identity (already hash-bound in
// canonical_details). Additive: it changes output, never a verdict.
test('0.6.0 rootSubject => surfaced from the root human_attestation.identity_assurance (source verbatim)', async () => {
  const a = await makeSignedAssignment({});
  delete a.human_attestation.delegator_authority.signature;
  delete a.human_attestation.delegator_authority.org_root;
  a.human_attestation.identity_assurance = { source: 'self_asserted', subject_claim: 'Marie Dupont' };
  const r = await verifyValChain(await mkRow(a));
  assert.deepEqual(r.rootSubject, { subject_claim: 'Marie Dupont', source: 'self_asserted' });
  assert.equal(r.conformanceProfile, 'A'); // verdict unaffected — a name with no signature stays A
  assert.equal(r.integrity, 'green');
});

test('0.6.0 rootSubject => null when the root carries no identity_assurance (pre-declaration chains)', async () => {
  const a = await makeSignedAssignment({});
  delete a.human_attestation.delegator_authority.signature;
  delete a.human_attestation.delegator_authority.org_root;
  const r = await verifyValChain(await mkRow(a));
  assert.equal(r.rootSubject, null);
});
