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

/** Build a self-attested org-root + a delegation signed by the same key. keyBinding chosen.
 *  `identityAssurance` (optional) stamps the block-level human_attestation.identity_assurance —
 *  the IDENTITY-SOURCE axis (self_asserted | kyb_attested | eidas_eaa | qes), orthogonal to the
 *  instrument axis this file otherwise exercises. */
async function makeSignedAssignment({ keyBinding = 'device_bound', delegationKey, relabelBinding, identityAssurance } = {}) {
  const root = newKey();
  const rootSpki = spkiB64(root.publicKey);
  const assurance = { source: 'self_asserted', subject_claim: 'John Doe' };
  const orgRootBase = { org_id: 'org-acme', signatory_identity_hash: 'sha256:sig', public_key: rootSpki, identity_assurance: assurance, key_binding: keyBinding };
  const selfSig = signAssertion(await orgRootBindingChallenge(orgRootBase), root.privateKey, root.publicKey);
  // relabelBinding: stamp a DIFFERENT key_binding than what was signed (tamper).
  const org_root = { ...orgRootBase, key_binding: relabelBinding ?? keyBinding, self_signature: selfSig };
  const dk = delegationKey ?? root; // by default the delegation is signed by the org-root key.
  const signature = signAssertion('Z3JhbnQ', dk.privateKey, dk.publicKey);
  return {
    v: 2, block_type: 'ASSIGNMENT', scope: { act: ['read'], res: { in_workspace: 'w' } },
    human_attestation: { method: 'webauthn', subject_user_hash: 'sha256:sig', ...(identityAssurance ? { identity_assurance: identityAssurance } : {}), delegator_authority: { basis: 'org_verified_representative', capability: 'org_verified_representative', scope_ref: 'w', signature, org_root } },
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

// §5.2 amendment 2026-07-02: 'unattested' = no verified hardware attestation at enrollment.
// Still earns B on a verified+linked signature (the letter grades the instrument); the
// binding is the orthogonal hardware axis, surfaced verbatim — never rounded up.
test("Profile B unattested: verified+linked signature => conformance B, keyBinding 'unattested' verbatim", async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({ keyBinding: 'unattested' })));
  assert.equal(r.conformanceProfile, 'B');
  assert.equal(r.signature, 'green');
  assert.equal(r.keyBinding, 'unattested');
});

test("relabel key_binding (unattested→device_bound) without re-signing org-root => signature red (tamper-evident)", async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({ keyBinding: 'unattested', relabelBinding: 'device_bound' })));
  assert.equal(r.signature, 'red');
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

// ── "B+" cell (device instrument × eID identity source) — the PREPARED-not-built rung of the
// operator's canonical ladder (2026-07-02): A = self-declaration · B = self-declaration + device ·
// B+ = eID (e.g. FranceConnect+) + device · C = QES. The profile letter grades the INSTRUMENT;
// the identity source is an orthogonal axis surfaced verbatim. This locks the cell's rendering
// BEFORE any eID integration exists, so the future proofing flow is purely additive: a
// device-signed root carrying identity_assurance.source='eidas_eaa' classifies B (instrument
// unchanged) and the verifier surfaces the eID source verbatim — never rounded up to a stronger
// claim, never collapsed back to self_asserted. ──
test("B+ cell: device-signed root with identity_assurance.source='eidas_eaa' => conformance B, eID source surfaced verbatim", async () => {
  const r = await verifyValChain(await mkRow(await makeSignedAssignment({
    keyBinding: 'device_bound',
    identityAssurance: { source: 'eidas_eaa', subject_claim: 'Jean Dupont' },
  })));
  assert.equal(r.conformanceProfile, 'B'); // instrument axis: still a device signature — not C
  assert.deepEqual(r.profilesPresent, ['B']);
  assert.equal(r.signature, 'green');
  assert.deepEqual(r.rootSubject, { subject_claim: 'Jean Dupont', source: 'eidas_eaa' }); // eID axis: verbatim
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
  a.human_attestation.identity_assurance = { source: 'self_asserted', subject_claim: 'John Doe' };
  const r = await verifyValChain(await mkRow(a));
  assert.deepEqual(r.rootSubject, { subject_claim: 'John Doe', source: 'self_asserted' });
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
