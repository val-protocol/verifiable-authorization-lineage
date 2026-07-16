// Profile C (§7.1(f)) — a qualified delegation (`qes`/`eidas_qes`/`eidas_eaa`) is CLASSIFIED by default
// (`qualified_unverified`) and only VERIFIED when the caller supplies a resolved QES verdict via
// `options.qesValidation` (produced by @val-protocol/qes-validator). The zero-dep core consumes the
// verdict; it never validates the QES itself. Default behaviour is unchanged (classified, never upgraded).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyValChain, reconstructChainHash } from '../dist/esm/index.js';

const SCOPE = 's-profile-c';

// A root ASSIGNMENT carrying a qualified delegation signature. The qualified path keys ONLY on
// `signature.alg` (the core short-circuits before signature-bytes verification — that is the
// qes-validator's job), so the blob content is a placeholder.
function makeQualifiedAssignment() {
  return {
    v: 2,
    block_type: 'ASSIGNMENT',
    scope: { act: ['read'], res: { in_workspace: 'w' } },
    human_attestation: {
      method: 'qes',
      subject_user_hash: 'sha256:sig',
      identity_assurance: { source: 'self_asserted', subject_claim: 'Declared Name' },
      delegator_authority: {
        basis: 'org_verified_representative',
        capability: 'org_verified_representative',
        scope_ref: 'w',
        signature: { alg: 'qes', public_key: 'placeholder', signature: 'placeholder' },
      },
    },
  };
}

async function mkRow(body) {
  const canonical_details = JSON.stringify(body);
  const chain_hash = await reconstructChainHash({ scopeKey: SCOPE, sequenceNumber: 1, eventType: 'assign', canonicalDetails: canonical_details, previousHash: null });
  return [{ scope_key: SCOPE, sequence_number: 1, event_type: 'assign', canonical_details, previous_hash: null, chain_hash }];
}

test('Profile C default (no qesValidation) => classified C, signature NOT green (qualified_unverified)', async () => {
  const r = await verifyValChain(await mkRow(makeQualifiedAssignment()));
  assert.equal(r.conformanceProfile, 'C'); // declared/classified
  assert.notEqual(r.signature, 'green'); // NOT verified — never silently upgraded
  assert.equal(r.firstSignatureViolation, null); // classified is not a violation either
  assert.equal(r.rootSubject?.source, 'self_asserted'); // declared identity, not QES-proven
});

test('Profile C verified (qesValidation qualified:true) => conformance C, signature green, QES identity surfaced', async () => {
  const r = await verifyValChain(await mkRow(makeQualifiedAssignment()), {
    qesValidation: {
      reports: [
        {
          qualified: true,
          signerIdentity: { given_name: 'Jane', family_name: 'Doe', date_of_birth: '1980-01-02', persistent_id: 'FR/CITIZEN/123', country: 'FR' },
          reportRef: 'dss-report-001',
        },
      ],
    },
  });
  assert.equal(r.conformanceProfile, 'C');
  assert.equal(r.signature, 'green');
  assert.deepEqual(r.rootSubject, { subject_claim: 'Jane Doe', source: 'qes' });
});

test('Profile C with qualified:false verdict => still classified, NOT upgraded', async () => {
  const r = await verifyValChain(await mkRow(makeQualifiedAssignment()), {
    qesValidation: { reports: [{ qualified: false }] },
  });
  assert.equal(r.conformanceProfile, 'C');
  assert.notEqual(r.signature, 'green'); // a non-qualified verdict never verifies
});

// ── §7.1(f) per-signature matching: PER-SIGNATURE matching (signatureRef) — the anti-borrow proof ──────────────────
import { createHash } from 'node:crypto';
const refOf = (sig) => createHash('sha256').update(sig, 'utf8').digest('hex'); // == qes-validator's signatureRef

test('item 5: keyed report matching THIS signature => green, and a decoy qualified report is NOT borrowed', async () => {
  const thisRef = refOf('placeholder'); // the assignment's signature blob
  const r = await verifyValChain(await mkRow(makeQualifiedAssignment()), {
    qesValidation: {
      reports: [
        { qualified: true, signatureRef: 'deadbeef'.repeat(8), reportRef: 'decoy-other-signature' }, // different signature
        { qualified: true, signatureRef: thisRef, signerIdentity: { given_name: 'Real', family_name: 'Signer', country: 'FR' }, reportRef: 'matches-this' },
      ],
    },
  });
  assert.equal(r.conformanceProfile, 'C');
  assert.equal(r.signature, 'green'); // verified by ITS OWN report
  assert.deepEqual(r.rootSubject, { subject_claim: 'Real Signer', source: 'qes' });
});

test('item 5: keyed reports present but NONE matches THIS signature => NOT green (no borrowing the old "first qualified")', async () => {
  const r = await verifyValChain(await mkRow(makeQualifiedAssignment()), {
    qesValidation: {
      reports: [
        { qualified: true, signatureRef: 'deadbeef'.repeat(8), reportRef: 'a-different-signatures-verdict' },
      ],
    },
  });
  assert.equal(r.conformanceProfile, 'C'); // still classified C by alg
  assert.notEqual(r.signature, 'green'); // but NOT verified — the decoy verdict belongs to another signature
});
