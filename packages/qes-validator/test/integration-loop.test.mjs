// LEG 4 + LEG 5 — full VAL loop wiring the two packages together on REAL signatures.
// Leg 4: a real qes-validator report flows into chain-verifier's verifyValChain; the two packages'
//        signatureRef must agree WIRED-TOGETHER (not just by construction) — proven by a qualified:true
//        report keyed to the qes-validator-computed ref going GREEN, and a wrong-ref report not.
// Leg 5: two DISTINCT real signatures (DSS-emitted + JS-assembled) → distinct signatureRefs; each block
//        matches only its own verdict, neither borrows the other's (anti-borrow on real bytes).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateQes } from '../dist/esm/index.js';
import { verifyValChain, reconstructChainHash } from '@val-protocol/chain-verifier';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const DSS = join(FX, 'dss-emitted.jades.b64');
const JS = join(FX, 'sslcom-real.jades.b64');
const skip = existsSync(DSS) && existsSync(JS) ? false : 'needs dss-emitted + sslcom-real fixtures';

function anchorOf(jadesB64) {
  const h = JSON.parse(Buffer.from(Buffer.from(jadesB64, 'base64').toString('utf8').split('.')[0], 'base64url').toString('utf8'));
  return { anchor: h.x5c[h.x5c.length - 1], iat: h.iat };
}
function assignmentBlock(jadesB64) {
  return {
    v: 2, block_type: 'ASSIGNMENT', scope: { act: ['record.append'], res: { in_workspace: 'w' } },
    human_attestation: {
      method: 'qes', subject_user_hash: 'sha256:sig',
      identity_assurance: { source: 'self_asserted', subject_claim: 'Declared' },
      delegator_authority: { basis: 'org_verified_representative', capability: 'org_verified_representative', scope_ref: 'w', signature: { alg: 'eidas_qes', public_key: 'na', signature: jadesB64 } },
    },
  };
}
async function chainOf(block, scope) {
  const canonical_details = JSON.stringify(block);
  const chain_hash = await reconstructChainHash({ scopeKey: scope, sequenceNumber: 1, eventType: 'assign', canonicalDetails: canonical_details, previousHash: null });
  return [{ scope_key: scope, sequence_number: 1, event_type: 'assign', canonical_details, previous_hash: null, chain_hash }];
}

test('LEG 4: real qes-validator report flows into verifyValChain; signatureRef agrees wired-together', { skip }, async () => {
  const jades = readFileSync(DSS, 'utf8').trim();
  const canonical = readFileSync(join(FX, 'dss-emitted.canonical.json'), 'utf8');
  const { anchor, iat } = anchorOf(jades);
  const rows = await chainOf(assignmentBlock(jades), 's-leg4');

  // (a) the REAL report from qes-validator on real bytes — its actual signatureRef + honest verdict.
  const realReport = await validateQes({ signedCanonical: canonical, signature: { alg: 'eidas_qes', signature: jades }, validationTime: new Date(iat * 1000).toISOString(), trust: { intermediateHintsDer: [anchor] } });
  console.log('  real report: status=', realReport.status, 'signatureRef=', realReport.signatureRef.slice(0, 16) + '…');
  const realOutcome = await verifyValChain(rows, { qesValidation: { reports: [realReport] } });
  assert.equal(realOutcome.conformanceProfile, 'C');
  assert.notEqual(realOutcome.signature, 'green'); // SSL.com not qualified ⇒ qualified_unverified (honest)

  // (b) WIRED-TOGETHER proof: a qualified:true report keyed to qes-validator's OWN computed ref goes GREEN.
  //     If the verifier computed signatureRef differently than qes-validator, no match ⇒ not green.
  const greenIfWired = await verifyValChain(rows, { qesValidation: { reports: [{ qualified: true, signatureRef: realReport.signatureRef, signerIdentity: { given_name: 'Wired', family_name: 'Match' } }] } });
  assert.equal(greenIfWired.signature, 'green', 'verifier signatureRef must equal qes-validator signatureRef on real bytes');
  assert.equal(greenIfWired.conformanceProfile, 'C');
  assert.deepEqual(greenIfWired.rootSubject, { subject_claim: 'Wired Match', source: 'qes' });

  // (c) control: same qualified:true but WRONG ref ⇒ not matched ⇒ not green.
  const wrong = await verifyValChain(rows, { qesValidation: { reports: [{ qualified: true, signatureRef: 'f'.repeat(64) }] } });
  assert.notEqual(wrong.signature, 'green');
});

test('LEG 5: two DISTINCT real signatures — each block matches only its own ref, neither borrows', { skip }, async () => {
  const dss = readFileSync(DSS, 'utf8').trim();
  const js = readFileSync(JS, 'utf8').trim();
  const refA = (await validateQes({ signedCanonical: readFileSync(join(FX, 'dss-emitted.canonical.json'), 'utf8'), signature: { alg: 'eidas_qes', signature: dss }, trust: { intermediateHintsDer: [anchorOf(dss).anchor] } })).signatureRef;
  const refB = (await validateQes({ signedCanonical: readFileSync(join(FX, 'sslcom-real.canonical.json'), 'utf8'), signature: { alg: 'eidas_qes', signature: js }, trust: { intermediateHintsDer: [anchorOf(js).anchor] } })).signatureRef;
  console.log('  refA(dss)=', refA.slice(0, 12), '| refB(js)=', refB.slice(0, 12));
  assert.notEqual(refA, refB, 'two distinct signatures ⇒ distinct signatureRefs');

  const chainA = await chainOf(assignmentBlock(dss), 's-leg5-A');
  const chainB = await chainOf(assignmentBlock(js), 's-leg5-B');
  const both = [{ qualified: true, signatureRef: refA, signerIdentity: { given_name: 'A', family_name: 'Sig' } }, { qualified: true, signatureRef: refB, signerIdentity: { given_name: 'B', family_name: 'Sig' } }];

  // each chain verifies via ITS OWN ref when both reports are present
  assert.equal((await verifyValChain(chainA, { qesValidation: { reports: both } })).signature, 'green');
  assert.equal((await verifyValChain(chainB, { qesValidation: { reports: both } })).signature, 'green');

  // ANTI-BORROW: feed chain A only B's qualified report (and vice versa) — must NOT borrow it.
  assert.notEqual((await verifyValChain(chainA, { qesValidation: { reports: [{ qualified: true, signatureRef: refB }] } })).signature, 'green', 'A must not borrow B verdict');
  assert.notEqual((await verifyValChain(chainB, { qesValidation: { reports: [{ qualified: true, signatureRef: refA }] } })).signature, 'green', 'B must not borrow A verdict');

  // and A verified via refA is unaffected by a decoy qualified:true keyed to a wrong ref
  assert.equal((await verifyValChain(chainA, { qesValidation: { reports: [{ qualified: true, signatureRef: refA }, { qualified: true, signatureRef: 'e'.repeat(64) }] } })).signature, 'green');
});
