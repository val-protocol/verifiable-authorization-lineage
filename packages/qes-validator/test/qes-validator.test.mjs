// @val-protocol/qes-validator — offline (no-DSS, no-server) test suite.
//
// Exercises the full pure-JS determination against DETERMINISTIC openssl fixtures (test/fixtures/gen.sh):
// a JAdES is constructed here over a canonical payload, signed with the fixture leaf key, in the spec
// shape (detached, sigD ObjectIdByURIHash) the DSS producer emits. Stub Trusted-List XML is built inline.
//
// HONEST LIMITATION (stated, not hidden): this proves the validator's logic — JWS parse, x5c
// signature-value, cert-path, QcStatements, CA/QC-vs-TSA, conclusive-vs-indeterminate. It does NOT prove
// byte-compatibility with a real DSS-emitted JAdES: the held SSL.com 13 KB artifact is not on disk and
// regenerating it needs SSL.com + a running DSS (infra-gated). Case 1 below is the SYNTHETIC analog of
// "real non-EU cert → conclusive not_qualified", not the literal SSL.com bytes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate, createPrivateKey, createHash, sign as cryptoSign } from 'node:crypto';
import { validateQes, matchGrantedCaQc } from '../dist/esm/index.js';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const read = (f) => readFileSync(join(FX, f));
const derB64 = (pem) => new X509Certificate(pem).raw.toString('base64');
const b64url = (buf) => Buffer.from(buf).toString('base64url');

const SIGNING_MS = Date.parse('2023-06-01T00:00:00Z');
const SIGNING_ISO = new Date(SIGNING_MS).toISOString();
const CANONICAL = JSON.stringify({ v: 2, block_type: 'ASSIGNMENT', scope: { act: ['record.append'] } });

const rootPem = read('root.cert.pem');
const ROOT_DER_B64 = derB64(rootPem);

/** Build a detached JAdES compact (sigD ObjectIdByURIHash) over CANONICAL, signed with the fixture key.
 *  Returned base64-wrapped to mirror the producer (DSS returns the JAdES as `bytes` base64). */
function makeJades({ leaf, key, alg = 'ES256', tamper = false, canonical = CANONICAL }) {
  const leafDer = derB64(read(leaf));
  const protectedHeader = {
    alg,
    x5c: [leafDer],
    sigT: SIGNING_ISO,
    sigD: {
      mId: 'http://uri.etsi.org/19182/ObjectIdByURIHash',
      hashM: 'S256',
      pars: ['grant.json'],
      hashV: [createHash('sha256').update(canonical, 'utf8').digest('base64url')],
    },
  };
  const protB64 = b64url(Buffer.from(JSON.stringify(protectedHeader)));
  const signingInput = Buffer.from(`${protB64}.`, 'ascii'); // payload empty (detached)
  const privKey = createPrivateKey(read(key));
  const sig = cryptoSign('sha256', signingInput, { key: privKey, dsaEncoding: 'ieee-p1363' });
  if (tamper) sig[10] ^= 0xff;
  const compact = `${protB64}..${b64url(sig)}`;
  return Buffer.from(compact).toString('base64');
}
const sigOf = (jades) => ({ alg: 'eidas_qes', signature: jades });

// ── stub Trusted-List builders (ETSI TS 119 612 shape, minimal — matches the validator's regex picks) ──
function tsl({ svcType, status = 'granted', startISO = '2015-01-01T00:00:00Z', foreSign = true, certB64 = ROOT_DER_B64 }) {
  const ext = foreSign
    ? `<ServiceInformationExtensions><Extension><AdditionalServiceInformation><URI>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension></ServiceInformationExtensions>`
    : '';
  return `<TrustServiceStatusList><TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceTypeIdentifier>${svcType}</ServiceTypeIdentifier>
    <ServiceName><Name xml:lang="en">VAL Test QC CA</Name></ServiceName>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>${certB64}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/${status}</ServiceStatus>
    <StatusStartingTime>${startISO}</StatusStartingTime>
    ${ext}
  </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;
}
const CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const TSA_QTST = 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST';
const TSL_CAQC_GRANTED = tsl({ svcType: CA_QC });
const TSL_TSA_ONLY = tsl({ svcType: TSA_QTST });
const TSL_WITHDRAWN = tsl({ svcType: CA_QC, status: 'withdrawn' });
const TSL_GRANTED_LATE = tsl({ svcType: CA_QC, startISO: '2999-01-01T00:00:00Z' });
const TSL_SEALS_ONLY = tsl({ svcType: CA_QC, foreSign: false }); // CA/QC but not ForeSignatures

const anchors = [ROOT_DER_B64];

// ── CASE 2 — the qualified positive (synthetic fixture chaining to an injected trusted root) ──────────
test('qualified leaf + CA/QC-granted TSL → status=qualified (the positive)', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({
    signedCanonical: CANONICAL,
    signature: sigOf(jades),
    validationTime: SIGNING_ISO,
    trust: { tslXml: TSL_CAQC_GRANTED, trustAnchorsDer: anchors },
  });
  console.log('  [qualified]', r.status, '|', r.indication, '|', r.reason);
  assert.equal(r.qualified, true);
  assert.equal(r.status, 'qualified');
  assert.equal(r.indication, 'TOTAL-PASSED');
  assert.ok(r.signatureRef && r.signatureRef.length === 64, 'signatureRef populated (refinement 1)');
  assert.equal(r.signatureRef, createHash('sha256').update(jades, 'utf8').digest('hex'));
  assert.equal(r.signerIdentity?.given_name, 'Alice');
  assert.equal(r.signerIdentity?.family_name, 'Signer');
  assert.equal(r.signerIdentity?.country, 'FR');
});

// ── CASE 1 (analog) — real non-EU cert → CONCLUSIVE not_qualified ─────────────────────────────────────
test('non-qualified leaf (no QcStatements) → conclusive not_qualified [SSL.com-analog]', async () => {
  const jades = makeJades({ leaf: 'plain.cert.pem', key: 'plain.key.pem' });
  const r = await validateQes({
    signedCanonical: CANONICAL,
    signature: sigOf(jades),
    validationTime: SIGNING_ISO,
    trust: { tslXml: TSL_CAQC_GRANTED, trustAnchorsDer: anchors },
  });
  console.log('  [plain]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.qualified, false);
  assert.equal(r.status, 'not_qualified'); // conclusive, NOT indeterminate
  assert.match(r.reason, /QcStatements/);
});

// ── NEGATIVES ─────────────────────────────────────────────────────────────────────────────────────────
test('mangled signature value → not_qualified SIG_CRYPTO_FAILURE', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem', tamper: true });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_CAQC_GRANTED, trustAnchorsDer: anchors } });
  console.log('  [tamper]', r.status, '|', r.subIndication);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'SIG_CRYPTO_FAILURE');
});

test('TSA-only issuer → not_qualified (refinement 3: TSA hit must NOT count as qualified-eSig)', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_TSA_ONLY, trustAnchorsDer: anchors } });
  console.log('  [tsa-only]', r.status, '|', r.reason);
  assert.equal(r.qualified, false);
  assert.equal(r.status, 'not_qualified');
  assert.match(r.reason, /TSA\/QTST|timestamping/);
});

test('service withdrawn before signing time → not_qualified', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_WITHDRAWN, trustAnchorsDer: anchors } });
  console.log('  [withdrawn]', r.status, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
});

test('service granted only AFTER signing time → not_qualified', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_GRANTED_LATE, trustAnchorsDer: anchors } });
  console.log('  [granted-late]', r.status, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
});

test('CA/QC but not ForeSignatures (seals/web-auth only) → not_qualified', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_SEALS_ONLY, trustAnchorsDer: anchors } });
  console.log('  [no-foresign]', r.status, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
});

test('LOTL unreachable → indeterminate (refinement 2: distinct from conclusive false)', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({
    signedCanonical: CANONICAL,
    signature: sigOf(jades),
    validationTime: SIGNING_ISO,
    trust: { fetchLive: true, fetchImpl: async () => { throw new Error('network down'); }, trustAnchorsDer: anchors },
  });
  console.log('  [lotl-down]', r.status, '|', r.reason);
  assert.equal(r.status, 'indeterminate');
  assert.equal(r.qualified, false);
});

test('CAdES/PAdES (non-JWS) input → indeterminate with reason', async () => {
  const cades = Buffer.from('-----BEGIN CMS----- not a JWS, a CAdES blob -----END CMS-----').toString('base64');
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(cades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_CAQC_GRANTED, trustAnchorsDer: anchors } });
  console.log('  [cades]', r.status, '|', r.reason);
  assert.equal(r.status, 'indeterminate');
  assert.match(r.reason, /JAdES|CAdES|parse/);
});

test('no trust anchor → indeterminate (cannot conclude), not a false negative', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_CAQC_GRANTED, trustAnchorsDer: [] } });
  console.log('  [no-anchor]', r.status, '|', r.reason);
  assert.equal(r.status, 'indeterminate');
});

test('signature does not bind the supplied canonical bytes → not_qualified HASH_FAILURE', async () => {
  const jades = makeJades({ leaf: 'qualified.cert.pem', key: 'qualified.key.pem' });
  const r = await validateQes({ signedCanonical: '{"different":"bytes"}', signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: TSL_CAQC_GRANTED, trustAnchorsDer: anchors } });
  console.log('  [wrong-canonical]', r.status, '|', r.subIndication);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'HASH_FAILURE');
});

test('matchGrantedCaQc unit: TSA service type is never a qualified-eSig hit', () => {
  const fp = createHash('sha256').update(Buffer.from(ROOT_DER_B64, 'base64')).digest('hex');
  assert.equal(matchGrantedCaQc(TSL_TSA_ONLY, fp, SIGNING_MS).matched, false);
  assert.equal(matchGrantedCaQc(TSL_CAQC_GRANTED, fp, SIGNING_MS).matched, true);
});
