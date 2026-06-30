// CERT-PATH CONFORMANCE — RFC 5280 §6 path validation at arbitrary depth (Defect 1) + TL-derived trust
// anchor, never the x5c top (Defect 2). DSS is not involved here (these are JS-conformance tests); test 1
// reuses the real DSS-emitted artifact. Synthetic chains are openssl-generated (gen.sh); each assertion
// states real-bytes vs synthetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate, createPrivateKey, createHash, sign as cryptoSign } from 'node:crypto';
import { validateQes, matchGrantedCaQc } from '../dist/esm/index.js';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const read = (f) => readFileSync(join(FX, f));
const derB64 = (pem) => new X509Certificate(pem).raw.toString('base64');
const fpHex = (f) => createHash('sha256').update(new X509Certificate(read(f)).raw).digest('hex');
const b64url = (b) => Buffer.from(b).toString('base64url');
const SIGNING_MS = Date.now();
const SIGNING_ISO = new Date(SIGNING_MS).toISOString();
const CANONICAL = JSON.stringify({ v: 2, block_type: 'ASSIGNMENT', scope: { act: ['record.append'] } });

// build a detached JAdES (sigD ObjectIdByURIHash) with an explicit x5c chain, signed by the leaf key
function makeJades({ leafCert, leafKey, chain = [], alg = 'ES256', canonical = CANONICAL }) {
  const x5c = [derB64(read(leafCert)), ...chain.map((c) => derB64(read(c)))];
  const header = { alg, x5c, sigT: SIGNING_ISO, sigD: { mId: 'http://uri.etsi.org/19182/ObjectIdByURIHash', hashM: 'S256', pars: ['grant.json'], hashV: [createHash('sha256').update(canonical, 'utf8').digest('base64url')] } };
  const protB64 = b64url(Buffer.from(JSON.stringify(header)));
  const signingInput = Buffer.from(`${protB64}.`, 'ascii');
  const sig = cryptoSign('sha256', signingInput, { key: createPrivateKey(read(leafKey)), dsaEncoding: 'ieee-p1363' });
  return Buffer.from(`${protB64}..${b64url(sig)}`).toString('base64');
}
const sigOf = (jades) => ({ alg: 'eidas_qes', signature: jades });
// a TL granting CA/QC-for-eSignatures for each given cert PEM (by embedded cert)
function tlGranting(certPems, { startISO = '2015-01-01T00:00:00Z' } = {}) {
  const svc = (pem) => `<TSPService><ServiceInformation>
    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
    <ServiceName><Name xml:lang="en">Test Granted QC CA</Name></ServiceName>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>${derB64(read(pem))}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
    <StatusStartingTime>${startISO}</StatusStartingTime>
    <ServiceInformationExtensions><Extension><AdditionalServiceInformation><URI>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension></ServiceInformationExtensions>
  </ServiceInformation></TSPService>`;
  return `<TrustServiceStatusList><TrustServiceProviderList><TrustServiceProvider><TSPServices>${certPems.map(svc).join('')}</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;
}

// ── TEST 1 — real DSS-emitted SSL.com JAdES, anchor decided by the TL (not x5c top) → not_qualified ──
test('TEST 1 [real DSS bytes]: SSL.com chain, TL does not list it → not_qualified via TL-anchor', async () => {
  const J = join(FX, 'dss-emitted.jades.b64');
  if (!existsSync(J)) return; // produced by scripts/qes/produce-dss-jades.ts
  const jades = readFileSync(J, 'utf8').trim();
  const canonical = readFileSync(join(FX, 'dss-emitted.canonical.json'), 'utf8');
  const header = JSON.parse(Buffer.from(Buffer.from(jades, 'base64').toString('utf8').split('.')[0], 'base64url').toString('utf8'));
  // TL grants the synthetic root (unrelated) — SSL.com is NOT on it.
  const r = await validateQes({ signedCanonical: canonical, signature: sigOf(jades), validationTime: new Date(header.iat * 1000).toISOString(), trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  TEST1 [real]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
  assert.notEqual(r.subIndication, 'FORMAT_FAILURE'); // parse + sig-verify still succeeded on real bytes
  assert.notEqual(r.subIndication, 'SIG_CRYPTO_FAILURE');
});

// ── TEST 2 — synthetic 4-cert chain builds to a depth-4 TL anchor → qualified; +resolver-consistency ──
test('TEST 2 [synthetic]: 4-cert chain → builds to depth-4 TL anchor → qualified (+ anchor is resolver-granted)', async () => {
  const jades = makeJades({ leafCert: 'leaf4.cert.pem', leafKey: 'leaf4.key.pem', chain: ['issuing.cert.pem', 'int.cert.pem', 'root.cert.pem'] });
  const tsl = tlGranting(['root.cert.pem']); // anchor = the root, at depth 3 (4 certs)
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tsl } });
  console.log('  TEST2', r.status, '|', r.reason);
  assert.equal(r.status, 'qualified');
  assert.match(r.reason, /depth 3/); // leaf←issuing←int←root = 3 links to anchor
  // RULING 2 — feed the anchored cert back through the resolver: MUST be granted (no walker drift).
  assert.ok(r.anchorFingerprint, 'positive carries the anchor fingerprint');
  assert.equal(r.anchorFingerprint, fpHex('root.cert.pem'));
  assert.equal(matchGrantedCaQc(tsl, r.anchorFingerprint, SIGNING_MS).matched, true);
});

// ── TEST 3 — ANCHOR-SPOOFING (the Defect-2 proof). Attacker's fully self-consistent chain with QcStatements,
//    internally verifying to their OWN self-signed root, NOT on the TL → MUST NOT anchor → not_qualified. ──
test('TEST 3 [synthetic] ANCHOR-SPOOFING: valid-looking chain to an attacker root not on the TL → not_qualified', async () => {
  const jades = makeJades({ leafCert: 'attacker-leaf.cert.pem', leafKey: 'attacker-leaf.key.pem', chain: ['attacker-root.cert.pem'] });
  // The TL grants the LEGIT root; the attacker root is not on it.
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  TEST3 [spoof]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.qualified, false);
  assert.equal(r.status, 'not_qualified'); // NOT qualified, despite QcStatements + an internally-valid chain
  // item 2: the spoof root is PRESENT and self-consistent — it just isn't on the TL → anchor-not-on-TL,
  // NOT incomplete-chain.
  assert.equal(r.subIndication, 'ANCHOR_NOT_ON_TRUSTED_LIST');
  assert.match(r.reason, /self-issued top|not a trust anchor|Trusted List/i);
  // sanity: the chain DID internally verify (not a crypto/format failure) — it fails ONLY on TL membership.
  assert.notEqual(r.subIndication, 'FORMAT_FAILURE');
  assert.notEqual(r.subIndication, 'SIG_CRYPTO_FAILURE');
});

// ── ITEM 1 — the explicit basicConstraints cA=TRUE check is independently EXERCISED ───────────────────
// fakeca has keyUsage:keyCertSign + SKI (so node's checkIssued ACCEPTS it as issuer — probed: true) but
// basicConstraints cA=FALSE. The rejection therefore comes from the validator's EXPLICIT cA check, not
// from checkIssued's issuer-finding (which would have produced a not-anchored/incomplete reason instead).
test('ITEM 1 [synthetic]: cA=FALSE issuer that checkIssued ACCEPTS → rejected by the explicit basicConstraints check', async () => {
  const jades = makeJades({ leafCert: 'leaf-fakeca.cert.pem', leafKey: 'leaf-fakeca.key.pem', chain: ['fakeca.cert.pem', 'root.cert.pem'] });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  ITEM1 [explicit cA]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'CHAIN_CONSTRAINTS_FAILURE'); // the cA check, not name-chain/anchor
  assert.match(r.reason, /cA=FALSE|basicConstraints/i);
  // prove it did NOT fall through to the not-anchored / incomplete paths
  assert.doesNotMatch(r.reason, /not a trust anchor|incomplete|Trusted List/i);
});

// ── ITEM 2 — incomplete-chain reason is DISTINCT from anchor-not-on-TL (spoof) ────────────────────────
test('ITEM 2 [synthetic]: incomplete x5c (leaf only, issuer omitted) → CHAIN_INCOMPLETE, distinct from spoof', async () => {
  const jades = makeJades({ leafCert: 'qualified.cert.pem', leafKey: 'qualified.key.pem', chain: [] }); // x5c = [leaf] only
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  ITEM2 [incomplete]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'CHAIN_INCOMPLETE'); // distinct from TEST 3's ANCHOR_NOT_ON_TRUSTED_LIST
  assert.match(r.reason, /incomplete|not present in x5c|no AIA chasing/i);
});

// ── TEST 4 — RFC 5280 link negatives ─────────────────────────────────────────────────────────────────
test('TEST 4a [synthetic]: an intermediate with cA=FALSE → reject (not used as a CA in the path)', async () => {
  const jades = makeJades({ leafCert: 'leaf-under-notca.cert.pem', leafKey: 'leaf-under-notca.key.pem', chain: ['notca.cert.pem', 'root.cert.pem'] });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  TEST4a [cA=FALSE]', r.status, '|', r.reason);
  // RFC 5280 §6: a cA=FALSE cert cannot be a path issuer. node's checkIssued already refuses to accept a
  // non-CA as issuer (probed: returns false), so the chain cannot be built through `notca` → not anchored.
  // (The validator ALSO has an explicit basicConstraints cA=TRUE check as defense-in-depth behind this.)
  assert.equal(r.status, 'not_qualified');
});

test('TEST 4b [synthetic]: pathLenConstraint violated (sub-CA below a pathlen:0 issuing CA) → reject', async () => {
  const jades = makeJades({ leafCert: 'leaf-pathlen.cert.pem', leafKey: 'leaf-pathlen.key.pem', chain: ['subca.cert.pem', 'issuing.cert.pem', 'int.cert.pem', 'root.cert.pem'] });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  TEST4b [pathLen]', r.status, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
  assert.match(r.reason, /pathLenConstraint/);
});

test('TEST 4c [synthetic]: broken name-chain (issuer cert absent / not the real issuer) → reject (not anchored)', async () => {
  // x5c = [leaf4, root] but leaf4 is issued by `issuing`, NOT root → no valid issuer link to walk.
  const jades = makeJades({ leafCert: 'leaf4.cert.pem', leafKey: 'leaf4.key.pem', chain: ['root.cert.pem'] });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: SIGNING_ISO, trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  TEST4c [name-chain]', r.status, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
});

test('TEST 4d [synthetic]: a path cert expired at signing time → reject', async () => {
  const jades = makeJades({ leafCert: 'leaf4.cert.pem', leafKey: 'leaf4.key.pem', chain: ['issuing.cert.pem', 'int.cert.pem', 'root.cert.pem'] });
  const r = await validateQes({ signedCanonical: CANONICAL, signature: sigOf(jades), validationTime: '2099-01-01T00:00:00Z', trust: { tslXml: tlGranting(['root.cert.pem']) } });
  console.log('  TEST4d [expired]', r.status, '|', r.subIndication);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'EXPIRED');
});
