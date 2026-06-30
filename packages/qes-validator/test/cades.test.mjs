// CAdES (.p7m / detached CMS) front-end — synthetic coverage (the front-end + the binding trap + routing).
// The downstream pipeline (RFC 5280 path → TL anchor → QcStatements) is the SAME proven code as JAdES;
// these tests prove the CAdES FRONT-END produces the right { x5c, signedBytes-bound, signatureValue }.
//
// TEST 1 (the milestone — real TrustPro qualified .p7m → qualified:true) is OPERATOR-SUPPLIED and lives in
// trustpro-real.cades.test.mjs (skips until the operator drops test/fixtures/trustpro-real.p7m). It is NOT
// faked here: SSL.com is US/AATL and these openssl fixtures are synthetic. See findings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate, createHash } from 'node:crypto';
import { validateQes } from '../dist/esm/index.js';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const p7mB64 = (f) => readFileSync(join(FX, f)).toString('base64');
const derB64 = (f) => new X509Certificate(readFileSync(join(FX, f))).raw.toString('base64');
// the EXACT bytes the .p7m was signed over (gen.sh: grant-canonical.bin)
const CANONICAL = '{"v":2,"block_type":"ASSIGNMENT","scope":{"act":["record.append"]}}';
const tlGrantRoot = () => `<TrustServiceStatusList><TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
  <ServiceName><Name xml:lang="en">Test Granted QC CA</Name></ServiceName>
  <ServiceDigitalIdentity><DigitalId><X509Certificate>${derB64('root.cert.pem')}</X509Certificate></DigitalId></ServiceDigitalIdentity>
  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
  <StatusStartingTime>2015-01-01T00:00:00Z</StatusStartingTime>
  <ServiceInformationExtensions><Extension><AdditionalServiceInformation><URI>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension></ServiceInformationExtensions>
</ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;
const skip = existsSync(join(FX, 'cades-qualified.p7m')) ? false : 'run gen.sh (needs openssl) to make .p7m fixtures';

test('CAdES synthetic positive: detached CMS over the grant canonical → parse + verify + bind + qualified', { skip }, async () => {
  const r = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: p7mB64('cades-qualified.p7m') }, trust: { tslXml: tlGrantRoot() } });
  console.log('  [cades qualified]', r.status, '|', r.adesLevel, '|', r.reason.slice(0, 80));
  assert.equal(r.status, 'qualified'); // signature verified over signedAttributes, messageDigest bound, path→TL anchor, QcStatements
  assert.match(r.adesLevel, /^CAdES/); // routed to the CAdES front-end
  assert.equal(r.anchorFingerprint, createHash('sha256').update(new X509Certificate(readFileSync(join(FX, 'root.cert.pem'))).raw).digest('hex'));
});

test('CAdES digest-agnostic bind: SHA-384 messageDigest over the canonical → binds (no SHA-256 assumption)', { skip }, async () => {
  // signatureFolder's digest is tool-configurable (SHA-256/384/512). The bind must read the CMS
  // digestAlgorithm and hash the canonical with IT — a SHA-384 .p7m must bind, not false-fail.
  const r = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: p7mB64('cades-qualified-sha384.p7m') }, trust: { tslXml: tlGrantRoot() } });
  console.log('  [cades sha384]', r.status, '|', r.adesLevel, '|', r.subIndication ?? 'bound');
  assert.notEqual(r.subIndication, 'HASH_FAILURE', 'SHA-384 messageDigest must bind (read the CMS digestAlgorithm, do not assume SHA-256)');
  assert.equal(r.status, 'qualified');
});

test('CAdES ENVELOPED: embedded content == canonical → extracted, bound, qualified', { skip }, async () => {
  const r = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: p7mB64('cades-enveloped.p7m') }, trust: { tslXml: tlGrantRoot() } });
  console.log('  [cades enveloped]', r.status, '|', r.adesLevel, '|', r.subIndication ?? 'bound');
  assert.equal(r.status, 'qualified'); // content extracted from eContent, messageDigest bound, embedded==canonical
});

test('CAdES ENVELOPED negative: embedded content != canonical → HASH_FAILURE (different document)', { skip }, async () => {
  const r = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: p7mB64('cades-enveloped-wrong.p7m') }, trust: { tslXml: tlGrantRoot() } });
  console.log('  [cades enveloped-wrong]', r.status, '|', r.subIndication, '|', r.reason.slice(0, 80));
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'HASH_FAILURE'); // a qualified sig over a different embedded doc must NOT bind
});

test('CAdES binding trap: qualified .p7m over DIFFERENT bytes (not the grant canonical) → HASH_FAILURE', { skip }, async () => {
  // the .p7m is a valid qualified signature, but over "other content" — messageDigest != SHA-256(canonical)
  const r = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: p7mB64('cades-wrongbytes.p7m') }, trust: { tslXml: tlGrantRoot() } });
  console.log('  [cades wrong-bytes]', r.status, '|', r.subIndication, '|', r.reason.slice(0, 90));
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'HASH_FAILURE'); // a qualified sig over the wrong bytes must NOT validate as bound
});

test('CAdES tamper: flip a byte of the CMS signatureValue → SIG_CRYPTO_FAILURE', { skip }, async () => {
  const der = readFileSync(join(FX, 'cades-qualified.p7m'));
  const t = Buffer.from(der);
  t[t.length - 5] ^= 0xff; // last bytes are inside the signature OCTET STRING
  const r = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: t.toString('base64') }, trust: { tslXml: tlGrantRoot() } });
  console.log('  [cades tamper]', r.status, '|', r.subIndication);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'SIG_CRYPTO_FAILURE');
});

test('format routing: a CAdES blob → CAdES front-end; a JAdES blob → JAdES front-end; both reach the shared pipeline', { skip }, async () => {
  const cades = await validateQes({ signedCanonical: CANONICAL, signature: { alg: 'eidas_qes', signature: p7mB64('cades-qualified.p7m') }, trust: { tslXml: tlGrantRoot() } });
  assert.match(cades.adesLevel, /^CAdES/, 'CMS DER routed to CAdES');

  if (existsSync(join(FX, 'dss-emitted.jades.b64'))) {
    const jadesB64 = readFileSync(join(FX, 'dss-emitted.jades.b64'), 'utf8').trim();
    const r = await validateQes({ signedCanonical: readFileSync(join(FX, 'dss-emitted.canonical.json'), 'utf8'), signature: { alg: 'eidas_qes', signature: jadesB64 }, trust: { tslXml: tlGrantRoot() } });
    console.log('  [routing] cades=', cades.adesLevel, '| jades=', r.adesLevel);
    assert.match(r.adesLevel, /^JAdES/, 'JWS compact routed to JAdES');
  }
});
