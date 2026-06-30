// LEG 1 + LEG 3 — differential against a DSS-EMITTED JAdES (the real producer path: DSS 6.4 assemble
// over SSL.com's signHash value). This is the framing-gap killer: the JS validator must eat genuine DSS
// bytes (header order, the extra kid/x5t#o/typ/iat/crit headers, empty detached payload, sigD), not just
// this codebase's own JS-assembled JAdES. DSS is oracle/emitter only; the JS validator is what's tested.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { validateQes } from '../dist/esm/index.js';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const JADES = join(FX, 'dss-emitted.jades.b64');
const skip = existsSync(JADES) ? false : 'no DSS-emitted fixture (run scripts/qes/produce-dss-jades.ts with DSS:8085 + SSL.com)';

// A real, well-formed TL that grants a CA/QC-for-eSignatures service for an UNRELATED cert (the synthetic
// fixtures root) — i.e. a TL that does NOT list SSL.com. Forces the anchor decision onto the TL (Defect 2):
// SSL.com's chain walks to its real top, finds no TL match → not_qualified. (Was: trusted the x5c top.)
function stubTlWithoutSslcom() {
  const root = new X509Certificate(readFileSync(join(FX, 'root.cert.pem'))).raw.toString('base64');
  return `<TrustServiceStatusList><TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
    <ServiceName><Name xml:lang="en">Unrelated Test QC CA</Name></ServiceName>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>${root}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
    <StatusStartingTime>2015-01-01T00:00:00Z</StatusStartingTime>
    <ServiceInformationExtensions><Extension><AdditionalServiceInformation><URI>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension></ServiceInformationExtensions>
  </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;
}

function load() {
  const jadesB64 = readFileSync(JADES, 'utf8').trim();
  const canonical = readFileSync(join(FX, 'dss-emitted.canonical.json'), 'utf8');
  const compact = Buffer.from(jadesB64, 'base64').toString('utf8');
  const [protB64, payloadB64, sigB64] = compact.split('.');
  const header = JSON.parse(Buffer.from(protB64, 'base64url').toString('utf8'));
  const anchor = header.x5c[header.x5c.length - 1];
  return { jadesB64, canonical, compact, protB64, payloadB64, sigB64, header, anchor };
}

test('LEG 1: JS validator eats real DSS-emitted bytes — parse + sig-value verify + x5c path succeed', { skip }, async () => {
  const { jadesB64, canonical, header, anchor } = load();
  console.log('  DSS header keys:', Object.keys(header).join(','), '| crit:', JSON.stringify(header.crit));
  const r = await validateQes({
    signedCanonical: canonical,
    signature: { alg: 'eidas_qes', signature: jadesB64 },
    validationTime: header.iat ? new Date(header.iat * 1000).toISOString() : header.sigT,
    // FIXED (was `intermediateHintsDer:[anchor]` with no TL — which only "worked" because the old builder
    // treated the x5c top as the anchor). Now a real TL that does NOT list SSL.com is supplied; the verdict
    // is reached via TL-anchoring, not by trusting the bundle top.
    trust: { tslXml: stubTlWithoutSslcom(), intermediateHintsDer: [anchor] },
  });
  console.log('  [DSS-emitted]', r.status, '|', r.indication, '|', r.subIndication, '|', r.reason);
  // The framing-gap kill: NOT a parse failure and NOT a signature failure on real DSS bytes.
  assert.notEqual(r.subIndication, 'FORMAT_FAILURE', 'JS parser must eat DSS header/sigD/payload framing');
  assert.notEqual(r.subIndication, 'SIG_CRYPTO_FAILURE', 'JS must verify the real RSA signature DSS assembled');
  assert.ok(r.signatureRef && r.signatureRef.length === 64);
  // Honest outcome: SSL.com not on the TL → conclusive not_qualified, reached via TL-anchor (not x5c-top).
  assert.equal(r.qualified, false);
  assert.equal(r.status, 'not_qualified');
  assert.match(r.reason, /Trusted List|trust anchor|CA\/QC/i);
});

test('LEG 3a: tamper the DSS signature value → SIG_CRYPTO_FAILURE', { skip }, async () => {
  const { canonical, protB64, payloadB64, sigB64, header, anchor } = load();
  const sb = Buffer.from(sigB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  sb[15] ^= 0xff;
  const tampered = Buffer.from(`${protB64}.${payloadB64}.${sb.toString('base64url')}`).toString('base64');
  const r = await validateQes({ signedCanonical: canonical, signature: { alg: 'eidas_qes', signature: tampered }, validationTime: header.iat ? new Date(header.iat * 1000).toISOString() : header.sigT, trust: { intermediateHintsDer: [anchor] } });
  console.log('  [DSS sig-tamper]', r.status, '|', r.subIndication);
  assert.equal(r.subIndication, 'SIG_CRYPTO_FAILURE');
});

test('crit enforcement (RFC 7515): DSS crit:["sigD"] accepted; an unknown crit param is rejected', { skip }, async () => {
  const { jadesB64, canonical, protB64, payloadB64, sigB64, header, anchor } = load();
  const vt = header.iat ? new Date(header.iat * 1000).toISOString() : header.sigT;
  assert.deepEqual(header.crit, ['sigD'], 'DSS marks sigD critical');

  // (1) the real DSS JAdES (crit:["sigD"]) must STILL pass parse/verify (sigD is understood).
  const ok = await validateQes({ signedCanonical: canonical, signature: { alg: 'eidas_qes', signature: jadesB64 }, validationTime: vt, trust: { intermediateHintsDer: [anchor] } });
  assert.notEqual(ok.subIndication, 'FORMAT_FAILURE', 'understood crit (sigD) must not be rejected');

  // (2) inject an unknown crit param → must reject at parse stage (before the qualification gate).
  const hdr = { ...header, crit: ['sigD', 'x-evil'] };
  const evilProt = Buffer.from(JSON.stringify(hdr)).toString('base64url');
  const evil = Buffer.from(`${evilProt}.${payloadB64}.${sigB64}`).toString('base64');
  const r = await validateQes({ signedCanonical: canonical, signature: { alg: 'eidas_qes', signature: evil }, validationTime: vt, trust: { intermediateHintsDer: [anchor] } });
  console.log('  [crit x-evil]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.subIndication, 'FORMAT_FAILURE');
  assert.match(r.reason, /critical header|crit/i);
});

test('LEG 3b: tamper the signed canonical (detached "payload") → HASH_FAILURE (binding rejects)', { skip }, async () => {
  const { jadesB64, canonical, header, anchor } = load();
  const tamperedCanonical = canonical.replace('record.append', 'record.DELETE');
  assert.notEqual(tamperedCanonical, canonical, 'sanity: canonical actually mutated');
  const r = await validateQes({ signedCanonical: tamperedCanonical, signature: { alg: 'eidas_qes', signature: jadesB64 }, validationTime: header.iat ? new Date(header.iat * 1000).toISOString() : header.sigT, trust: { intermediateHintsDer: [anchor] } });
  console.log('  [DSS canonical-tamper]', r.status, '|', r.subIndication);
  assert.equal(r.subIndication, 'HASH_FAILURE'); // sigD hashV no longer matches sha256(tampered canonical)
});
