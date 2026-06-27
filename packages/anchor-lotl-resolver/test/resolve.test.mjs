// Offline unit suite for @val-protocol/anchor-lotl-resolver.
// Real data, no network: a real Sectigo qualified RFC 3161 token + the real Spain (ES) TSL QTST/granted
// service block extracted from the live EU Trusted List (2026-06-27). Proves the resolver derives the
// anchorTrust SPKI set from the token + LOTL bound to the granted CA identity at genTime — NOT a pinned
// leaf — and fails closed on a non-granted / wrong-CA list.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  parseTokenChain,
  matchGrantedQtst,
  resolveAnchorTrust,
} from '../src/index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TOKEN = readFileSync(join(HERE, 'fixtures', 'sectigo-qualified-token.b64'), 'utf8').trim();
const TSL = readFileSync(join(HERE, 'fixtures', 'sectigo-es-qtst-service.xml'), 'utf8');

test('parseTokenChain: extracts genTime, qualified CA chain, and leaf signer SPKI', () => {
  const t = parseTokenChain(TOKEN);
  assert.ok(Number.isFinite(t.genTime), 'genTime parsed');
  assert.equal(new Date(t.genTime).getUTCFullYear(), 2026);
  assert.match(t.leaf.subject, /Sectigo Qualified Time Stamping Signer #3/);
  assert.match(t.caCert.subject, /Sectigo Qualified Time Stamping CA R35/);
  assert.equal(t.caCert.subject, t.leaf.issuer, 'CA is the leaf issuer');
  assert.equal(t.countryCode, 'ES');
  assert.ok(t.signerSpkiB64.startsWith('MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A'), 'RSA-4096 SPKI b64');
});

test('matchGrantedQtst: token CA == a QTST/granted service on the ES Trusted List, granted at genTime', () => {
  const t = parseTokenChain(TOKEN);
  const r = matchGrantedQtst(TSL, t.caFingerprintSha256, t.genTime);
  assert.equal(r.matched, true);
  assert.equal(r.granted, true);
  assert.equal(r.grantedAtGenTime, true, 'StatusStartingTime <= genTime');
  assert.match(r.serviceName, /Sectigo Qualified Time Stamping CA R35/);
  assert.ok(r.statusStartingTimeMs < t.genTime, 'granted before the token genTime');
});

test('resolveAnchorTrust: returns the resolved signer SPKI set (not a hardcoded leaf) + evidence', () => {
  const t = parseTokenChain(TOKEN);
  const res = resolveAnchorTrust({ tstBase64: TOKEN, tslXml: TSL });
  assert.equal(res.ok, true);
  assert.equal(res.spkis.length, 1);
  assert.equal(res.spkis[0], t.signerSpkiB64, 'resolved SPKI == the token signer SPKI');
  assert.equal(res.evidence.serviceTypeIdentifier, 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST');
  assert.equal(res.evidence.serviceStatus, 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted');
  assert.equal(res.evidence.countryCode, 'ES');
});

test('resolveAnchorTrust: fails closed when the CA is NOT on the granted list (status withdrawn)', () => {
  const withdrawn = TSL.replace(
    'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
    'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn',
  );
  const res = resolveAnchorTrust({ tstBase64: TOKEN, tslXml: withdrawn });
  assert.equal(res.ok, false);
  assert.equal(res.spkis.length, 0);
});

test('resolveAnchorTrust: fails closed when the grant is in the FUTURE (StatusStartingTime after genTime)', () => {
  const future = TSL.replace(
    /<(?:[a-z0-9]+:)?StatusStartingTime>[\s\S]*?<\/(?:[a-z0-9]+:)?StatusStartingTime>/i,
    '<StatusStartingTime>2030-01-01T00:00:00Z</StatusStartingTime>',
  );
  const res = resolveAnchorTrust({ tstBase64: TOKEN, tslXml: future });
  assert.equal(res.ok, false);
  assert.equal(res.spkis.length, 0); // no trust returned
  assert.match(res.reason, /not granted at genTime/);
});

test('resolveAnchorTrust: fails closed on a wrong-CA / non-matching trusted list (empty list)', () => {
  const res = resolveAnchorTrust({ tstBase64: TOKEN, tslXml: '<TrustServiceStatusList></TrustServiceStatusList>' });
  assert.equal(res.ok, false);
  assert.equal(res.spkis.length, 0); // no trust returned
  assert.match(res.reason, /no QTST\/granted service certificate matched/);
});

test('cross-check: resolver reproduces the chain-verifier pinned SPKI WITHOUT the pin (closes C6)', () => {
  // The verifier fixture pins a scraped leaf SPKI (the C6 defect). The resolver derives the same SPKI
  // from the token + LOTL, bound to the granted CA identity — so the brittle pin is no longer load-bearing.
  const fx = JSON.parse(
    readFileSync(join(HERE, '..', '..', 'chain-verifier', 'test', 'fixtures', 'anchor-fixtures.json'), 'utf8'),
  );
  const pinned = fx.tsas.find((t) => t.name === 'sectigo-qualified').spkis[0];
  const res = resolveAnchorTrust({ tstBase64: TOKEN, tslXml: TSL });
  assert.equal(res.ok, true);
  assert.equal(res.spkis[0], pinned, 'resolver-derived anchorTrust SPKI == the verifier-pinned SPKI');
});
