// LEG 2 — live EU LOTL differential (gated by RUN_LIVE=1; network). Proves the JS resolver
// (findTslPointer + matchGrantedCaQc) handles REAL ETSI TS 119 612 XML — namespaces, AdditionalService-
// Information nesting — not just the hand-written stub TSL the unit suite uses. DSS-as-oracle set
// comparison is a separate Java harness (see scripts/qes-tsl-oracle); this leg proves the JS side eats
// real bytes and matches a real granted CA/QC-for-eSignatures service.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { findTslPointer } from '@val-protocol/anchor-lotl-resolver';
import { matchGrantedCaQc } from '../dist/esm/index.js';

const LOTL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';
const CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const FORESIG = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures';
const skip = process.env.RUN_LIVE === '1' ? false : 'live network test — set RUN_LIVE=1';
const pick = (x, t) => { const m = new RegExp(`<(?:[a-z0-9]+:)?${t}>([\\s\\S]*?)</(?:[a-z0-9]+:)?${t}>`, 'i').exec(x); return m ? m[1].trim() : null; };

test('LEG 2: findTslPointer resolves real member-state TSLs from the live EU LOTL', { skip }, async () => {
  const lotl = await (await fetch(LOTL)).text();
  for (const cc of ['EE', 'IT', 'FR', 'BE']) {
    const url = findTslPointer(lotl, cc);
    console.log(`  ${cc} →`, url);
    assert.ok(url && url.startsWith('http') && url.endsWith('.xml'), `real TSL pointer for ${cc}`);
  }
});

test('LEG 2: matchGrantedCaQc matches a REAL granted CA/QC-for-eSignatures service on the Estonia TSL', { skip }, async () => {
  const lotl = await (await fetch(LOTL)).text();
  const tslUrl = findTslPointer(lotl, 'EE');
  const tsl = await (await fetch(tslUrl)).text();

  // enumerate granted CA/QC-for-eSignatures services on the REAL TSL, grab one real cert
  const svcRe = /<(?:[a-z0-9]+:)?TSPService>([\s\S]*?)<\/(?:[a-z0-9]+:)?TSPService>/gi;
  let m, foresig = 0, firstCert = null;
  while ((m = svcRe.exec(tsl))) {
    const s = m[1];
    if (pick(s, 'ServiceTypeIdentifier') !== CA_QC) continue;
    if (pick(s, 'ServiceStatus') !== GRANTED) continue;
    if (!s.includes(FORESIG)) continue;
    foresig++;
    if (!firstCert) { const c = /<(?:[a-z0-9]+:)?X509Certificate>([\s\S]*?)<\/(?:[a-z0-9]+:)?X509Certificate>/i.exec(s); if (c) firstCert = c[1].replace(/\s+/g, ''); }
  }
  console.log(`  EE granted CA/QC-for-eSignatures services: ${foresig}`);
  assert.ok(foresig > 0, 'real TSL has granted CA/QC-for-eSig services (regex handles real namespaces/nesting)');
  assert.ok(firstCert, 'extracted a real service cert');

  const fp = createHash('sha256').update(Buffer.from(firstCert, 'base64')).digest('hex');
  // POSITIVE: the exported matcher matches a REAL granted CA/QC-eSig service at now.
  const hit = matchGrantedCaQc(tsl, fp, Date.now());
  console.log('  matchGrantedCaQc(real granted cert) →', hit.matched, '|', hit.serviceName);
  assert.equal(hit.matched, true);
  // NEGATIVE: a bogus fingerprint does not match (no false positive on real XML).
  assert.equal(matchGrantedCaQc(tsl, 'deadbeef'.repeat(8), Date.now()).matched, false);
});
