// REAL-ARTIFACT test — validates a JAdES signed by SSL.com's ACTUAL qualified key (no DSS; produced by
// rigacn/apps/backend/scripts/qes/produce-real-jades.ts via CSC signHash + JS assembly). This closes the
// "synthetic fixtures only" gap: it proves the pure-JS parser + RSA signature-value verification + x5c
// chain handling work on GENUINE signer bytes, not bytes this package constructed.
//
// SSL.com's demo cert is a US/AATL cert (NOT on the EU Trusted List), so qualified:true is correctly
// NOT expected — the value here is that parse + sig-crypto SUCCEED (we get PAST them to the
// qualification stage), which is the byte-compat fact the synthetic suite could not establish.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateQes } from '../dist/esm/index.js';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const JADES = join(FX, 'sslcom-real.jades.b64');

test('REAL SSL.com JAdES: parse + signature-value verify + x5c succeed on genuine signer bytes', { skip: existsSync(JADES) ? false : 'no real fixture (run scripts/qes/produce-real-jades.ts with SSL.com creds)' }, async () => {
  const jadesB64 = readFileSync(JADES, 'utf8').trim();
  const canonical = readFileSync(join(FX, 'sslcom-real.canonical.json'), 'utf8');

  // anchor = the top cert of the embedded x5c (so the real chain terminates), extracted from the artifact itself.
  const compact = Buffer.from(jadesB64, 'base64').toString('utf8');
  const header = JSON.parse(Buffer.from(compact.split('.')[0], 'base64url').toString('utf8'));
  const anchor = header.x5c[header.x5c.length - 1];

  const r = await validateQes({
    signedCanonical: canonical,
    signature: { alg: 'eidas_qes', signature: jadesB64 },
    validationTime: header.sigT,
    trust: { intermediateHintsDer: [anchor] }, // no EU TSL supplied → CA/QC stage cannot conclude
  });
  console.log('  [REAL ssl.com]', r.status, '|', r.indication, '|', r.subIndication, '|', r.reason);

  // The core proof: parse + signature-value verification PASSED on real DSS-shaped bytes — we are NOT
  // failing at FORMAT_FAILURE (parse) or SIG_CRYPTO_FAILURE (signature). signatureRef is computed.
  assert.notEqual(r.subIndication, 'FORMAT_FAILURE', 'real JAdES must PARSE');
  assert.notEqual(r.subIndication, 'SIG_CRYPTO_FAILURE', 'real RSA signature must VERIFY');
  assert.ok(r.signatureRef && r.signatureRef.length === 64, 'signatureRef computed over real bytes');
  // And it is honestly NOT qualified (US demo cert): either not_qualified (no QcStatements / not CA/QC)
  // or indeterminate (no EU TSL supplied) — but NEVER a false qualified:true.
  assert.equal(r.qualified, false);
  assert.notEqual(r.status, 'qualified');
});

test('REAL SSL.com JAdES, TAMPERED signature → SIG_CRYPTO_FAILURE (verify discriminates on real bytes)', { skip: existsSync(JADES) ? false : 'no real fixture' }, async () => {
  const jadesB64 = readFileSync(JADES, 'utf8').trim();
  const canonical = readFileSync(join(FX, 'sslcom-real.canonical.json'), 'utf8');
  const compact = Buffer.from(jadesB64, 'base64').toString('utf8');
  const [protB64, payloadB64, sigB64] = compact.split('.');
  const header = JSON.parse(Buffer.from(protB64, 'base64url').toString('utf8'));
  const anchor = header.x5c[header.x5c.length - 1];

  // Flip one byte of the REAL RSA signature value (decode b64url → mutate → re-encode), keep everything else.
  const sigBytes = Buffer.from(sigB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  sigBytes[20] ^= 0xff;
  const tamperedSig = sigBytes.toString('base64url');
  const tamperedCompact = `${protB64}.${payloadB64}.${tamperedSig}`;
  const tamperedJadesB64 = Buffer.from(tamperedCompact).toString('base64');

  const r = await validateQes({
    signedCanonical: canonical,
    signature: { alg: 'eidas_qes', signature: tamperedJadesB64 },
    validationTime: header.sigT,
    trust: { intermediateHintsDer: [anchor] },
  });
  console.log('  [REAL tampered]', r.status, '|', r.subIndication, '|', r.reason);
  assert.equal(r.status, 'not_qualified');
  assert.equal(r.subIndication, 'SIG_CRYPTO_FAILURE'); // real valid bytes verify; one flipped byte fails — discriminates
});
