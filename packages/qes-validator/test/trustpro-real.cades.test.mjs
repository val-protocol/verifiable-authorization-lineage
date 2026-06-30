// TEST 1 — THE BUSINESS-GATE MILESTONE: a REAL TrustPro-qualified detached CAdES (.p7m) over the grant
// canonical → the first real qualified:true through our own validator, against the LIVE EU Trusted List.
//
// OPERATOR-SUPPLIED (cannot be synthesized — it needs your real TrustPro qualified cert). To run it:
//   1. In signatureFolder, sign the EXACT grant-canonical bytes as a DETACHED CAdES (.p7m).
//   2. Drop the file at        test/fixtures/trustpro-real.p7m
//      and the exact bytes at  test/fixtures/trustpro-real.canonical.json  (what you signed)
//   3. RUN_LIVE=1 node --test test/trustpro-real.cades.test.mjs   (fetches the live EU LOTL → IE TSL)
// Skips (does NOT fake) until the artifact is present. SSL.com is US/AATL and the openssl fixtures are
// synthetic — neither can stand in for a real EU-qualified cert.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateQes } from '../dist/esm/index.js';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const P7M = join(FX, 'trustpro-real.p7m');
const CANON = join(FX, 'trustpro-real.canonical.json');
const have = existsSync(P7M) && existsSync(CANON) && process.env.RUN_LIVE === '1';
const skip = have ? false : 'operator-supplied: drop trustpro-real.p7m + trustpro-real.canonical.json and set RUN_LIVE=1';

test('TEST 1 [REAL TrustPro cert, live EU LOTL]: detached CAdES over the grant canonical → qualified:true', { skip }, async () => {
  const p7m = readFileSync(P7M).toString('base64');
  const canonical = readFileSync(CANON, 'utf8');
  const r = await validateQes({
    signedCanonical: canonical,
    signature: { alg: 'eidas_qes', signature: p7m },
    // no tslXml → fetchLive resolves the EU LOTL → IE member-state TSL → TrustPro's granted CA/QC-for-eSig
    trust: { fetchLive: true },
  });
  console.log('  [TrustPro REAL]', r.status, '|', r.adesLevel, '|', r.reason);
  console.log('  signerIdentity:', JSON.stringify(r.signerIdentity));
  assert.equal(r.qualified, true, 'a real TrustPro qualified cert on the live EU TL must produce qualified:true');
  assert.equal(r.status, 'qualified');
  assert.match(r.adesLevel, /^CAdES/);
});
