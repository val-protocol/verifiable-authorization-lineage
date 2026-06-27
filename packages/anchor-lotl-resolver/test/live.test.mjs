// Live integration — gated by RUN_LIVE=1 (network: EU LOTL + member-state TSL). Not part of the default
// offline suite. Proves the resolver works against the *live* EU Trusted List end-to-end.
//   RUN_LIVE=1 node --test test/live.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { resolveAnchorTrustLive, parseTokenChain } from '../src/index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TOKEN = readFileSync(join(HERE, 'fixtures', 'sectigo-qualified-token.b64'), 'utf8').trim();

test('resolveAnchorTrustLive: resolves the Sectigo token against the live EU LOTL → ES TSL', { skip: process.env.RUN_LIVE !== '1' }, async () => {
  const res = await resolveAnchorTrustLive({ tstBase64: TOKEN });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.spkis[0], parseTokenChain(TOKEN).signerSpkiB64);
  assert.match(res.tslUrl, /\.xml$/);
  assert.equal(res.evidence.serviceTypeIdentifier, 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST');
});
