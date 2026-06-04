/**
 * Unit tests for HMAC verification + signature header parsing.
 *
 * Runner: node:test (stdlib). Run via `npm test` or
 * `node --test --import tsx test/verify.test.ts` directly.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createHash } from 'node:crypto';
import {
  computeHmacSha256Hex,
  deriveKidFromSecret,
  parseSignatureHeader,
  timingSafeEqualHex,
  verifyWebhook,
} from '../src/verify';

const FIXED_TS = 1700000000;
const BODY = '{"type":"send.created","id":"abc","created_at":"2026-01-01T00:00:00Z","data":{}}';
const SECRET_A = 'whsec_a'.padEnd(64, 'a');
const SECRET_B = 'whsec_b'.padEnd(64, 'b');
const KID_A = createHash('sha256').update(SECRET_A, 'utf8').digest('hex').slice(0, 8);
const KID_B = createHash('sha256').update(SECRET_B, 'utf8').digest('hex').slice(0, 8);

function sign(secret: string, ts: number, body: string): string {
  return createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
}

describe('parseSignatureHeader', () => {
  it('parses single (v1, kid) pair', () => {
    const h = `t=${FIXED_TS},v1=${'ab'.repeat(32)},kid=${KID_A}`;
    const parsed = parseSignatureHeader(h);
    assert.ok(parsed);
    assert.equal(parsed!.timestamp, FIXED_TS);
    assert.equal(parsed!.signatures.length, 1);
    assert.equal(parsed!.signatures[0].kid, KID_A);
  });

  it('parses dual (v1, kid) pairs in rotation-grace order', () => {
    const h = `t=${FIXED_TS},v1=${'ab'.repeat(32)},kid=${KID_A},v1=${'cd'.repeat(32)},kid=${KID_B}`;
    const parsed = parseSignatureHeader(h);
    assert.ok(parsed);
    assert.equal(parsed!.signatures.length, 2);
    assert.equal(parsed!.signatures[0].kid, KID_A);
    assert.equal(parsed!.signatures[1].kid, KID_B);
  });

  it('rejects malformed headers', () => {
    assert.equal(parseSignatureHeader(''), null);
    assert.equal(parseSignatureHeader('not_a_header'), null);
    assert.equal(parseSignatureHeader(`v1=${'ab'.repeat(32)},kid=${KID_A}`), null); // no t=
    assert.equal(parseSignatureHeader(`t=${FIXED_TS},kid=${KID_A}`), null); // kid before v1
    assert.equal(parseSignatureHeader(`t=${FIXED_TS},v1=NOT_HEX,kid=${KID_A}`), null);
    assert.equal(parseSignatureHeader(`t=-1,v1=${'ab'.repeat(32)},kid=${KID_A}`), null);
  });

  it('ignores unknown segments forward-compatibly', () => {
    const h = `t=${FIXED_TS},v2=future,v1=${'ab'.repeat(32)},kid=${KID_A}`;
    const parsed = parseSignatureHeader(h);
    assert.ok(parsed);
    assert.equal(parsed!.signatures.length, 1);
  });
});

describe('timingSafeEqualHex', () => {
  it('returns true on identical hex', () => {
    assert.equal(timingSafeEqualHex('abcd1234', 'abcd1234'), true);
  });
  it('returns false on differing hex', () => {
    assert.equal(timingSafeEqualHex('abcd1234', 'abcd1235'), false);
  });
  it('returns false on length mismatch (no throw)', () => {
    assert.equal(timingSafeEqualHex('abcd', 'abcd1234'), false);
  });
});

describe('verifyWebhook', () => {
  it('accepts a valid single-signature delivery', () => {
    const sig = sign(SECRET_A, FIXED_TS, BODY);
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: `t=${FIXED_TS},v1=${sig},kid=${KID_A}`,
      secrets: [{ kid: KID_A, secret: SECRET_A }],
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.matchedKid, KID_A);
      assert.equal(r.timestamp, FIXED_TS);
    }
  });

  it('rejects invalid signature on otherwise-known kid', () => {
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: `t=${FIXED_TS},v1=${'00'.repeat(32)},kid=${KID_A}`,
      secrets: [{ kid: KID_A, secret: SECRET_A }],
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'no_signature_verifies');
  });

  it('rejects on unknown kid (no secret matches)', () => {
    const sig = sign(SECRET_A, FIXED_TS, BODY);
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: `t=${FIXED_TS},v1=${sig},kid=deadbeef`,
      secrets: [{ kid: KID_A, secret: SECRET_A }],
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'no_secret_matches_kid');
  });

  it('rejects timestamp outside window (replay layer 1)', () => {
    const sig = sign(SECRET_A, FIXED_TS, BODY);
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: `t=${FIXED_TS},v1=${sig},kid=${KID_A}`,
      secrets: [{ kid: KID_A, secret: SECRET_A }],
      now: () => FIXED_TS + 600, // 10 min ahead
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'timestamp_outside_window');
  });

  it('accepts dual-signature during rotation grace — primary kid wins', () => {
    const sigA = sign(SECRET_A, FIXED_TS, BODY);
    const sigB = sign(SECRET_B, FIXED_TS, BODY);
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: `t=${FIXED_TS},v1=${sigA},kid=${KID_A},v1=${sigB},kid=${KID_B}`,
      secrets: [{ kid: KID_A, secret: SECRET_A }], // only primary known
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.matchedKid, KID_A);
  });

  it('accepts dual-signature during rotation grace — secondary kid wins', () => {
    const sigA = sign(SECRET_A, FIXED_TS, BODY);
    const sigB = sign(SECRET_B, FIXED_TS, BODY);
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: `t=${FIXED_TS},v1=${sigA},kid=${KID_A},v1=${sigB},kid=${KID_B}`,
      secrets: [{ kid: KID_B, secret: SECRET_B }], // only new kid known
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.matchedKid, KID_B);
  });

  it('rejects body-tamper attempts (HMAC mismatch on modified body)', () => {
    const sig = sign(SECRET_A, FIXED_TS, BODY);
    const tampered = BODY.replace('send.created', 'send.TAMPER');
    const r = verifyWebhook({
      body: tampered,
      signatureHeader: `t=${FIXED_TS},v1=${sig},kid=${KID_A}`,
      secrets: [{ kid: KID_A, secret: SECRET_A }],
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'no_signature_verifies');
  });

  it('rejects malformed signature header', () => {
    const r = verifyWebhook({
      body: BODY,
      signatureHeader: 'this_is_garbage',
      secrets: [{ kid: KID_A, secret: SECRET_A }],
      now: () => FIXED_TS,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'malformed_signature_header');
  });
});

describe('deriveKidFromSecret', () => {
  it('matches sha256(secret)[0:8]', () => {
    assert.equal(deriveKidFromSecret(SECRET_A), KID_A);
    assert.equal(deriveKidFromSecret(SECRET_B), KID_B);
  });
});

describe('computeHmacSha256Hex', () => {
  it('signs `<t>.<body>` shape', () => {
    const expected = createHmac('sha256', SECRET_A).update(`${FIXED_TS}.${BODY}`).digest('hex');
    assert.equal(computeHmacSha256Hex(SECRET_A, FIXED_TS, BODY), expected);
  });
});
