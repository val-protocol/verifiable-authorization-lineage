/**
 * HMAC verification + replay-protection primitives for VAL signed-webhook deliveries.
 *
 * Design contract:
 *   - HMAC-SHA256 over the EXACT raw body bytes received (NOT a re-serialized JSON).
 *   - Constant-time signature comparison via crypto.timingSafeEqual (avoids
 *     string-comparison timing side-channels).
 *   - Multi-signature acceptance during rotation grace: accept ANY (v1, kid) pair
 *     in the header whose kid is in the receiver's known-secret set.
 *   - Timestamp window enforced before HMAC check (cheap pre-filter for replay storms).
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import type {
  ParsedSignatureHeader,
  Secret,
  VerifyOptions,
  VerifyResult,
} from './types.js';

/**
 * Parse the `Webhook-Signature` header.
 *
 * Format:
 *   t=<unix>,v1=<hex>,kid=<8hex>[,v1=<hex>,kid=<8hex>]
 *
 * The dual (v1, kid) form ships during a rotation grace window.
 */
export function parseSignatureHeader(headerValue: string): ParsedSignatureHeader | null {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return null;
  const segments = headerValue.split(',').map((s) => s.trim()).filter(Boolean);
  let timestamp: number | null = null;
  const signatures: { v1: string; kid: string }[] = [];

  // Pair up `v1=...,kid=...` segments in declaration order (signers emit them adjacent).
  let pendingV1: string | null = null;
  for (const seg of segments) {
    const eq = seg.indexOf('=');
    if (eq < 0) return null;
    const k = seg.slice(0, eq);
    const v = seg.slice(eq + 1);
    if (k === 't') {
      const n = Number(v);
      if (!Number.isInteger(n) || n <= 0) return null;
      timestamp = n;
    } else if (k === 'v1') {
      if (!/^[0-9a-f]+$/.test(v)) return null;
      pendingV1 = v;
    } else if (k === 'kid') {
      if (!/^[0-9a-f]+$/.test(v)) return null;
      if (pendingV1 === null) return null;
      signatures.push({ v1: pendingV1, kid: v });
      pendingV1 = null;
    } else {
      // Unknown segment — ignore for forward-compat, do not reject.
    }
  }
  if (timestamp === null || signatures.length === 0) return null;
  return { timestamp, signatures };
}

/**
 * Constant-time hex comparison.
 *
 * Naive `a === b` on hex strings leaks length + early-match through V8 short-
 * circuit semantics. Convert to Buffer + timingSafeEqual. Mismatched lengths
 * return false without comparison (timingSafeEqual throws on length mismatch).
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Compute the canonical HMAC for a delivery: HMAC_SHA256(secret, `<t>.<body>`).
 *
 * The `<t>.<body>` shape mirrors the common signed-payload convention. This is the
 * ONE source of truth for the signing input — receivers and signers must compute it identically.
 */
export function computeHmacSha256Hex(secret: string, timestamp: number, body: string): string {
  return createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
}

/**
 * Verify a webhook delivery against the receiver's secret store.
 *
 * Algorithm:
 *   1. Parse `Webhook-Signature` header. Reject if malformed.
 *   2. Reject if abs(now - signature.timestamp) > tolerance (default 5 min).
 *   3. For each (v1, kid) pair, look up the secret by kid.
 *      - If kid not in secret set → skip (do NOT short-circuit; we want
 *        constant-time over the whole set when a single kid mismatches).
 *      - Else compute HMAC and constant-time-compare. Accept on match.
 *   4. If no pair verified → reject.
 *
 * Returns `{ ok: true, matchedKid, timestamp }` on success.
 */
export function verifyWebhook(options: VerifyOptions): VerifyResult {
  const parsed = parseSignatureHeader(options.signatureHeader);
  if (!parsed) {
    return { ok: false, reason: 'malformed_signature_header' };
  }
  const tolerance = options.timestampToleranceSeconds ?? 300;
  const now = (options.now ?? (() => Math.floor(Date.now() / 1000)))();
  if (Math.abs(now - parsed.timestamp) > tolerance) {
    return {
      ok: false,
      reason: 'timestamp_outside_window',
      detail: `now=${now} sig.timestamp=${parsed.timestamp} tolerance=${tolerance}s`,
    };
  }
  const secretByKid = new Map<string, string>();
  for (const s of options.secrets) secretByKid.set(s.kid, s.secret);

  let anyKidKnown = false;
  for (const sig of parsed.signatures) {
    const secret = secretByKid.get(sig.kid);
    if (!secret) continue;
    anyKidKnown = true;
    const expected = computeHmacSha256Hex(secret, parsed.timestamp, options.body);
    if (timingSafeEqualHex(expected, sig.v1)) {
      return { ok: true, matchedKid: sig.kid, timestamp: parsed.timestamp };
    }
  }
  if (!anyKidKnown) {
    return { ok: false, reason: 'no_secret_matches_kid' };
  }
  return { ok: false, reason: 'no_signature_verifies' };
}

/**
 * Derive a kid from a secret using the reference algorithm:
 * kid = sha256(secret_utf8_bytes).slice(0, 8).
 *
 * Convenience for receivers that load secrets from env vars and want to
 * cross-check the kid the operator configured vs the kid in the delivery
 * header.
 */
export function deriveKidFromSecret(secret: string): string {
  const fullHex = createHmac('sha256', '').update('').digest('hex'); // sanity invocation
  // The real derivation: SHA-256 of the secret string (not HMAC, just hash).
  // Per webhook signing convention, kid = sha256(secret)[0:8].
  // We need crypto.createHash('sha256') here, not createHmac.
  const { createHash } = require('node:crypto') as typeof import('node:crypto');
  void fullHex;
  return createHash('sha256').update(secret, 'utf8').digest('hex').slice(0, 8);
}
