/**
 * @val-protocol/webhook-receiver — public exports.
 *
 * The package serves two consumption modes:
 *
 *   1. LIBRARY MODE — integrators with an existing HTTP server import the
 *      verification primitives and wire them into their own routes.
 *
 *        import {
 *          verifyWebhook,
 *          InMemoryReplayCache,
 *          routeEvent,
 *          extractChainFields,
 *          verifyChainLink,
 *        } from '@val-protocol/webhook-receiver';
 *
 *   2. SERVER MODE — integrators run the bundled `val-webhook-receiver`
 *      binary (or import { createReceiverServer } to embed it). Reads
 *      VAL_WEBHOOK_SECRET_PRIMARY/KID_PRIMARY (+ optional SECONDARY pair
 *      during rotation grace) from env and listens on PORT (default 4321).
 *
 * Both modes share the same verification semantics:
 *   - HMAC-SHA256 over the EXACT raw body received (no JSON re-serialization)
 *   - Constant-time signature comparison (crypto.timingSafeEqual)
 *   - Timestamp window (default ±300s) before HMAC check
 *   - Replay protection via in-memory nonce cache (timestamp+body hash)
 *   - Multi-signature acceptance during rotation grace (any matching kid wins)
 *
 * Verification is re-derivable by the receiver from the delivery bytes + its
 * configured secrets alone — no trust in the sender at receive time.
 */
export {
  parseSignatureHeader,
  computeHmacSha256Hex,
  timingSafeEqualHex,
  deriveKidFromSecret,
  verifyWebhook,
} from './verify.js';
export { InMemoryReplayCache } from './replay-cache.js';
export type { ReplayCache } from './replay-cache.js';
export {
  routeEvent,
  extractChainFields,
  familyOf,
  verifyChainLink,
} from './router.js';
export { createReceiverServer, main } from './server.js';
export type {
  Secret,
  SignaturePair,
  ParsedSignatureHeader,
  VerifyOptions,
  VerifyResult,
  ChainFields,
  WebhookEnvelope,
  EventFamily,
  FamilyHandler,
  RouterHandlers,
} from './types.js';
