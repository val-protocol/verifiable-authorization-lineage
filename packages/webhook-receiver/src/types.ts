/**
 * Types for the VAL webhook receiver reference implementation.
 *
 * The wire shape matches the VAL signed-webhook delivery contract:
 *   POST <integrator-url>
 *   Headers:
 *     Content-Type: application/json
 *     Webhook-Signature: t=<unix>,v1=<hex>,kid=<8hex>[,v1=<hex>,kid=<8hex>]
 *     X-Webhook-Event-Id: <uuid>
 *     X-Webhook-Event-Type: <family.verb>
 *     Idempotency-Key: <uuid>
 *   Body:
 *     {
 *       "type": "send.created",        // family-prefixed event type
 *       "id": "<event uuid>",
 *       "created_at": "<ISO timestamp>",
 *       "data": {
 *         "chain_event_id": "<uuid>",     // chain row id
 *         "sequence_number": 1,           // monotonic per (scope, scope_key)
 *         "chain_hash": "<64-hex>",       // SHA-256 of canonical event row
 *         "previous_hash": "<64-hex>|null", // prior chain_hash; null = genesis
 *         ...family-specific fields...
 *       }
 *     }
 */

export interface Secret {
  /** 8-hex kid identifying which secret signed this delivery.
   * kid = sha256(secret).slice(0, 8) identifies which secret signed. */
  kid: string;
  /** The HMAC-SHA256 signing secret (a `whsec_*`-style prefix is a common convention). */
  secret: string;
}

export interface SignaturePair {
  /** Hex HMAC value from the `v1=<hex>` segment. */
  v1: string;
  /** Hex kid from the `kid=<8hex>` segment. */
  kid: string;
}

export interface ParsedSignatureHeader {
  /** Unix timestamp (seconds) from `t=<unix>` segment. */
  timestamp: number;
  /** One or more (v1, kid) pairs. Multiple during rotation grace. */
  signatures: SignaturePair[];
}

export interface VerifyOptions {
  /** Raw HTTP body bytes (exactly as received — no JSON re-serialization). */
  body: string;
  /** Value of the `Webhook-Signature` header. */
  signatureHeader: string;
  /** All known signing secrets (primary + rotation grace). */
  secrets: Secret[];
  /** Replay protection window in seconds. Default 300 (5 minutes). */
  timestampToleranceSeconds?: number;
  /** Optional time override for deterministic tests. */
  now?: () => number;
}

export type VerifyResult =
  | {
      ok: true;
      /** Which kid was matched — for structured logging. */
      matchedKid: string;
      /** Parsed timestamp (epoch seconds). */
      timestamp: number;
    }
  | {
      ok: false;
      /** Machine-readable rejection reason. */
      reason:
        | 'malformed_signature_header'
        | 'timestamp_outside_window'
        | 'no_secret_matches_kid'
        | 'no_signature_verifies';
      /** Human-readable detail. */
      detail?: string;
    };

export interface ChainFields {
  chain_event_id: string | null;
  sequence_number: number | null;
  chain_hash: string | null;
  previous_hash: string | null;
}

export interface WebhookEnvelope {
  /** Family-prefixed event type, e.g. "send.created". */
  type: string;
  /** Per-event uuid for idempotency. */
  id: string;
  /** ISO timestamp at emit time. */
  created_at: string;
  /** Family-specific payload. Includes chain fields. */
  data: Record<string, unknown> & Partial<ChainFields>;
}

/**
 * An event family is the prefix of `event.type` before the first dot. Families are
 * operator-defined (e.g. `resource.*`, `notification.*`, `order.*`); the protocol does
 * not enumerate them. `familyOf` splits on the first dot.
 */
export type EventFamily = string;

/** Handler signature for family-prefixed event routing. */
export type FamilyHandler = (event: WebhookEnvelope, chain: ChainFields) => Promise<void> | void;

/**
 * Map of family name → handler. Operators register handlers for whichever families they
 * receive; `unknown` is the fallback for any family with no registered handler.
 */
export interface RouterHandlers {
  [family: string]: FamilyHandler | undefined;
  /** Fallback for any family with no registered handler. */
  unknown?: FamilyHandler;
}
