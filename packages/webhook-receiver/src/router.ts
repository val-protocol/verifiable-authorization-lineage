/**
 * Family-prefixed event router.
 *
 * Operators emit events with a family prefix (e.g. `resource.*`, `notification.*`,
 * `order.*`). Integrators typically want a different code path per family.
 *
 * The router parses `event.type`, splits on the first '.', dispatches to the
 * registered family handler. Unknown families route to `unknown` (or, if not
 * provided, are silently accepted — operators add new families forward-
 * compatibly).
 *
 * Chain fields (chain_event_id, sequence_number, chain_hash, previous_hash)
 * are extracted into a separate `chain` arg so handlers don't have to
 * re-parse `event.data`.
 */
import type {
  ChainFields,
  FamilyHandler,
  RouterHandlers,
  WebhookEnvelope,
} from './types.js';

export function extractChainFields(event: WebhookEnvelope): ChainFields {
  const data = event.data ?? {};
  const num = (v: unknown): number | null =>
    typeof v === 'number' && Number.isFinite(v)
      ? v
      : typeof v === 'string' && /^-?\d+$/.test(v)
        ? Number(v)
        : null;
  const str = (v: unknown): string | null =>
    typeof v === 'string' && v.length > 0 ? v : null;
  return {
    chain_event_id: str(data.chain_event_id),
    sequence_number: num(data.sequence_number),
    chain_hash: str(data.chain_hash),
    previous_hash: str(data.previous_hash),
  };
}

export function familyOf(eventType: string): string {
  const dot = eventType.indexOf('.');
  return dot < 0 ? eventType : eventType.slice(0, dot);
}

export async function routeEvent(
  event: WebhookEnvelope,
  handlers: RouterHandlers,
): Promise<{ family: string; routed: boolean; chain: ChainFields }> {
  const family = familyOf(event.type);
  const chain = extractChainFields(event);
  const handler: FamilyHandler | undefined =
    (handlers as Record<string, FamilyHandler | undefined>)[family] ?? handlers.unknown;
  if (handler) {
    await handler(event, chain);
    return { family, routed: true, chain };
  }
  return { family, routed: false, chain };
}

/**
 * Optional helper for receivers that chain multiple events from the same
 * chain: assert that `event.previous_hash === priorEvent.chain_hash`.
 *
 * Returns `{ ok: true }` on a clean link, `{ ok: false, reason }` on a
 * mismatch — the receiver decides whether to alert / discard / quarantine.
 *
 * Genesis case (priorEvent === null): expects previous_hash to be null.
 */
export function verifyChainLink(
  prior: { chain_hash: string | null } | null,
  current: { previous_hash: string | null },
): { ok: true } | { ok: false; reason: string; expected: string | null; observed: string | null } {
  const expected = prior?.chain_hash ?? null;
  const observed = current.previous_hash ?? null;
  if (expected === observed) return { ok: true };
  return {
    ok: false,
    reason: expected === null ? 'expected_genesis_link' : 'previous_hash_mismatch',
    expected,
    observed,
  };
}
