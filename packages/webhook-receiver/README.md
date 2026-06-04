# @val-protocol/webhook-receiver

> Reference webhook receiver for [Verifiable Authorization Lineage (VAL)](https://github.com/val-protocol/verifiable-authorization-lineage) chain-event deliveries. HMAC-SHA256 timing-safe verification with rotation grace, replay protection, family-prefixed event router, and chain-field extraction. **Zero runtime dependencies** — Node stdlib only (`crypto`, `http`).

This is **reference tooling**, not part of the normative protocol: VAL is transport-agnostic (spec §1.2), and signed webhooks are one delivery transport an operator MAY use. The package gives integrators a correct, verify-first receiver so they don't reinvent the easy-to-get-wrong parts. It pairs with [`@val-protocol/chain-verifier`](../chain-verifier) for end-to-end chain verification of the delivered events.

---

## Why a reference receiver?

A signed-webhook contract is easy to get subtly wrong. Integrators who roll their own verifier reliably miss one of:

- **Constant-time HMAC comparison** — naïve `===` on hex strings leaks length + early-match through V8 short-circuit semantics. Use `crypto.timingSafeEqual` on equal-length Buffers.
- **Timestamp window before HMAC** — cheap pre-filter against replay storms; reject `abs(now − sig.t) > 5min` BEFORE running expensive crypto.
- **Replay nonce cache** — the same `<timestamp, body>` arriving twice is an attempted replay; reject the second.
- **Rotation grace** — during a secret rotation, deliveries are dual-signed (`v1=<sig_old>,kid=<kid_old>,v1=<sig_new>,kid=<kid_new>`). The receiver must accept either.
- **Family-prefixed routing** — operators emit families (`resource.*`, `notification.*`, …) that are orthogonal concerns; route by family to keep handlers focused.
- **Chain-link verification** — propagate `chain_event_id`, `sequence_number`, `chain_hash`, `previous_hash` from `event.data` so the receiver can chain-verify consecutive events with `@val-protocol/chain-verifier`.

This package ships all of the above as a single Apache-2.0 npm dependency with `node:test` unit + integration coverage of the verification, replay, and rotation paths.

---

## Quickstart

### As a CLI

```bash
npm install -g @val-protocol/webhook-receiver
export VAL_WEBHOOK_SECRET_PRIMARY=<the signing secret from your operator>
export VAL_WEBHOOK_SECRET_KID_PRIMARY=<the 8-hex kid your operator shows you>
export PORT=4321
val-webhook-receiver
```

```text
{"ts":"2026-05-27T16:45:00Z","level":"info","msg":"webhook_receiver_listening","port":4321,"tolerance_seconds":300,"kids":["45e005f0"]}
```

Point your operator's webhook endpoint at `http://your-receiver:4321/webhook` (ngrok / Cloudflare Tunnel for local dev). Each delivery emits a structured JSON log line on stdout.

### As a library

```ts
import { verifyWebhook, InMemoryReplayCache, routeEvent, verifyChainLink } from '@val-protocol/webhook-receiver';

const replayCache = new InMemoryReplayCache();
const secrets = [
  { kid: process.env.VAL_WEBHOOK_SECRET_KID_PRIMARY!, secret: process.env.VAL_WEBHOOK_SECRET_PRIMARY! },
];

app.post('/webhook', async (req, res) => {
  const body = req.rawBody; // raw bytes — DO NOT re-serialize
  const verify = verifyWebhook({ body, signatureHeader: req.headers['webhook-signature'], secrets });
  if (!verify.ok) return res.status(401).json({ error: verify.reason });
  if (replayCache.checkAndRecord(verify.timestamp, body)) return res.status(409).json({ error: 'replay' });

  const event = JSON.parse(body);
  const { family, chain } = await routeEvent(event, {
    record: (e, c) => handleRecord(e, c),
    send: (e, c) => handleSend(e, c),
  });
  res.status(204).end();
});
```

---

## Wire format reference

### Signature header

```
Webhook-Signature: t=1700000000,v1=<64-hex>,kid=<8-hex>[,v1=<64-hex>,kid=<8-hex>]
```

- `t` — Unix epoch seconds at sign time
- `v1` — `HMAC_SHA256(secret, "<t>.<body>")` in lowercase hex
- `kid` — `sha256(secret).slice(0, 8)` — identifies which secret signed

Dual `v1=...,kid=...` segments ship during a rotation grace window following a secret rotation. The receiver accepts the delivery if **any** pair verifies.

### Envelope body

```json
{
  "type": "send.created",
  "id": "<event uuid>",
  "created_at": "2026-05-27T13:31:39.270Z",
  "data": {
    "chain_event_id": "<uuid>",
    "sequence_number": 1,
    "chain_hash": "<64-hex>",
    "previous_hash": "<64-hex>|null",
    "...family-specific fields...": null
  }
}
```

The four chain fields (`chain_event_id`, `sequence_number`, `chain_hash`, `previous_hash`) let the receiver chain-verify consecutive events with `@val-protocol/chain-verifier`. Optional side headers (`X-Webhook-Event-Id`, `X-Webhook-Event-Type`) duplicate the envelope's `id`/`type` for cheap pre-parse routing; the receiver falls back to the envelope when absent.

---

## Security considerations

| Concern | Mitigation |
|---|---|
| HMAC timing-attack | `crypto.timingSafeEqual` on equal-length Buffers (see `src/verify.ts:timingSafeEqualHex`). String `===` on hex is forbidden. |
| Replay attacks | timestamp window + in-memory nonce cache keyed on `sha256(t.body)`. |
| Secret rotation | dual-signature acceptance during the grace window. Set both `VAL_WEBHOOK_SECRET_PRIMARY` and `VAL_WEBHOOK_SECRET_SECONDARY`. |
| Multi-instance receivers | swap `InMemoryReplayCache` for a Redis-backed `ReplayCache` (interface seam in `src/replay-cache.ts`). |
| Body re-serialization | NEVER re-parse + re-stringify the body before the HMAC check. The signer signed exact bytes; the verifier MUST verify the exact same bytes. |
| Body size DoS | default 1 MB body limit in `src/server.ts:readBody`. Adjust for known-large event types. |

---

## Tests

```bash
npm test
```

`node:test` (stdlib) coverage of: single + dual signature parsing; rejection of malformed headers, bad sigs, unknown kids, out-of-window timestamps, body tamper; rotation-grace dual-sig acceptance; replay cache accept/reject/prune; family routing + chain-field extraction; `verifyChainLink` genesis/linked/mismatch; server `/health` + `/webhook` accept/reject/replay paths.

---

## Build artifacts

ESM + CJS dual-build (`dist/esm`, `dist/cjs`) + `.d.ts` (`dist/types`) for both legacy CommonJS and modern ESM integrators. CLI entrypoint in `bin/`.

---

## License

Apache-2.0. See [LICENSE](./LICENSE).
