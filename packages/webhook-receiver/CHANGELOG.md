# @val-protocol/webhook-receiver — CHANGELOG

## 0.1.0 — 2026-06-04

Initial public release under the `@val-protocol` scope. Reference signed-webhook receiver for VAL chain-event deliveries.

### Features

- **HMAC-SHA256 verification** with constant-time comparison (`crypto.timingSafeEqual`).
- **Rotation grace** — dual `(v1, kid)` pair acceptance during the secret-rotation window.
- **Timestamp window** — configurable replay-protection pre-filter (default ±300s).
- **In-memory nonce cache** — keyed on `sha256(timestamp.body)`, prunes after TTL. Interface seam (`ReplayCache`) for Redis / etcd swap in multi-instance deployments.
- **Family-prefixed event router** — splits `event.type` on the first dot, dispatches to a family handler, `unknown` fallback.
- **Chain field extraction** — pulls `chain_event_id`, `sequence_number`, `chain_hash`, `previous_hash` from `event.data`.
- **`verifyChainLink()` helper** — assert `previous_hash === priorEvent.chain_hash` for receivers chaining multiple events.
- **Reference HTTP server** — `node:http` (no Express dep), `/health` + `/webhook` endpoints, structured JSON logging on stdout.
- **CLI** — `val-webhook-receiver` binary reads env, starts the server.
- **Zero runtime dependencies** — Node stdlib only.

### Tests

`node:test` (stdlib) unit + integration coverage of the verification, replay, rotation, routing, and server paths.
