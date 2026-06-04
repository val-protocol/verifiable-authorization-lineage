# @val-protocol/chain-verifier — CHANGELOG

## 0.1.0 — 2026-06-04

Initial public release under the `@val-protocol` scope. Offline verifier for
VAL hash-chained authorization-lineage ledgers.

### Features

- **Offline integrity** — recomputes SHA-256 over the canonical preimage
  (`scope_key|sequence_number|event_type|canonical_details|previous_hash`, spec §4.3);
  verifies `previous_hash` linkage and contiguous `sequence_number` ordering across
  the chain; no network, no DB, no vendor runtime.
- **Lineage** — walks each non-ASSIGNMENT block's `parent_assignment_hash` to a
  human-rooted ASSIGNMENT bearing `human_attestation` (Profile A); rejects orphan
  blocks and chains deeper than 16 hops.
- **Scope** — enforces the `in_workspace` container predicate and per-block
  `resource`/`scope.res` consistency; including the §6.4 Merkle isolation-membership
  check on ACCESS blocks via `computeMembershipRoot` / `verifyMembershipProof`.
- **Grounding (read-before-derive)** — a MUTATION's cited `grounded_document_hashes`
  must each appear as a `content_hash` in a prior ACCESS by the same principal in
  the chain.
- **`verifyChain` + `verifyValChain`** — emits conformance profile A
  (operator-attested).
- **Zero runtime dependencies** — Node `crypto` only.

### Tests

`node:test` (stdlib) coverage of integrity, lineage, scope, grounding, and the
Merkle membership path.
