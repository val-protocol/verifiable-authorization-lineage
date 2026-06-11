# @val-protocol/chain-verifier — CHANGELOG

## 0.2.0 — 2026-06-11

### Features

- **Pass 5 — delegator authority (spec §7.2, §5.2).** Every ASSIGNMENT's delegated
  scope is checked against its delegator's declared authority, recorded on the block
  as `human_attestation.delegator_authority = { basis, capability, scope_ref }`.
  - ASSIGNMENT body `v: 2` REQUIRES the carrier — a v2 block without it fails the pass.
  - With `options.delegatorAuthorityPolicy` (the §7.1(d) trust-anchor input — the
    operator's capability → delegable-action mapping, pinned by the verifying party
    independently of chain bytes), the pass asserts `scope.act ⊆ policy[capability]`;
    an unknown capability or any excess action is an authority-escalation failure.
  - Pre-carrier `v: 1` bodies are tolerated and counted
    (`legacyPreAuthorityAssignmentCount`) — chain bytes are immutable; conforming
    producers MUST NOT emit new v1 ASSIGNMENT bodies.
  - The carrier's `signature` sub-field is RESERVED for the Profile B/C cryptographic
    binding (trustless authority claims); absent under Profile A.
- New result fields: `authority: 'green' | 'red' | 'none'`, `firstAuthorityViolation`,
  `legacyPreAuthorityAssignmentCount`. New exports: `ValBlockDelegatorAuthority`,
  `DelegatorAuthorityPolicy`.

### Compatibility

- Additive only. `verifyValChain(rows)` call shape unchanged (`options` is a new,
  optional second parameter); passes 1–3 + grounding semantics untouched. v1 chains
  verify exactly as before, with `authority: 'none'` and a legacy count.

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
