# Changelog

All notable changes to the VAL reference packages (`@val-protocol/*`) are documented here. Packages follow [semantic versioning](https://semver.org/); the specification is versioned independently (currently draft v0.1).

## [0.2.0] — 2026-06-11

- **`@val-protocol/chain-verifier` 0.2.0** — Pass 5 (delegator authority): every ASSIGNMENT's delegated scope checked against the delegator's declared authority (`human_attestation.delegator_authority`, REQUIRED on v2 bodies; `scope.act ⊆ policy[capability]` with the §7.1(d) policy input; v1 pre-carrier bodies tolerated + counted; reserved `signature` sub-field = Profile B/C binding slot). Additive API — existing callers unaffected.
- **`@val-protocol/chain-verifier-cli` 0.2.0** — initial release under the protocol scope (`val-verify` bin): file-mode and MCP-URL-mode row-by-row integrity verification of `audit.export` NDJSON chains, folded in from the vendor scope to complete the two-scope split. Depends on `@val-protocol/chain-verifier@^0.2.0`.
- **Spec** — §4.4 ASSIGNMENT body v2 + `delegator_authority`; §5.2 delegator-authority definition with version gate; §7.1(d) delegator-authority policy input; §7.2 Pass 5; §7.3 `authority` + `legacyPreAuthorityAssignmentCount` report fields; §7.5 traceability row.

## [0.1.0] — 2026-06-04

Initial public release of the VAL reference implementation under the `@val-protocol` scope.

- **`@val-protocol/chain-verifier`** — the offline verifier. Zero runtime dependencies (Node `crypto` only); pure SHA-256 against the canonical preimage (spec §4). Implements passes 1–3 (integrity, lineage, scope — including the §6.4 Merkle isolation-membership check) plus the grounding re-derivation, via `verifyChain` + `verifyValChain`. Emits conformance profile A.
- **`@val-protocol/webhook-receiver`** — reference signed-webhook receiver (delivery transport tooling; transport is §1.2 out-of-scope for the normative protocol). HMAC-SHA256 timing-safe verification, rotation-grace dual-signature acceptance, replay protection, family-prefixed routing, chain-field extraction. Zero runtime dependencies.
- **License: Apache-2.0** across spec and reference implementation — explicit patent grant, royalty-free, no contributor licensing agreement.
