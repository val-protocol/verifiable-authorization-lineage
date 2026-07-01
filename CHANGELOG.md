# Changelog

All notable changes to the VAL reference packages (`@val-protocol/*`) are documented here. Packages follow [semantic versioning](https://semver.org/); the specification is versioned independently (currently draft v0.1).

## [0.10.0 — UNRELEASED] — 2026-07-01

- **`@val-protocol/chain-verifier` 0.10.0 (unpublished — publish is consent-gated)** — implements the 2026-07-01 spec amendments (report legibility, one release):
  - **`conformanceProfile` is now the FLOOR** (weakest profile among the chain's ASSIGNMENTs) — **BEHAVIOR CHANGE** for mixed-profile chains (previously the maximum, which let one qualified grant mask a chain of operator-attested ones). New additive `profilesPresent: ('A'|'B'|'C')[]` itemizes every profile observed (§5.2 per-lineage model, §7.3).
  - **`authorityCarriers`** (additive): every `delegator_authority` carrier surfaced verbatim — `{ sequenceNumber, basis, capability, attested_by?, session_ref? }` — so a report answers "who attested entitlement?" without reading raw blocks. Verbatim, never a judgement.
  - **Reserved basis `ceremony_session_delegated`** (§7.2 Pass 5): two policy-independent chain-byte re-derivations — `scope_ref == scope.res.in_workspace`, and the carrier MUST co-occur with a **qualified** delegator signature (account-less authority requires a qualified instrument). Additive — fires only on a basis no prior chain emitted.

## [Spec amendments — unreleased] — 2026-07-01

- **Spec** — §5.2: conformance profile is a **per-lineage** property read at each root ASSIGNMENT; a chain MAY carry mixed-profile lineages (replaces "exactly one profile per `chain_scope`"; withdraws the v0.2 profile-change record). §7.3: `conformanceProfile` becomes the **floor** across roots (a verifier MUST NOT round up) + new additive `profilesPresent` itemization; reference status noted (published verifier ≤ 0.9.x still reports the maximum — floor release pending).
- **Spec** — §7.1: new optional input **(f) QES validation verdicts** (caller-side, reference `@val-protocol/qes-validator` + EU Trusted List). §5.2 Profile C / §7.4 / §7.5 / README: Profile C is **verified** when a verdict is supplied (`authority_verified_qualified`) and classified `qualified_unverified` otherwise — documents the shipped two-package model (previously described as "pending").
- **Spec** — §7.2 Pass 5: reserved well-known basis **`ceremony_session_delegated`** (account-less hosted-ceremony delegation): two chain-byte re-derivations (`scope_ref == scope.res.in_workspace`; MUST co-occur with a qualified `delegator_authority.signature`), attestor named in-carrier (`attested_by`, `session_ref`); entitlement remains attested, never offline-proven. Verifier support pending; treated as an ordinary operator-namespaced label until then.

## [0.4.0] — 2026-06-14

- **`@val-protocol/chain-verifier` 0.4.0** — Profile B verification (spec §5.2): the reserved `delegator_authority.signature` slot is now cryptographically verified offline. A present WebAuthn assertion (ES256) is checked against its embedded key AND must chain to the enrolled, self-attested org-root (`org_root.self_signature` over `orgRootBindingChallenge(...)`, so `key_binding`/`identity_assurance` are tamper-evident; the delegation key must equal the org-root key). New report fields `signature` (`green`/`red`/`none`), `firstSignatureViolation`, `keyBinding` (`device_bound`/`syncable`, surfaced verbatim — never rounded up). `conformanceProfile` now reaches **B** (only on a verified+linked signature — no over-claim) and **C** (qualified algs classified; QTSP-anchored crypto verification reserved as a future trust input, never a silent default). New exports `verifyDelegatorSignature` / `verifyDelegationTrustChain` / `orgRootBindingChallenge`. Additive, zero runtime dependencies.
- **Spec** — §5.2 Profile B/C: org-root self-attestation, device-signature trust chain, `device_bound`/`syncable` key binding surfaced verbatim; conformance ladder A→B→C.

## [0.3.0] — 2026-06-11

- **`@val-protocol/chain-verifier` 0.3.0** — Pass 5: the reserved `container_owner` basis is re-derived from chain bytes where the chain permits (`scope_ref == scope.res.in_workspace`, policy-independent; a rooted COMMUNICATION's `user:` principal must hash to the attested `subject_user_hash`; `agent:` principals carry the Profile-A residual). Additive — the checks fire only on a basis no prior chain emitted.
- **Spec** — §7.2 Pass 5: reserved well-known basis `container_owner` with its two chain-byte re-derivations; §7.5 traceability row updated.

## [0.2.0] — 2026-06-11

- **`@val-protocol/chain-verifier` 0.2.0** — Pass 5 (delegator authority): every ASSIGNMENT's delegated scope checked against the delegator's declared authority (`human_attestation.delegator_authority`, REQUIRED on v2 bodies; `scope.act ⊆ policy[capability]` with the §7.1(d) policy input; v1 pre-carrier bodies tolerated + counted; reserved `signature` sub-field = Profile B/C binding slot). Additive API — existing callers unaffected.
- **`@val-protocol/chain-verifier-cli` 0.2.0** — initial release under the protocol scope (`val-verify` bin): file-mode and MCP-URL-mode row-by-row integrity verification of `audit.export` NDJSON chains, folded in from the vendor scope to complete the two-scope split. Depends on `@val-protocol/chain-verifier@^0.2.0`.
- **Spec** — §4.4 ASSIGNMENT body v2 + `delegator_authority`; §5.2 delegator-authority definition with version gate; §7.1(d) delegator-authority policy input; §7.2 Pass 5; §7.3 `authority` + `legacyPreAuthorityAssignmentCount` report fields; §7.5 traceability row.

## [0.1.0] — 2026-06-04

Initial public release of the VAL reference implementation under the `@val-protocol` scope.

- **`@val-protocol/chain-verifier`** — the offline verifier. Zero runtime dependencies (Node `crypto` only); pure SHA-256 against the canonical preimage (spec §4). Implements passes 1–3 (integrity, lineage, scope — including the §6.4 Merkle isolation-membership check) plus the grounding re-derivation, via `verifyChain` + `verifyValChain`. Emits conformance profile A.
- **`@val-protocol/webhook-receiver`** — reference signed-webhook receiver (delivery transport tooling; transport is §1.2 out-of-scope for the normative protocol). HMAC-SHA256 timing-safe verification, rotation-grace dual-signature acceptance, replay protection, family-prefixed routing, chain-field extraction. Zero runtime dependencies.
- **License: Apache-2.0** across spec and reference implementation — explicit patent grant, royalty-free, no contributor licensing agreement.
