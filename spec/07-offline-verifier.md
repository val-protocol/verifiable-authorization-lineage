# VAL v0.1 — Offline Verifier

## 7. Offline Verifier

### 7.1 Inputs

The verifier takes (a) chain bytes over one or more `chain_scope` ranges, (b) a trust anchor describing acceptable signing public keys for principals appearing in the chain, (c) optionally, a QTSP trust list for verifying anchor blocks, (d) optionally, a **delegator-authority policy** — a mapping from the operator's capability identifiers to the action names a holder of that capability may delegate (consumed by Pass 5), and (e) optionally, **bytes-binding disclosures** — for one or more documents, the bytes the verifying party holds plus the producer-side `nonce` disclosed in an evidence bundle (consumed by Pass 6). Like the QTSP trust list, inputs (d) and (e) are obtained and pinned independently of the chain bytes; without (d), Pass 5 still enforces carrier presence on v2 ASSIGNMENT bodies but cannot evaluate scope-versus-authority; without (e), Pass 6 reports `not_evaluated`. None of these is an operator secret: a disclosure's `nonce` ships in the evidence bundle, not from a live call to the operator, and collision-resistance makes it a self-authenticating witness rather than a trust dependency.

### 7.2 Procedure

The verifier executes six passes; passes 1–3 are mandatory, passes 4, 5, and 6 are conditional.

**Pass 1 — Integrity.** Walk blocks in sequence order. For each block: recompute its `chain_hash` from the canonical preimage (§4.3); verify `previous_hash` matches the preceding block's `chain_hash`. Stop on first failure. Output: `integrity = green | red`, `first_break_at = <seq> | n/a`. *(VAL v0.1 defines no per-block signature in the wire format (§4.3); root human-binding strength is a conformance-profile property, §5.2.)*

**Pass 2 — Lineage.** For each block `B` of type not in `{ASSIGNMENT, ANCHOR}`: resolve `B.parent_assignment_hash`; assert the referenced ASSIGNMENT exists in the supplied chain bytes; recurse `parent_assignment_hash` up to root; assert root's principal is human per §5.2; assert depth ≤ 16. Output: `lineage = green | red`, `first_orphan_at = <seq> | n/a`.

**Pass 3 — Scope.** For each non-assignment block `B`: compute the effective scope of `B.parent_assignment_hash` (transitive intersection per §6.7); evaluate satisfaction per §6.6; if not satisfied, fail. Output: `scope = green | red`, `first_violation_at = <seq> | n/a`.

**Pass 4 — Anchor (optional).** For each ANCHOR block: recompute the Merkle root from the blocks in `batch_range`; assert equality with `payload.batch_root`; verify `payload.tst_bytes` against the QTSP trust list. Output: `anchor = green | red | none`.

**Pass 5 — Delegator authority.** For each ASSIGNMENT block (root or sub-assignment, whatever surface minted it): if the body version is ≥ 2, assert `human_attestation.delegator_authority` is present — absence fails the pass; if the body version is 1 and the carrier is absent, count the block as pre-carrier legacy without failing. For each block carrying the carrier, when the delegator-authority policy (§7.1(d)) is supplied: resolve `policy[delegator_authority.capability]` — an unknown capability fails the pass; assert `scope.act ⊆` the resolved delegable-action set — any excess action fails the pass (authority escalation: the ASSIGNMENT delegates more than its issuer could grant). When the carrier's reserved `signature` sub-field is populated (Profiles B/C), the verifier additionally validates it against the profile's trust anchor; under Profile A the slot is absent and the authority claim carries the profile's operator-attested residual. Output: `authority = green | red | none`, `legacyPreAuthorityAssignmentCount = <uint>`. `none` means no ASSIGNMENT in the verified range engaged the pass.

**Well-known basis `container_owner` — re-derived where the chain permits.** `basis` values are operator-namespaced, but `container_owner` is RESERVED by this spec for the standing "the attesting human owns the from-scratch, participant-less container this ASSIGNMENT scopes" (e.g. a send/share container created by its sender). Because the claim is about the chain's own subjects, two checks are re-derivable from chain bytes alone, and a conforming verifier MUST apply them to every carrier with this basis — independent of whether a §7.1(d) policy is supplied: (a) `delegator_authority.scope_ref` MUST equal the ASSIGNMENT's `scope.res.in_workspace` — the claimed authority is scoped to the very container the ASSIGNMENT scopes; (b) for each COMMUNICATION block whose `parent_assignment_hash` is this ASSIGNMENT and whose `principal` is a human (`user:<id>`), `SHA-256(<id>)` MUST equal the ASSIGNMENT's `human_attestation.subject_user_hash` — the act was performed by the attested owner, not relabelled. Either failure fails the pass. An `agent:` principal has no second chain occurrence of the delegating human to cross-check; its ownership claim carries the Profile-A operator-attested residual like any other basis, until the Profile B/C `signature` binding ships. Implemented in the reference verifier as of `@val-protocol/chain-verifier` 0.3.0.

**Pass 6 — Bytes-binding (optional).** For each MUTATION carrying `bytes_commitment` (§4.4): if a bytes-binding disclosure (§7.1(e)) is supplied for the block's `resource.resource_id`, compute `c' = SHA-256(disclosed_bytes)`, then `C' = SHA-256("val.bytes-commitment.v1" ‖ 0x00 ‖ disclosed_nonce ‖ c')`, and assert `C'` equals the block's `bytes_commitment.value`. The verifier hashes the disclosed bytes itself — it MUST NOT accept a caller-supplied hash in place of the bytes. Output: `bytesBinding = bound | mismatch | not_evaluated`. `bound` = at least one commitment was disclosed and every disclosed one reproduced; `mismatch` = a disclosed commitment failed to reproduce (the bytes in hand are not the committed document) — sticky, a later match does not clear it; `not_evaluated` = no MUTATION carried both a commitment and a matching disclosure. This pass is the **bytes-binding rail**: it answers "the content-address on the chain *is this document in hand*," a property distinct from grounding ("the actor read content-address X before deriving from it", §7.5) — the two are orthogonal. A commitment with no disclosure, or a disclosure for an uncommitted block, is `not_evaluated` and **never fails** the verdict; bytes-binding is opt-in and additive. Because the on-chain `value` is a *hiding* commitment (the nonce is producer-side, never on chain or in any export), an exported chain reveals nothing about the bytes and is not a cross-tenant confirmation oracle. Implemented in the reference verifier as of `@val-protocol/chain-verifier` 0.7.0.

### 7.3 Output

A verification report — the `ValVerificationResult` shape the reference verifier (`@val-protocol/chain-verifier`) returns, as a JSON object:

```
{
  "integrity":              "green" | "red",
  "lineage":                "green" | "red",
  "scope":                  "green" | "red",
  "grounding":              "green" | "red",
  "authority":              "green" | "red" | "none",
  "conformanceProfile":     "A" | "B" | "C" | "unknown",
  "firstLineageViolation":  { "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "firstScopeViolation":    { "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "firstGroundingViolation":{ "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "firstAuthorityViolation":{ "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "legacyPreAuthorityAssignmentCount": <uint>,
  "nonValBlockCount":       <uint>
}
```

This is the shape the reference implementation emits today; the external-anchor pass (§7.2 pass 4) is not reflected because the ANCHOR block type is not yet implemented (§7.4). A deployment that wraps the report for transport MAY add envelope fields (verifier identity, timestamp, a signature over the report); those are not part of the reference output.

All four properties green (integrity, lineage, scope, grounding) — plus `authority` green or `none` (Pass 5) — is the protocol's affirmative statement. The semantic content of "lineage green" depends on the conformance profile per §5.2: under Profile A, it means every action traces to a human-attributed authorization within the tamper-evident chain; under Profiles B and C, it means every action traces to a cryptographically-signed authorization by an identified natural person. Verifier consumers MUST read the `conformanceProfile` field alongside the lineage result to interpret the residual-trust statement correctly.

### 7.4 Reference Implementation

`@val-protocol/chain-verifier` (Apache-2.0) is the protocol's reference implementation. Passes 1 (integrity), 2 (lineage), and 3 (scope — including the §6.4 Merkle isolation-membership check) ship as `verifyChain` + `verifyValChain`, alongside a **grounding** re-derivation (§7.5): a MUTATION that cites `grounded_document_hashes` must cite content the same principal already read (via a prior ACCESS) in the chain — re-derived from the chain bytes alone, independent of any substrate enforcement.

The reference verifier distinguishes **conformance profiles A, B, and C** (§5.2). Profile A (operator-attested, chained) is bound by the *presence* of `human_attestation` at the root; **Profile B (WebAuthn device key) is fully verified** — the delegator signature is cryptographically checked (`verifyDelegatorSignature`) and chained to the enrolled, self-attested org-root key (`verifyDelegationTrustChain`); **Profile C (qualified / eIDAS) is classified by algorithm but not yet trust-verified** — it returns `qualified_unverified`, pending a QTSP trust list. **CONSENT and COMMUNICATION carry dedicated verifier passes** (a per-action signature check and a container-owner re-derivation respectively) and are verified if present, though the reference producer does not emit them. **Pass 4 (anchor) and the SETTLEMENT block type are not yet implemented** — `verifyValChain` skips ANCHOR blocks, and SETTLEMENT is recognized only for generic lineage/scope. A conforming implementation MAY emit any reserved type ahead of this reference. The block types shipped end-to-end (reference producer + verifier) today are ASSIGNMENT, ACCESS, and MUTATION.

**Pass 6 (bytes-binding)** ships in `verifyValChain` as of `@val-protocol/chain-verifier` 0.7.0 via the optional `bytesDisclosures` input (§7.1(e)), reporting `bytesBinding` (`bound` / `mismatch` / `not_evaluated`). It is opt-in and additive: it never affects the four core properties, and a verifier predating it ignores the `bytes_commitment` field per the §4.4 unknown-field rule.

### 7.5 Property → reference-function traceability

Each property the verifier asserts maps to a specific function in `@val-protocol/chain-verifier`. **Profile-A** binding is the *presence* of `human_attestation` at the root ASSIGNMENT (§5.2), not a cryptographic verification; **Profile B** additionally performs a cryptographic check of the delegator signature (`verifyDelegatorSignature`, WebAuthn/ECDSA-P256) chained to the org-root key, and the CONSENT pass verifies the per-action signature bound to `{document_hash, parent_assignment_hash, principal}`. **Profile C** (qualified / eIDAS) is classified by algorithm but its QTSP-anchored verification is a future trust-anchor input (`qualified_unverified`).

| Property | Re-derived by | What it checks |
|---|---|---|
| Integrity | `verifyChain` | genesis (`sequence_number=1 ⇒ previous_hash=null`), `previous_hash` linkage, and per-row SHA-256 of the §4.3 pipe-preimage |
| Lineage | `verifyValChain` → `walkLineage` | every non-ASSIGNMENT/ANCHOR block walks `parent_assignment_hash` to a root ASSIGNMENT bearing `human_attestation`; depth ≤ 16; orphan / non-human-root ⇒ red |
| Scope | `verifyValChain` → `satisfies` | `principal` / `action ∈ scope.act` / container match over the lineage path's intersected scope, including the §6.4 `verifyMembershipProof` Merkle isolation check on ACCESS blocks |
| Grounding | `verifyValChain` (read-before-derive) | for every MUTATION citing a non-empty `grounded_document_hashes`, each hash MUST appear as a `content_hash` in a **prior ACCESS by the same `principal` in this chain** — else grounding ⇒ red. A MUTATION with no/empty `grounded_document_hashes` is green (the actor declares it is not content-derived). v0.1 **replaces** the earlier type/scope-flag formulation with this domain-neutral property and **removes** the doc-scope consistency check; same-`parent_assignment_hash` co-location is a reserved v0.2 strengthening |
| Authority | `verifyValChain` (Pass 5) | every v2 ASSIGNMENT body MUST carry `human_attestation.delegator_authority` (absence ⇒ red); with the §7.1(d) policy supplied, `scope.act ⊆ policy[capability]` (unknown capability or excess action ⇒ red); v1 pre-carrier bodies are tolerated and counted in `legacyPreAuthorityAssignmentCount`. For the reserved `container_owner` basis, two chain-byte re-derivations apply policy-independently: `scope_ref == scope.res.in_workspace`, and `SHA-256` of a rooted COMMUNICATION's `user:` principal id `== subject_user_hash` (either mismatch ⇒ red). The reserved `signature` sub-field is the Profile B/C binding slot — unvalidated (absent) under Profile A |
| Bytes-binding | `verifyValChain` (Pass 6) | for each MUTATION carrying `bytes_commitment`, when a §7.1(e) disclosure is supplied for its `resource_id`: re-derive `SHA-256("val.bytes-commitment.v1" ‖ 0x00 ‖ nonce ‖ SHA-256(bytes))` from the disclosed bytes (the verifier hashes the bytes itself, never a supplied hash) and compare to the on-chain `value` ⇒ `bound` / `mismatch` (sticky). No commitment or no disclosure ⇒ `not_evaluated`, never a failure. Opt-in, additive (`bytesDisclosures` input). Distinct from grounding: binds the content-address to the document *in hand*, where grounding is read-before-derive. The on-chain commitment is *hiding* (nonce off-chain) so an export is not a cross-tenant oracle |

`reconstructChainHash` builds the §4.3 preimage; `computeMembershipRoot` / `verifyMembershipProof` implement the §6.4 Merkle membership. CBOR, magic bytes, single-byte type codes, and per-block signatures named in earlier drafts of §4 are **not** present in the reference implementation and are not part of v0.1.

---
