# VAL v0.1 — Offline Verifier

## 7. Offline Verifier

### 7.1 Inputs

The verifier takes (a) chain bytes over one or more `chain_scope` ranges, (b) a trust anchor describing acceptable signing public keys for principals appearing in the chain, and (c) optionally, a QTSP trust list for verifying anchor blocks.

### 7.2 Procedure

The verifier executes four passes; passes 1–3 are mandatory, pass 4 is conditional.

**Pass 1 — Integrity.** Walk blocks in sequence order. For each block: recompute its `chain_hash` from the canonical preimage (§4.3); verify `previous_hash` matches the preceding block's `chain_hash`. Stop on first failure. Output: `integrity = green | red`, `first_break_at = <seq> | n/a`. *(VAL v0.1 defines no per-block signature in the wire format (§4.3); root human-binding strength is a conformance-profile property, §5.2.)*

**Pass 2 — Lineage.** For each block `B` of type not in `{ASSIGNMENT, ANCHOR}`: resolve `B.parent_assignment_hash`; assert the referenced ASSIGNMENT exists in the supplied chain bytes; recurse `parent_assignment_hash` up to root; assert root's principal is human per §5.2; assert depth ≤ 16. Output: `lineage = green | red`, `first_orphan_at = <seq> | n/a`.

**Pass 3 — Scope.** For each non-assignment block `B`: compute the effective scope of `B.parent_assignment_hash` (transitive intersection per §6.7); evaluate satisfaction per §6.6; if not satisfied, fail. Output: `scope = green | red`, `first_violation_at = <seq> | n/a`.

**Pass 4 — Anchor (optional).** For each ANCHOR block: recompute the Merkle root from the blocks in `batch_range`; assert equality with `payload.batch_root`; verify `payload.tst_bytes` against the QTSP trust list. Output: `anchor = green | red | none`.

### 7.3 Output

A verification report — the `ValVerificationResult` shape the reference verifier (`@val-protocol/chain-verifier`) returns, as a JSON object:

```
{
  "integrity":              "green" | "red",
  "lineage":                "green" | "red",
  "scope":                  "green" | "red",
  "grounding":              "green" | "red",
  "conformanceProfile":     "A" | "B" | "C" | "unknown",
  "firstLineageViolation":  { "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "firstScopeViolation":    { "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "firstGroundingViolation":{ "sequenceNumber": <tstr>, "reason": <tstr> } | null,
  "nonValBlockCount":       <uint>
}
```

This is the shape the reference implementation emits today; the external-anchor pass (§7.2 pass 4) is not reflected because the ANCHOR block type is not yet implemented (§7.4). A deployment that wraps the report for transport MAY add envelope fields (verifier identity, timestamp, a signature over the report); those are not part of the reference output.

All four properties green (integrity, lineage, scope, grounding) is the protocol's affirmative statement. The semantic content of "lineage green" depends on the conformance profile per §5.2: under Profile A, it means every action traces to a human-attributed authorization within the tamper-evident chain; under Profiles B and C, it means every action traces to a cryptographically-signed authorization by an identified natural person. Verifier consumers MUST read the `conformanceProfile` field alongside the lineage result to interpret the residual-trust statement correctly.

### 7.4 Reference Implementation

`@val-protocol/chain-verifier` (Apache-2.0) is the protocol's reference implementation. Passes 1 (integrity), 2 (lineage), and 3 (scope — including the §6.4 Merkle isolation-membership check) ship as `verifyChain` + `verifyValChain`, alongside a **grounding** re-derivation (§7.5): a MUTATION that cites `grounded_document_hashes` must cite content the same principal already read (via a prior ACCESS) in the chain — re-derived from the chain bytes alone, independent of any substrate enforcement.

The reference verifier emits **conformance profile A** (operator-attested, chained). Profiles B and C are defined in §5.2 as the strong forms; the reference verifier does not yet distinguish them. **Pass 4 (anchor), and the CONSENT / COMMUNICATION / SETTLEMENT block types, are specified in this document but not yet implemented in the reference packages** — `verifyValChain` skips ANCHOR blocks, and the reference producer reserves the unshipped block types rather than emitting them. A conforming implementation MAY add them ahead of this reference. The block types shipped end-to-end today are ASSIGNMENT, ACCESS, and MUTATION.

### 7.5 Property → reference-function traceability

Each property the verifier asserts maps to a specific function in `@val-protocol/chain-verifier`. There is no per-block signature check anywhere in the reference verifier — Profile-A binding is the *presence* of `human_attestation` at the root ASSIGNMENT (§5.2), not a cryptographic verification.

| Property | Re-derived by | What it checks |
|---|---|---|
| Integrity | `verifyChain` | genesis (`sequence_number=1 ⇒ previous_hash=null`), `previous_hash` linkage, and per-row SHA-256 of the §4.3 pipe-preimage |
| Lineage | `verifyValChain` → `walkLineage` | every non-ASSIGNMENT/ANCHOR block walks `parent_assignment_hash` to a root ASSIGNMENT bearing `human_attestation`; depth ≤ 16; orphan / non-human-root ⇒ red |
| Scope | `verifyValChain` → `satisfies` | `principal` / `action ∈ scope.act` / container match over the lineage path's intersected scope, including the §6.4 `verifyMembershipProof` Merkle isolation check on ACCESS blocks |
| Grounding | `verifyValChain` (read-before-derive) | for every MUTATION citing a non-empty `grounded_document_hashes`, each hash MUST appear as a `content_hash` in a **prior ACCESS by the same `principal` in this chain** — else grounding ⇒ red. A MUTATION with no/empty `grounded_document_hashes` is green (the actor declares it is not content-derived). v0.1 **replaces** the earlier type/scope-flag formulation with this domain-neutral property and **removes** the doc-scope consistency check; same-`parent_assignment_hash` co-location is a reserved v0.2 strengthening |

`reconstructChainHash` builds the §4.3 preimage; `computeMembershipRoot` / `verifyMembershipProof` implement the §6.4 Merkle membership. CBOR, magic bytes, single-byte type codes, and per-block signatures named in earlier drafts of §4 are **not** present in the reference implementation and are not part of v0.1.

---
