# VAL v0.1 — Lineage Invariant

## 5. Lineage Invariant

### 5.1 Statement

For every block `B` in any chain `C` where `B.block_type` is neither `ASSIGNMENT` nor `ANCHOR`:

1. `B.parent_assignment_hash` MUST be non-null and MUST reference, by hash, an `ASSIGNMENT` block `A` previously committed within `C` (or cross-chain per §5.4).
2. Walking `A.parent_assignment_hash` recursively MUST terminate, in finite steps, at an `ASSIGNMENT` block `A_root` such that:
   - `A_root.principal` designates a human (per §5.2), and
   - `A_root.parent_assignment_hash` is null.
3. The walk MUST be bounded; v0.1 sets the maximum depth at 16. An assignment chain longer than 16 is rejected as ill-formed.

### 5.2 Human-Principal Designation — Conformance Profiles

The lineage invariant in §5.1 requires the root ASSIGNMENT to be signed by a human principal. VAL defines three conformance profiles that differ in how strongly the human designation is bound. A chain operates under exactly one profile per `chain_scope` at any point in time; migrations between profiles are permitted and produce a profile-change record (mechanism reserved for v0.2).

**Profile A — operator-attested, chained.** The root ASSIGNMENT is signed by the operator's service key on behalf of an authenticated human user identified by an operator-namespaced URI. The operator-attested human designation is a typed attribute in the ASSIGNMENT content (`human_attestation = { method: "session", subject_user_hash: <hex>, attested_at: <unix> }`, §4.4) and forms part of the canonical hash. The verifier accepts the operator's attribution as authoritative at root but verifies that attribution is itself in the tamper-evident chain — meaning the operator cannot revise the designation post-hoc without breaking integrity. *Residual trust:* the operator's runtime attribution at the moment of chain emission. *Verifier statement:* "every action traces to a human-attributed authorization within the tamper-evident chain." Achievable in any deployment today without natural-person PKI dependency.

**Profile B — declarative identity, device-bound (live).** The root ASSIGNMENT is signed by a WebAuthn/FIDO2 **biometric device key** (Face ID / passkey) under the human delegator's control. The human's identity is **declarative** (a self-asserted name); the binding is the cryptographic **device-key signature**. The verifier validates the WebAuthn assertion (`verifyDelegatorSignature`) and chains the key to the enrolled, self-attested org-root key (`verifyDelegationTrustChain`). *Residual trust:* the declarative name↔person link — **key-control is proven, legal identity is not**. *Verifier statement:* "every action traces to a device-key-signed authorization by a self-declared human." Implemented in the reference verifier today.

**Profile C — eIDAS conformity (pending).** The root ASSIGNMENT is signed under a **qualified eIDAS** mechanism (QES / qualified certificate / EAA, EU 910/2014) asserting an **identity-proofed** natural person; the verifier validates the signature against a QTSP trust list. *Residual trust:* the QTSP. *Verifier statement:* "every action traces to a qualified-eIDAS-signed authorization by an identity-proofed natural person." The reference verifier **classifies** Profile C by algorithm but its QTSP-anchored verification is a future trust-anchor input (returns `qualified_unverified`).

**Delegator authority (`human_attestation.delegator_authority`) — REQUIRED as of ASSIGNMENT body v2.** The human designation answers *who* authorized; the delegator-authority carrier answers *with what standing*: it records, on the ASSIGNMENT block itself, the authority basis under which the attesting human could grant the delegated scope — `{ basis, capability, scope_ref, signature? }`, where `capability` is an operator-namespaced authority-tier identifier and `scope_ref` names the container the authority is scoped to. Given the operator's capability policy (a trust-anchor input, §7.1(d)), an offline verifier checks `scope.act ⊆ policy[capability]` — a holder of read-only authority cannot have delegated write actions, whatever the operator's runtime claimed (Pass 5, §7.2). **Version gate:** ASSIGNMENT bodies with `v ≥ 2` MUST carry `delegator_authority`; a v2 block without it fails Pass 5. Bodies with `v = 1` predate the carrier and are tolerated as legacy — verifiers MUST count and report them, and conforming producers MUST NOT emit new v1 ASSIGNMENT bodies. **The `signature` sub-field by profile:** under Profile A it is absent and the authority claim carries the profile's operator-attested residual trust; under **Profile B it carries the delegator's WebAuthn device-key signature** (live), making the claim trustless as to key-control; under **Profile C** it carries a qualified eIDAS signature (classified, QTSP verification pending). The slot is profile-additive — no chain migration, no body-shape change across profiles.

**Per-action signatures (sign-class).** Beyond the root binding, *sign-class* (CONSENT) actions carry their own cryptographic signature — a WebAuthn assertion bound to `{document_hash, parent_assignment_hash, principal}` — verified per-action by the reference verifier's CONSENT pass (§7.4). A qualified (QES) per-action signature is the Profile-C form (classified, QTSP verification pending). The verifier therefore evaluates, beyond Profile A's root-presence check, the **Profile B device-key signature at the root** and the **per-action CONSENT signature** where present.

Profiles B and C are the protocol's strong forms — the verifier reaches its conclusion without trusting the operator's runtime at all. Profile A is a transitional deployment mode that nonetheless delivers a strict upgrade over tamper-evident-logging-only: the verifier evaluates lineage and scope from chain bytes, with only the human-designation-at-root falling back to operator attribution (and that attribution itself recorded in the chain). Operators using Profile A SHOULD publish a roadmap to Profile B or C and SHOULD NOT describe Profile A chains as "human-signed" in external positioning; the precise term is "human-attributed."

**Equivalence to Verifiable Intent's signing model.** VI (verifiableintent.dev) REQUIRES cryptographic
user-key signing at its Layer 2 from day one — structurally equivalent to VAL Profile B/C (a human-key-signed
root). VAL ships Profile A (operator-attributed) and **Profile B (WebAuthn device-key-signed root, live)**
today, with Profile C (qualified eIDAS) pending. On the **root-signing axis, VAL Profile B is now
structurally equivalent to VI's user-key signing**; VAL's differentiation is the **six action classes,
persistence (statutory retention), the four-property single-pass verification, and the non-payment
regulated-agreement domain**. Positioning that implies VAL is "ahead of VI on cryptographic signing" is
false and MUST NOT be used.

The verifier's output (§7.3) MUST include the conformance profile of the chain's root ASSIGNMENT.

### 5.3 Schema-Level Enforcement

The `parent_assignment_hash` field is a **chain-hash reference**, not a foreign key into a mutable table. The verifier resolves the reference by searching the chain for an ASSIGNMENT block whose computed hash matches; no out-of-chain lookup is performed. This is a deliberate property: it means the verifier never trusts a mutable application-layer table to mediate the lineage. Implementations that today store lineage via a foreign key into a mutable assignments / tasks table MUST migrate this to a chain-hash reference for VAL compliance.

Implementations SHOULD enforce `parent_assignment_hash` non-null at the persistence layer (database NOT-NULL constraint, append trigger, or equivalent) for the affected block types. The protocol's verifier rejects orphan blocks regardless of storage enforcement, but storage enforcement prevents an honest operator from accidentally emitting an unverifiable chain.

### 5.4 Cross-Chain References (reserved)

A non-assignment block in chain `C_a` MAY reference an `ASSIGNMENT` block in a different chain `C_b` via a cross-chain reference structure containing `(chain_scope_b, assignment_hash, witness_signature)`. The witness signature is by an operator or trust anchor known to both chains. Detailed mechanism is reserved for v0.2; two-sided isolated-workspace scenarios are the motivating use case.

### 5.5 Why this matters

The lineage invariant is the property that distinguishes verifiable *intent* from verifiable *action*. A chain that records actions with cryptographic integrity but does not enforce a structural binding to authorization is a tamper-evident log — strong, but reducible to "trust the operator's enforcement was correct, and the record of that enforcement is unforgeable." A chain that enforces the lineage invariant proves, without trusting the operator's runtime, that every action sits inside an authorization that traces to a human signature.

---
