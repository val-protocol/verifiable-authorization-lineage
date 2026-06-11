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

**Profile B — eIDAS-EAA bound.** The root ASSIGNMENT is signed by a key bound to an X.509 certificate carrying an Electronic Attestation of Attributes (EAA) under eIDAS Regulation EU 910/2014 asserting natural-personhood. The verifier validates the signature, validates the certificate against an eIDAS trust list, and accepts the natural-person attestation as authoritative. *Residual trust:* the QTSP that issued the EAA. *Verifier statement:* "every action traces to a cryptographically-signed authorization by an eIDAS-attested natural person."

**Profile C — natural-person DID.** The root ASSIGNMENT is signed by a key whose corresponding DID document includes a verifiable natural-person attribute (national eID binding, KYC-bound DID method, or equivalent). The verifier validates the signature against the DID document and accepts the natural-person attribute as authoritative. *Residual trust:* the DID method's issuance integrity. *Verifier statement:* "every action traces to a cryptographically-signed authorization by a DID-attested natural person."

**Delegator authority (`human_attestation.delegator_authority`) — REQUIRED as of ASSIGNMENT body v2.** The human designation answers *who* authorized; the delegator-authority carrier answers *with what standing*: it records, on the ASSIGNMENT block itself, the authority basis under which the attesting human could grant the delegated scope — `{ basis, capability, scope_ref, signature? }`, where `capability` is an operator-namespaced authority-tier identifier and `scope_ref` names the container the authority is scoped to. Given the operator's capability policy (a trust-anchor input, §7.1(d)), an offline verifier checks `scope.act ⊆ policy[capability]` — a holder of read-only authority cannot have delegated write actions, whatever the operator's runtime claimed (Pass 5, §7.2). **Version gate:** ASSIGNMENT bodies with `v ≥ 2` MUST carry `delegator_authority`; a v2 block without it fails Pass 5. Bodies with `v = 1` predate the carrier and are tolerated as legacy — verifiers MUST count and report them, and conforming producers MUST NOT emit new v1 ASSIGNMENT bodies. **The `signature` sub-field is RESERVED:** under Profile A it is absent and the authority claim carries the profile's operator-attested residual trust; under Profiles B/C it will carry the delegator's cryptographic signature binding the authority claim to a natural-person key, making the claim itself trustless. Reserving the slot now means the B/C upgrade is additive — no chain migration, no body-shape change.

**Per-action signatures (profile extensions, reserved).** The profiles above bind the human principal at the lineage *root*. Some deployments additionally require a cryptographic signature on individual *sign-class* (CONSENT) actions: a WebAuthn assertion (informally "Profile A+") or a Qualified Electronic Signature (QES, "Profile A++"); Profile B may further imply per-action national-scheme signing. These per-action signatures are **not** part of the v0.1 wire format (§4 defines no per-block signature field) and are reserved until the CONSENT block type ships in the reference implementation. Under v0.1, the only binding the verifier evaluates is the root `human_attestation` presence (Profile A); everything stronger is reserved.

Profiles B and C are the protocol's strong forms — the verifier reaches its conclusion without trusting the operator's runtime at all. Profile A is a transitional deployment mode that nonetheless delivers a strict upgrade over tamper-evident-logging-only: the verifier evaluates lineage and scope from chain bytes, with only the human-designation-at-root falling back to operator attribution (and that attribution itself recorded in the chain). Operators using Profile A SHOULD publish a roadmap to Profile B or C and SHOULD NOT describe Profile A chains as "human-signed" in external positioning; the precise term is "human-attributed."

**Equivalence to Verifiable Intent's signing model.** VI (verifiableintent.dev) REQUIRES cryptographic
user-key signing at its Layer 2 from day one — structurally equivalent to VAL Profile B/C (a human-key-signed
root). VAL deliberately ships Profile A first (operator-attributed) to be deployable without natural-person
PKI, then closes to B/C. So on the **root-signing axis, VI is already at VAL's strong form**; VAL's
differentiation is NOT the root signature but the **six action classes, persistence (statutory retention),
the four-property single-pass verification, and the non-payment regulated-agreement domain**. Positioning
that implies VAL is "ahead of VI on cryptographic signing" is false and MUST NOT be used.

The verifier's output (§7.3) MUST include the conformance profile of the chain's root ASSIGNMENT.

### 5.3 Schema-Level Enforcement

The `parent_assignment_hash` field is a **chain-hash reference**, not a foreign key into a mutable table. The verifier resolves the reference by searching the chain for an ASSIGNMENT block whose computed hash matches; no out-of-chain lookup is performed. This is a deliberate property: it means the verifier never trusts a mutable application-layer table to mediate the lineage. Implementations that today store lineage via a foreign key into a mutable assignments / tasks table MUST migrate this to a chain-hash reference for VAL compliance.

Implementations SHOULD enforce `parent_assignment_hash` non-null at the persistence layer (database NOT-NULL constraint, append trigger, or equivalent) for the affected block types. The protocol's verifier rejects orphan blocks regardless of storage enforcement, but storage enforcement prevents an honest operator from accidentally emitting an unverifiable chain.

### 5.4 Cross-Chain References (reserved)

A non-assignment block in chain `C_a` MAY reference an `ASSIGNMENT` block in a different chain `C_b` via a cross-chain reference structure containing `(chain_scope_b, assignment_hash, witness_signature)`. The witness signature is by an operator or trust anchor known to both chains. Detailed mechanism is reserved for v0.2; two-sided isolated-workspace scenarios are the motivating use case.

### 5.5 Why this matters

The lineage invariant is the property that distinguishes verifiable *intent* from verifiable *action*. A chain that records actions with cryptographic integrity but does not enforce a structural binding to authorization is a tamper-evident log — strong, but reducible to "trust the operator's enforcement was correct, and the record of that enforcement is unforgeable." A chain that enforces the lineage invariant proves, without trusting the operator's runtime, that every action sits inside an authorization that traces to a human signature.

---
