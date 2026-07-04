# VAL Protocol v0.1 — Draft Specification

**Status:** Draft v0.1. Maintained by RIGA Solutions; open to multi-stakeholder contribution — see [CONTRIBUTING](../CONTRIBUTING.md).
**License:** This specification and its reference implementation are licensed under [Apache-2.0](../LICENSE).
**IPR commitment:** Royalty-free; the Apache-2.0 patent grant applies; no contributor licensing agreement required.

---


## Abstract

VAL specifies a wire format and verification procedure for binding actions — taken by humans or by AI agents acting on their behalf — to human-rooted authorizations, in a way an outside party can verify offline without trusting any operator. It fills the gap between authorization-issuance protocols (OAuth 2.0, JWT, RFC 8693) which prove a token was minted, and audit / SIEM systems which record actions, by introducing a typed, hash-chained, cryptographically-walkable lineage from every action back to a human-signed root authorization, with machine-checkable scope predicates evaluated at verification time.

Where Mastercard's Verifiable Intent makes the same property a centralized, payment-scoped service operated by a card network, VAL makes it a sovereign, jurisdictionally-neutral wire format and verifier any operator can adopt, in any regulatory regime, across six action classes (read, write, assign, sign, send, settle).

---

## 1. Scope

### 1.1 In scope

The protocol defines (a) the canonical wire format for attestation blocks, (b) the structural lineage invariant requiring every non-assignment block to trace to a human-signed root, (c) a minimal scope predicate language expressing what an authorization permits, (d) the offline verifier procedure, and (e) an optional external timestamp anchor mechanism over RFC 3161 / eIDAS QTSP.

### 1.2 Out of scope

Identity issuance — out of scope; VAL consumes identity artifacts, it does not issue them. Profiles B/C assume W3C DIDs, X.509 / eIDAS certificates, or compatible natural-person PKI; **Profile A requires none of these** — the human principal is operator-attested in-chain (§5.2). Transport — the format is transport-agnostic (HTTP, MCP, message queue, file). Storage layer — any append-only persistence; the format prescribes structure, not implementation. Runtime authorization decisions — operators may use FGA, OPA, Zanzibar, or anything; the protocol only constrains what is recorded, not how decisions are made. Payload confidentiality — payloads MAY be encrypted; the protocol covers integrity and authorization-lineage only.

---


## 2. Design Principles

**Trustless verification.** The verifier never trusts the chain operator. Every property an outside party asserts about the chain must be re-derivable from the chain bytes and a small set of public trust anchors (signing keys, QTSP trust list). This is the protocol's reason for existence; every other principle serves it.

**Sovereign by construction.** No central registry, no operator-in-the-loop, no protocol-level dependency on any one company, jurisdiction, or rail. A French notaire-tech, a Japanese accounting platform, and a US healthcare records vendor all run their own chains and verify with the same library. Where eIDAS QTSP anchoring is used, that's a local jurisdictional choice, not a protocol prerequisite.

**Confidentiality-compatible.** Payloads are content-addressed via hashes; encrypted payloads, payloads stored off-chain, and payloads exchanged out-of-band are all supported without modification to the format. The protocol proves *that authorized actions occurred*; what was authorized may be confidential.

**Typed but extensible.** v0.1 defines seven block types — six action classes (assignment, access, mutation, consent, communication, settlement) plus an anchor type. Of these, **assignment, access, and mutation ship end-to-end** (reference producer + verifier); the reference verifier additionally carries **dedicated passes for consent and communication** (verified if present, producer-reserved), while **settlement and anchor are not yet implemented** (§4.2). Future versions MAY add classes (revocation, attestation-of-attestation, cross-chain bridge) under a reserved type-code range.

**Minimal.** Verification is linear in chain length. The scope predicate language is decidable in time bounded by predicate size. No turing-complete evaluation, no SAT solver, no out-of-band lookups during verification.

**Interoperable with adjacent layers.** VAL coexists with AP2 / Universal Commerce Protocol (purchases), W3C VC / DID (identity claims), OpenFGA / Zanzibar / OPA (runtime authorization), and RFC 8693 (token delegation). It does not replace them; it records the bound-to-authorization actions that result from their use.

**Conformance profiles.** Recognizing that natural-person PKI infrastructure varies widely by jurisdiction and operator, VAL defines three conformance profiles (A, B, C) at §5.2 that differ in how strongly the human-principal designation at the root of an authorization lineage is bound. Profile A (operator-attested, chained) is achievable in any deployment today; **Profile B (declarative identity + device-bound WebAuthn biometric key — Face ID/passkey)** is the live strong form whose device-key signature the verifier checks offline; **Profile C (eIDAS conformity — qualified, identity-proofed)** is the legal-grade form, verified when a caller-supplied QES validation verdict is provided (§7.1(f); `@val-protocol/qes-validator` + EU Trusted List) and honestly classified `qualified_unverified` without one. Verifier output reports the conformance profile — per-lineage, with the chain-level letter as the floor across roots (§5.2/§7.3) — so consumers of a verification report interpret the residual-trust statement correctly. Operators SHOULD migrate to B (and C where eIDAS applies) as natural-person PKI matures in their jurisdiction.

**Relationship to adjacent protocols (the family).** VAL is a sibling, not a competitor, in the
agent-action-verification family that Mastercard + Google legitimized:

| Protocol | Domain | Substrate | Lifecycle | Root signing |
|---|---|---|---|---|
| **Verifiable Intent (VI)** | commerce / payment | layered SD-JWT credential | ephemeral (L3 ~5 min) | user-key signed (≈ VAL Profile B) |
| **AP2 / UCP** (Google) | agent commerce intent | mandate format | per-transaction | — |
| **W3C VC / DID** | identity claims | per-credential issuance | per-credential | issuer-signed |
| **in-toto / SLSA** | build-artifact provenance | attestation graph | per-artifact | builder-signed |
| **VAL** | **regulated agreements** | **hash-chained append log** | **persistent (10–75 y)** | A: operator-attested → B/C: human-signed |

"**Verifiable Intent**" is the **category name** for this family; VAL is its regulated-agreement member.
VAL **does NOT implement the VI spec** (verifiableintent.dev) — SD-JWT credential chain vs hash-chained
ledger; commerce vs regulated agreements; two mandate types vs six action classes. External positioning
uses "Verifiable Intent" as the family and always distinguishes VAL's claim; it never claims VI conformance.

---


## 3. Components Overview

The protocol defines five components, treated in detail in §§4–8:

1. **Wire format** (§4) — RFC 8785 JSON-canonical (JCS) encoding of typed attestation blocks, with the chain hash computed over a deterministic pipe-delimited preimage. (A binary CBOR frame is recorded as a non-normative future direction; it is not part of v0.1.)
2. **Lineage invariant** (§5) — structural rule that every non-assignment block carries a non-null parent assignment hash terminating, by recursion, at a human-signed root.
3. **Scope predicate language** (§6) — small declarative grammar for expressing what an authorization permits, evaluable in linear time.
4. **Offline verifier** (§7) — re-derives five properties from chain bytes (integrity, lineage, scope, grounding, delegator authority) and emits a verification report. The external-anchor pass (§8, RFC 3161) and the bytes-binding pass (§7.2 Pass 6) are implemented in the reference verifier (0.8.0 / 0.7.0).
5. **External anchor** (§8) — optional RFC 3161 timestamp over Merkle roots of contiguous block ranges, providing temporal proof that does not trust the operator's clock.

---


## Specification map

| Section | File |
|---|---|
| Scope, design principles, components | this file |
| Wire format (encoding, block types, headers) | [04-wire-format.md](04-wire-format.md) |
| Lineage invariant | [05-lineage-invariant.md](05-lineage-invariant.md) |
| Scope-predicate language | [06-scope-predicate.md](06-scope-predicate.md) |
| Offline verifier | [07-offline-verifier.md](07-offline-verifier.md) |
| External anchor | [08-external-anchor.md](08-external-anchor.md) |
