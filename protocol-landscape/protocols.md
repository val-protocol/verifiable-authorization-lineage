# Protocol Ecosystem

How Verifiable Authorization Lineage (VAL) sits alongside the other protocols in the agent-action-verification family.

> **Versions referenced:** Verifiable Intent (VI) as published at verifiableintent.dev; Google's Agent Payments Protocol (AP2) and the Universal Commerce Protocol (UCP); W3C Verifiable Credentials / DID; in-toto / SLSA. Statements about what each "does not define" are bounded by those versions.

---

## The Core Relationship

"Verifiable intent" is the **category** Mastercard and Google legitimized: cryptographic proof that an AI agent's action reflected a human's authorization. VAL is the member of that family scoped to **regulated agreements** — legal, notarial, accounting — where the obligation to prove authorization persists for **years to decades**, not minutes, and where the verifying party is a **regulator or counterparty who does not trust the operator.**

VAL is a **portable, independently verifiable record** of what a human authorized, and proof that every subsequent action stayed within those bounds. It does not handle transport, identity issuance, or the runtime authorization decision. It **rides alongside** whatever issuance, transport, and policy stack is already in use, adding a trustless lineage layer.

---

## What VAL Adds to Any Stack

**Operator-trustless verification.** The verifier re-derives integrity, lineage, scope-respect, and grounding from the chain bytes plus public trust anchors — **zero reads against the operator.** A regulator can replay a ten-year-old chain offline and reach the same verdict the operator would.

**Human-rooted lineage.** Every non-root block must trace, by hash, to a human-signed root authorization. There is no "the agent says it was allowed" — the chain either walks back to a human root within scope, or it fails.

**Machine-checkable scope, evaluated at verification time.** The root authorization carries a scope predicate (actions, resources, isolation commitment). Verifiers confirm each downstream action falls within it, decidable in time bounded by predicate size — no Turing-complete evaluation, no out-of-band lookups.

---

## VAL vs Verifiable Intent (VI)

VI and VAL solve the **same property** (action-stayed-within-human-authority) for **different worlds**, with **different primitives**:

| | Verifiable Intent (VI) | VAL |
|---|---|---|
| Domain | commerce / payment | regulated agreements |
| Substrate | layered **SD-JWT credential** | **hash-chained append-only ledger** |
| Verification trust root | the **issuer's signature** + key binding (RFC 7800) | **offline replay** — trusts no operator |
| Disclosure | selective disclosure per role (SD-JWT) | content-addressed hashes; payloads MAY be encrypted/off-chain |
| Lifecycle | ephemeral (transaction-scoped) | persistent (10–75 years) |
| Isolation | role-scoped claim disclosure | Merkle membership proof over a committed set |
| Operator | maintained by a card network | sovereign — any operator, any jurisdiction |

**VAL does not implement the VI spec** and never claims VI conformance. A VI mandate could be *recorded into* a VAL chain (VAL as the durable lineage under VI's ephemeral credential), but they are independent.

## VAL vs AP2 / UCP

AP2 (Google) and UCP define **how** agents create checkout sessions, exchange payment credentials, and complete purchases — transport and lifecycle. VAL defines a **different concern**: durable, offline-verifiable authorization proof. A commerce stack on AP2/UCP can carry VAL blocks to gain a regulator-grade audit lineage the payment protocols don't define.

## VAL vs W3C VC / DID

VC/DID issue and verify **identity and attribute claims** (per-credential, issuer-signed). VAL **consumes** DIDs/X.509 as the identity layer (out of scope for VAL) and records the **authorized actions** that follow — a chain, not a credential.

## VAL vs in-toto / SLSA

in-toto/SLSA prove **build-artifact provenance** (who built what, from which inputs). The shape is similar — an attestation graph with signed steps — but the domain (software supply chain vs human-delegated agreements) and the root (builder vs human principal) differ. VAL is the regulated-agreement analogue.

---

## One-line summary

> **VI is a selectively-disclosable credential verified against an issuer signature. VAL is an append-only ledger verified by offline replay that trusts no operator.** Same family; different jobs.
