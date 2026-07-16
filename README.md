# Verifiable Authorization Lineage (VAL)

**Records prove what your agents did. VAL proves they were allowed to.**

An open protocol for offline-verifiable proof that an action — by a human or by an AI agent acting on their behalf — stayed within human-delegated authority.

**Status**: Draft (v0.1). Maintained by RIGA Solutions; open to multi-stakeholder contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

VAL specifies a wire format and a verification procedure that bind every action back to a human-signed root authorization through a typed, hash-chained lineage — so an outside party (a regulator, a counterparty, an auditor) can verify the action was authorized **without trusting the operator that recorded it**.

## The Problem

When a professional delegates work to an AI agent — or simply acts inside a regulated process — no outside party can later verify that what happened actually reflected the human's authority. The agent might act beyond its scope, read what it shouldn't, or commit the principal to something never approved. Authorization-issuance protocols (OAuth 2.0, JWT, RFC 8693) prove a *token was minted*; audit/SIEM systems *record actions* in logs the operator controls. Neither proves, to someone who doesn't trust the operator, that **the action stayed within the authority a human granted.**

| Stakeholder | Risk without a verifiable lineage |
|-------------|-----------------------------------|
| **Principal / client** | The agent acts beyond delegated authority; no portable proof of what was authorized |
| **Professional / operator** (notaire, lawyer, accountant, healthcare vendor) | Cannot prove to a regulator that an action stayed in scope; carries the liability |
| **Regulator / auditor** | Must trust the operator's logs — no independent, offline way to verify |
| **Counterparty** | No proof the agent was authorized to transact, sign, or send |
| **Agent platform** | Liability for agent actions with no provable authorization chain |

## What VAL Does

VAL records every action as a typed **block** in an append-only, hash-chained **lineage**. Every non-root block must trace, cryptographically, back to a **human-signed root authorization** carrying a machine-checkable **scope predicate** (what the authorization permits). A standalone **offline verifier** re-derives five properties — **integrity, lineage, scope-respect, grounding, and delegator authority** (the issuing human's standing to grant the delegated scope) — from the chain bytes plus a small set of public trust anchors, with **zero reads against the operator**. *Grounding* means the actor **read a content-address before deriving from it** (read-before-derive, chain-internal); it does not by itself tie that content-address to a particular file. An optional sixth pass — **bytes-binding** (§7.2 Pass 6) — adds that tie: it matches a content-address to a specific document produced as evidence, via a *hiding commitment* re-derived from a `{ bytes, nonce }` disclosure at evidence time, still with zero operator reads. An optional **external anchor** (RFC 3161 / eIDAS QTSP) provides independent timestamping.

**In scope:** the canonical wire format for attestation blocks; the lineage invariant (every non-assignment block traces to a human-signed root); a minimal scope-predicate language; the offline verifier procedure; the optional external timestamp anchor; six action classes (read, write, assign, sign, send, settle).

**Out of scope:** identity issuance (assume W3C DIDs / X.509); transport (format is transport-agnostic — HTTP, MCP, queue, file); storage (any append-only persistence); **runtime authorization decisions** (use FGA, OPA, Zanzibar — *the protocol constrains what is recorded, not how decisions are made*); payload confidentiality (payloads MAY be encrypted; VAL covers integrity and authorization-lineage only).

> VAL proves *that authorized actions occurred and stayed in scope*; what was authorized may remain confidential.

## How It Works

- **ASSIGNMENT** roots a lineage in a human-signed authorization with a scope predicate.
- **ACCESS / MUTATION** (and CONSENT / COMMUNICATION / SETTLEMENT) record actions that must reference a parent assignment — satisfied by *lineage + action + container*, or by a Merkle **membership proof** for isolation-scoped reads.
- **ANCHOR** periodically commits the chain head to an external timestamp authority.
- The **[offline verifier](spec/07-offline-verifier.md)** walks the chain, recomputes the hashes, checks the lineage to a human root, evaluates the scope predicates, checks each ASSIGNMENT's delegated scope against its issuer's **declared authority** (so a read-only delegator cannot have granted writes), and reports a **conformance profile** (A: operator-attested → B/C: human-signed) so consumers interpret the residual-trust statement correctly.

## What VAL Proves — and What It Does Not

Every claim below is re-derived by the verifier from chain bytes plus public trust anchors; every boundary is stated so no claim has to be taken on faith. The verifier reports the chain-level conformance profile as the **floor** across lineage roots — never rounded up ([§5.2](spec/05-lineage-invariant.md), [§7.3](spec/07-offline-verifier.md)).

| Claim (verifier pass) | Proves | Does not prove / residual trust |
|---|---|---|
| **Integrity** (Pass 1) | Committed blocks were not modified, inserted, deleted, or reordered — recomputed hash by hash | That every action was captured. No record system can self-certify capture completeness; coverage is an instrumentation property, not a hashing property |
| **Human root — Profile A** (Pass 2) | Every action traces to a **human-attributed** authorization inside the tamper-evident chain; the attribution itself cannot be revised post-hoc | The attribution is the operator's runtime claim at emission. Profile A chains are "human-attributed", **not** "human-signed" |
| **Human root — Profile B** (Pass 2) | The root authorization is signed by a WebAuthn **device key** under the delegator's control — key control is cryptographically verified, with zero operator trust | Legal identity: the name is declarative. Key control is proven; who the keyholder legally is, is not |
| **Human root — Profile C** (Pass 2) | The root is signed under a **qualified eIDAS** mechanism by an identity-proofed natural person — verified when a QES validation verdict is supplied | Without a verdict, honestly classified `qualified_unverified`, never silently upgraded. Residual trust: the QTSP |
| **Scope-respect** (Pass 3) | Each action fell within its **effective granted authority** (intersected down the delegation chain) — re-evaluated by the verifier, not read back from the operator's decision log | What *should* have been granted. VAL checks actions against the grant, not the grant against your policy intentions |
| **Delegator authority** (Pass 5) | The issuing human had **standing to grant** the delegated scope — a read-only delegator cannot have granted writes | Requires the operator's capability policy as a pinned input; without it, only carrier presence is enforced |
| **Grounding** | The actor **read a content-address before deriving from it** (read-before-derive, chain-internal) | That the content-address is a particular file — that is bytes-binding, below |
| **Bytes-binding** (Pass 6, optional) | A chain content-address **is the document in hand**, re-derived at evidence time from a `{ bytes, nonce }` disclosure | Nothing about undisclosed documents; the on-chain commitment is hiding by design |
| **External anchor** (Pass 4, optional) | The covered blocks **existed no later than** the TSA-attested time — an independent timestamp authority's signature, not the operator's clock | Completeness or freshness. Temporal existence only; no time-policy evaluation |

What VAL deliberately does **not** do: capture completeness, runtime enforcement (permit/deny decisions — [§1.2](spec/README.md)), identity issuance, configuration/environment snapshots, payload confidentiality beyond content-addressing. Adjacent layers own those; [ATC.md](ATC.md) maps the boundaries control by control.

The row no tamper-evident log can offer: **every action traces to a human-rooted authorization whose scope the verifier re-checks.** A chain that records actions with cryptographic integrity but no structural binding to authorization still reduces to "trust the operator's enforcement was correct" ([§5.5](spec/05-lineage-invariant.md)).

## VAL in the Protocol Landscape

"Verifiable intent" is the *category* Mastercard + Google legitimized. VAL is the **regulated-agreement member** of that family — a sibling, not a competitor. It does not implement the Verifiable Intent (VI) spec.

| Protocol | Domain | Substrate | Lifecycle | Root signing |
|---|---|---|---|---|
| **Verifiable Intent (VI)** | commerce / payment | layered SD-JWT credential | ephemeral (~minutes) | user-key signed |
| **AP2 / UCP** | agent commerce | mandate format | per-transaction | — |
| **W3C VC / DID** | identity claims | per-credential | per-credential | issuer-signed |
| **in-toto / SLSA** | build provenance | attestation graph | per-artifact | builder-signed |
| **VAL** | **regulated agreements** | **hash-chained append log** | **persistent (10–75 y)** | operator-attested → human-signed |

The distinction in one line: VI is a **selectively-disclosable credential** verified against an **issuer signature**; VAL is an **append-only ledger** verified by **offline replay that trusts no operator**. See [protocol-landscape/](protocol-landscape/protocols.md).

## Specification

The normative spec lives in [`spec/`](spec/README.md): [scope & principles](spec/README.md) · [wire format](spec/04-wire-format.md) · [lineage invariant](spec/05-lineage-invariant.md) · [scope predicate](spec/06-scope-predicate.md) · [offline verifier](spec/07-offline-verifier.md) · [external anchor](spec/08-external-anchor.md).

Control-framework alignment (informative): [ATC.md](ATC.md) maps VAL mechanisms to the Vanta Agentic Trust Controls draft and AARM Core R1–R6, stating coverage — and non-coverage — control by control.

## Reference Implementation

The reference packages live under [`packages/`](packages/) (Apache-2.0, published under the `@val-protocol` scope):

| Package | Purpose |
|---|---|
| [`chain-verifier`](packages/chain-verifier) | the offline verifier — zero runtime dependencies, pure SHA-256 against the canonical preimage; implements passes 1–3 (integrity, lineage, scope) plus the grounding re-derivation, pass 5 (delegator authority, §7.2), and pass 6 (bytes-binding, §7.2 — optional, evidence-time), and reporting conformance profile A / B / C (Profile B device-key signature fully verified; C classified, QTSP verification pending) |
| [`chain-verifier-cli`](packages/chain-verifier-cli) | `val-verify` — one-command verification of an exported chain (file or live MCP `audit.export`), and `--html`: a single-file, **self-verifying HTML report** that embeds the chain bytes + the verifier source and re-derives every pass in the reader's browser, offline |
| [`demo`](packages/demo) | `npx @val-protocol/demo` — mints a live Profile-B chain in your terminal, verifies it, then attacks it four ways (edit / full rewrite / signature strip / silent truncation), showing what each attack breaks and what it can only demote |
| [`qes-validator`](packages/qes-validator) | caller-side, pure-JS eIDAS QES validator for Profile C — produces the §7.1(f) validation verdicts the zero-dep core consumes |
| [`anchor-lotl-resolver`](packages/anchor-lotl-resolver) | caller-side EU Trusted List (LOTL) resolution for qualified external anchors — resolves the `anchorTrust` input (§7.1(c)) |
| [`webhook-receiver`](packages/webhook-receiver) | reference receiver for signed chain-event webhooks — HMAC verification, rotation grace, replay protection, chain-link extraction. Delivery transport tooling (transport is §1.2 out-of-scope for the normative protocol) |

The verifier is transport- and producer-agnostic: it consumes exported chain bytes and re-derives the protocol's properties without contacting any operator. Chain producers and API clients are deployment-specific and live with each operator's stack, not in this protocol repository.

## License

[Apache-2.0](LICENSE) — specification and reference implementation alike. Apache-2.0 carries an explicit patent grant; VAL asserts no patent claims and requires no contributor licensing agreement. See [NOTICE](NOTICE).

## Contributing

Open to multi-stakeholder contribution under a [DCO](CONTRIBUTING.md) sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [Code of Conduct](CODE_OF_CONDUCT.md).
