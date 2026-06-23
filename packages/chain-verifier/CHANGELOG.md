# @val-protocol/chain-verifier — CHANGELOG

## 0.6.0 — 2026-06-23

### Features

- **`rootSubject` — the root human's declared identity, surfaced (additive, output-only).** The
  name the root human declared (`human_attestation.identity_assurance.subject_claim`) is already
  hash-bound in the root ASSIGNMENT's `canonical_details` and integrity-checked by passes 1–3;
  0.6.0 surfaces it on the report so consumers don't have to re-parse `canonical_details`:
  - `ValVerificationResult` gains `rootSubject: { subject_claim: string; source: string } | null`,
    set from the first human-rooted ASSIGNMENT's `human_attestation.identity_assurance`
    (first human root wins). `source` is surfaced **verbatim** — a `self_asserted` name is never
    rounded up to `vouched`.
  - `ValBlock.human_attestation` gains the optional carrier this is read from:
    `identity_assurance?: { source, subject_claim }`.
  - `rootSubject` is `null` when the root carries no `identity_assurance` (pre-declaration chains).
- **No verdict changes.** `integrity` / `lineage` / `scope` / `grounding` / `authority` /
  `signature` / `conformanceProfile` are byte-for-byte unaffected — `rootSubject` is purely an
  additional output field. Full suite passes (24/24), including two new rootSubject cases
  (surfaced-from-root, and null-when-absent). Proven against a live RIGA chain:
  `rootSubject = { "John Doe", "self_asserted" }`, integrity green.

## 0.5.0 — 2026-06-16

### Breaking

- **Isomorphic crypto (runs in the browser now); the verify API is `async`.** The verifier was
  Node-only (`node:crypto` `createHash`/`createPublicKey`/`createVerify` + `Buffer`), so it could
  not run in a browser — the "verify client-side without trusting the operator" promise was only
  deliverable from Node (the CLI). It now uses the **Web Crypto API** (`crypto.subtle`) +
  `Uint8Array`, available in Node 18+ AND browsers, with **zero new dependencies**. Because
  `crypto.subtle` is async, the verification functions now return `Promise` and must be `await`ed:
  `reconstructChainHash`, `verifyChain`, `verifyValChain`, `verifyMembershipProof`,
  `computeMembershipRoot`, `orgRootBindingChallenge`, `verifyDelegatorSignature`,
  `verifyDelegationTrustChain`.
- **New verification behavior can turn a previously-`green` chain `red`.** 0.5.0 adds the
  scope/authority/consent checks under Features below. A chain that passed under 0.4.0 may now
  report `scope: 'red'`, `signature: 'red'`, or an authority/lineage violation if it relied on
  behavior the verifier did not previously enforce (e.g. a sub-assignment granting more than its
  parent, or a v≥3 grant whose action principal ≠ grantee). Intentional; it rides the 0.5.0
  breaking boundary.

### Features (new verification behavior — parity with the operator backend mirror)

- **Agent-equity (Pass-3 ↔ Pass-5 boundary).** Every action block rooting in a **v≥3** ASSIGNMENT
  must carry `principal == grantee` ("it's THIS actor's own mandate"). New `grantee` field on the
  ValBlock shape; v1/v2 grants carry no grantee and are grandfathered. An external zero-trust
  auditor now gets the agent-equity check, not just the backend.
- **§6.6 temporal window (`win`).** `satisfies()` enforces `not_before ≤ timestamp_local ≤
  not_after` where bounds are present, **fail-closed** when a scope is windowed but the action is
  unstamped. New `ValBlock.timestamp_local` + `ScopePredicate.win`. Mirrors the operator's
  preventive PG-trigger comparison over the same field.
- **§6.6 count limit (`lim.max_count`).** Running per-grant action count in `verifyValChain`; the
  `(max_count + 1)`-th action block rooting in a grant is the violation (verifier-side aggregate).
  New `ScopePredicate.lim` (`max_value` / `max_value_currency` typed but deployment-specific).
- **§6.7 transitive effective scope.** `walkLineage` returns the ancestor path; a leaf is
  evaluated **conjunctively against every ancestor** (subj/act/res/win) — it passes only if it
  clears each one, so a sub-assignment cannot grant more than its parent had. `lim` is transitive
  too: a grandchild is bounded by the root grant's `max_count` (effective = min over the path).
- **CONSENT block per-action signature (§4.2 / §5.2).** A CONSENT block's embedded per-action
  signature is verified offline: the consent challenge is recomputed over `{document_hash,
  parent_assignment_hash, principal}` and the embedded WebAuthn assertion validated against its
  public key (reusing the delegator-signature path), binding the signed `document_hash`. New
  `document_hash` + `signature` on the CONSENT ValBlock shape; valid → `signature: green`, a
  signature over a different document → `red`.

### Note

- The **isomorphic crypto migration itself is verdict-preserving** — byte-identical hashes and
  verdicts (SHA-256, ECDSA-P256, ADR-0007 preimage, §6.4 Merkle, §5.2 signature logic unchanged),
  proven by the full suite passing after `await`. The verdict changes above come from the NEW
  checks, not from the Node→Web-Crypto swap.

## 0.4.0 — 2026-06-14

### Features

- **Profile B verification — offline device-signature trust chain (spec §5.2).** The reserved
  `delegator_authority.signature` slot is now VERIFIED, not merely carried. A present WebAuthn
  assertion is checked cryptographically (ES256 over `authenticatorData || sha256(clientDataJSON)`
  against its embedded SPKI key) and must chain to the enrolled, self-attested org-root key:
  - The embedded `delegator_authority.org_root` self-attestation is re-derived from chain bytes —
    its `self_signature` must sign `orgRootBindingChallenge({org_id, signatory_identity_hash,
    public_key, identity_assurance, key_binding})`. So `key_binding` / `identity_assurance` cannot
    be relabeled without breaking the signature (tamper-evident: relabeling device_bound→syncable
    ⇒ `signature: red`).
  - The delegation `signature.public_key` must equal the enrolled org-root `public_key`
    (linkage; a signature by any other key ⇒ `signature: red`).
  - New report fields: `signature: 'green' | 'red' | 'none'`, `firstSignatureViolation`, and
    `keyBinding: 'device_bound' | 'syncable' | null` — surfaced **verbatim**; `syncable` is never
    rounded up to `device_bound`.
- **Conformance now reaches B/C — and only on verified evidence (no silent default).**
  `conformanceProfile` is the highest profile actually established by the chain's ASSIGNMENTs:
  - **B** requires a delegation signature that VERIFIES and LINKS to the org-root. A present but
    invalid/unlinked signature claims NO profile (conformance stays A) and is flagged
    `signature: red` — no over-claim.
  - **C** is reached when a qualified algorithm (`qes` / `eidas_qes` / `eidas_eaa`) is declared.
    It is CLASSIFIED, not crypto-verified — the QTSP trust-list anchor is a future input, never a
    silent pass — so a C signature reports `signature: 'none'` (neither green nor red) until that
    anchor exists.
  - Otherwise **A**. (Through 0.3.0 `conformanceProfile` could only ever report A.)
- **Profile C anticipated, no rebuild required.** Qualified algs are recognized and slotted now;
  `verifyDelegationTrustChain` returns `qualified_unverified` so a C chain is detected and reported
  without any shape/API change when QTSP-anchored verification is later added.
- New exports: `verifyDelegatorSignature`, `verifyDelegationTrustChain`, `orgRootBindingChallenge`,
  and the `ValDelegatorSignature` / `ValOrgRootAttestation` / `ValIdentityAssurance` / `ValKeyBinding`
  types.

### Compatibility

- Additive only. The new pass fires exclusively when a block carries
  `delegator_authority.signature`; chains without it verify exactly as before and report
  `signature: 'none'`, `conformanceProfile: 'A'`. Existing call shapes are unchanged. Still **zero
  runtime dependencies** (Node `crypto` only).

### Known limitation

- The delegation signature is verified for cryptographic validity + org-root linkage, but its
  WebAuthn challenge is not yet bound to a specific grant payload offline (that needs the operator's
  grant-payload canonicalization as a trust-anchor input — a future strengthening). The
  device_bound/syncable org-root verdict does not depend on it.

## 0.3.0 — 2026-06-11

### Features

- **Pass 5 — `container_owner` basis re-derived from chain bytes (spec §7.2).** The
  well-known `container_owner` basis records ownership of a from-scratch,
  participant-less container as the delegator's standing. Where the chain carries the
  material, the claim is now DERIVED, not trusted:
  - `delegator_authority.scope_ref` must equal the ASSIGNMENT's
    `scope.res.in_workspace` (chain-internal consistency; policy-independent, like
    carrier presence). Mismatch ⇒ `authority: red`.
  - A COMMUNICATION rooted directly in a `container_owner` ASSIGNMENT and performed
    by a human (`user:<id>` principal) must be performed by the attested owner:
    `sha256(<id>)` must equal the root's `human_attestation.subject_user_hash`.
    Mismatch ⇒ `authority: red`.
  - An `agent:` principal has no second chain occurrence of the delegating human to
    cross-check — it carries the Profile-A operator-attested residual, like every
    other basis (the reserved `signature` slot is the Profile B/C upgrade).
- `ValBlock.human_attestation` type now includes `subject_user_hash`.

### Compatibility

- Additive only. The new checks fire exclusively on `basis: 'container_owner'`,
  which no chain emitted before this release; all existing chains and call shapes
  verify exactly as before. Operators adopting the basis must also ship the
  matching §7.1(d) policy row (e.g. `container_owner → ['send']`) to their
  verifying parties — an unknown capability remains `authority: red`.

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
