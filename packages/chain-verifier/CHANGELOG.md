# @val-protocol/chain-verifier — CHANGELOG

## 0.11.2 — 2026-07-16 — internal-reference normalization (docs/comments only)

- Repository-internal decision-record numbers in source comments, tests, and CHANGELOG
  entries are replaced with their public spec anchors (§7.2 Pass 6, §7.1(f), §8.4, §5.2).
  No functional change, no API change — byte-identical verification behavior to 0.11.1.

## 0.11.1 — 2026-07-16 — floor fix: no phantom 'A' from action-block lineage walks

- **BUG FIX (report correctness, no API change).** Since the 0.10.0 floor model, every successful
  action-block lineage walk added `'A'` to the profile set — a leftover from the pre-floor maximum
  model, where the extra add was harmless. Under the floor it dragged a cleanly B/C-rooted chain
  with ANY action block down to `conformanceProfile: 'A'` and stamped a phantom `'A'` into
  `profilesPresent` (no A root exists in such a chain). Roots classify themselves in their own
  ASSIGNMENT iteration (signed → B/C; unsigned or failed-signature → A); the walk now contributes
  no profile — the same double-count discipline 0.10.0 applied to sub-ASSIGNMENT walks. Chains
  whose floor was genuinely A (any unsigned root) are unaffected. Regression-locked in
  `test/profile-b-signature.test.mjs` (B root + in-scope ACCESS ⇒ floor B, `profilesPresent: ['B']`;
  mixed unsigned+signed roots + action ⇒ still floor A).

## 0.11.0 — 2026-07-13 — personal-scope self-attestation (§5.2 twin, additive)

- **`ValPersonalAttestation` + `personalBindingChallenge` + `verifyPersonalAttestation`**
  (additive) — the PERSONAL-scope twin of the org-root self-attestation: a natural
  person's org-free §4.3 CONSENT key self-attests
  `{signatory_identity_hash, public_key, identity_assurance, key_binding}` — identical
  construction to `orgRootBindingChallenge` minus `org_id` (a consent is a personal act;
  no organization appears in the signed statement). `verifyPersonalAttestation` checks the
  self-signature offline (self-signed: attesting key == attested key) and surfaces
  `key_binding` + the self-asserted subject verbatim — never rounded up.
- **`consentBonds` report itemization** (additive) — every §4.3 CONSENT bond surfaced as
  `{ sequenceNumber, alg, profile, signatureValid }`: the per-bond INSTRUMENT grade
  (webauthn ⇒ 'B', qualified alg ⇒ 'C'), legible from the report alone. DISTINCT from
  `conformanceProfile`/`profilesPresent` (which grade ASSIGNMENT roots, §5.2 per-lineage):
  an A-rooted chain carrying a webauthn bond reports floor 'A' AND a B-graded bond — both
  true, never rounded either way. (Follows the 0.10.0 `authorityCarriers` verbatim-surface
  precedent.)
- **Qualified CONSENT signatures follow the delegation discipline** (fix) — pre-0.11.0 the
  CONSENT pass fed every signature to the WebAuthn verifier, so a spec-valid Profile-C bond
  went `signature: red` ("unsupported alg"). Now: with a matching per-signature
  `qesValidation` verdict ⇒ verified (green); without ⇒ CLASSIFIED, not verified (pass
  untouched — never red on verdict absence, never green on declaration). Same
  per-signature `signatureRef` matching as qualified delegations (§7.1(f) per-signature matching).
- The CONSENT per-action pass otherwise stays as-is: a personal-key (org-free) webauthn
  CONSENT verifies trustlessly against the embedded key and its bond grades **B** — the
  self-asserted identity is the honest residual. The attestation exports are the offline
  primitive for producers that record personal attestations (spec §5.2).
- Tests: 62/62 (adds bond itemization, qualified-consent classification + verified paths).

## 0.10.0 — 2026-07-04 — floor conformance + carrier legibility + honest key_binding

- **`conformanceProfile` is now the FLOOR** (weakest profile among the chain's root
  ASSIGNMENTs) — **BEHAVIOR CHANGE for mixed-profile chains** (previously the maximum,
  which let one qualified grant mask a chain of operator-attested ones). Consumers that
  gated on `conformanceProfile === 'B'|'C'` may see chains report a LOWER profile than
  under ≤ 0.9.x; read the new field below for the full picture. Also fixes the root
  double-count where every human-rooted root added 'A' even when device/qualified-signed.
- **`profilesPresent: ('A'|'B'|'C')[]`** (additive) — every profile observed across the
  chain's lineages (spec §5.2 per-lineage model, §7.3).
- **`authorityCarriers`** (additive) — every `delegator_authority` carrier surfaced
  verbatim: `{ sequenceNumber, basis, capability, attested_by?, session_ref? }`. A report
  answers "who attested entitlement?" without reading raw blocks. Verbatim, never a judgement.
- **Reserved basis `ceremony_session_delegated`** (spec §7.2 Pass 5) — two policy-independent
  chain-byte re-derivations: `scope_ref == scope.res.in_workspace`, and the carrier MUST
  co-occur with a **qualified** delegator signature (account-less authority requires a
  qualified instrument). Additive — fires only on a basis no prior chain emitted.
- **`key_binding` gains `unattested`** (spec §5.2 amendment 2026-07-02) — `ValKeyBinding`
  widens to `device_bound | syncable | unattested`; new outcome
  `authority_verified_org_root_unattested`. An `unattested` binding (no verified hardware
  attestation at enrollment) still earns Profile B on a verified+linked signature — the
  letter grades the instrument; the binding is the orthogonal hardware axis, surfaced
  verbatim, never rounded up. Additive for existing chains.
- Tests: 59/59 (incl. the B+ cell lock — device-signed root × `identity_assurance.source
  'eidas_eaa'` ⇒ B, source verbatim — and the unattested relabel-tamper case).

## 0.9.0 — 2026-06-30 — Profile C QES verdict seam (§7.1(f))

- **Profile C (eIDAS QES) verdict-consumption seam — additive, default-preserving, still zero-dep.**
  `verifyValChain` gains `options.qesValidation?: { reports: QesVerdict[] }`; `verifyDelegationTrustChain`
  takes an optional resolved verdict and gains the `authority_verified_qualified` outcome. A qualified
  delegation with a `qualified: true` verdict (produced caller-side by the new, separate
  `@val-protocol/qes-validator`) now verifies Profile C — conformance `C`, signature green, the proven
  natural-person identity surfaced as `rootSubject` (source `qes`). Without a verdict, behaviour is
  **unchanged**: Profile C stays classified-not-verified (`qualified_unverified`). The core still does NOT
  do LOTL/X.509/OCSP/AdES — it consumes a reproducible verdict, exactly as Pass 4 consumes `anchorTrust`.
  Tests: `profile-c-qes.test.mjs` (default classified / verified / false-verdict-not-upgraded), suite 54/54.
  The companion `@val-protocol/qes-validator` (0.1.0) ships alongside this release — implemented **pure-JS,
  no DSS** (auto-routes CAdES/JAdES, binds `messageDigest == H(canonical)`, resolves trust against the live
  EU LOTL), superseding §7.1(f) S1's "wrap EU DSS" for the BYO arm. The BYO Profile-C path (signer brings
  a CAdES/JAdES, RIGA verifies + mints on bind) is live and end-to-end proven (REST + dev-console UI).

## 0.8.0 — 2026-06-27

### Features

- **Pass 4 — external anchor (VAL §8, RFC 3161).** The verifier no longer skips ANCHOR blocks: it
  re-derives the checkpoint Merkle root over the in-band covered range and verifies the block's
  RFC 3161 TimeStampToken offline, with **zero new dependencies** (hand-rolled CMS/DER + Web Crypto).
  `verifyValChain` gains an optional `anchorTrust` input — `{ tsaCertSpkis: string[] }`, a *resolved*
  set of acceptable TSA signer SPKIs (base64). Phase 1 pins the set directly; in eIDAS deployments the
  caller resolves the QTSP cert from the EU Trusted List (LOTL) and supplies it already-resolved
  (identical shape — the verifier never fetches a trust list). New result fields:
  `anchorBinding ∈ { verified, mismatch, not_evaluated }`, `firstAnchorViolation`, and
  `anchors: [{ sequenceNumber, genTime, covered_range }]`. `ValBlock` gains the optional
  `merkle_root` / `merkle_alg` / `covered_range` / `tst` carriers.
- **Verification (§8.4):** for each ANCHOR block — (1) recompute the `val.checkpoint-merkle.v1` root
  (leaf `SHA-256("<seq>|<chain_hash>")`, sequence order, promote-odd; a byte-faithful port of the RIGA
  producer, locked by a shared parity vector) and assert it equals `merkle_root`; (2) assert the token's
  `messageImprint.hashedMessage` equals that root (the root is the timestamped digest, not re-hashed);
  (3) verify the CMS signature over the DER `signedAttributes` (re-tagged to SET-OF), with the
  `message-digest` signed attribute equal to `SHA-256(TSTInfo)`, against a pinned SPKI (RSA PKCS#1-v1.5 /
  PSS, or ECDSA P-256/384/521); (4) require the signer cert to carry the `id-kp-timeStamping` EKU;
  (5) surface the attested `genTime`. **Temporal existence only** — no time-policy is evaluated.
- **Opt-in and additive:** no `anchorTrust`, or a chain with no ANCHOR block ⇒ `not_evaluated`, never a
  failure; the core verdict (integrity / lineage / scope / grounding / authority / signature / bytes-
  binding) is unchanged. Still **zero runtime dependencies** (Web Crypto only).
- **Tests:** full suite **54/54 green** — verified against **real tokens from three independent TSAs**,
  including a genuinely **eIDAS-qualified** one: DigiCert (RSA-SHA256), FreeTSA (ECDSA-P521-SHA512), and
  **Sectigo Qualified** (TSU signs RSA-4096 / SHA-384; EU Trusted List, listed `TSA/QTST` `granted`;
  ETSI EN 319 422; policy OID `0.4.0.2023.1.1` is the EN 319 421 BTSP baseline — standards-conformance,
  **not** a qualification signal: qualification is established by the LOTL, not the OID) — plus
  the Merkle parity vector and tamper cases (wrong cert, tampered range, mismatched messageImprint,
  corrupted token). The qualified token verifies through the identical Pass 4 (the verifier proves
  `anchorBinding`, never "qualified" — that label is operator-asserted). Spec: VAL §8 + §7.2 Pass 4.

## 0.7.0 — 2026-06-26

### Features

- **Pass 6 — bytes-binding (§7.2 Pass 6).** A second rail binding a chain content-address to the literal
  document bytes, re-derivable offline with zero operator trust. `verifyValChain` gains an optional
  `bytesDisclosures` input — `[{ resourceId, documentBytesBase64, nonceHex }]` — and a
  `bytesBinding ∈ { bound, mismatch, not_evaluated }` result (+ `firstBytesBindingViolation`). For each
  MUTATION carrying a hiding `bytes_commitment`, the verifier hashes the disclosed bytes itself (never a
  supplied hash) and recomputes `SHA-256("val.bytes-commitment.v1" ‖ 0x00 ‖ nonce ‖ SHA-256(bytes))`,
  comparing to the on-chain value. The opening nonce lives producer-side, never on the chain — so an
  exported chain is not a cross-tenant confirmation oracle. Opt-in and additive: absent commitment or
  disclosure ⇒ `not_evaluated`, never a failure; the five core properties are unaffected. `ValBlock`
  gains the optional `bytes_commitment?: { alg?, value? }` carrier.
- **No verdict changes** to integrity / lineage / scope / grounding / authority / signature. Full suite
  green (41/41), with 5 new bytes-binding cases (bound / mismatch-bytes / mismatch-nonce / not-evaluated×2).
  Spec: VAL §4.4 + §7.2 Pass 6.

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
