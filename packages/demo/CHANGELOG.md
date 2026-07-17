# @val-protocol/demo — CHANGELOG

## 0.1.1 — 2026-07-17

Two published-surface corrections. No verdict changes: every act reports the same properties
and the same floor as 0.1.0. Note the chain *bytes* do differ — `subject_claim` is part of
`identity_assurance`, which feeds the org-root binding challenge and therefore the root
self-signature, so renaming the subject re-derives the attestation. (The demo mints a fresh
key per run, so its bytes were never reproducible across runs regardless.)

- **Placeholder convention.** The Profile-B root's `subject_claim` carried a locale-flavored
  surname alongside the placeholder given name. A real-looking full name in a shipped artifact
  is, to an outside reader, indistinguishable from a leaked chain subject, so the publish
  procedure's placeholder gate refuses it. The claim is now the bare canonical cryptographic
  placeholder — unambiguously synthetic. No real person was ever referenced: this was a
  perception surface, not a disclosure.
- **`description` understated the act count**, naming fewer acts than the demo runs. It runs
  five: Act 0 mints and verifies the pristine chain, Acts 1–4 are the four attacks. The act
  count is unrelated to the pillar count — the five pillars are integrity, lineage,
  scope-respect, grounding, and authority-equity, and the demo reports all five (plus
  `signature`) on every act.

## 0.1.0 — 2026-07-16 — initial release

- `npx @val-protocol/demo`: mints a live Profile-B chain in-process (P-256 root key,
  WebAuthn-shaped assertions, delegated agent actions, grounded MUTATION, per-action consent
  bond), verifies it offline, then attacks it four ways — in-place edit (integrity red),
  competent full-history rewrite (integrity/lineage green, signature red — the seam
  tamper-evident logging alone does not cover), signature strip (floor demoted B → A,
  consent bond necessarily dropped: it pins the original grant hash), and silent truncation
  (green — stated honestly as the §8 external anchor's job).
- `--out=<ndjson>` and `--html=<report>` emit the pristine chain and the self-verifying
  HTML report (via `@val-protocol/chain-verifier-cli/report`).
- Every act asserts its expected verdict; non-zero exit on any deviation — the demo doubles
  as an integration test of the reference verifier.
