# @val-protocol/demo — CHANGELOG

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
