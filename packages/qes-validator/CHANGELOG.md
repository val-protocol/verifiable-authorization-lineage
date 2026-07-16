# @val-protocol/qes-validator — CHANGELOG

## 0.1.1 — 2026-07-16 — internal-reference normalization (docs/comments only)

- Repository-internal decision-record numbers in source comments, README, and CHANGELOG
  are replaced with their public spec anchors (§7.1(f), §5.2 Profile C, §8.4 anchor genTime).
  No functional change — identical validation behavior to 0.1.0.

## 0.1.0 — 2026-06-30 — first release (Profile C BYO validator)

- **Pure-JS eIDAS QES validator — zero runtime dependencies, no DSS.** Validates a brought qualified
  signature for VAL Profile C (the bring-your-own-signature arm of §7.1(f)): auto-routes **CAdES**
  (`.p7m`, detached or enveloped) vs **JAdES** (JWS), binds the signature to the grant
  (`messageDigest == SHA-256(canonical)`), builds the X.509 path, checks ETSI EN 319 412 QcStatements,
  and resolves trust against the live EU **LOTL** (List of Trusted Lists).
- **Honest structured verdict (`QesValidationReport`).** `status` (qualified / not_qualified /
  indeterminate) + `subIndication` (`HASH_FAILURE`, `SIG_CRYPTO_FAILURE`, `FORMAT_FAILURE`,
  `ANCHOR_NOT_ON_TRUSTED_LIST`, `CHAIN_INCOMPLETE`, …), `adesLevel`, and the eIDAS natural-person
  `signerIdentity` — surfaced verbatim for the relying party's offline call, never collapsed to "failed".
- **Exports:** `validateQes`, `matchGrantedCaQc`. Dual ESM + CJS.
- Supersedes §7.1(f) S1's "wrap EU DSS (Java sidecar)" for the BYO arm — this validator is
  dependency-light pure-JS. The CSC orchestrated-ceremony arm remains parked pending CSC/MultiSign access.
