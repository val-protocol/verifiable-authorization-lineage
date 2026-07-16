# @val-protocol/chain-verifier-cli — CHANGELOG

## 0.5.1 — 2026-07-16 — internal-reference normalization (CHANGELOG only)

- A repository-internal decision-record number in a past CHANGELOG entry is replaced with
  its public spec anchor. No code change — identical behavior to 0.5.0.

## 0.5.0 — 2026-07-16 — self-verifying HTML report (`--html`)

- **`--html=<path>`** — beyond the per-row integrity walk, runs the FULL `verifyValChain`
  (§7.2, all passes), prints the §7.3 summary, and writes a **single-file, self-verifying
  HTML report**: the document embeds the exact chain bytes (base64 NDJSON) and the complete
  ESM source of `@val-protocol/chain-verifier`, and on every open the reader's browser
  imports the embedded verifier and **re-derives every pass locally** — offline, zero
  network requests, zero reads against the operator. The verdict is painted from the
  in-browser run, never asserted by the generator; the embedded chain and verifier are
  downloadable from the report for out-of-band re-verification. Plain-language pass cards
  state what each pass proves and what it does not (capture completeness is an
  instrumentation property; the profile letter is the §5.2 floor, never rounded up).
- **`--trust=<path>`** — a JSON file of §7.1 trust-anchor inputs (`delegatorAuthorityPolicy`,
  `anchorTrust`, `qesValidation`, `bytesDisclosures`) passed to `verifyValChain` and embedded
  verbatim in the report so the in-browser re-run evaluates the same inputs.
- **`./report` subpath export** — `buildHtmlReport()` is importable
  (`@val-protocol/chain-verifier-cli/report`) so other tooling (e.g. the demo package) can
  emit the same artifact. Declarations now ship (`declaration: true`).
- Exit code: with `--html`, non-zero also when any VAL pass is red or an opt-in pass
  reports `mismatch`.
- Bump `@val-protocol/chain-verifier` `^0.10.0` → `^0.11.1` (floor fix: no phantom 'A'
  from action-block lineage walks — a B/C-rooted chain with actions now reports its true floor).

## 0.4.0 — 2026-07-04

- **Bump `@val-protocol/chain-verifier` `^0.9.0` → `^0.10.0`** (a 0.x caret cannot cross minors).
  `val-verify` now reports the 0.10.0 surface: **floor** `conformanceProfile` (BEHAVIOR CHANGE for
  mixed-profile chains — was the maximum), `profilesPresent`, `authorityCarriers`, and the honest
  `key_binding` vocabulary incl. `unattested`. No CLI flag/output-format change beyond the richer
  report fields.

## 0.3.0 — 2026-06-30

- **Bump `@val-protocol/chain-verifier` `^0.7.0` → `^0.9.0`.** The published CLI was pinned to a verifier
  two minors stale (a `^0.7.0` caret cannot reach 0.8/0.9), so `val-verify` shipped without Pass 4
  (external-anchor / RFC 3161, chain-verifier 0.8.0) or the Profile-C QES verdict seam (0.9.0, §7.1(f)).
  This release tracks the current verifier. No CLI surface change — `val-verify` flags/output are unchanged;
  the underlying verification gains the newer passes.

## 0.2.0 — 2026-06-11

Initial release under the `@val-protocol` scope — the protocol-level CLI folded in from
the vendor scope (the `@riga-solutions/chain-verifier-cli` name was never published; its
source iterated privately and lands here as its public home, completing the two-scope
split: protocol substrate under `@val-protocol/*`, vendor surface under `@riga-solutions/*`).

### Features

- **`val-verify`** binary (renamed from the pre-fold `riga-verify`):
  - **File mode** — `val-verify --export=<chain.ndjson>`: row-by-row offline
    verification of an exported VAL chain (genesis invariant, sequence contiguity,
    `previous_hash` linkage, SHA-256 preimage recompute), per-row PASS/FAIL with
    expected-vs-observed hashes on failure.
  - **URL mode** — `val-verify --audit-export-url=<MCP_URL> --bearer=<token>
    --dataroom-id=<uuid>`: drains a VAL operator backend's MCP `audit.export` tool
    with internal pagination and verifies inline; nothing written to disk.
- Exit codes: `0` all rows verify · `1` any row fails · `2` argument error ·
  `3` runtime error.
- Depends on `@val-protocol/chain-verifier@^0.2.0` (the Pass-5-capable verifier);
  the CLI itself covers the integrity layer (pass 1) with per-row diagnostics —
  use the library's `verifyValChain` for passes 2/3/5 over a parsed slice.
- Zero non-protocol runtime dependencies (the verifier library only).
