# @val-protocol/chain-verifier-cli — CHANGELOG

## 0.3.0 — 2026-06-30

- **Bump `@val-protocol/chain-verifier` `^0.7.0` → `^0.9.0`.** The published CLI was pinned to a verifier
  two minors stale (a `^0.7.0` caret cannot reach 0.8/0.9), so `val-verify` shipped without Pass 4
  (external-anchor / RFC 3161, chain-verifier 0.8.0) or the Profile-C QES verdict seam (0.9.0, ADR 0063).
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
