# @val-protocol/demo

**Records prove what your agents did. VAL proves they were allowed to. See it in 60 seconds:**

```bash
npx @val-protocol/demo
```

No install, no account, no network calls after the package download. The demo:

1. **Mints a live chain** — a human (Alice) roots two grants with a fresh P-256 key: one delegating
   scoped `read` + `record.append` to an agent, one keeping sign-class authority to herself. The
   agent reads a document and derives a record from it (grounding); Alice signs a consent bond.
2. **Verifies it offline** — the reference verifier re-derives integrity, lineage, scope, grounding,
   delegator authority, and the root signatures from the chain bytes plus one pinned capability
   policy. Zero reads against any operator. Conformance floor: **Profile B** (device-key-signed root).
3. **Attacks it, four ways:**

| Act | Attack | What catches it |
|---|---|---|
| 1 | **Edit** one committed block in place | `integrity: red` — any hash chain catches this |
| 2 | **Rewrite the whole history** (recompute every hash, re-link every parent, upgrade the key-binding claim) | integrity and lineage stay **green** — a tamper-evident log alone calls the forged chain intact. `signature: red` — the self-attestation binding challenge breaks. **This is the seam VAL exists for.** |
| 3 | **Strip the signatures** (and drop the consent bond they cannot re-sign) | everything green — but the conformance floor drops **B → A**: the report now says *human-attributed*, no longer *human-signed*. Forgery cannot be hidden, only demoted. |
| 4 | **Silently truncate** the tail, present the valid prefix | nothing — honestly. A self-held chain cannot prove completeness; that is the §8 external anchor's job (an independent RFC 3161 timestamp authority holds the head). |

Every act asserts its expected verdict — the demo doubles as an integration test of the
[reference verifier](../chain-verifier).

## Flags

```bash
npx @val-protocol/demo --out=chain.ndjson --html=report.html
```

- `--out=<path>` — write the pristine minted chain (NDJSON). Re-verify it yourself:
  `npx @val-protocol/chain-verifier-cli --export=chain.ndjson`
- `--html=<path>` — write the **self-verifying HTML report**: a single file embedding the chain
  bytes and the full verifier source; opening it re-runs verification in your browser, offline.

## Honesty notes

- The demo key is generated in software, so the chain declares `key_binding: 'unattested'` —
  §5.2 forbids claiming `device_bound` without a verified WebAuthn attestation statement. The
  profile letter (B) grades the instrument; the binding is the orthogonal hardware axis,
  surfaced verbatim.
- Act 4 is a feature, not a bug: no record system can self-certify capture completeness, and the
  demo says so instead of hiding it. See the spec's [external anchor](../../spec/08-external-anchor.md).

Apache-2.0 · spec + protocol: [val-protocol/verifiable-authorization-lineage](https://github.com/val-protocol/verifiable-authorization-lineage)
