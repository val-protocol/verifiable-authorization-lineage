# @val-protocol/chain-verifier-cli — `val-verify`

CLI wrapper for [@val-protocol/chain-verifier](../chain-verifier/README.md). Verifies a VAL `audit.export` NDJSON chain from a local file, or directly from a VAL operator backend over MCP — offline-replayable, no trust in the operator at verification time.

## Install

```bash
npm install -g @val-protocol/chain-verifier-cli
```

## Modes

### File mode

Reads a local NDJSON file produced by an operator's `audit.export` tool (or any chain export conforming to the VAL wire format). Verifies row-by-row.

```bash
val-verify --export=./chain.ndjson
```

### URL mode

POSTs `tools/call` against a running VAL operator backend's MCP endpoint, paginates internally, verifies inline. No file is written to disk.

```bash
val-verify \
  --audit-export-url=https://backend.example.com/api/mcp/records \
  --bearer=$OAUTH_TOKEN \
  --dataroom-id=e33143e3-7a34-42b6-98f6-e2576d988de4
```

The bearer token must carry the operator's audit-export scope (e.g. `agent:audit.read`), and the identity behind the token must hold export access on the target workspace per the operator's authorization model.

## Options

| Flag | Required for | Description |
|---|---|---|
| `--export=<path>` | file mode | Local NDJSON file path. |
| `--audit-export-url=<url>` | URL mode | MCP endpoint URL of a running VAL operator backend. |
| `--bearer=<token>` | URL mode | OAuth access token with the operator's audit-export scope. |
| `--dataroom-id=<uuid>` | URL mode | Workspace to export and verify. |
| `--limit=N` | optional | Page size for URL mode (default 100, max 1000). |
| `--quiet`, `-q` | optional | Print only FAIL lines + final summary. |
| `--help`, `-h` | optional | Show usage. |

## Output

Each row produces one line:

```
seq=1   event=dataroom.created                     PASS
seq=2   event=governance.context_resolved          PASS
seq=3   event=participant.added                    FAIL
  reason: chain_hash mismatch
  expected: ef7df62bebfb36b34ae1057477f008b0a8fd3d47c38e10a6c0711df995a56c22
  observed: 7334009b343bae6cd060d69296de5c36fd70890c6f4dca11c046fbe89b7b5f19
…
── 119/120 PASS, 1 FAIL ──
```

## Exit code

- `0` — all rows verified.
- `1` — at least one row failed verification.
- `2` — argument error (missing required flag).
- `3` — runtime error (network failure, malformed input).

## What it verifies

Same construction as [@val-protocol/chain-verifier](https://github.com/val-protocol/verifiable-authorization-lineage/tree/main/packages/chain-verifier). The CLI is a thin wrapper around the same SHA-256 preimage construction specified by the [VAL wire format (§4)](https://github.com/val-protocol/verifiable-authorization-lineage/blob/main/spec/04-wire-format.md). No proprietary algorithm; an auditor who distrusts the operator can implement their own verifier in any language against the spec and cross-check.

For the full VAL pass suite (lineage, scope, grounding, delegator authority — §7.2 passes 2/3/5) over a parsed slice, use the library's `verifyValChain` directly; the CLI covers the integrity layer (pass 1) row-by-row with per-row diagnostics.

## License

Apache-2.0. See `LICENSE`.
