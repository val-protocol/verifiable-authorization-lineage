# Contributing to VAL

Verifiable Authorization Lineage is an open protocol. It is maintained by RIGA Solutions and open to multi-stakeholder contribution — implementers, auditors, regulators, and adjacent-protocol authors are all welcome.

## How to contribute

- **Spec changes** — open an issue describing the gap or ambiguity before a PR. Normative changes to `spec/` require rationale and, where they affect the wire format, a migration note.
- **Reference implementation** — PRs against `packages/` should keep zero-runtime-dependency packages dependency-free, and include tests.
- **Protocol-landscape** — corrections to how VAL is positioned relative to other protocols are welcome; keep claims version-pinned and factual.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) — **not** a CLA. By signing off, you certify you have the right to submit the contribution under the project's license.

Add a `Signed-off-by` trailer to every commit:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it automatically. PRs without sign-off on every commit will be asked to amend.

> `Signed-off-by` is the DCO attestation. It is distinct from co-author/model-attribution trailers, which this project does not use.

## Licensing & IPR

All contributions are licensed under [Apache-2.0](LICENSE) — specification and code alike. Apache-2.0 carries an explicit patent grant. The protocol is offered royalty-free; no patent claims are asserted; no contributor licensing agreement is required.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Report security issues per [SECURITY.md](SECURITY.md) — not via public issues.
