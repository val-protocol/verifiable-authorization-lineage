# Protocol Landscape

VAL is one member of the **agent-action-verification** family — the category Mastercard and Google named "verifiable intent." This section places VAL relative to the others so adopters understand what it does, what it deliberately does not, and where it composes with adjacent layers.

- **[protocols.md](protocols.md)** — VAL vs Verifiable Intent, AP2 / UCP, W3C VC / DID, in-toto / SLSA.
- **[glossary.md](glossary.md)** — the vocabulary used across the spec.

## The short version

| | |
|---|---|
| **What VAL is** | an open wire format + offline verifier for human-rooted authorization lineage |
| **What it proves** | every action traces to a human-signed root and stayed within its scope — verifiable without trusting the operator |
| **What it is not** | an identity system, a transport, a runtime policy engine, or a payment protocol |
| **Who it's for** | regulated agreements (legal, notarial, accounting) where authorization must be provable for years |
| **Closest sibling** | Verifiable Intent (commerce, SD-JWT credential) — VAL is the regulated-agreement, ledger-model counterpart |
