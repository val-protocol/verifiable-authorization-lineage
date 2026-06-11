# Glossary

Vocabulary used across the VAL specification.

| Term | Meaning |
|---|---|
| **Block** | A typed, hash-linked entry in a VAL chain. One of: ANCHOR, ASSIGNMENT, ACCESS, MUTATION, CONSENT, COMMUNICATION, SETTLEMENT. |
| **Lineage** | The hash-chained path from any block back to a human-signed root ASSIGNMENT. The core invariant: every non-ASSIGNMENT/ANCHOR block must have a non-null `parent_assignment_hash`. |
| **ASSIGNMENT** | The root authorization block. Carries a *scope predicate* and a *human attestation*; optionally an *isolation commitment*. |
| **ACCESS** | A scoped read. Satisfies scope via a Merkle *membership proof* that the read resource is in the assignment's committed set. |
| **MUTATION** | A state change. Satisfies scope via *lineage + action + container* — no membership proof. |
| **Scope predicate** | The machine-checkable statement of what an authorization permits — `act` (action vocabulary) and `res` (resource clause: container, isolation, document scope). |
| **Human attestation** | The binding of an authorization to a natural-person principal. Strength varies by *conformance profile*. |
| **Conformance profile** | How strongly the human-principal root is bound: **A** (operator-attested, chained — achievable today), **B** (eIDAS-EAA), **C** (natural-person DID). The verifier reports the profile so consumers interpret residual trust correctly. |
| **Isolation commitment** | A Merkle root over the set of resources an assignment is permitted to touch — committed at authorization time, proven against at ACCESS time. |
| **Membership proof** | A Merkle inclusion proof that a resource's content hash is in an assignment's committed set (VAL §6.4). |
| **Offline verifier** | The procedure (and reference library) that re-derives integrity, lineage, scope-respect, grounding, and delegator authority from chain bytes + public trust anchors, with zero operator reads. |
| **Grounding** | Property #4: where an action class requires it (e.g. an agent's answer citing source documents), the cited content hashes are carried in the chain so the verifier confirms the grounding presence independently. |
| **External anchor** | A periodic commitment of the chain head to an external timestamp authority (RFC 3161 / eIDAS QTSP) for independent time and tamper-evidence. |
| **Canonical preimage** | The exact byte string a block's hash is computed over — RFC 8785 (JCS) canonical JSON. |
| **Trust anchor** | Public material a verifier needs and trusts: signing keys, QTSP trust list. Not the operator's database. |
