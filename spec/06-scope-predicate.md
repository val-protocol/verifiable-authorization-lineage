# VAL v0.1 — Scope-Predicate Language

## 6. Scope Predicate Language

### 6.1 Design Goals

Machine-checkable, intersectable (so sub-assignments can have effective scope computed as ancestor intersection), decidable in time linear in predicate size, and expressible as a JSON object (carried in the ASSIGNMENT's `scope` field, §4.4). No turing-completeness. No external lookups during evaluation.

A deployment's runtime authorization engine (FGA, OPA, Zanzibar, or any other) is typically more expressive than what VAL's scope predicate language captures — composed relations, set-algebraic relation expressions, and rich isolation properties (e.g. adversarial-partition isolation between cohabiting principal populations) exist in those engines that do not map one-to-one onto VAL's predicate shape. The protocol does not require the runtime engine to be reducible to the predicate; it requires the *effective scope at assignment time* to be serializable into a form the verifier can evaluate offline. The serialization SHOULD preserve all properties whose violation would be a privacy or compliance breach (e.g. party-isolation between adversarial cohorts); properties that are runtime-dynamic and not material to scope-respect MAY be omitted. The serialization fidelity is a deployment design decision documented per chain.

### 6.2 Top-Level Grammar

A scope predicate is a JSON object with the following optional keys. The empty object `{}` denotes the "no constraint" scope and SHOULD be rejected by operators as too permissive except for explicitly root-of-trust assignments.

```
{
  "subj":  <subject-clause>,           # required for any non-root assignment
  "act":   [<action-name>, ...],       # set of permitted action names
  "res":   <resource-clause>,          # resources in scope
  "win":   { "not_before": <uint>,
             "not_after":  <uint> },   # time window
  "lim":   { "max_count": <uint>,
             "max_value": <uint>,
             "max_value_currency": <tstr> }  # quantitative limits
}
```

### 6.3 Subject Clause

```
{
  "principal_uri": <URI>              # exact match
}
```
v0.1 supports exact-match only. v0.2 may add principal-set expressions.

### 6.4 Resource Clause

```
{
  "resource_type": <tstr>,
  "ids":           [<tstr>],          # exact set
  "id_glob":       <tstr> or null,    # optional glob (e.g. "doc_workspace_42_*")
  "in_workspace":  <tstr> or null,    # container for nested resources
  "isolation":     <tstr> or null,    # e.g. "cohort-a" (label only — see isolation_commitment)
  "isolation_commitment": <bstr 32> or null  # OPTIONAL Merkle root committing the permitted resource SET
}
```

**Isolation commitment (optional, recommended for adversarial-counterparty isolation).** A free-text
`isolation` label is verifier-uncheckable against reality: it asserts a side but does not let an outsider
confirm a given action targeted a resource that was *actually* a member of that side. For deployments where
the isolation property is adversarial (non-leakage between cohabiting adversarial cohorts being the canonical case), the
ASSIGNMENT MAY carry `isolation_commitment` — the Merkle root of the set of resource content-hashes that
were permitted under this assignment at the moment it was authorized. Each non-assignment block targeting
such a resource then carries a Merkle **inclusion proof** in `payload.membership_proof` (a sibling-hash path).
The verifier recomputes the root from `(resource content-hash + proof)` and asserts equality with the
ASSIGNMENT's committed root — re-deriving membership from chain bytes alone, with **no per-action operator
trust**. The commitment is a *snapshot at authorization time*: this is the correct lineage semantic — the
scope of an authorization is what was permitted when the human authorized it, not what the mutable access
matrix says later. Committing the root (not the set) is a selective-disclosure property: a verifier checking
one action learns only that action's member, never the cardinality or contents of the permitted set.

**Residual location (precise).** The per-action `membership_proof` is *self-verifying*: the verifier
recomputes the root from `(resource content-hash ‖ proof)` and rejects any proof that does not reproduce the
committed root — so a forged or mis-targeted proof is caught without trusting the operator, and the proof's
*generation* is not trust-critical. The single trust-critical act is computing the **commitment root over the
correct per-side set at authorization time** and writing it atomically into the chained ASSIGNMENT. That makes
this mechanism's residual exactly **one-per-assignment** ("was the committed set correct when the human
authorized?") — root-level, named, chain-embedded — the same grade as the Profile-A human-attribution
residual, and strictly stronger than a per-action tag. The commitment MUST therefore be emitted in the same
transaction as the ASSIGNMENT block; the per-action proof MAY be generated wherever convenient.

**Membership-tree leaf convention.** A membership commitment is over an *unordered set*, not an ordered
sequence, so it does NOT reuse the checkpoint leaf convention (`sha256(seq ‖ '|' ‖ hash)`). Membership leaves
are the resources' content-hashes, **sorted lexicographically** for determinism, then combined with the same
pairwise-hashing structure as the deployment's canonical Merkle function (duplicate-last on odd counts). The
committer and the verifier MUST use byte-identical tree construction; a conformance test asserting
`commit_root(set) == verifier_root(set)` over shared fixtures is mandatory.

### 6.5 Action Names

Normative v0.1 action names: `read`, `view`, `list`, `search`, `create`, `update`, `delete`, `rename`, `classify`, `sign`, `acknowledge`, `send`, `share-create`, `share-access`, `qa-post`, `qa-answer`, `charge`, `refund`, `subscribe`, `cancel`, `invoice`.

### 6.6 Satisfaction

An action block `B` *satisfies* predicate `P` iff all of:

- `B.principal == P.subj.principal_uri`.
- `B.payload.action ∈ P.act`.
- `B.payload.resource_id` matches `P.res` (either in `ids`, matches `id_glob`, and/or is in the `in_workspace` container).
- If `P.res.isolation_commitment` is present **and `B` is an ACCESS block** (a resource read): `B.payload.membership_proof` is a valid Merkle inclusion proof for `B`'s resource content-hash against that committed root. Absent or invalid proof → not satisfied. This is the cryptographic isolation check; the `isolation` label alone is informative, not satisfying. The check is **ACCESS-only by design**: isolation governs which documents an action *reads*. A MUTATION (record write), CONSENT, or COMMUNICATION block is not a document read — it satisfies via lineage + action + container (`in_workspace`); any document it grounds in is enforced at write time by the deployment and recorded as its own ACCESS blocks. Requiring a membership proof on a non-read action would be a category error.
- `P.win.not_before ≤ B.timestamp_local ≤ P.win.not_after` (where bounds are present).
- The aggregate counts and values for `B.parent_assignment_hash`'s descendants do not exceed `P.lim` (verifier computes the aggregate over the chain).

### 6.7 Intersection (Delegated Sub-Assignments)

When an `ASSIGNMENT` `A_child` has a non-null `parent_assignment_hash` pointing to `A_parent`, its *effective* scope is the intersection of `A_child.scope` and `A_parent`'s effective scope (which is in turn the intersection back to root). The verifier MUST compute effective scope transitively and evaluate action blocks against the effective scope, not the literal declared scope.

This makes delegation strictly narrowing: a sub-assignment cannot grant more than its parent had.

---
