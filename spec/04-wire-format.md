# VAL v0.1 — Wire Format

## 4. Wire Format

### 4.1 Encoding (v0.1 normative)

VAL v0.1 commits chains over a **JSON-canonical** encoding. Each block's content is serialized with the **RFC 8785 JSON Canonicalization Scheme (JCS)** into a `canonical_details` byte string, and the chain hash is computed over a deterministic pipe-delimited preimage (§4.3). This is exactly what the reference implementation (`@val-protocol/chain-verifier`) computes and verifies, and it is the sole canonical hash domain a VAL v0.1 chain MUST use.

> **Future encodings (non-normative).** A deterministic-CBOR frame (RFC 8949 §4.2) with single-byte block-type codes and a fixed binary header is a candidate for a future major version where binary compactness or a self-describing on-the-wire frame is wanted. It is **not** part of v0.1, and the v0.1 reference implementation neither produces nor accepts it. It is recorded here only as a direction; v0.1 conformance is defined solely by §4.1–§4.4 as written.

### 4.2 Block Types and Action Classes

VAL defines seven block types. Six correspond to the protocol's six **action classes**; the seventh (ANCHOR) is an operational checkpoint (§8). The block type is carried as a `block_type` string inside each block's canonical content (§4.4).

| Block type | Action class | Meaning | v0.1 reference status |
|---|---|---|---|
| ASSIGNMENT | `assign` | Roots a lineage: authorizes a principal within a scope. | **shipped** |
| ACCESS | `read` | Read / view / list / search of a resource. | **shipped** |
| MUTATION | `write` | Create / update / delete / classify / rename of a resource. | **shipped** |
| CONSENT | `sign` | Signature, agreement acceptance, NDA, disclosure attestation. | specified; not yet implemented |
| COMMUNICATION | `send` | Send, share-link create/access, Q&A post/answer, outbound message. | specified; not yet implemented |
| SETTLEMENT | `settle` | Payment, refund, subscription change, invoice. | specified; not yet implemented |
| ANCHOR | — | External timestamp over a Merkle root of preceding blocks (§8). | specified; not yet implemented |

"Shipped" means the reference producer emits the block and the reference verifier re-derives its properties end-to-end. The four not-yet-implemented types are recognized by the reference verifier's type set (it will verify them if present) but are not emitted by the reference producer; a conforming implementation MAY emit them ahead of this reference. **The block types that ship end-to-end today are ASSIGNMENT, ACCESS, and MUTATION.**

Operators MAY define private block types; a verifier MUST ignore any `block_type` it does not recognize rather than fail.

### 4.3 Chain Row and Hash Construction (v0.1 normative)

A chain is an append-only sequence of rows partitioned by `scope_key`. Each row carries:

| Field | Type | Description |
|---|---|---|
| `scope_key` | string | Identifier partitioning one chain from another. Each scope has its own genesis and its own monotonic `sequence_number`. |
| `sequence_number` | integer | Per-`scope_key` monotonic counter; the genesis row is `1`. |
| `event_type` | string | The action/event label committed over (e.g. `record.created`). |
| `canonical_details` | string | RFC 8785 JCS serialization of the block content (§4.4). Hashed verbatim — never re-serialized by the verifier. |
| `previous_hash` | string or null | The prior row's `chain_hash`; null only for the genesis row. |
| `chain_hash` | string | 64-char lowercase-hex SHA-256 of the preimage below. |

The **chain-hash preimage** is the UTF-8 string formed by joining five components with `'|'`:

```
chain_hash = SHA-256( UTF-8(
    scope_key                          + '|' +
    decimal(sequence_number)           + '|' +
    event_type                         + '|' +
    canonical_details                  + '|' +
    (previous_hash ?? 'GENESIS')
) )
```

This is the sole canonical hash domain for VAL v0.1. There is **no per-block signature field** in the wire format; the strength of the human-principal binding at the lineage root is a conformance-profile property (§5.2), not a wire-format field.

### 4.4 Block Content (`canonical_details`)

`canonical_details` is the RFC 8785 JCS serialization of a JSON object. Every VAL block carries `v` (schema version, `1`) and `block_type`; the remaining members are per type. A row whose content carries no `block_type` is a non-VAL event (operator-private or pre-VAL) and is skipped by the lineage / scope / grounding passes.

**ASSIGNMENT** — the lineage root. No `parent_assignment_hash` (§5.1).
```json
{
  "v": 1,
  "block_type": "ASSIGNMENT",
  "scope": { "act": ["read", "write"], "res": { "...": "..." } },
  "human_attestation": { "method": "session", "subject_user_hash": "<hex>", "attested_at": 1700000000 }
}
```
`scope` is the §6 scope predicate (`act` = authorized action vocabulary; `res` = resource clause, incl. an optional `isolation_commitment`). `human_attestation` carries the Profile-A human designation (§5.2); its presence on a root ASSIGNMENT is what the verifier reads as the human binding under Profile A.

**ACCESS** — a scoped read under an ASSIGNMENT.
```json
{
  "v": 1,
  "block_type": "ACCESS",
  "parent_assignment_hash": "<hex>",
  "action": "read",
  "principal": "<URI>",
  "resource": { "content_hash": "<hex>", "resource_id": "<id>", "in_workspace": "<id>" },
  "membership_proof": [ { "hash": "<hex>", "side": "L" } ]
}
```
`action` ∈ {`read`, `view`, `list`, `search`}. `membership_proof` is the §6.4 Merkle inclusion proof of `resource.content_hash` against the assignment's committed `isolation_commitment`, present only when the assignment is isolation-scoped (`null` = the resource is outside the committed set).

**MUTATION** — a state change rooted in an ASSIGNMENT (§6.6: satisfied by lineage + action + container, never a membership proof). Same resource clause as ACCESS, minus `membership_proof`, plus an optional `grounded_document_hashes`.
```json
{
  "v": 1,
  "block_type": "MUTATION",
  "parent_assignment_hash": "<hex>",
  "action": "<capability-specific action name>",
  "principal": "<URI>",
  "resource": { "content_hash": "<hex>", "resource_id": "<id>", "in_workspace": "<id>" },
  "grounded_document_hashes": ["<hex>", "..."]
}
```
`action` is a free string the capability defines; the verifier does not enumerate action names. `grounded_document_hashes` is **optional** — present (non-empty) when the mutation derives from content the actor read, omitted or empty when it is not content-derived; §7.5 defines the read-before-derive check over it. Operators MAY carry additional metadata in the canonical object; the verifier neither requires nor evaluates such fields.

**CONSENT / COMMUNICATION / SETTLEMENT / ANCHOR** — specified as action classes (§4.2) but not emitted by the v0.1 reference producer; the canonical content shape of each is reserved to the capability that introduces it. A conforming implementation that emits them MUST carry `v`, `block_type`, and — for the action classes — `parent_assignment_hash`.

---
