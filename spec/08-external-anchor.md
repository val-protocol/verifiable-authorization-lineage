# VAL v0.1 — External Anchor

## 8. External Anchor

### 8.1 ANCHOR Blocks

An `ANCHOR` block carries an RFC 3161 TimeStampToken over a Merkle root computed deterministically from the hashes of a contiguous range of preceding blocks in the same `chain_scope`. The Merkle construction is the standard binary tree with SHA-256 inner nodes; duplicate-last-leaf for odd counts; leaf hash is the block hash directly (no re-hashing).

### 8.2 Cadence

The operator MAY anchor at any cadence. RECOMMENDED minima: once per 24 hours per active `chain_scope`; once per N blocks where N is operator-chosen, with N ≤ 1000 advised for high-assurance use cases. The protocol does not mandate a cadence.

### 8.3 QTSP Independence

The protocol is QTSP-agnostic. Any RFC 3161 timestamp authority works. For eIDAS-qualified assurance, any QTSP listed on the EU Trusted List (LOTL) is acceptable. In other jurisdictions, any ETSI EN 319 422-conformant QTSP works. Operators MAY anchor to multiple QTSPs in different jurisdictions for cross-jurisdictional resilience; the protocol places no restriction.

### 8.4 Verification

The verifier (pass 4) recomputes the Merkle root from the in-band block range, verifies equality with the anchored root, and verifies the QTSP signature against the trust list. A green pass-4 result establishes that the anchored blocks existed no later than the QTSP-attested time, independently of the operator's `timestamp_local` claims.

### 8.5 Without an Anchor

The chain is verifiable for integrity, lineage, and scope without any ANCHOR block (passes 1–3). The anchor strengthens temporal claims; it is not a prerequisite for the lineage property. v0.1 marks anchor as optional precisely because operators with strong internal time guarantees may defer QTSP procurement; the protocol still works.

---
