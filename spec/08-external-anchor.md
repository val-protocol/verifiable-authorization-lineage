# VAL v0.1 — External Anchor

## 8. External Anchor

### 8.1 ANCHOR Blocks

An `ANCHOR` block carries an RFC 3161 TimeStampToken over a Merkle root computed deterministically from a contiguous range of preceding blocks in the **same** `chain_scope` (the anchor is in-band — it lives in the chain it anchors). The covered range is `covered_range.from_sequence … to_sequence`, inclusive (§4.4).

The Merkle construction is **`val.checkpoint-merkle.v1`**, defined as:

- **Leaf** for each covered block: `SHA-256( UTF-8( decimal(sequence_number) ‖ "|" ‖ chain_hash ) )`, where `chain_hash` is the block's §4.3 chain hash. (The leaf hashes the `sequence_number|chain_hash` pair — it does **not** hash the block hash directly.)
- **Order:** leaves are taken in ascending `sequence_number` order (the chain's own order); they are **not** sorted.
- **Inner node:** `SHA-256( left_digest ‖ right_digest )` over the raw 32-byte child digests.
- **Odd count:** an odd final node at any level is **promoted unchanged** to the next level (it is **not** duplicated).
- **Root:** the single remaining digest, as 64-char lowercase hex. A single-leaf range has that leaf as its root.

The root is bound to time by setting it as the TimeStampToken's `messageImprint.hashedMessage`: the root **is** the timestamped digest and is **not** re-hashed before timestamping. (This `messageImprint = { SHA-256, merkle_root }` convention is what Pass 4 re-checks, §8.4.)

> `val.checkpoint-merkle.v1` is a checkpoint Merkle over an ordered block-hash range. It is a distinct construction from the §6.4 isolation-membership Merkle (a sorted set of content-hashes for inclusion proofs); the two are not interchangeable.

### 8.2 Cadence

The operator MAY anchor at any cadence. RECOMMENDED minima: once per 24 hours per active `chain_scope`; once per N blocks where N is operator-chosen, with N ≤ 1000 advised for high-assurance use cases. The protocol does not mandate a cadence.

### 8.3 QTSP Independence

The protocol is QTSP-agnostic. Any RFC 3161 timestamp authority works. For eIDAS-qualified assurance, any QTSP listed on the EU Trusted List (LOTL) is acceptable. In other jurisdictions, any ETSI EN 319 422-conformant QTSP works. Operators MAY anchor to multiple QTSPs in different jurisdictions for cross-jurisdictional resilience; the protocol places no restriction.

### 8.4 Verification

The verifier (Pass 4, §7.2) for each ANCHOR block:

1. recomputes the Merkle root over the in-band blocks `covered_range.from_sequence … to_sequence` using `merkle_alg` (`val.checkpoint-merkle.v1`, §8.1) and asserts it equals `merkle_root`;
2. parses the RFC 3161 TimeStampToken (`tst`) and asserts `messageImprint.hashedMessage == merkle_root` (the root is the timestamped digest, §8.1) — this binds the token to *this* chain range rather than to unrelated data;
3. verifies the token's CMS signature against a resolved trust anchor (§7.1) — the set of acceptable TSA signing certificates. The signature is verified over the DER-encoded `signedAttributes` (the CMS `SignedData` form RFC 3161 tokens take), and the `message-digest` signed attribute MUST equal `SHA-256(TSTInfo)`. The signing certificate MUST carry the `id-kp-timeStamping` extended-key-usage (RFC 3161 §2.3);
4. surfaces the TSA-attested `genTime` from the token.

A green Pass-4 result establishes that the anchored blocks existed no later than the TSA-attested `genTime`, independently of the operator's `timestamp_local` claim. Pass 4 asserts **temporal existence only** — it does not evaluate any time *policy* (e.g. comparing `genTime` against an ASSIGNMENT validity window); such evaluation is reserved for a later version. A chain MAY carry multiple ANCHOR blocks (one per anchoring cadence, §8.2); Pass 4 iterates all of them, each verified against its own `covered_range`.

How a deployment obtains the resolved trust anchor is out of band: in Phase-1 / any-TSA deployments it is a pinned set of TSA certificate public keys; for eIDAS-qualified assurance it is resolved from the EU Trusted List (LOTL) on the caller's side and passed to the verifier as a resolved certificate set — the verifier never fetches a trust list itself (§7.1), so the verification logic is identical across both.

### 8.5 Without an Anchor

The chain is verifiable for integrity, lineage, scope, grounding, and delegator authority without any ANCHOR block (passes 1–3 and 5). The anchor strengthens temporal claims; it is not a prerequisite for the lineage property. v0.1 marks anchor as optional precisely because operators with strong internal time guarantees may defer QTSP procurement; the protocol still works.

---
