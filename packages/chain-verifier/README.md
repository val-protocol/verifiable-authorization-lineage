# @val-protocol/chain-verifier

The reference offline verifier for [Verifiable Authorization Lineage (VAL)](https://github.com/val-protocol/verifiable-authorization-lineage). Zero runtime dependencies — pure SHA-256 against the canonical preimage specified in the [VAL wire format (§4)](https://github.com/val-protocol/verifiable-authorization-lineage/blob/main/spec/04-wire-format.md).

This package lets any subscriber, regulator, counterparty, or third-party auditor verify a VAL chain client-side — re-deriving integrity, lineage, and scope from the chain bytes alone, without trusting the operator that recorded it. RIGA Solutions maintains it as the protocol's reference implementation; it is deployment-agnostic and verifies any conforming VAL chain, not only RIGA's.

## Install

```bash
npm install @val-protocol/chain-verifier
```

## Usage

### Verify a single contiguous slice

```ts
import { verifyChain, ChainRow } from '@val-protocol/chain-verifier';
import { readFileSync } from 'node:fs';

const ndjson = readFileSync('chain.ndjson', 'utf-8');
const rows: ChainRow[] = ndjson
  .trim()
  .split('\n')
  .map((line) => JSON.parse(line));

const result = verifyChain(rows);
if (!result.ok) {
  console.error(`chain broken at row ${result.firstBadIndex}: ${result.reason}`);
  process.exit(1);
}
console.log(`verified ${rows.length} rows; chain intact.`);
```

### Reconstruct a single row's hash

```ts
import { reconstructChainHash } from '@val-protocol/chain-verifier';

const expected = reconstructChainHash({
  scopeKey: '1f0ee1e2-6f2c-4f95-955b-5aa5270ce05c',
  sequenceNumber: 42,
  eventType: 'record.created',
  canonicalDetails: '{"actor":"system","resource_id":"…"}',
  previousHash: '6a3f…',
});
// expected === the row's chain_hash
```

## Input shape — `ChainRow`

Each row corresponds to one line of an exported VAL chain (e.g. an NDJSON export). The verifier needs only six fields per row; everything else in the export line is ignored.

```ts
interface ChainRow {
  scope_key: string;              // the discrete chain-scope key (see §4)
  sequence_number: number | bigint;
  event_type: string;
  canonical_details: string;      // RFC 8785 canonical JSON — pass verbatim
  previous_hash: string | null;   // null only for genesis (sequence_number=1)
  chain_hash: string;             // the 64-char hex SHA-256 the row claims
}
```

The verifier's input contract requires the slice to be (a) all from the same `scope_key`, (b) sorted ASC by `sequence_number`, (c) contiguous (`sequence_number` forms an arithmetic progression with step 1). The verifier checks (a) and (c) defensively but treats violations as errors.

## What it verifies

For each row in the slice:

1. **Genesis invariant** — if `sequence_number === 1`, `previous_hash` must be `null`.
2. **Linkage** — non-genesis `previous_hash` must equal the prior row's `chain_hash`.
3. **Preimage** — `chain_hash` must equal `SHA-256(UTF-8(scope_key || '|' || sequence_number || '|' || event_type || '|' || canonical_details || '|' || (previous_hash ?? 'GENESIS')))`.

Returns the FIRST failure with a human-readable `reason`. Does not continue past first failure (so the `firstBadIndex` is unambiguous).

The VAL passes 2 (lineage) and 3 (scope), plus the grounding re-derivation and pass 5 (delegator authority), are exposed via `verifyValChain` over the same `ChainRow[]`. See the [offline-verifier spec (§7)](https://github.com/val-protocol/verifiable-authorization-lineage/blob/main/spec/07-offline-verifier.md).

### Delegator authority (pass 5, 0.2.0+)

Every ASSIGNMENT body of version ≥ 2 must carry `human_attestation.delegator_authority` — the
authority basis under which the issuing human could grant the delegated scope. Supply your
operator's capability policy (a trust-anchor input you pin independently of the chain bytes,
spec §7.1(d)) to have the verifier assert `scope.act ⊆ policy[capability]`:

```ts
import { verifyValChain } from '@val-protocol/chain-verifier';

const result = verifyValChain(rows, {
  delegatorAuthorityPolicy: {
    // operator-namespaced capability → actions a holder may delegate
    administrator: ['read', 'view', 'list', 'create', 'upload', 'send'],
    read_only: ['read', 'view', 'list'],
  },
});
// result.authority                          → 'green' | 'red' | 'none'
// result.firstAuthorityViolation            → first escalation (e.g. a read-only
//                                             delegator granting writes), or null
// result.legacyPreAuthorityAssignmentCount  → v1 pre-carrier blocks (tolerated, counted)
```

Without the policy, pass 5 still hard-fails any v2 ASSIGNMENT missing the carrier; the
subset check needs the policy. Pre-0.2.0 (v1) chains verify exactly as before, reporting
`authority: 'none'` plus the legacy count.

**Trust boundary (read before citing pass-5 results):** pass 5 verifies the authority claim's
*internal consistency* — the recorded capability could grant the delegated scope, against a
policy YOU pin independently of the chain bytes (§7.1(d)); never accept a policy handed to you
by the operator at verification time. It does **not** cryptographically prove the named human
held that capability: under Profile A the carrier is operator-attested, and that residual trust
is the profile's, not the pass's. The cryptographic binding is the carrier's reserved
`signature` sub-field (Profiles B/C, spec §5.2) — until an operator ships it, no pass-5 result
should be described as "trustless authority verification."

One basis is stronger: for the reserved `container_owner` basis (spec §7.2, v0.3.0), two
sub-claims ARE re-derived from chain bytes alone — `scope_ref` must equal the ASSIGNMENT's
`scope.res.in_workspace`, and a human-performed COMMUNICATION rooted in it must hash
(`sha256` of the `user:` principal id) to the attested `subject_user_hash`. Those two
mismatches are detected without trusting the operator; the rest of the basis carries the
same Profile-A residual as above.

## Partial-slice verification

A slice that does NOT include the genesis row can still be verified — only the genesis invariant (step 1) is skipped. The caller is responsible for trusting the slice's starting row (e.g., from an externally-anchored sequence_number, or by independent verification of an earlier overlapping slice).

## What it does NOT do

- It does NOT fetch data — feed it rows; you handle I/O.
- It does NOT decrypt payloads — payload confidentiality is outside the chain layer (VAL covers integrity and authorization-lineage only).
- It does NOT validate canonical-JSON well-formedness of `canonical_details` — the chain only commits to the byte string. If your `canonical_details` came from outside the canonical-JSON pipeline, RFC 8785 validation is your responsibility.

## Self-test

A simple adversarial round-trip you can run to sanity-check the package after install:

```ts
import { reconstructChainHash, verifyChain } from '@val-protocol/chain-verifier';

const cd = '{"foo":"bar"}';
const h1 = reconstructChainHash({
  scopeKey: 'x',
  sequenceNumber: 1,
  eventType: 'genesis',
  canonicalDetails: cd,
  previousHash: null,
});
const h2 = reconstructChainHash({
  scopeKey: 'x',
  sequenceNumber: 2,
  eventType: 'next',
  canonicalDetails: cd,
  previousHash: h1,
});
console.log(verifyChain([
  { scope_key: 'x', sequence_number: 1, event_type: 'genesis', canonical_details: cd, previous_hash: null, chain_hash: h1 },
  { scope_key: 'x', sequence_number: 2, event_type: 'next',    canonical_details: cd, previous_hash: h1,   chain_hash: h2 },
]));
// { ok: true, firstBadIndex: null, reason: null }

// Tamper:
console.log(verifyChain([
  { scope_key: 'x', sequence_number: 1, event_type: 'genesis', canonical_details: cd + ' ', previous_hash: null, chain_hash: h1 },
  { scope_key: 'x', sequence_number: 2, event_type: 'next',    canonical_details: cd,        previous_hash: h1,   chain_hash: h2 },
]));
// { ok: false, firstBadIndex: 0, reason: 'chain_hash mismatch at index 0: ...' }
```

## Trust model

This package is the structural realization of VAL's core promise: any party can pull a chain's history, replay it client-side, and verify integrity, lineage, and scope **without trusting the operator that produced it**.

- The package has zero runtime dependencies. Its dependency closure is `crypto` (Node built-in).
- Anyone who doesn't trust this published verifier can write their own against the [VAL wire-format spec (§4)](https://github.com/val-protocol/verifiable-authorization-lineage/blob/main/spec/04-wire-format.md) — the byte-level preimage is fully documented, the algorithm is standard SHA-256, and the spec's test vectors are reproducible from any environment.
- The verifier MUST be exercised against adversarial inputs as well as happy-path replays; integrators reusing it should preserve equivalent regression coverage in their own builds.

## License

Apache-2.0. See `LICENSE`.
