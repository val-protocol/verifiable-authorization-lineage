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

const result = await verifyChain(rows);
if (!result.ok) {
  console.error(`chain broken at row ${result.firstBadIndex}: ${result.reason}`);
  process.exit(1);
}
console.log(`verified ${rows.length} rows; chain intact.`);
```

### Reconstruct a single row's hash

```ts
import { reconstructChainHash } from '@val-protocol/chain-verifier';

const expected = await reconstructChainHash({
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

const result = await verifyValChain(rows, {
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
by the operator at verification time. Under Profile A it does **not** cryptographically prove the
named human held that capability — the carrier is operator-attested, and that residual trust is
the profile's, not the pass's.

One basis is stronger even under Profile A: for the reserved `container_owner` basis (spec §7.2,
v0.3.0), two sub-claims ARE re-derived from chain bytes alone — `scope_ref` must equal the
ASSIGNMENT's `scope.res.in_workspace`, and a human-performed COMMUNICATION rooted in it must hash
(`sha256` of the `user:` principal id) to the attested `subject_user_hash`. Those two mismatches
are detected without trusting the operator; the rest of the basis carries the Profile-A residual.

### Profile B — device-signature verification (v0.4.0, spec §5.2)

When the carrier ships a `delegator_authority.signature` (a WebAuthn assertion), it is now
**cryptographically verified offline**, closing the Profile-A residual for that grant:

```ts
const result = await verifyValChain(rows);
// result.signature          → 'green' (verified + linked) | 'red' (present but invalid) | 'none'
// result.keyBinding         → 'device_bound' | 'syncable' | 'unattested' | null  ← surfaced verbatim
// result.firstSignatureViolation → first failure, or null
// result.conformanceProfile → 'A' | 'B' | 'C'  — the FLOOR: the WEAKEST profile among the
//                              chain's root ASSIGNMENTs (never rounded up; one qualified
//                              grant cannot mask operator-attested ones)
// result.profilesPresent    → ('A'|'B'|'C')[]  — every profile observed across lineages
// result.authorityCarriers  → [{ sequenceNumber, basis, capability, attested_by?, session_ref? }]
//                              — every delegator_authority carrier, verbatim (who attested
//                              entitlement, without reading raw blocks)
```

What the pass proves, from the chain bytes alone:

- The delegation signature is a valid ES256 assertion over its own `authenticatorData ||
  sha256(clientDataJSON)`.
- It chains to the enrolled, self-attested **org-root** key: the embedded
  `delegator_authority.org_root.self_signature` must sign
  `orgRootBindingChallenge({org_id, signatory_identity_hash, public_key, identity_assurance,
  key_binding})`, and the delegation key must equal that org-root key. Relabeling `key_binding`
  (e.g. `device_bound` → `syncable`) or `identity_assurance` breaks the self-signature ⇒
  `signature: 'red'`. A signature by any other key ⇒ `signature: 'red'` (linkage failure).
- `keyBinding` is reported **verbatim** — `syncable` (iCloud-synced passkey) is never rounded up
  to `device_bound`, and `unattested` (no verified hardware attestation at enrollment — the
  provenance is the enrollee's claim) is never rounded up to either. A verifying party decides
  for itself whether a synced or unattested key meets its bar. An `unattested` binding still
  earns Profile B on a verified + linked signature: the letter grades the instrument; the
  binding is the orthogonal hardware axis.

A lineage reaches **B only on a verified + linked signature** (a present-but-invalid
signature claims no profile and is flagged `signature: 'red'` — no over-claim). It reaches **C
verified** when the caller supplies a QES validation verdict via
`options.qesValidation: { reports }` (produced offline by the separate
`@val-protocol/qes-validator` against the EU Trusted List — outcome
`authority_verified_qualified`); with a qualified algorithm declared but **no verdict
supplied**, the lineage is classified `qualified_unverified` — never silently upgraded. The
chain-level `conformanceProfile` is the **floor** across all root ASSIGNMENTs; read
`profilesPresent` for the full per-lineage picture.

Known limitation: the signature's WebAuthn challenge is not yet bound offline to a specific grant
payload (a future strengthening); the device_bound/syncable org-root verdict does not depend on it.

#### Lower-level signature exports

`verifyValChain` runs the signature pass for you. For callers that want to verify a delegation
signature outside the chain context, three helpers are also exported:

```ts
import {
  verifyDelegatorSignature,   // (sig, expectedChallenge?) → boolean — pure ES256 assertion check
  verifyDelegationTrustChain,  // (delegationSig, orgRoot?) → { outcome, signatureValid, linkageVerified, keyBinding, reason }
  orgRootBindingChallenge,     // (orgRoot) → string — the canonical challenge the org-root self-signature must cover
} from '@val-protocol/chain-verifier';
```

`verifyDelegationTrustChain` is the building block the chain pass uses: it verifies the delegation
signature AND its linkage to the self-attested org-root, returning the same `device_bound`/`syncable`
binding surfaced verbatim. `orgRootBindingChallenge` lets you independently re-derive (and thus
audit) the exact preimage the org-root `self_signature` commits to.

### Root subject (v0.6.0)

`verifyValChain` surfaces the root human's **declared identity** so consumers don't have to
re-parse `canonical_details`:

```ts
const result = await verifyValChain(rows);
// result.rootSubject → { subject_claim: string; source: string } | null
//   e.g. { subject_claim: 'John Doe', source: 'self_asserted' }
```

It is read from the first human-rooted ASSIGNMENT's
`human_attestation.identity_assurance.subject_claim`, which is already hash-bound in that block's
`canonical_details` and integrity-checked by passes 1–3 — so surfacing it adds no new trust. `source`
is reported **verbatim** (a `self_asserted` name is never rounded up to `vouched`), and `rootSubject`
is `null` for pre-declaration chains that carry no `identity_assurance`. This is an additive,
output-only field; it changes no verdict.

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
const h1 = await reconstructChainHash({
  scopeKey: 'x',
  sequenceNumber: 1,
  eventType: 'genesis',
  canonicalDetails: cd,
  previousHash: null,
});
const h2 = await reconstructChainHash({
  scopeKey: 'x',
  sequenceNumber: 2,
  eventType: 'next',
  canonicalDetails: cd,
  previousHash: h1,
});
console.log(await verifyChain([
  { scope_key: 'x', sequence_number: 1, event_type: 'genesis', canonical_details: cd, previous_hash: null, chain_hash: h1 },
  { scope_key: 'x', sequence_number: 2, event_type: 'next',    canonical_details: cd, previous_hash: h1,   chain_hash: h2 },
]));
// { ok: true, firstBadIndex: null, reason: null }

// Tamper:
console.log(await verifyChain([
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
