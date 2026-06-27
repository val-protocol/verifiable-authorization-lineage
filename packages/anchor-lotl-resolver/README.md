# @val-protocol/anchor-lotl-resolver

Caller-side **EU Trusted List (LOTL) trust resolution** for VAL external-anchor (Pass 4) **qualified**
timestamps. Given an RFC 3161 TimeStampToken, it resolves the `anchorTrust` SPKI set to hand to
[`@val-protocol/chain-verifier`](../chain-verifier), bound to the **granted CA/root identity** on the EU
Trusted List and validated as `TSA/QTST` + `granted` **at the token's `genTime`**.

## Why

The unit of *qualification* on the LOTL is the **CA / service** (e.g. *"Sectigo Qualified Time Stamping
CA R35"*), not the rotating leaf signer. Pinning a single scraped **leaf** SPKI breaks silently when the
QTSP rotates its signer (#3 → #4) — even though nothing changed on the Trusted List. This resolver binds
trust to the granted CA identity instead, so it is **re-resolvable across rotation** and never depends on
a hardcoded leaf. (RIGA audit finding **C6**, 2026-06-27.)

## Trustless

A third-party relying party runs this (or any reimplementation) against the **public** EU LOTL to
reproduce the trust set **without trusting RIGA's resolver**. It is a separate, caller-side package — the
zero-dep `@val-protocol/chain-verifier` core stays zero-dep and unchanged; it still only consumes
`anchorTrust.tsaCertSpkis: string[]` and proves `anchorBinding`. **"Qualified / Art-42" remains an
operator assertion backed by a legal opinion** (audit **C7**); this resolver establishes only the
*cryptographic* "CA is QTST/granted on the LOTL at genTime" fact.

## Usage

```js
import { resolveAnchorTrustLive } from '@val-protocol/anchor-lotl-resolver';
import { verifyValChain } from '@val-protocol/chain-verifier';

// 1) resolve anchorTrust from the token + the live EU Trusted List (network)
const { ok, spkis, evidence, reason } = await resolveAnchorTrustLive({ tstBase64 });
if (!ok) throw new Error(`anchor trust not established: ${reason}`);

// 2) feed the resolved SPKI set to the zero-dep verifier (no network, no hardcoded leaf)
const result = await verifyValChain(rows, { anchorTrust: { tsaCertSpkis: spkis } });
// result.anchorBinding === 'verified'  +  evidence.serviceStatus === '.../granted'
```

`resolveAnchorTrust({ tstBase64, tslXml })` is the **pure** (offline, testable) form; pass the
member-state TSL XML yourself.

## Scope / hardening notes

- Zero runtime deps: `node:crypto` (`X509Certificate`, hashes) + a minimal DER walk + global `fetch`.
- TSL parsing is regex-based over well-formed ETSI TS 119 612 XML (deliberate, zero-dep). A relying party
  MAY substitute a full XML/XAdES validator.
- **Out of scope (documented):** validating the **LOTL/TSL's own qualified signature** before trusting it,
  and **CRL/OCSP revocation** of the signer at genTime. Those belong to the LTV evidence-capture path —
  see RIGA ADR 0064 (evidence-storage model). This package establishes the CA-granted-at-genTime binding;
  it does not yet persist long-term validation material.

## Test

```bash
node --test            # offline suite (real Sectigo token + real ES TSL service block, no network)
RUN_LIVE=1 node --test # also the live EU LOTL → member-state TSL round-trip
```

License: Apache-2.0.
