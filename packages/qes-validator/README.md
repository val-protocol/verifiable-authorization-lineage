# @val-protocol/qes-validator

**Not published.** Caller-side, **no-DSS, pure-JS** eIDAS **QES** (Qualified Electronic Signature)
validator for VAL **Profile C**. See spec §7.1(f) and §5.2 Profile C.

`anchoring proves time; Profile C proves identity.` This package validates the qualified signature at the
**root** of a VAL lineage — proving the human delegator is a **legally identified natural person** (eIDAS
Art-25), not merely a device-key holder (Profile B).

## Why a separate package

The reference verifier `@val-protocol/chain-verifier` is **zero-dependency** (Charter §II — "verify
without trusting RIGA"). QES validation (X.509 path-building, QcStatements, Trusted-List resolution) is
not zero-dep, so it lives here. The core **consumes its verdict** — exactly as Pass 4 consumes a resolved
`anchorTrust`. The relying party runs this validator themselves, so verification stays **trustless**.

## No DSS, no server (the trustless point)

A relying party verifies a VAL grant's qualified signature **without standing up a Java DSS** — this is
pure JS (Node 18+ / browser-friendly via Web Crypto + `node:crypto` X509). It reuses
`@val-protocol/anchor-lotl-resolver` for the LOTL→member-state pointer, and adds a **CA/QC-for-eSignatures**
Trusted-List matcher beside the resolver's TSA/QTST one (a TSA hit is **never** counted as a
qualified-eSignature hit).

## Documented ETSI subset (honest scope)

1. JWS/JAdES parse — ETSI TS 119 182-1
2. signature-value verification over the JWS signing input via the embedded `x5c` — ETSI TS 119 102-1
3. certificate-path build + verification leaf → issuer → trust anchor — ETSI TS 119 102-1
4. qualification-status determination — ETSI TS 119 615: `QcCompliance` (0.4.0.1862.1.1) **and**
   `QcType-eSign` (0.4.0.1862.1.6.1) in the signing cert **and** the issuer is a granted
   **CA/QC-for-eSignatures** Trusted-List service at signing time.

**Out of scope (DSS's job, not reimplemented):** per-certificate OCSP/CRL revocation, full AdES-LTA /
archive-timestamp LTV. Revocation here is at Trusted-List **service-status** granularity (granted /
withdrawn at signing time), not per-cert OCSP.

## Precondition: complete certificate chain (no AIA chasing)

The validator anchors a signature ONLY if the full path **leaf → … → TL-listed granted CA/QC service**
is present in the JAdES `x5c` header or in `trust.intermediateHintsDer`. It does **not** fetch missing
issuer certificates (no AIA / `caIssuers` chasing) — that would require a network call and break the
offline/trustless model. DSS-emitted JAdES carries the full chain in `x5c`; a leaner non-DSS QTSP that
emits a partial `x5c` (leaf only) will return **`status: 'not_qualified'`, `subIndication: 'CHAIN_INCOMPLETE'`**
(supply the full chain, or pass the intermediates via `intermediateHintsDer`) — **never a false `qualified`**.
This is distinct from `ANCHOR_NOT_ON_TRUSTED_LIST` (the chain WAS complete and reached a self-issued top
that simply isn't a granted CA/QC service — e.g. an attacker's self-signed root).

## Verdict — conclusive vs indeterminate, and per-signature keying

`validateQes(input) → QesValidationReport`. `qualified: boolean` is the only field the core treats as the
gate, and is `true` **only** on a conclusive positive. Everything else is `status: 'not_qualified'`
(conclusive negative) or `status: 'indeterminate'` (could not conclude — e.g. LOTL unreachable, no trust
anchor, CAdES input) — never a silent `qualified:true`. `signatureRef` (sha256-hex of the delegation
signature bytes) lets the core match **this** report to **this** signature (per-signature matching), so
distinct qualified delegations never borrow each other's verdict.

```ts
import { verifyValChain } from '@val-protocol/chain-verifier';
import { validateQes } from '@val-protocol/qes-validator';

const report = await validateQes({
  signedCanonical,                 // the root ASSIGNMENT canonical bytes the QES was computed over
  signature,                       // ValQesSignature { alg, signature } (detached JAdES)
  validationTime: anchorGenTime,   // §8.4 anchor genTime anchor time for at-signing-time determination
  trust: { tslXml, trustAnchorsDer }, // or { fetchLive: true } to pull the EU LOTL live
});
const result = await verifyValChain(rows, { qesValidation: { reports: [report] } });
// result.conformanceProfile === 'C' and result.signature === 'green' when report.qualified === true
```

## Tests

`npm test` — deterministic openssl fixtures (`test/fixtures/gen.sh`), no DSS, no network: the positive
(real ES256 signature verified + cert-path + QcStatements + CA/QC TSL), and negatives (mangled sig,
TSA-only issuer, withdrawn / granted-late service, no-ForeSignatures, wrong canonical, no anchor,
CAdES → indeterminate). **Not proven here:** byte-compatibility with a real DSS-emitted JAdES (needs the
infra-gated SSL.com artifact) — the fixtures are spec-shaped (sigD ObjectIdByURIHash) but synthetic.
