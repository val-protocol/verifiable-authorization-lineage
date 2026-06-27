# @val-protocol/qes-validator

**SCAFFOLD — not published.** Optional eIDAS **QES** (Qualified Electronic Signature) validator for VAL
**Profile C**. See **ADR 0063**.

`anchoring proves time; Profile C proves identity.` This package validates the qualified signature at the
**root** of a VAL lineage — proving the human delegator is a **legally identified natural person** (eIDAS
Art-25), not merely a device-key holder (Profile B).

## Why a separate package

The reference verifier `@val-protocol/chain-verifier` is **zero-dependency** (Charter §II — "verify
without trusting RIGA"). Full QES validation (LOTL X.509 path-building, QcStatements, OCSP/CRL, AdES, LTV)
is **not** zero-dep. So it lives here, with its own (heavy) dependencies, and the core **consumes its
verdict** — exactly as Pass 4 consumes a resolved `anchorTrust`. The relying party runs this validator
themselves, so verification stays **trustless**.

## Contract

`validateQes(input) → QesValidationReport`. The report's `qualified: boolean` is the only field the core
treats as the gate; `signerIdentity` carries the eIDAS minimum dataset. Feed it to the core:

```ts
import { verifyValChain } from '@val-protocol/chain-verifier';
import { validateQes } from '@val-protocol/qes-validator';

const report = await validateQes({ signedCanonical, signature, validationTime: anchorGenTime });
const result = await verifyValChain(rows, { qesValidation: { reports: [report] } });
// result.conformanceProfile === 'C' (verified) when report.qualified === true
```

## Status / gating (ADR 0063)

- **S1 (ruled):** wrap the EU **DSS** library (self-host, trustless) as default; Art-33 service mode as a
  convenience. DSS is Java → wrapped via a pinned container/CLI; the contract is backend-agnostic.
- **Format:** JAdES (ETSI TS 119 182-1). **LTV** reuses the external-anchor rail (ADR 0062).
- Implementation is **demand-gated** on a paying notary/legal partner + the S2/S3 test certs + a legal
  opinion mapping a Profile-C chain to Art-25 effect. Until then `validateQes` throws and Profile C stays
  `qualified_unverified` in core output (correctly honest).
