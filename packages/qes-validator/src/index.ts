/**
 * @val-protocol/qes-validator — eIDAS QES validation for VAL Profile C (ADR 0063).
 *
 * 🔴 SCAFFOLD. The validation IMPLEMENTATION is demand-gated (a paying notary/legal partner + the S1–S3
 * rulings in ADR 0063). This file pins the **contract**: the `QesValidationReport` shape that the
 * zero-dep `@val-protocol/chain-verifier` consumes (`options.qesValidation`), and the `validateQes`
 * entry point a relying party runs themselves so verification stays trustless.
 *
 * Architecture (ADR 0063):
 *   - This package is SEPARATE and carries its own (heavy) dependencies — it does NOT taint the core
 *     verifier's zero-dependency guarantee. The core never imports LOTL/X.509/OCSP/AdES logic; it only
 *     consumes the `QesValidationReport` produced here.
 *   - S1 (ruled): wrap the EU Commission's **DSS** library (self-host, maximally trustless) as the
 *     default backend; expose an Art-33 qualified-validation **service** mode as a convenience. DSS is
 *     Java, so the wrap is via a pinned DSS container/CLI over a local boundary, NOT in-process — the
 *     public contract below is identical regardless of backend.
 *   - Format: JAdES (ETSI TS 119 182-1). LTV (AdES-LTA) reuses the VAL external-anchor rail (ADR 0062)
 *     for archive-timestamp temporal evidence.
 *
 * Honesty: this validator — not the core — is the authority for "qualified / identity-proofed". It emits
 * a reproducible report; the relying party can re-run it. The core never invents "qualified".
 */

/** eIDAS natural-person minimum dataset, surfaced verbatim from the qualified certificate (S3). */
export interface QesSignerIdentity {
  given_name: string;
  family_name: string;
  /** ISO date (YYYY-MM-DD) when present in the qualified cert. */
  date_of_birth: string | null;
  /** Persistent identifier from the qualified cert (e.g. the eIDAS uniqueness identifier). */
  persistent_id: string | null;
  /** Issuing country (ISO-3166-1 alpha-2) of the qualified certificate. */
  country: string | null;
}

/** A reproducible QES validation verdict over one qualified delegation signature. */
export interface QesValidationReport {
  /** True iff the signature is a valid QES per ETSI/eIDAS at signing time (qualified cert on the LOTL,
   *  QcStatements present, not revoked at genTime, AdES-valid). The ONLY field the core treats as the
   *  qualified gate. */
  qualified: boolean;
  /** The proven natural-person identity (S3 minimum dataset), present iff `qualified`. */
  signerIdentity: QesSignerIdentity | null;
  /** ETSI EN 319 102-1 main indication, surfaced verbatim (e.g. 'TOTAL-PASSED'). */
  indication: string;
  /** Sub-indication when not passed (e.g. 'REVOKED_NO_POE'), else null. */
  subIndication: string | null;
  /** AdES level proven (e.g. 'JAdES-BASELINE-LTA'), for LTV/retention reasoning. */
  adesLevel: string | null;
  /** Opaque reference to the full DSS/Art-33 validation report (the relying party can re-fetch/re-run). */
  reportRef: string | null;
  /** Which backend produced this report (S1). */
  backend: 'dss' | 'service';
}

/** Input to validate one qualified delegation signature carried on a VAL root ASSIGNMENT. */
export interface QesValidationInput {
  /** The canonical bytes the QES was computed over (the root ASSIGNMENT canonical_details). */
  signedCanonical: string;
  /** The JAdES (or other AdES) qualified signature blob, as carried in
   *  `human_attestation.delegator_authority.signature`. */
  signature: unknown;
  /** Validation time (defaults to now). For LTV, pass a chain anchor genTime (ADR 0062) so the report
   *  reflects validity at the attested instant, not merely today. */
  validationTime?: string;
  /** Backend selection (S1). Default 'dss' (self-host, trustless). */
  backend?: 'dss' | 'service';
}

/**
 * Validate a QES → a reproducible `QesValidationReport`. NOT YET IMPLEMENTED — demand-gated (ADR 0063).
 * The relying party runs this themselves; its output feeds `verifyValChain({ qesValidation })`.
 */
export async function validateQes(_input: QesValidationInput): Promise<QesValidationReport> {
  throw new Error(
    '@val-protocol/qes-validator: not yet implemented — Profile C QES validation is demand-gated ' +
      '(ADR 0063: wrap EU DSS / Art-33 service, JAdES, LTV via the anchor rail). This is a scaffold ' +
      'pinning the QesValidationReport contract the zero-dep chain-verifier consumes.',
  );
}
