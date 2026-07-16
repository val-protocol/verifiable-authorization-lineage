/**
 * @val-protocol/qes-validator — eIDAS QES validation for VAL Profile C (§7.1(f)).
 *
 * The `validateQes` entry point a relying party runs THEMSELVES (so verification stays trustless), plus
 * the `QesValidationReport` contract the zero-dep `@val-protocol/chain-verifier` consumes
 * (`options.qesValidation.reports`). Structurally a superset of the core's `QesVerdict`
 * ({ qualified, signerIdentity?, reportRef? }) so it drops into the seam unchanged, PLUS `signatureRef`
 * (per-signature keying the WS6 verifier PR / §11.4 item 5 will match on) and `status`/`reason`
 * (conclusive-vs-indeterminate, never collapsed into a bare boolean for the operator).
 *
 * ── BACKEND DECISION (supersedes the scaffold's "S1: wrap DSS") ────────────────────────────────────
 * The closeout build prompt (operator-ratified, 2026-06-29) makes this a **no-DSS, no-server, pure-JS**
 * validator — that is the entire point of "the auditor's trustless tool": a relying party verifies a VAL
 * grant's qualified signature WITHOUT standing up a Java DSS. The earlier scaffold wrapped a self-hosted
 * DSS over REST; that defeated trustlessness and is replaced here. (`@val-protocol/chain-verifier` stays
 * zero-dep; this package carries the X.509/LOTL logic + reuses `@val-protocol/anchor-lotl-resolver`.)
 *
 * ── DOCUMENTED SUBSET (honest scope, ETSI) ─────────────────────────────────────────────────────────
 * Implements a SUBSET of the ETSI validation chain, labelled per document:
 *   (1) JWS/JAdES parse (ETSI TS 119 182-1);
 *   (2) signature-value verification over the JWS signing input via the embedded x5c — ETSI TS 119 102-1;
 *   (3) certificate-path build + verification leaf→issuer→trust-anchor — ETSI TS 119 102-1;
 *   (4) qualification-status determination — ETSI TS 119 615: QcStatements in the signing cert
 *       (QcCompliance 0.4.0.1862.1.1 AND QcType-eSign 0.4.0.1862.1.6.1) AND the issuer resolves to a
 *       Trusted-List service of type CA/QC, granted-for-eSignatures, granted at signing time.
 * NOT in scope (this is DSS's job, not reimplemented here): per-certificate OCSP/CRL revocation, full
 * AdES-LTA/archive-timestamp LTV. Revocation here is at the Trusted-List SERVICE-STATUS granularity
 * (granted/withdrawn at signing time), NOT per-cert OCSP. Anything this subset cannot conclude returns
 * `indeterminate` — never a silent `qualified:true`.
 *
 * PRECONDITION (cert path): the full chain leaf → … → TL-listed granted CA/QC service MUST be present in
 * `x5c` or `trust.intermediateHintsDer`. There is NO AIA/caIssuers chasing (it would need network + break
 * the offline model). A partial `x5c` (leaf only) ⇒ `not_qualified`/`CHAIN_INCOMPLETE` (supply the chain),
 * NOT a false `qualified`, and distinct from `ANCHOR_NOT_ON_TRUSTED_LIST` (complete chain, top not on the TL).
 *
 * Honesty: this validator — not the core — is the authority for "qualified". `qualified` is TRUE only on
 * a conclusive positive determination; anything else is `not_qualified` (conclusive negative) or
 * `indeterminate` (could not conclude). The core treats only `qualified` as the gate, so neither a null
 * identity nor an indeterminate verdict can fake a green.
 */

import { X509Certificate, createHash, verify as cryptoVerify } from 'node:crypto';

/**
 * Resolve the member-state TSL location for a country from the EU LOTL. Inlined (was reused from
 * `@val-protocol/anchor-lotl-resolver`) so this package is SELF-CONTAINED and consumable from a CommonJS
 * backend without an unpublished `.mjs` transitive dependency. Kept byte-identical to the resolver's
 * function; the live-LOTL differential test still cross-checks against the resolver + DSS.
 */
function findTslPointer(lotlXml: string, country: string): string | null {
  const re = /<(?:[a-z0-9]+:)?OtherTSLPointer>([\s\S]*?)<\/(?:[a-z0-9]+:)?OtherTSLPointer>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(lotlXml))) {
    const b = m[1];
    if (new RegExp(`<(?:[a-z0-9]+:)?SchemeTerritory>${country}</`, 'i').test(b)) {
      const loc = /<(?:[a-z0-9]+:)?TSLLocation>([\s\S]*?\.xml)<\/(?:[a-z0-9]+:)?TSLLocation>/i.exec(b);
      if (loc) return loc[1].trim();
    }
  }
  return null;
}

// ── eIDAS / ETSI constants ────────────────────────────────────────────────────────────────────────
const OID_QC_STATEMENTS = '1.3.6.1.5.5.7.1.3'; // id-pe-qcStatements (RFC 3739)
const OID_QC_COMPLIANCE = '0.4.0.1862.1.1'; // esi4-qcStatement-1 (QcCompliance)
const OID_QC_SSCD = '0.4.0.1862.1.4'; // esi4-qcStatement-4 (QcSSCD)
const OID_QC_TYPE = '0.4.0.1862.1.6'; // esi4-qcStatement-6 (QcType)
const OID_QC_TYPE_ESIGN = '0.4.0.1862.1.6.1'; // id-etsi-qct-esign
const OID_BASIC_CONSTRAINTS = '2.5.29.19'; // RFC 5280 §4.2.1.9
const OID_KEY_USAGE = '2.5.29.15'; // RFC 5280 §4.2.1.3 (keyCertSign = bit 5)
const MAX_PATH_DEPTH = 12; // loop backstop for the certification-path walk

const SVCTYPE_CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const SVCTYPE_TSA_QTST = 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST';
const ASI_FOR_ESIGNATURES = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures';
const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const EU_LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

/**
 * crit-header allow-list (RFC 7515 §4.1.11). MUST cover EVERY crit param the producer/DSS legitimately
 * emits at the current AdES baseline, or we reject our own valid signatures. Today: only `sigD` (JAdES
 * detached, confirmed by the DSS-emitted artifact's `crit:["sigD"]`), which our binding step processes.
 * When moving to JAdES-BASELINE-T/-LT, DSS may add crit params (e.g. timestamp-related) — extend this
 * list DELIBERATELY at that bump so a new baseline updates the allow-list instead of breaking silently.
 */
const UNDERSTOOD_CRIT: ReadonlySet<string> = new Set(['sigD']);

// ── public contract ─────────────────────────────────────────────────────────────────────────────────

/** eIDAS natural-person minimum dataset, surfaced verbatim from the qualified certificate. */
export interface QesSignerIdentity {
  given_name: string;
  family_name: string;
  date_of_birth: string | null;
  persistent_id: string | null;
  country: string | null;
}

/** Conclusive-vs-indeterminate (refinement 2). `qualified` (the core gate) is TRUE only iff `'qualified'`. */
export type QesStatus = 'qualified' | 'not_qualified' | 'indeterminate';

/** A reproducible QES validation verdict over one qualified delegation signature. */
export interface QesValidationReport {
  /** The ONLY field the core verifier treats as the qualified gate. TRUE only iff `status==='qualified'`. */
  qualified: boolean;
  /** Conclusive positive / conclusive negative / could-not-conclude (refinement 2). */
  status: QesStatus;
  /** Human-readable reason — distinguishes "off the EU Trusted List" from "LOTL unreachable". */
  reason: string;
  /** Per-signature key (refinement 1 / WS6): sha256-hex of the delegation `signature.signature` bytes,
   *  so §11.4 item 5 can match THIS report to THIS signature instead of "first qualified report". */
  signatureRef: string | null;
  /** Proven natural-person identity (minimum dataset), present iff `qualified`. */
  signerIdentity: QesSignerIdentity | null;
  /** ETSI EN 319 102-1 main indication: 'TOTAL-PASSED' | 'TOTAL-FAILED' | 'INDETERMINATE'. */
  indication: string;
  /** Sub-indication when not passed (e.g. 'SIG_CRYPTO_FAILURE', 'NO_CERTIFICATE_CHAIN_FOUND'), else null. */
  subIndication: string | null;
  /** AdES level proven (best-effort from the JAdES header), for LTV/retention reasoning. */
  adesLevel: string | null;
  /** Opaque reference to this verdict's reproducible inputs (the relying party can re-run). */
  reportRef: string | null;
  /** Which backend produced this report. */
  backend: 'offline-js';
  /** sha256-hex of the TL-granted CA/QC cert the path anchored at (present iff `qualified`). Ruling 2:
   *  feeding this back through `matchGrantedCaQc` MUST return granted — the walker cannot drift from the
   *  DSS-cross-checked resolver. */
  anchorFingerprint?: string | null;
}

/**
 * Trust inputs for the offline determination.
 *
 * INVARIANT (EU-Trusted-List-only invariant): **the trust anchor is ONLY derived from the EU Trusted List.** No caller
 * can inject a trust anchor — `x5c`-supplied and `intermediateHintsDer` certificates are untrusted path-
 * building HINTS, validated per RFC 5280 §6 but NEVER trusted as a root. A path is anchored only when it
 * reaches a cert the LOTL resolver (`matchGrantedCaQc`) calls a granted CA/QC-for-eSignatures service at
 * signing time. (Replaces the prior `trustAnchorsDer`, which let the x5c top become the anchor — a forgeable
 * trust root.)
 */
export interface QesTrustInput {
  /** Pre-fetched member-state Trusted List XML (ETSI TS 119 612). Offline/test path. */
  tslXml?: string;
  /** Fetch the EU LOTL → member-state TSL live (network). */
  fetchLive?: boolean;
  lotlUrl?: string;
  fetchImpl?: typeof fetch;
  /** Extra intermediate CA certs (base64 DER) to help BUILD the path when `x5c` omits them. HINTS ONLY —
   *  validated as path links, never a trust source. The anchor is always the TL-matched cert. */
  intermediateHintsDer?: string[];
}

/** Input to validate one qualified delegation signature carried on a VAL root ASSIGNMENT. */
export interface QesValidationInput {
  /** The canonical bytes the QES was computed over (the root ASSIGNMENT canonical_details). */
  signedCanonical: string;
  /** The qualified signature carried in `human_attestation.delegator_authority.signature`
   *  (a ValQesSignature { alg, signature } or a bare base64 JAdES string). */
  signature: unknown;
  /** Validation/signing time (defaults to now). For LTV, pass a chain anchor genTime (§8.4 anchor genTime). */
  validationTime?: string;
  /** Trust material for the offline determination. */
  trust: QesTrustInput;
}

const indeterminate = (
  reason: string,
  subIndication: string | null,
  signatureRef: string | null,
  adesLevel: string | null = null,
): QesValidationReport => ({
  qualified: false,
  status: 'indeterminate',
  reason,
  signatureRef,
  signerIdentity: null,
  indication: 'INDETERMINATE',
  subIndication,
  adesLevel,
  reportRef: null,
  backend: 'offline-js',
});

const notQualified = (
  reason: string,
  subIndication: string | null,
  signatureRef: string | null,
  adesLevel: string | null = null,
  indication = 'TOTAL-FAILED',
): QesValidationReport => ({
  qualified: false,
  status: 'not_qualified',
  reason,
  signatureRef,
  signerIdentity: null,
  indication,
  subIndication,
  adesLevel,
  reportRef: null,
  backend: 'offline-js',
});

/**
 * Validate a QES → a reproducible `QesValidationReport`, with NO DSS and NO server (pure JS). The relying
 * party runs this THEMSELVES; its output feeds `verifyValChain({ qesValidation: { reports: [...] } })`,
 * so the core never trusts RIGA for "qualified" (Charter §II claim #12). See the file header for the
 * documented ETSI subset and the never-silently-upgrade discipline.
 */
export async function validateQes(input: QesValidationInput): Promise<QesValidationReport> {
  const signatureBytes = extractSignatureBytes(input.signature);
  const signatureRef = signatureBytes ? sha256Hex(signatureBytes) : null;
  if (!signatureBytes) {
    return indeterminate('unrecognized signature shape (expected ValQesSignature { alg, signature } or base64 JAdES/CAdES)', 'FORMAT_FAILURE', null);
  }

  // FRONT-END (format-specific): produce the normalized { x5cB64, signedBytes-bound, signatureValue,
  // signingTime } by parsing + binding to the canonical + verifying the signature value. Everything AFTER
  // is format-agnostic (anchorAndQualify). JAdES = JWS compact; CAdES = detached CMS/PKCS#7 (DER).
  const fe = parseFrontEnd(signatureBytes, input, signatureRef);
  if (!fe.ok) return fe.verdict;

  // SHARED downstream (format-agnostic): RFC 5280 §6 path → TL anchor → QcStatements → verdict.
  return anchorAndQualify(fe, input, signatureRef);
}

/** Normalized output every format front-end produces (after bind + signature-value verification). */
type FrontEnd = { ok: true; x5cB64: string[]; signingTimeMs: number; adesLevel: string };
type FrontEndResult = FrontEnd | { ok: false; verdict: QesValidationReport };

/** Detect the format from structure (JWS compact → JAdES; CMS SignedData DER → CAdES) and route. */
function parseFrontEnd(signatureBytes: string, input: QesValidationInput, signatureRef: string | null): FrontEndResult {
  let jws: ParsedJws | null = null;
  try {
    jws = parseCompactJades(signatureBytes);
  } catch {
    jws = null;
  }
  if (jws) return jadesFrontEnd(jws, input, signatureRef);

  let der: Buffer | null = null;
  try {
    der = Buffer.from(signatureBytes.trim(), 'base64');
  } catch {
    der = null;
  }
  if (der && der.length > 1 && der[0] === 0x30 && looksLikeSignedData(der)) {
    return cadesFrontEnd(der, input, signatureRef);
  }
  return { ok: false, verdict: indeterminate('unrecognized signature format — expected JAdES (JWS compact) or CAdES (detached CMS/PKCS#7 DER); PAdES/XAdES out of scope', 'FORMAT_FAILURE', signatureRef) };
}

/** JAdES front-end: crit enforcement + x5c + sigD/payload binding + JWS signature-value verification. */
function jadesFrontEnd(jws: ParsedJws, input: QesValidationInput, signatureRef: string | null): FrontEndResult {
  const adesLevel = jws.header.sigT ? 'JAdES-BASELINE-T(approx)' : 'JAdES-BASELINE-B(approx)';
  const signingTimeMs = input.validationTime ? Date.parse(input.validationTime) : Date.now();
  const critUnknown = (jws.header.crit ?? []).filter((p) => !UNDERSTOOD_CRIT.has(p));
  if (critUnknown.length > 0) {
    return { ok: false, verdict: indeterminate(`unsupported critical header param(s) ${JSON.stringify(critUnknown)} — RFC 7515 requires rejecting a signature whose crit set is not fully understood`, 'FORMAT_FAILURE', signatureRef, adesLevel) };
  }
  if (!jws.header.x5c || jws.header.x5c.length === 0) {
    return { ok: false, verdict: indeterminate('JAdES header carries no x5c certificate chain (cannot identify the signer)', 'NO_SIGNING_CERTIFICATE_FOUND', signatureRef, adesLevel) };
  }
  const bind = bindsToCanonical(jws, input.signedCanonical);
  if (!bind.ok) {
    return { ok: false, verdict: notQualified(`signature does not bind the supplied canonical bytes: ${bind.reason}`, 'HASH_FAILURE', signatureRef, adesLevel) };
  }
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(Buffer.from(jws.header.x5c[0], 'base64'));
  } catch (e) {
    return { ok: false, verdict: indeterminate(`leaf certificate (x5c[0]) is not a valid X.509: ${(e as Error).message}`, 'FORMAT_FAILURE', signatureRef, adesLevel) };
  }
  const sigOk = verifyJwsSignature(jws, leaf);
  if (!sigOk.ok) {
    return { ok: false, verdict: notQualified(`signature-value verification failed: ${sigOk.reason}`, 'SIG_CRYPTO_FAILURE', signatureRef, adesLevel) };
  }
  return { ok: true, x5cB64: jws.header.x5c, signingTimeMs, adesLevel };
}

/** Shared downstream: resolve the TL once, build+validate the RFC 5280 path to a TL anchor, QcStatements. */
async function anchorAndQualify(fe: FrontEnd, input: QesValidationInput, signatureRef: string | null): Promise<QesValidationReport> {
  const { x5cB64, signingTimeMs, adesLevel } = fe;
  const leaf = new X509Certificate(Buffer.from(x5cB64[0], 'base64'));
  // Resolve the Trusted List ONCE (single trust source; ruling 1). The same tslXml + single signingTimeMs
  // feed path-validity, cert-validity, and TL-granted-at-time (ruling 3 — one reference instant).
  const tslRes = await resolveTslXml(input.trust, leaf);
  if (tslRes.indeterminate) {
    return indeterminate(`Trusted List unavailable: ${tslRes.reason}`, 'CERTIFICATE_CHAIN_GENERAL_FAILURE', signatureRef, adesLevel);
  }
  const path = buildAndAnchorPath({ x5cB64, hintsDer: input.trust.intermediateHintsDer ?? [], tslXml: tslRes.xml!, signingTimeMs });
  if (!path.ok) {
    return notQualified(`certificate path: ${path.reason}`, path.subIndication, signatureRef, adesLevel);
  }
  const qc = extractQcStatements(leaf);
  if (!qc.qcCompliance || !qc.qcTypeEsign) {
    const miss = [!qc.qcCompliance && 'QcCompliance', !qc.qcTypeEsign && 'QcType-eSign'].filter(Boolean).join(' + ');
    return notQualified(`signing certificate lacks required QcStatements (${miss}) — not a qualified e-signature certificate`, 'CHAIN_CONSTRAINTS_FAILURE', signatureRef, adesLevel);
  }
  return {
    qualified: true,
    status: 'qualified',
    reason: `valid QES (${adesLevel}): signature verified, path validated (RFC 5280, depth ${path.depth}) to TL-granted CA/QC-for-eSignatures "${path.anchorServiceName}", QcStatements present (QcCompliance${qc.qcSscd ? ' + QcSSCD' : ''} + QcType-eSign) at signing time`,
    signatureRef,
    signerIdentity: extractSignerIdentity(leaf),
    indication: 'TOTAL-PASSED',
    subIndication: null,
    adesLevel,
    reportRef: `offline-js:${signatureRef?.slice(0, 16)}`,
    backend: 'offline-js',
    anchorFingerprint: path.anchorCertDer ? sha256Hex(Buffer.from(path.anchorCertDer, 'base64'), 'buffer') : null,
  };
}

// ── (1) JAdES compact parsing ─────────────────────────────────────────────────────────────────────

interface JadesHeader {
  alg: string;
  x5c?: string[];
  b64?: boolean;
  crit?: string[];
  sigT?: string; // signing time (JAdES)
  sigD?: { mId?: string; hashM?: string; pars?: string[]; hashV?: string[] };
  [k: string]: unknown;
}
interface ParsedJws {
  protectedB64: string;
  payloadB64: string;
  signature: Buffer; // raw (ieee-p1363 for ECDSA, PKCS#1 v1.5 / PSS bytes for RSA)
  header: JadesHeader;
}

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/** Parse JAdES compact serialization: `BASE64URL(protected).BASE64URL(payload).BASE64URL(signature)`. */
function parseCompactJades(blob: string): ParsedJws {
  // The blob may itself be base64 (the producer returns DSS `bytes` base64) wrapping the compact JWS.
  let compact = blob.trim();
  if (!compact.includes('.')) {
    const decoded = Buffer.from(compact, 'base64').toString('utf8');
    if (decoded.includes('.')) compact = decoded.trim();
  }
  const parts = compact.split('.');
  if (parts.length !== 3) throw new Error(`expected 3 JWS compact segments, got ${parts.length}`);
  const [protectedB64, payloadB64, sigB64] = parts;
  let header: JadesHeader;
  try {
    header = JSON.parse(b64urlToBuf(protectedB64).toString('utf8')) as JadesHeader;
  } catch (e) {
    throw new Error(`protected header is not JSON: ${(e as Error).message}`);
  }
  if (typeof header.alg !== 'string') throw new Error('protected header missing "alg"');
  return { protectedB64, payloadB64, signature: b64urlToBuf(sigB64), header };
}

/** Detached JAdES binds via sigD (ObjectIdByURIHash): one hashV must equal BASE64URL(sha256(canonical)). */
function bindsToCanonical(jws: ParsedJws, canonical: string): { ok: boolean; reason?: string } {
  const want = createHash('sha256').update(canonical, 'utf8').digest('base64url');
  const sigD = jws.header.sigD;
  if (sigD && Array.isArray(sigD.hashV) && sigD.hashV.length > 0) {
    const hit = sigD.hashV.some((h) => normalizeB64url(h) === want);
    return hit ? { ok: true } : { ok: false, reason: 'no sigD hashV matches sha256(canonical)' };
  }
  // Attached: the payload itself must be the canonical bytes.
  if (jws.payloadB64) {
    const payload = b64urlToBuf(jws.payloadB64).toString('utf8');
    return payload === canonical ? { ok: true } : { ok: false, reason: 'attached payload != canonical bytes' };
  }
  return { ok: false, reason: 'detached signature carries no sigD hashV and no attached payload to bind' };
}

function normalizeB64url(s: string): string {
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── CAdES front-end: detached CMS/PKCS#7 (.p7m) → the same { x5c, signingTime } the JAdES parser yields ──
// CAdES is what most EU QTSPs + a notary's clé REAL emit. This is a FRONT-END only: it extracts the signer
// cert chain, verifies the signature over the DER-encoded SignedAttributes, and BINDS via the messageDigest
// attribute (= SHA-256 of the content, which MUST equal SHA-256(grant canonical)). Everything downstream
// (path → TL anchor → QcStatements) is the shared, format-agnostic pipeline.
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const CMS_SIG_ALG: Record<string, { hash: string; type: 'ec' | 'rsa' | 'rsa-pss' }> = {
  '1.2.840.10045.4.3.2': { hash: 'sha256', type: 'ec' },
  '1.2.840.10045.4.3.3': { hash: 'sha384', type: 'ec' },
  '1.2.840.10045.4.3.4': { hash: 'sha512', type: 'ec' },
  '1.2.840.113549.1.1.11': { hash: 'sha256', type: 'rsa' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', type: 'rsa' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', type: 'rsa' },
  '1.2.840.113549.1.1.10': { hash: 'sha256', type: 'rsa-pss' },
};
// CMS SignerInfo digestAlgorithm (the algorithm the messageDigest attribute was computed with). The QTSP
// chooses this (SHA-256/384/512 are all eIDAS-valid) — the bind MUST hash the canonical with THIS algorithm,
// never a hardcoded SHA-256. (SHA-1 deliberately absent → unsupported → reject.)
const CMS_DIGEST_ALG: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

function looksLikeSignedData(der: Buffer): boolean {
  try {
    const ci = readTLV(der, 0);
    const first = children(der, ci.vStart, ci.vEnd)[0];
    return first.tag === 0x06 && decodeOid(der, first.vStart, first.vEnd) === OID_SIGNED_DATA;
  } catch {
    return false;
  }
}

function parseAsn1Time(der: Buffer, node: TLV): number {
  const s = der.subarray(node.vStart, node.vEnd).toString('ascii');
  if (node.tag === 0x17) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) return NaN;
    const yy = +m[1];
    return Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  if (node.tag === 0x18) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(s);
    if (!m) return NaN;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  return NaN;
}

function cadesFrontEnd(der: Buffer, input: QesValidationInput, signatureRef: string | null): FrontEndResult {
  const fail = (reason: string, sub: string, status: 'indeterminate' | 'not_qualified' = 'not_qualified'): FrontEndResult => ({
    ok: false,
    verdict: status === 'indeterminate' ? indeterminate(reason, sub, signatureRef, 'CAdES-BES(approx)') : notQualified(reason, sub, signatureRef, 'CAdES-BES(approx)'),
  });
  try {
    const ci = readTLV(der, 0);
    const ciCh = children(der, ci.vStart, ci.vEnd);
    const content0 = children(der, ciCh[1].vStart, ciCh[1].vEnd)[0]; // [0] EXPLICIT → SignedData
    const sdCh = children(der, content0.vStart, content0.vEnd);
    // encapContentInfo (first SEQUENCE in SignedData): ENVELOPED CMS embeds eContent [0]; DETACHED omits it.
    let embeddedContent: Buffer | null = null;
    const encap = sdCh.find((t) => t.tag === 0x30);
    if (encap) {
      const eContent = children(der, encap.vStart, encap.vEnd).find((t) => t.tag === 0xa0); // [0] EXPLICIT
      if (eContent) {
        const oct = children(der, eContent.vStart, eContent.vEnd)[0]; // OCTET STRING (primitive; BER-chunked = open-set)
        if (oct && oct.tag === 0x04) embeddedContent = Buffer.from(der.subarray(oct.vStart, oct.vEnd));
      }
    }
    const certsNode = sdCh.find((t) => t.tag === 0xa0); // certificates [0] IMPLICIT
    if (!certsNode) return fail('CMS carries no certificates', 'NO_SIGNING_CERTIFICATE_FOUND', 'indeterminate');
    const certs = children(der, certsNode.vStart, certsNode.vEnd)
      .filter((t) => t.tag === 0x30)
      .map((t) => new X509Certificate(der.subarray(t.hStart, t.vEnd)));
    const siSet = [...sdCh].reverse().find((t) => t.tag === 0x31); // signerInfos is the last SET
    if (!siSet) return fail('CMS has no signerInfos', 'FORMAT_FAILURE', 'indeterminate');
    const si = children(der, siSet.vStart, siSet.vEnd).find((t) => t.tag === 0x30);
    if (!si) return fail('CMS signerInfos empty', 'FORMAT_FAILURE', 'indeterminate');
    const siCh = children(der, si.vStart, si.vEnd);

    const saIdx = siCh.findIndex((t) => t.tag === 0xa0); // signedAttrs [0] IMPLICIT
    if (saIdx < 0) return fail('CMS SignerInfo has no signed attributes (CAdES messageDigest binding required)', 'FORMAT_FAILURE', 'indeterminate');
    const signedAttrs = siCh[saIdx];
    const sigAlgNode = siCh.slice(saIdx + 1).find((t) => t.tag === 0x30);
    const sigNode = siCh.slice(saIdx + 1).find((t) => t.tag === 0x04);
    if (!sigAlgNode || !sigNode) return fail('CMS SignerInfo missing signatureAlgorithm or signature', 'FORMAT_FAILURE', 'indeterminate');
    const sigAlgOid = decodeOid(der, children(der, sigAlgNode.vStart, sigAlgNode.vEnd)[0].vStart, children(der, sigAlgNode.vStart, sigAlgNode.vEnd)[0].vEnd);
    const alg = CMS_SIG_ALG[sigAlgOid];
    if (!alg) return fail(`unsupported CMS signature algorithm ${sigAlgOid}`, 'FORMAT_FAILURE', 'indeterminate');
    const signature = der.subarray(sigNode.vStart, sigNode.vEnd);

    // signed attribute lookup (SET OF Attribute; each = SEQUENCE { OID, SET attrValues })
    const attrs = children(der, signedAttrs.vStart, signedAttrs.vEnd);
    const attrVal = (oid: string): TLV | null => {
      for (const a of attrs) {
        const ac = children(der, a.vStart, a.vEnd);
        if (ac[0]?.tag === 0x06 && decodeOid(der, ac[0].vStart, ac[0].vEnd) === oid && ac[1]) {
          return children(der, ac[1].vStart, ac[1].vEnd)[0] ?? null;
        }
      }
      return null;
    };

    // THE BINDING TRAP — check (1) "the signature binds to THESE bytes": messageDigest == H_cms(canonical),
    // where H_cms is the CMS-DECLARED digestAlgorithm (NOT a hardcoded SHA-256 — the QTSP may use
    // SHA-256/384/512, all eIDAS-valid). check (2) "those bytes are the grant's canonical" is the caller's
    // job: `input.signedCanonical` IS canonicalJsonStringify(grant), identified upstream. A qualified
    // signature over the wrong bytes (some uploaded doc) must NOT validate as a bound Profile-C signature.
    const digestAlgNode = siCh.find((t, i) => i >= 2 && i < saIdx && t.tag === 0x30); // version, sid, digestAlgorithm, …
    const digestOid = digestAlgNode ? decodeOid(der, children(der, digestAlgNode.vStart, digestAlgNode.vEnd)[0].vStart, children(der, digestAlgNode.vStart, digestAlgNode.vEnd)[0].vEnd) : null;
    const hCms = digestOid ? CMS_DIGEST_ALG[digestOid] : null;
    if (!hCms) return fail(`unsupported or missing CMS digestAlgorithm ${digestOid ?? '(none)'} (expected SHA-256/384/512)`, 'FORMAT_FAILURE', 'indeterminate');
    const mdNode = attrVal(OID_MESSAGE_DIGEST);
    if (!mdNode) return fail('CMS has no messageDigest signed attribute (cannot bind to the grant)', 'HASH_FAILURE');
    const messageDigest = der.subarray(mdNode.vStart, mdNode.vEnd);
    const canonicalBuf = Buffer.from(input.signedCanonical, 'utf8');
    // The bytes the signature is over: the EMBEDDED content (enveloped) or the supplied canonical (detached).
    const signedBytes = embeddedContent ?? canonicalBuf;
    const wantDigest = createHash(hCms).update(signedBytes).digest(); // (1) H_cms(signed content) — algorithm-agnostic
    if (!messageDigest.equals(wantDigest)) {
      return fail(`CMS messageDigest does not equal ${hCms.toUpperCase()}(signed content) — the signature is not over these bytes`, 'HASH_FAILURE');
    }
    // (2) those bytes ARE the grant canonical. Detached: signedBytes === canonical by construction. Enveloped:
    // the embedded content MUST equal the grant canonical, else a qualified sig over a DIFFERENT document slips in.
    if (embeddedContent && !embeddedContent.equals(canonicalBuf)) {
      return fail('enveloped CMS embedded content does not equal the grant canonical bytes — signature is over a different document', 'HASH_FAILURE');
    }

    // signer cert: the issuerAndSerialNumber sid → match the embedded cert by serial; else the non-CA leaf.
    let leaf = certs.find((c) => c.ca === false) ?? certs[0];
    const sid = siCh[1];
    if (sid?.tag === 0x30) {
      const serialNode = children(der, sid.vStart, sid.vEnd).find((t) => t.tag === 0x02);
      if (serialNode) {
        const serial = der.subarray(serialNode.vStart, serialNode.vEnd).toString('hex').toUpperCase().replace(/^0+/, '');
        const m = certs.find((c) => c.serialNumber.toUpperCase().replace(/^0+/, '') === serial);
        if (m) leaf = m;
      }
    }

    // signature-value verification over the DER-encoded SignedAttributes RE-TAGGED as SET (RFC 5652 §5.4):
    // CAdES signs SET OF Attribute, but it travels [0] IMPLICIT — swap the tag byte 0xA0 → 0x31 to verify.
    const saDer = Buffer.from(der.subarray(signedAttrs.hStart, signedAttrs.vEnd));
    saDer[0] = 0x31;
    const verifyKey =
      alg.type === 'ec'
        ? { key: leaf.publicKey, dsaEncoding: 'der' as const }
        : alg.type === 'rsa-pss'
          ? { key: leaf.publicKey, padding: 6, saltLength: 32 }
          : leaf.publicKey;
    let sigOk = false;
    try {
      sigOk = cryptoVerify(alg.hash, saDer, verifyKey as never, signature);
    } catch {
      sigOk = false;
    }
    if (!sigOk) return fail('CMS signature does not verify over the signed attributes', 'SIG_CRYPTO_FAILURE');

    const stNode = attrVal(OID_SIGNING_TIME);
    const signingTimeMs = input.validationTime
      ? Date.parse(input.validationTime)
      : stNode
        ? parseAsn1Time(der, stNode)
        : Date.now();

    // leaf first, then the rest of the bundle (untrusted path-building hints for the shared walker).
    const x5cB64 = [leaf.raw.toString('base64'), ...certs.filter((c) => c !== leaf).map((c) => c.raw.toString('base64'))];
    return { ok: true, x5cB64, signingTimeMs: Number.isFinite(signingTimeMs) ? signingTimeMs : Date.now(), adesLevel: 'CAdES-BES(approx)' };
  } catch (e) {
    return fail(`CAdES parse failed: ${(e as Error).message}`, 'FORMAT_FAILURE', 'indeterminate');
  }
}

// ── (2) signature-value verification (ETSI TS 119 102-1) ────────────────────────────────────────────

function verifyJwsSignature(jws: ParsedJws, leaf: X509Certificate): { ok: boolean; reason?: string } {
  const signingInput = Buffer.from(`${jws.protectedB64}.${jws.payloadB64}`, 'ascii');
  const pub = leaf.publicKey;
  const alg = jws.header.alg;
  try {
    if (/^ES\d{3}$/.test(alg)) {
      const hash = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' }[alg];
      if (!hash) return { ok: false, reason: `unsupported ECDSA alg ${alg}` };
      const ok = cryptoVerify(hash, signingInput, { key: pub, dsaEncoding: 'ieee-p1363' }, jws.signature);
      return ok ? { ok: true } : { ok: false, reason: `${alg} signature invalid` };
    }
    if (/^RS\d{3}$/.test(alg)) {
      const hash = { RS256: 'sha256', RS384: 'sha384', RS512: 'sha512' }[alg];
      if (!hash) return { ok: false, reason: `unsupported RSA alg ${alg}` };
      const ok = cryptoVerify(hash, signingInput, pub, jws.signature);
      return ok ? { ok: true } : { ok: false, reason: `${alg} signature invalid` };
    }
    if (/^PS\d{3}$/.test(alg)) {
      const hash = { PS256: 'sha256', PS384: 'sha384', PS512: 'sha512' }[alg];
      if (!hash) return { ok: false, reason: `unsupported RSA-PSS alg ${alg}` };
      const ok = cryptoVerify(
        hash,
        signingInput,
        { key: pub, padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: 32 },
        jws.signature,
      );
      return ok ? { ok: true } : { ok: false, reason: `${alg} signature invalid` };
    }
    return { ok: false, reason: `unsupported alg "${alg}" (QES expects ES*/RS*/PS*)` };
  } catch (e) {
    return { ok: false, reason: `verify error: ${(e as Error).message}` };
  }
}

// ── (3) certification-path build + validation (RFC 5280 §6) with TL-derived anchor (ETSI TS 119 615) ──
//
// Generalizes the old one-hop builder (Defect 1): walk leaf → … → anchor at ANY depth, validating every
// link per RFC 5280 §6 (signature, validity-at-signing-time, name-chain, cA, pathLenConstraint, keyUsage).
// The anchor is NOT the x5c top (Defect 2): x5c + hints are untrusted building material; the path is
// anchored only at the first cert the LOTL resolver (matchGrantedCaQc) calls a granted CA/QC-for-eSig
// service at signing time. A chain that internally verifies to an attacker's self-signed root therefore
// does NOT anchor (it is never on the Trusted List).

interface AnchorPathResult {
  ok: boolean;
  broken: boolean; // an RFC 5280 link failed (conclusive)
  notAnchored: boolean; // well-formed chain that reached no TL-granted CA/QC service (conclusive)
  reason: string;
  subIndication: string | null;
  depth: number; // links validated leaf → anchor
  anchorCertDer: string; // base64 DER of the TL-granted anchor cert (feed back through matchGrantedCaQc ⇒ granted)
  anchorServiceName: string | null;
}

/** Validity of a cert at the (single) reference time. */
function validAt(cert: X509Certificate, ms: number): { ok: true } | { ok: false; reason: string; sub: string } {
  const vfrom = Date.parse(cert.validFrom);
  const vto = Date.parse(cert.validTo);
  if (Number.isFinite(vfrom) && ms < vfrom) return { ok: false, reason: `not yet valid at signing time (notBefore ${new Date(vfrom).toISOString()})`, sub: 'NOT_YET_VALID' };
  if (Number.isFinite(vto) && ms > vto) return { ok: false, reason: `expired at signing time (notAfter ${new Date(vto).toISOString()})`, sub: 'EXPIRED' };
  return { ok: true };
}

/** RFC 5280 §4.2.1.9 basicConstraints (node exposes `ca` but NOT pathLenConstraint → DER-parse). */
function parseBasicConstraints(certDer: Buffer): { cA: boolean; pathLen: number | null } {
  const ext = findExtension(certDer, OID_BASIC_CONSTRAINTS);
  if (!ext) return { cA: false, pathLen: null };
  const seq = readTLV(ext, 0);
  let cA = false;
  let pathLen: number | null = null;
  for (const t of children(ext, seq.vStart, seq.vEnd)) {
    if (t.tag === 0x01) cA = ext[t.vStart] !== 0x00; // BOOLEAN
    else if (t.tag === 0x02) {
      let v = 0;
      for (let i = t.vStart; i < t.vEnd; i++) v = (v << 8) | ext[i]; // INTEGER pathLenConstraint
      pathLen = v;
    }
  }
  return { cA, pathLen };
}

/** RFC 5280 §4.2.1.3 keyUsage (node `keyUsage` is undefined here → DER-parse the BIT STRING; keyCertSign = bit 5). */
function parseKeyUsage(certDer: Buffer): { present: boolean; keyCertSign: boolean } {
  const ext = findExtension(certDer, OID_KEY_USAGE);
  if (!ext) return { present: false, keyCertSign: false };
  const bs = readTLV(ext, 0); // BIT STRING: [unusedBits][bit bytes…]
  const firstBitByte = ext[bs.vStart + 1] ?? 0;
  return { present: true, keyCertSign: (firstBitByte & 0x04) !== 0 }; // bit 5 from MSB
}

function buildAndAnchorPath(args: { x5cB64: string[]; hintsDer: string[]; tslXml: string; signingTimeMs: number }): AnchorPathResult {
  const fail = (reason: string, sub: string, broken = false, notAnchored = false): AnchorPathResult => ({ ok: false, broken, notAnchored, reason, subIndication: sub, depth: 0, anchorCertDer: '', anchorServiceName: null });
  const parse = (b: string): X509Certificate | null => {
    try {
      return new X509Certificate(Buffer.from(b, 'base64'));
    } catch {
      return null;
    }
  };
  const x5c = args.x5cB64.map(parse);
  if (x5c.some((c) => c == null)) return fail('an x5c entry is not a valid certificate', 'FORMAT_FAILURE', true);
  // x5c + hints are UNTRUSTED path-building material (never a trust source).
  const pool = [...(x5c as X509Certificate[]), ...args.hintsDer.map(parse).filter((c): c is X509Certificate => c != null)];
  const leaf = (x5c as X509Certificate[])[0];

  const lv = validAt(leaf, args.signingTimeMs);
  if (!lv.ok) return fail(`signing certificate ${lv.reason}`, lv.sub, true);

  let current = leaf;
  let caBelow = 0; // CA certs already in the path below the issuer under test (pathLenConstraint accounting)
  let lastMatchReason = ''; // most-informative resolver reason (e.g. "matched only a TSA/QTST service")
  const seen = new Set<string>([fp256(leaf)]);
  for (let depth = 0; depth < MAX_PATH_DEPTH; depth++) {
    // Anchor test (ruling 2): is THIS cert a granted CA/QC-for-eSig service on the TL at signing time?
    const m = matchGrantedCaQc(args.tslXml, fp256(current), args.signingTimeMs);
    if (m.matched) {
      return { ok: true, broken: false, notAnchored: false, reason: `anchored at TL-granted CA/QC service "${m.serviceName ?? ''}"`, subIndication: null, depth, anchorCertDer: current.raw.toString('base64'), anchorServiceName: m.serviceName ?? null };
    }
    if (m.reason) lastMatchReason = m.reason;
    // Find the issuer among the untrusted pool (name + key-id chaining).
    const issuer = pool.find((c) => fp256(c) !== fp256(current) && safeCheckIssued(current, c));
    if (!issuer) {
      // Two distinct operator stories (do not collapse):
      //  • self-issued/top cert reached but NOT on the TL → ANCHOR_NOT_ON_TRUSTED_LIST (this isn't qualified).
      //  • a non-self-issued cert whose issuer is absent from x5c/hints → CHAIN_INCOMPLETE (fix the producer's
      //    x5c). The validator does NOT fetch missing issuers (no AIA chasing — offline/trustless by design).
      if (current.subject === current.issuer) {
        return fail(`path reached a self-issued top certificate that is NOT a granted CA/QC-for-eSignatures service on the EU Trusted List — the x5c top is NOT a trust anchor (${lastMatchReason || 'not on the TL'})`, 'ANCHOR_NOT_ON_TRUSTED_LIST', false, true);
      }
      return fail(`certificate path is incomplete: the issuer of "${current.subject}" is not present in x5c/intermediateHintsDer and the validator does not fetch it (no AIA chasing) — supply the full chain leaf→TL-listed CA`, 'CHAIN_INCOMPLETE', false, true);
    }
    if (seen.has(fp256(issuer))) return fail('certificate path loops', 'CHAIN_CONSTRAINTS_FAILURE', true);
    // ── RFC 5280 §6 link validation: current ← issuer ──
    if (!safeVerify(current, issuer)) return fail('a certificate signature does not verify under its issuer public key', 'SIG_CRYPTO_FAILURE', true);
    const iv = validAt(issuer, args.signingTimeMs);
    if (!iv.ok) return fail(`a CA certificate ${iv.reason}`, iv.sub, true);
    const bc = parseBasicConstraints(issuer.raw);
    if (!bc.cA) return fail('a path certificate used as a CA has basicConstraints cA=FALSE', 'CHAIN_CONSTRAINTS_FAILURE', true);
    if (bc.pathLen != null && bc.pathLen < caBelow) return fail(`pathLenConstraint violated (CA pathLen=${bc.pathLen} < ${caBelow} intermediate CA(s) below it)`, 'CHAIN_CONSTRAINTS_FAILURE', true);
    const ku = parseKeyUsage(issuer.raw);
    if (ku.present && !ku.keyCertSign) return fail('a path CA certificate lacks keyUsage keyCertSign', 'CHAIN_CONSTRAINTS_FAILURE', true);
    seen.add(fp256(issuer));
    caBelow++;
    current = issuer;
  }
  return fail(`certificate path exceeds maximum depth ${MAX_PATH_DEPTH}`, 'CHAIN_CONSTRAINTS_FAILURE', true);
}

function safeCheckIssued(subject: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return subject.checkIssued(issuer);
  } catch {
    return false;
  }
}
function safeVerify(subject: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return subject.verify(issuer.publicKey);
  } catch {
    return false;
  }
}
function fp256(c: X509Certificate): string {
  return c.fingerprint256.replace(/:/g, '').toLowerCase();
}

// ── (4a) QcStatements extraction (RFC 3739 / ETSI EN 319 412-5) ─────────────────────────────────────

interface QcResult {
  qcCompliance: boolean;
  qcSscd: boolean;
  qcTypeEsign: boolean;
}

function extractQcStatements(cert: X509Certificate): QcResult {
  const out: QcResult = { qcCompliance: false, qcSscd: false, qcTypeEsign: false };
  const der = findExtension(cert.raw, OID_QC_STATEMENTS);
  if (!der) return out;
  // `der` = the extnValue OCTET STRING content = DER SEQUENCE OF QCStatement.
  const seq = readTLV(der, 0);
  for (const st of children(der, seq.vStart, seq.vEnd)) {
    // each QCStatement = SEQUENCE { statementId OID, statementInfo OPTIONAL }
    const stCh = children(der, st.vStart, st.vEnd);
    const idNode = stCh[0];
    if (!idNode || idNode.tag !== 0x06) continue;
    const oid = decodeOid(der, idNode.vStart, idNode.vEnd);
    if (oid === OID_QC_COMPLIANCE) out.qcCompliance = true;
    else if (oid === OID_QC_SSCD) out.qcSscd = true;
    else if (oid === OID_QC_TYPE) {
      const info = stCh[1]; // SEQUENCE OF QcType (OID)
      if (info && info.tag === 0x30) {
        for (const t of children(der, info.vStart, info.vEnd)) {
          if (t.tag === 0x06 && decodeOid(der, t.vStart, t.vEnd) === OID_QC_TYPE_ESIGN) out.qcTypeEsign = true;
        }
      }
    }
  }
  return out;
}

/** Walk a Certificate DER to the extensions and return the raw extnValue OCTET-STRING content for `oid`. */
function findExtension(certDer: Buffer, oid: string): Buffer | null {
  const cert = readTLV(certDer, 0); // Certificate SEQUENCE
  const tbs = children(certDer, cert.vStart, cert.vEnd)[0]; // TBSCertificate SEQUENCE
  const tbsCh = children(certDer, tbs.vStart, tbs.vEnd);
  const extsCtx = tbsCh.find((t) => t.tag === 0xa3); // extensions [3] EXPLICIT
  if (!extsCtx) return null;
  const extsSeq = children(certDer, extsCtx.vStart, extsCtx.vEnd)[0]; // SEQUENCE OF Extension
  for (const ext of children(certDer, extsSeq.vStart, extsSeq.vEnd)) {
    const ec = children(certDer, ext.vStart, ext.vEnd);
    const idNode = ec[0];
    if (!idNode || idNode.tag !== 0x06) continue;
    if (decodeOid(certDer, idNode.vStart, idNode.vEnd) !== oid) continue;
    const octet = ec.find((t, i) => i > 0 && t.tag === 0x04); // extnValue OCTET STRING (after optional critical)
    if (!octet) return null;
    return certDer.subarray(octet.vStart, octet.vEnd);
  }
  return null;
}

// ── (4b) Trusted-List CA/QC matcher (ETSI TS 119 615 / 119 612) ────────────────────────────────────
//
// REUSE NOTE (refinement 3): `@val-protocol/anchor-lotl-resolver` already resolves the LOTL→member-state
// pointer (`findTslPointer`, reused below) and matches TSA/QTST services (`matchGrantedQtst`). It does NOT
// match CA/QC-for-eSignatures — a DIFFERENT service type. We add the CA/QC matcher HERE and deliberately
// do NOT treat a TSA/QTST match as a qualified-eSignature hit (that would be a false green; covered by a
// dedicated test).

interface CaQcMatch {
  matched: boolean;
  serviceName?: string;
  statusStartingTimeMs?: number;
  reason?: string;
}

export function matchGrantedCaQc(tslXml: string, issuerCaFingerprintHex: string, signingTimeMs: number): CaQcMatch {
  const want = (issuerCaFingerprintHex || '').replace(/:/g, '').toLowerCase();
  const serviceRe = /<(?:[a-z0-9]+:)?TSPService>([\s\S]*?)<\/(?:[a-z0-9]+:)?TSPService>/gi;
  let m: RegExpExecArray | null;
  let sawTsaForThisCa = false;
  while ((m = serviceRe.exec(tslXml))) {
    const s = m[1];
    const svcType = pick(s, 'ServiceTypeIdentifier');
    const isCaQc = svcType === SVCTYPE_CA_QC;
    const isTsa = svcType === SVCTYPE_TSA_QTST;
    if (!isCaQc && !isTsa) continue;
    if (!certMatches(s, want)) continue;
    if (isTsa) {
      sawTsaForThisCa = true; // recorded but NEVER accepted as a qualified-eSig hit (refinement 3)
      continue;
    }
    // CA/QC: require granted, granted-at-signing-time, and ForeSignatures (eSignatures, not seals/web-auth).
    if (pick(s, 'ServiceStatus') !== STATUS_GRANTED) continue;
    if (!s.includes(ASI_FOR_ESIGNATURES)) continue;
    const startMs = parseIsoOrNaN(pick(s, 'StatusStartingTime'));
    if (Number.isFinite(startMs) && startMs > signingTimeMs) {
      return { matched: false, statusStartingTimeMs: startMs, reason: `CA/QC service granted only from ${new Date(startMs).toISOString()}, after signing time ${new Date(signingTimeMs).toISOString()}` };
    }
    return { matched: true, serviceName: pickName(s) ?? undefined, statusStartingTimeMs: startMs };
  }
  return {
    matched: false,
    reason: sawTsaForThisCa
      ? 'issuer CA matched only a TSA/QTST (timestamping) service, not a CA/QC-for-eSignatures service — not qualified for e-signatures'
      : 'no granted CA/QC-for-eSignatures service certificate matched the issuer CA at signing time',
  };
}

// ── identity (minimum dataset, verbatim from the cert subject) ─────────────────────────────────────

function extractSignerIdentity(leaf: X509Certificate): QesSignerIdentity {
  const dn = leaf.subject || '';
  const given = subjectField(dn, 'GN') ?? subjectField(dn, 'givenName');
  const family = subjectField(dn, 'SN') ?? subjectField(dn, 'surname');
  const cn = subjectField(dn, 'CN') ?? '';
  const cnParts = cn.split(/\s+/);
  return {
    given_name: given ?? cnParts[0] ?? '',
    family_name: family ?? cnParts.slice(1).join(' '),
    date_of_birth: null, // not in the test cert subject; extracted from a dedicated attribute when present
    persistent_id: subjectField(dn, 'serialNumber'),
    country: subjectField(dn, 'C'),
  };
}

// ── trust-list resolution ───────────────────────────────────────────────────────────────────────────

async function resolveTslXml(
  trust: QesTrustInput,
  leaf: X509Certificate,
): Promise<{ xml?: string; indeterminate?: boolean; reason?: string }> {
  if (trust.tslXml) return { xml: trust.tslXml };
  if (!trust.fetchLive) return { indeterminate: true, reason: 'no tslXml supplied and fetchLive not set' };
  const country = subjectField(leaf.issuer || leaf.subject, 'C');
  if (!country) return { indeterminate: true, reason: 'cannot determine issuer country for member-state TSL lookup' };
  const fetchImpl = trust.fetchImpl ?? fetch;
  try {
    const lotl = await (await fetchImpl(trust.lotlUrl ?? EU_LOTL_URL)).text();
    const tslUrl = findTslPointer(lotl, country);
    if (!tslUrl) return { indeterminate: true, reason: `no TSL pointer for territory ${country} in the EU LOTL` };
    const xml = await (await fetchImpl(tslUrl)).text();
    return { xml };
  } catch (e) {
    return { indeterminate: true, reason: `LOTL/TSL fetch failed: ${(e as Error).message}` };
  }
}

// ── shared helpers ─────────────────────────────────────────────────────────────────────────────────

function extractSignatureBytes(signature: unknown): string | null {
  if (typeof signature === 'string') return signature;
  if (signature && typeof signature === 'object' && typeof (signature as { signature?: unknown }).signature === 'string') {
    return (signature as { signature: string }).signature;
  }
  return null;
}
function sha256Hex(s: string | Buffer, mode?: 'buffer'): string {
  const h = createHash('sha256');
  return mode === 'buffer' ? h.update(s as Buffer).digest('hex') : h.update(s as string, 'utf8').digest('hex');
}

// minimal DER reader (ported from @val-protocol/anchor-lotl-resolver; kept local to stay self-contained).
interface TLV {
  tag: number;
  hStart: number;
  vStart: number;
  vEnd: number;
}
function readTLV(buf: Buffer, off: number): TLV {
  const tag = buf[off];
  let i = off + 1;
  let len = buf[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | buf[i++];
  }
  return { tag, hStart: off, vStart: i, vEnd: i + len };
}
function children(buf: Buffer, vStart: number, vEnd: number): TLV[] {
  const out: TLV[] = [];
  let off = vStart;
  while (off < vEnd) {
    const t = readTLV(buf, off);
    out.push(t);
    off = t.vEnd;
  }
  return out;
}
function decodeOid(buf: Buffer, vStart: number, vEnd: number): string {
  const bytes = buf.subarray(vStart, vEnd);
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  for (let k = 1; k < bytes.length; k++) {
    val = (val << 7) | (bytes[k] & 0x7f);
    if (!(bytes[k] & 0x80)) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join('.');
}

// TSL XML helpers (regex; zero-dep — a relying party MAY substitute a full XAdES/TSL-signature validator).
function pick(xml: string, tag: string): string | null {
  const m = new RegExp(`<(?:[a-z0-9]+:)?${tag}>([\\s\\S]*?)</(?:[a-z0-9]+:)?${tag}>`, 'i').exec(xml);
  return m ? m[1].trim() : null;
}
function pickName(xml: string): string | null {
  const block = pick(xml, 'ServiceName');
  if (!block) return null;
  const m = /<(?:[a-z0-9]+:)?Name[^>]*>([\s\S]*?)<\/(?:[a-z0-9]+:)?Name>/i.exec(block);
  return m ? m[1].trim() : null;
}
function certMatches(serviceXml: string, wantFpHex: string): boolean {
  const re = /<(?:[a-z0-9]+:)?X509Certificate>([\s\S]*?)<\/(?:[a-z0-9]+:)?X509Certificate>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(serviceXml))) {
    const fp = createHash('sha256').update(Buffer.from(m[1].replace(/\s+/g, ''), 'base64')).digest('hex');
    if (fp === wantFpHex) return true;
  }
  return false;
}
function parseIsoOrNaN(s: string | null): number {
  if (!s) return NaN;
  const t = Date.parse(s);
  return Number.isNaN(t) ? NaN : t;
}
function subjectField(dn: string | undefined, key: string): string | null {
  if (!dn) return null;
  const m = new RegExp(`(?:^|[,\\n])\\s*${key}=([^,\\n]+)`).exec(dn);
  return m ? m[1].trim() : null;
}
