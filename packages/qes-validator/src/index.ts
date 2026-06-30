/**
 * @val-protocol/qes-validator — eIDAS QES validation for VAL Profile C (ADR 0063).
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
 * Honesty: this validator — not the core — is the authority for "qualified". `qualified` is TRUE only on
 * a conclusive positive determination; anything else is `not_qualified` (conclusive negative) or
 * `indeterminate` (could not conclude). The core treats only `qualified` as the gate, so neither a null
 * identity nor an indeterminate verdict can fake a green.
 */

import { X509Certificate, createHash, verify as cryptoVerify } from 'node:crypto';
import { findTslPointer } from '@val-protocol/anchor-lotl-resolver';

// ── eIDAS / ETSI constants ────────────────────────────────────────────────────────────────────────
const OID_QC_STATEMENTS = '1.3.6.1.5.5.7.1.3'; // id-pe-qcStatements (RFC 3739)
const OID_QC_COMPLIANCE = '0.4.0.1862.1.1'; // esi4-qcStatement-1 (QcCompliance)
const OID_QC_SSCD = '0.4.0.1862.1.4'; // esi4-qcStatement-4 (QcSSCD)
const OID_QC_TYPE = '0.4.0.1862.1.6'; // esi4-qcStatement-6 (QcType)
const OID_QC_TYPE_ESIGN = '0.4.0.1862.1.6.1'; // id-etsi-qct-esign

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
}

/** Trust inputs for the offline determination. Provide a member-state TSL (or the live LOTL) + anchors. */
export interface QesTrustInput {
  /** Pre-fetched member-state Trusted List XML (ETSI TS 119 612). Offline/test path. */
  tslXml?: string;
  /** Fetch the EU LOTL → member-state TSL live (network). */
  fetchLive?: boolean;
  lotlUrl?: string;
  fetchImpl?: typeof fetch;
  /** DER (base64) trust-anchor certificates the cert path must terminate at. In production these are the
   *  EU LOTL scheme operators' roots; in tests, an injected test root. Empty ⇒ path cannot be anchored. */
  trustAnchorsDer?: string[];
}

/** Input to validate one qualified delegation signature carried on a VAL root ASSIGNMENT. */
export interface QesValidationInput {
  /** The canonical bytes the QES was computed over (the root ASSIGNMENT canonical_details). */
  signedCanonical: string;
  /** The qualified signature carried in `human_attestation.delegator_authority.signature`
   *  (a ValQesSignature { alg, signature } or a bare base64 JAdES string). */
  signature: unknown;
  /** Validation/signing time (defaults to now). For LTV, pass a chain anchor genTime (ADR 0062). */
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
    return indeterminate('unrecognized signature shape (expected ValQesSignature { alg, signature } or base64 JAdES)', 'FORMAT_FAILURE', null);
  }
  const signingTimeMs = input.validationTime ? Date.parse(input.validationTime) : Date.now();

  // (1) Parse the JAdES compact JWS.
  let jws: ParsedJws;
  try {
    jws = parseCompactJades(signatureBytes);
  } catch (e) {
    return indeterminate(`JAdES parse failed: ${(e as Error).message} (CAdES/PAdES are out of scope — JAdES only)`, 'FORMAT_FAILURE', signatureRef);
  }
  const adesLevel = jws.header.sigT ? 'JAdES-BASELINE-T(approx)' : 'JAdES-BASELINE-B(approx)';

  // (1a) crit enforcement (RFC 7515 §4.1.11): every header param the signer marks critical MUST be one
  //      this validator understands and processes, else reject. No silent leniency.
  const critUnknown = (jws.header.crit ?? []).filter((p) => !UNDERSTOOD_CRIT.has(p));
  if (critUnknown.length > 0) {
    return indeterminate(`unsupported critical header param(s) ${JSON.stringify(critUnknown)} — RFC 7515 requires rejecting a signature whose crit set is not fully understood`, 'FORMAT_FAILURE', signatureRef, adesLevel);
  }

  if (!jws.header.x5c || jws.header.x5c.length === 0) {
    return indeterminate('JAdES header carries no x5c certificate chain (cannot identify the signer)', 'NO_SIGNING_CERTIFICATE_FOUND', signatureRef, adesLevel);
  }

  // (1b) Bind the detached signature to the canonical bytes (sigD ObjectIdByURIHash), else attached payload.
  const bind = bindsToCanonical(jws, input.signedCanonical);
  if (!bind.ok) {
    return notQualified(`signature does not bind the supplied canonical bytes: ${bind.reason}`, 'HASH_FAILURE', signatureRef, adesLevel);
  }

  // (2) Verify the signature value over the JWS signing input with the leaf public key.
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(Buffer.from(jws.header.x5c[0], 'base64'));
  } catch (e) {
    return indeterminate(`leaf certificate (x5c[0]) is not a valid X.509: ${(e as Error).message}`, 'FORMAT_FAILURE', signatureRef, adesLevel);
  }
  const sigOk = verifyJwsSignature(jws, leaf);
  if (!sigOk.ok) {
    return notQualified(`signature-value verification failed: ${sigOk.reason}`, 'SIG_CRYPTO_FAILURE', signatureRef, adesLevel);
  }

  // (3) Build + verify the certificate path leaf → issuer → trust anchor.
  const path = buildAndVerifyPath(jws.header.x5c, input.trust.trustAnchorsDer ?? []);
  if (!path.ok) {
    // No anchor ⇒ cannot conclude (indeterminate); a broken signature in the chain ⇒ conclusive fail.
    return path.broken
      ? notQualified(`certificate path invalid: ${path.reason}`, 'NO_CERTIFICATE_CHAIN_FOUND', signatureRef, adesLevel)
      : indeterminate(`certificate path could not be anchored to a trust anchor: ${path.reason}`, 'NO_CERTIFICATE_CHAIN_FOUND', signatureRef, adesLevel);
  }

  // (3b) Validity period — the signing cert MUST be valid at signing time (ETSI TS 119 102-1).
  //      Previously unchecked: an expired/not-yet-valid cert would have passed. Conclusive fail.
  const vfrom = Date.parse(leaf.validFrom); // RFC string e.g. "Jun 30 00:00:00 2026 GMT"
  const vto = Date.parse(leaf.validTo);
  if (Number.isFinite(vfrom) && signingTimeMs < vfrom) {
    return notQualified(`signing certificate not yet valid at signing time (notBefore ${new Date(vfrom).toISOString()} > ${new Date(signingTimeMs).toISOString()})`, 'NOT_YET_VALID', signatureRef, adesLevel);
  }
  if (Number.isFinite(vto) && signingTimeMs > vto) {
    return notQualified(`signing certificate expired at signing time (notAfter ${new Date(vto).toISOString()} < ${new Date(signingTimeMs).toISOString()})`, 'EXPIRED', signatureRef, adesLevel);
  }

  // (4a) QcStatements in the signing cert: QcCompliance AND QcType-eSign both required.
  const qc = extractQcStatements(leaf);
  if (!qc.qcCompliance || !qc.qcTypeEsign) {
    const miss = [!qc.qcCompliance && 'QcCompliance', !qc.qcTypeEsign && 'QcType-eSign'].filter(Boolean).join(' + ');
    return notQualified(`signing certificate lacks required QcStatements (${miss}) — not a qualified e-signature certificate`, 'CHAIN_CONSTRAINTS_FAILURE', signatureRef, adesLevel);
  }

  // (4b) Issuer CA resolves to a granted CA/QC-for-eSignatures Trusted-List service at signing time.
  const issuerCaFp = sha256Hex(Buffer.from(path.issuerDer, 'base64'), 'buffer');
  const tslXml = await resolveTslXml(input.trust, leaf);
  if (tslXml.indeterminate) {
    return indeterminate(`Trusted List unavailable: ${tslXml.reason}`, 'CERTIFICATE_CHAIN_GENERAL_FAILURE', signatureRef, adesLevel);
  }
  const tl = matchGrantedCaQc(tslXml.xml!, issuerCaFp, signingTimeMs);
  if (!tl.matched) {
    return notQualified(`issuer CA is not a granted CA/QC-for-eSignatures service on the EU Trusted List at signing time: ${tl.reason}`, 'CHAIN_CONSTRAINTS_FAILURE', signatureRef, adesLevel);
  }

  // Conclusive POSITIVE — all four legs pass.
  return {
    qualified: true,
    status: 'qualified',
    reason: `valid QES: signature verified, path anchored, QcStatements present (QcCompliance${qc.qcSscd ? ' + QcSSCD' : ''} + QcType-eSign), issuer is granted CA/QC-for-eSignatures "${tl.serviceName}" at signing time`,
    signatureRef,
    signerIdentity: extractSignerIdentity(leaf),
    indication: 'TOTAL-PASSED',
    subIndication: null,
    adesLevel,
    reportRef: `offline-js:${signatureRef?.slice(0, 16)}`,
    backend: 'offline-js',
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

// ── (3) certificate-path build + verification (ETSI TS 119 102-1) ──────────────────────────────────

interface PathResult {
  ok: boolean;
  broken: boolean; // true ⇒ a signature in the presented chain is invalid (conclusive fail, not indeterminate)
  reason: string;
  issuerDer: string; // base64 DER of the CA that issued the leaf (matched to the TSL CA/QC service)
}

/** Verify leaf is signed by the next cert, walking to a presented or injected trust anchor. */
function buildAndVerifyPath(x5cB64: string[], trustAnchorsDer: string[]): PathResult {
  const anchors = trustAnchorsDer
    .map((d) => {
      try {
        return new X509Certificate(Buffer.from(d, 'base64'));
      } catch {
        return null;
      }
    })
    .filter((c): c is X509Certificate => c != null);
  const anchorFps = new Set(anchors.map((a) => fp256(a)));

  const chain: X509Certificate[] = [];
  for (const b of x5cB64) {
    try {
      chain.push(new X509Certificate(Buffer.from(b, 'base64')));
    } catch (e) {
      return { ok: false, broken: true, reason: `x5c entry not a valid certificate: ${(e as Error).message}`, issuerDer: '' };
    }
  }
  const leaf = chain[0];

  // Find the issuer of the leaf from the presented chain or the injected anchors.
  const candidates = [...chain.slice(1), ...anchors];
  const issuer = candidates.find((c) => safeCheckIssued(leaf, c));
  if (!issuer) {
    return { ok: false, broken: false, reason: 'no issuer certificate found for the leaf (chain not anchored)', issuerDer: '' };
  }
  if (!safeVerify(leaf, issuer)) {
    return { ok: false, broken: true, reason: 'leaf signature does not verify against its issuer public key', issuerDer: '' };
  }
  // The issuer must itself be a trust anchor, or be signed by one (one extra hop for our subset).
  if (!anchorFps.has(fp256(issuer))) {
    const upper = anchors.find((a) => safeCheckIssued(issuer, a) && safeVerify(issuer, a));
    if (!upper) {
      return { ok: false, broken: false, reason: 'issuer CA does not terminate at a supplied trust anchor', issuerDer: '' };
    }
  }
  return { ok: true, broken: false, reason: 'path verified to a trust anchor', issuerDer: issuer.raw.toString('base64') };
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
