// @val-protocol/anchor-lotl-resolver
// ────────────────────────────────────────────────────────────────────────────
// CALLER-SIDE trust resolution for VAL external-anchor (Pass 4) qualified timestamps.
//
// WHY THIS EXISTS (audit C6, 2026-06-27): the unit of *qualification* on the EU Trusted List is the
// CA / service (e.g. "Sectigo Qualified Time Stamping CA R35"), NOT the rotating leaf signer. Pinning a
// single scraped leaf SPKI breaks silently on a routine signer rotation (#3 → #4) even though the QTSP
// is unchanged on the LOTL. This module resolves the anchorTrust SPKI set FROM the token + the live EU
// Trusted List, bound to the granted CA/root identity and validated as QTST/granted **at the token's
// genTime** — so it is re-resolvable across rotation and never depends on a hardcoded leaf.
//
// TRUSTLESS: a third-party relying party runs THIS (or any reimplementation) against the public EU LOTL
// to reproduce the trust set without trusting RIGA's resolver. It is a separate, caller-side package —
// the zero-dep `@val-protocol/chain-verifier` core stays zero-dep and unchanged; it still only consumes
// `anchorTrust.tsaCertSpkis: string[]` and proves `anchorBinding`. "Qualified" remains operator-asserted
// + legal-opinion-backed (audit C7); this resolver establishes the *cryptographic* CA-on-the-LOTL fact.
//
// Zero runtime deps: node:crypto (X509Certificate, hashes) + a minimal DER walk + global fetch (live).
// ────────────────────────────────────────────────────────────────────────────

import { X509Certificate, createHash } from 'node:crypto';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const SVCTYPE_QTST = 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST';
const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const EU_LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

// ── minimal DER reader ──────────────────────────────────────────────────────
/** Read one TLV at offset. Returns {tag, hStart, vStart, vEnd} (vEnd exclusive). */
function readTLV(buf, off) {
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
/** Iterate the TLV children contained in [vStart, vEnd). */
function children(buf, vStart, vEnd) {
  const out = [];
  let off = vStart;
  while (off < vEnd) {
    const t = readTLV(buf, off);
    out.push(t);
    off = t.vEnd;
  }
  return out;
}
function decodeOid(buf, vStart, vEnd) {
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

/** Parse "20260627185101Z" (GeneralizedTime) → epoch ms (UTC). */
function parseGeneralizedTime(s) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$/.exec(s.trim());
  if (!m) return NaN;
  const [, Y, Mo, D, H, Mi, S] = m;
  return Date.UTC(+Y, +Mo - 1, +D, +H, +Mi, +S);
}

// ── token parsing ───────────────────────────────────────────────────────────
/**
 * Parse an RFC 3161 TimeStampToken (base64 CMS SignedData). Returns the embedded cert set, the genTime,
 * the leaf (TSU) signer SPKI, and its issuing CA cert + sha-256 fingerprint.
 * @param {string} tstBase64
 */
export function parseTokenChain(tstBase64) {
  const der = Buffer.from(tstBase64.replace(/\s+/g, ''), 'base64');
  const ci = readTLV(der, 0); // ContentInfo SEQUENCE
  const ciCh = children(der, ci.vStart, ci.vEnd);
  const ctType = decodeOid(der, ciCh[0].vStart, ciCh[0].vEnd);
  if (ctType !== OID_SIGNED_DATA) throw new Error(`not CMS SignedData (contentType ${ctType})`);
  const content0 = ciCh[1]; // [0] EXPLICIT
  const sd = children(der, content0.vStart, content0.vEnd)[0]; // SignedData SEQUENCE
  const sdCh = children(der, sd.vStart, sd.vEnd);
  // sdCh: version, digestAlgorithms SET, encapContentInfo SEQ, [certificates [0]], [crls [1]], signerInfos SET
  const enc = sdCh[2]; // encapContentInfo SEQUENCE
  const encCh = children(der, enc.vStart, enc.vEnd);
  const eContentType = decodeOid(der, encCh[0].vStart, encCh[0].vEnd);
  if (eContentType !== OID_CT_TSTINFO) throw new Error(`eContentType not id-ct-TSTInfo (${eContentType})`);
  // eContent [0] EXPLICIT → OCTET STRING → TSTInfo SEQUENCE
  const eContentExpl = children(der, encCh[1].vStart, encCh[1].vEnd)[0]; // OCTET STRING
  const tstInfo = children(der, eContentExpl.vStart, eContentExpl.vEnd)[0]; // SEQUENCE
  const tstCh = children(der, tstInfo.vStart, tstInfo.vEnd);
  const gtNode = tstCh.find((t) => t.tag === 0x18); // GeneralizedTime
  if (!gtNode) throw new Error('TSTInfo genTime not found');
  const genTime = parseGeneralizedTime(der.subarray(gtNode.vStart, gtNode.vEnd).toString('ascii'));

  // certificates [0] IMPLICIT (context tag 0xA0) — a run of Certificate SEQUENCEs
  const certsNode = sdCh.find((t) => t.tag === 0xa0);
  if (!certsNode) throw new Error('token carries no certificates');
  const certs = children(der, certsNode.vStart, certsNode.vEnd)
    .filter((t) => t.tag === 0x30)
    .map((t) => new X509Certificate(der.subarray(t.hStart, t.vEnd)));

  // Leaf = the (unique) non-CA cert; if several, prefer one asserting the timeStamping EKU.
  const nonCa = certs.filter((c) => c.ca === false);
  const leaf =
    nonCa.find((c) => (c.keyUsage || []).includes('1.3.6.1.5.5.7.3.8')) || nonCa[0] || certs[0];
  if (!leaf) throw new Error('no leaf signer cert in token');
  const caCert = certs.find((c) => c.ca === true && c.subject === leaf.issuer) || null;

  const signerSpkiB64 = leaf.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return {
    genTime, // epoch ms
    certs,
    leaf,
    caCert,
    signerSpkiB64,
    caFingerprintSha256: caCert ? normFp(caCert.fingerprint256) : null,
    countryCode: subjectField(caCert?.subject || leaf.subject, 'C'),
  };
}

function normFp(fp) {
  return fp.replace(/:/g, '').toLowerCase();
}
function subjectField(dn, key) {
  if (!dn) return null;
  const m = new RegExp(`(?:^|\\n)${key}=([^\\n]+)`).exec(dn);
  return m ? m[1].trim() : null;
}

// ── Trusted-List matching ────────────────────────────────────────────────────
/**
 * Find a QTST / granted TSPService in `tslXml` whose embedded CA certificate matches `caFingerprintHex`
 * (sha-256, colon-stripped lowercase) AND whose granted status started at/before `genTimeMs`.
 * Regex extraction is used deliberately (zero-dep, well-formed ETSI TS 119 612 XML); a relying party MAY
 * substitute a full XML/XAdES validator — the LOTL/TSL signatures themselves are out of scope here and
 * are a documented hardening step (validate the TSL's own qualified signature before trusting it).
 */
export function matchGrantedQtst(tslXml, caFingerprintHex, genTimeMs) {
  const want = (caFingerprintHex || '').replace(/:/g, '').toLowerCase();
  const serviceRe = /<(?:[a-z0-9]+:)?TSPService>([\s\S]*?)<\/(?:[a-z0-9]+:)?TSPService>/gi;
  let m;
  while ((m = serviceRe.exec(tslXml))) {
    const s = m[1];
    if (!s.includes(SVCTYPE_QTST)) continue;
    const status = pick(s, 'ServiceStatus');
    if (status !== STATUS_GRANTED) continue;
    const startMs = parseIsoOrNaN(pick(s, 'StatusStartingTime'));
    const name = pickName(s);
    for (const certB64 of allCerts(s)) {
      const fp = createHash('sha256').update(Buffer.from(certB64, 'base64')).digest('hex');
      if (fp === want) {
        const grantedAtGenTime = Number.isFinite(startMs) ? startMs <= genTimeMs : true;
        return {
          matched: true,
          granted: status === STATUS_GRANTED,
          grantedAtGenTime,
          serviceName: name,
          statusStartingTimeMs: startMs,
          caFingerprintSha256: fp,
        };
      }
    }
  }
  return { matched: false, granted: false, grantedAtGenTime: false, reason: 'no QTST/granted service certificate matched the token CA' };
}

function pick(xml, tag) {
  const m = new RegExp(`<(?:[a-z0-9]+:)?${tag}>([\\s\\S]*?)</(?:[a-z0-9]+:)?${tag}>`, 'i').exec(xml);
  return m ? m[1].trim() : null;
}
function pickName(xml) {
  const block = pick(xml, 'ServiceName');
  if (!block) return null;
  const m = /<(?:[a-z0-9]+:)?Name[^>]*>([\s\S]*?)<\/(?:[a-z0-9]+:)?Name>/i.exec(block);
  return m ? m[1].trim() : null;
}
function allCerts(xml) {
  const out = [];
  const re = /<(?:[a-z0-9]+:)?X509Certificate>([\s\S]*?)<\/(?:[a-z0-9]+:)?X509Certificate>/gi;
  let m;
  while ((m = re.exec(xml))) out.push(m[1].replace(/\s+/g, ''));
  return out;
}
function parseIsoOrNaN(s) {
  if (!s) return NaN;
  const t = Date.parse(s);
  return Number.isNaN(t) ? NaN : t;
}

// ── public API ───────────────────────────────────────────────────────────────
/**
 * PURE resolver: given a token + the relevant member-state Trusted List XML, return the anchorTrust SPKI
 * set to feed `chain-verifier` `verifyValChain(..., { anchorTrust: { tsaCertSpkis } })`.
 * @returns {{ ok: boolean, spkis: string[], evidence?: object, reason?: string }}
 */
export function resolveAnchorTrust({ tstBase64, tslXml }) {
  const tok = parseTokenChain(tstBase64);
  if (!tok.caFingerprintSha256) return { ok: false, spkis: [], reason: 'token has no issuing CA cert to bind to the LOTL' };
  const tl = matchGrantedQtst(tslXml, tok.caFingerprintSha256, tok.genTime);
  if (!tl.matched) return { ok: false, spkis: [], reason: tl.reason, evidence: { genTime: new Date(tok.genTime).toISOString() } };
  if (!tl.granted || !tl.grantedAtGenTime) {
    return {
      ok: false,
      spkis: [],
      reason: `CA found but not granted at genTime (status start ${isoOrNull(tl.statusStartingTimeMs)} vs genTime ${new Date(tok.genTime).toISOString()})`,
      evidence: tlEvidence(tok, tl),
    };
  }
  return { ok: true, spkis: [tok.signerSpkiB64], evidence: tlEvidence(tok, tl) };
}

function tlEvidence(tok, tl) {
  return {
    genTime: new Date(tok.genTime).toISOString(),
    caFingerprintSha256: tok.caFingerprintSha256,
    serviceName: tl.serviceName,
    serviceTypeIdentifier: SVCTYPE_QTST,
    serviceStatus: STATUS_GRANTED,
    statusStartingTime: isoOrNull(tl.statusStartingTimeMs),
    signerSubject: tok.leaf?.subject?.replace(/\n/g, ', '),
    countryCode: tok.countryCode,
    note: 'CA cryptographically == a QTST/granted service identity on the EU Trusted List at genTime. ' +
      '"Qualified/Art-42 for the relying party" remains operator-asserted + legal-opinion-backed (audit C7).',
  };
}
function isoOrNull(ms) {
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/**
 * LIVE resolver: fetch the EU LOTL, follow the member-state TSL pointer for the token CA's country, and
 * resolve. Network; not exercised by the unit suite (see test/live.test.mjs, gated by RUN_LIVE=1).
 */
export async function resolveAnchorTrustLive({ tstBase64, lotlUrl = EU_LOTL_URL, fetchImpl = fetch } = {}) {
  const tok = parseTokenChain(tstBase64);
  const country = tok.countryCode;
  if (!country) return { ok: false, spkis: [], reason: 'cannot determine CA country for TSL lookup' };
  const lotl = await (await fetchImpl(lotlUrl)).text();
  const tslUrl = findTslPointer(lotl, country);
  if (!tslUrl) return { ok: false, spkis: [], reason: `no TSL pointer for territory ${country} in the EU LOTL` };
  const tslXml = await (await fetchImpl(tslUrl)).text();
  return { ...resolveAnchorTrust({ tstBase64, tslXml }), tslUrl };
}

/** Find the XML TSL location for a SchemeTerritory in the EU LOTL. */
export function findTslPointer(lotlXml, country) {
  const re = /<(?:[a-z0-9]+:)?OtherTSLPointer>([\s\S]*?)<\/(?:[a-z0-9]+:)?OtherTSLPointer>/gi;
  let m;
  while ((m = re.exec(lotlXml))) {
    const b = m[1];
    if (new RegExp(`<(?:[a-z0-9]+:)?SchemeTerritory>${country}</`, 'i').test(b)) {
      const loc = /<(?:[a-z0-9]+:)?TSLLocation>([\s\S]*?\.xml)<\/(?:[a-z0-9]+:)?TSLLocation>/i.exec(b);
      if (loc) return loc[1].trim();
    }
  }
  return null;
}
