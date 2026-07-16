/**
 * @val-protocol/chain-verifier — reference offline verifier for Verifiable
 * Authorization Lineage (VAL). Pure SHA-256 against the canonical preimage
 * specified by the VAL wire format (spec §4).
 *
 * Zero runtime dependency: only `crypto` (Node built-in).
 *
 * Usage:
 *   import { verifyChain, reconstructChainHash, ChainRow } from '@val-protocol/chain-verifier';
 *
 *   const rows: ChainRow[] = ndjsonLines.map(parseLineToChainRow);
 *   const result = verifyChain(rows);
 *   if (!result.ok) throw new Error(`row ${result.firstBadIndex}: ${result.reason}`);
 *
 * Scope-agnostic: one implementation verifies any VAL chain scope by passing
 * the appropriate `scope_key` form (see spec §4 for the per-scope mapping).
 * The verifier never knows or cares which store the data came from — its only
 * contract is "verify these rows against the preimage construction in §4."
 */

// ── Isomorphic crypto (Web Crypto + Uint8Array) — runs in Node 18+ AND browsers, zero deps.
// `crypto.subtle` and `atob`/`btoa` are global in both. The hash/verify fns are therefore
// async; this is the only API shape difference from the prior Node-only build. ──
const _enc = /* @__PURE__ */ new TextEncoder();
function utf8(s: string): Uint8Array {
  return _enc.encode(s);
}
function bytesToHex(b: Uint8Array): string {
  let h = '';
  for (let i = 0; i < b.length; i++) h += b[i].toString(16).padStart(2, '0');
  return h;
}
function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i << 1, (i << 1) + 2), 16);
  return out;
}
function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}
/** base64 OR base64url → bytes. */
function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
/** bytes → base64url (no padding). */
function bytesToB64url(b: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
/** Coerce a Uint8Array to a fresh ArrayBuffer for Web Crypto — sidesteps TS 5.7's
 *  `Uint8Array<ArrayBufferLike>` ≠ `BufferSource` generic (our arrays are never shared). */
function ab(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', ab(data)));
}

// ── Pass 6 (bytes-binding, §7.2 / ADR 0061) ──────────────────────────────────
// A MUTATION MAY carry a hiding `bytes_commitment` over the document's bytes:
//   value = SHA-256( "val.bytes-commitment.v1" ‖ 0x00 ‖ nonce(32B) ‖ SHA-256(file_bytes)(32B) )
// The nonce is held producer-side (never on chain / in any export), so the on-chain
// commitment leaks nothing — even a public export is not a cross-tenant oracle. It is
// re-derived ONLY at evidence time from a disclosed { bytes, nonce } (zero-trust: the
// disclosed nonce is a self-authenticating witness; collision-resistance binds the frozen
// commitment to exactly one file). The verifier hashes the BYTES itself — it never trusts
// a supplied hash.
const BYTES_COMMITMENT_TAG = /* @__PURE__ */ utf8('val.bytes-commitment.v1');
async function recomputeBytesCommitment(
  bytes: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  const inner = await sha256(bytes); // SHA-256(file_bytes), 32 raw bytes
  const preimage = concatBytes(BYTES_COMMITMENT_TAG, new Uint8Array([0x00]), nonce, inner);
  return bytesToHex(await sha256(preimage));
}
/** DER-encoded ECDSA signature (SEQUENCE{ INTEGER r, INTEGER s }) → raw r‖s (64 bytes),
 *  the IEEE-P1363 form Web Crypto's ECDSA verify expects. P-256 DER sigs are short-form. */
function derToRawEcdsaSig(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new Error('invalid DER ECDSA signature');
  let off = 2; // short-form SEQUENCE length (P-256 sig total < 128 bytes)
  if (der[off] !== 0x02) throw new Error('invalid DER ECDSA signature (r)');
  const rlen = der[off + 1];
  const r = der.slice(off + 2, off + 2 + rlen);
  off = off + 2 + rlen;
  if (der[off] !== 0x02) throw new Error('invalid DER ECDSA signature (s)');
  const slen = der[off + 1];
  const s = der.slice(off + 2, off + 2 + slen);
  const to32 = (x: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++; // strip DER sign-padding zeros
    x = x.slice(i);
    if (x.length > 32) x = x.slice(x.length - 32);
    const out = new Uint8Array(32);
    out.set(x, 32 - x.length);
    return out;
  };
  return concatBytes(to32(r), to32(s));
}

// ── Pass 4 (external anchor, §8) — RFC 3161 TimeStampToken verification, zero-dep. ───────────────
// An ANCHOR block carries an RFC 3161 token (`tst`, base64) over a `val.checkpoint-merkle.v1` Merkle
// root of a contiguous in-band block range. Pass 4 (a) recomputes that root and (b) verifies the
// token: a real TSA token is a CMS SignedData whose signature is over the DER `signedAttributes`
// (NOT over TSTInfo directly), with a `message-digest` signed attribute = SHA-256(TSTInfo); and the
// token's `messageImprint.hashedMessage` MUST equal the ANCHOR root. Temporal existence only — the
// attested `genTime` is surfaced, no time-policy is evaluated. The trust anchor is a *resolved* set
// of acceptable TSA signer SPKIs (pinned in Phase 1; LOTL-resolved caller-side in Phase 2 — identical
// shape). The ASN.1/DER is hand-parsed (no dependency), like `derToRawEcdsaSig` above.

// OID content bytes (tag/len stripped), lowercase hex.
const OID_SIGNED_DATA = '2a864886f70d010702';
const OID_TSTINFO = '2a864886f70d0109100104';
const OID_MESSAGE_DIGEST_ATTR = '2a864886f70d010904';
const OID_SHA256 = '608648016503040201';
const OID_SHA384 = '608648016503040202';
const OID_SHA512 = '608648016503040203';
const OID_SHA1 = '2b0e03021a';
const OID_RSA = '2a864886f70d010101';
const OID_RSASSA_PSS = '2a864886f70d01010a';
const OID_EC_PUBKEY = '2a8648ce3d0201';
const OID_EC_P256 = '2a8648ce3d030107';
const OID_EC_P384 = '2b81040022';
const OID_EC_P521 = '2b81040023';
// id-kp-timeStamping (1.3.6.1.5.5.7.3.8) as a full DER OID TLV — scanned for inside the cert set.
const EKU_TIMESTAMPING_TLV = hexToBytes('06082b06010505070308');

interface Der {
  tag: number;
  start: number; // offset of the tag byte
  cStart: number; // offset of the first content byte
  cEnd: number; // offset just past the content (= next TLV start)
}
/** Read one DER TLV at `off` (definite length; short or long form). */
function rd(b: Uint8Array, off: number): Der {
  const tag = b[off];
  let i = off + 1;
  let len = b[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: unsupported length form');
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | b[i++];
  }
  const cStart = i;
  const cEnd = i + len;
  if (cEnd > b.length) throw new Error('DER: length exceeds buffer');
  return { tag, start: off, cStart, cEnd };
}
/** All child TLVs of a constructed `der`. */
function rdChildren(b: Uint8Array, der: Der): Der[] {
  const out: Der[] = [];
  let o = der.cStart;
  while (o < der.cEnd) {
    const t = rd(b, o);
    out.push(t);
    o = t.cEnd;
  }
  return out;
}
const oidHex = (b: Uint8Array, d: Der): string => bytesToHex(b.subarray(d.cStart, d.cEnd));
const bytesEqual = (a: Uint8Array, c: Uint8Array): boolean =>
  a.length === c.length && a.every((x, i) => x === c[i]);
function indexOfSeq(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
function digestNameForOid(oid: string): string {
  switch (oid) {
    case OID_SHA256:
      return 'SHA-256';
    case OID_SHA384:
      return 'SHA-384';
    case OID_SHA512:
      return 'SHA-512';
    case OID_SHA1:
      return 'SHA-1';
    default:
      throw new Error(`unsupported digest OID ${oid}`);
  }
}
async function digestBy(name: string, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(name, ab(data)));
}

interface ParsedTst {
  tstInfoBytes: Uint8Array; // the eContent OCTET STRING content (DER TSTInfo)
  signedAttrs: Der | null; // SignerInfo signedAttrs ([0] IMPLICIT), or null
  digestOid: string; // SignerInfo digestAlgorithm OID
  sigAlgOid: string; // SignerInfo signatureAlgorithm OID
  signature: Uint8Array; // SignerInfo signature (raw OCTET STRING content)
  certSet: Uint8Array | null; // SignedData.certificates ([0] IMPLICIT) content, for the EKU scan
}
/** Parse an RFC 3161 TimeStampToken (CMS SignedData ContentInfo) DER into the parts Pass 4 needs. */
function parseTimeStampToken(token: Uint8Array): ParsedTst {
  const ci = rd(token, 0); // ContentInfo SEQUENCE
  const ciCh = rdChildren(token, ci); // [ contentType OID, [0] EXPLICIT content ]
  if (oidHex(token, ciCh[0]) !== OID_SIGNED_DATA) throw new Error('TST: contentType is not id-signedData');
  const signedData = rdChildren(token, ciCh[1])[0]; // SignedData SEQUENCE
  const sd = rdChildren(token, signedData);
  // sd: [0]=version, [1]=digestAlgorithms SET, [2]=encapContentInfo, ([0] certs)?, ([1] crls)?, signerInfos SET
  const encap = sd[2];
  let certSet: Uint8Array | null = null;
  for (let k = 3; k < sd.length - 1; k++) {
    if (sd[k].tag === 0xa0) certSet = token.subarray(sd[k].cStart, sd[k].cEnd); // [0] IMPLICIT certificates
  }
  const signerInfos = sd[sd.length - 1]; // SET OF SignerInfo (last element)

  // encapContentInfo: SEQUENCE { eContentType OID, [0] EXPLICIT OCTET STRING }
  const encapCh = rdChildren(token, encap);
  if (oidHex(token, encapCh[0]) !== OID_TSTINFO) throw new Error('TST: eContentType is not id-ct-TSTInfo');
  const octet = rdChildren(token, encapCh[1])[0]; // OCTET STRING holding the TSTInfo DER
  const tstInfoBytes = token.subarray(octet.cStart, octet.cEnd);

  // signerInfos → first SignerInfo
  const si = rdChildren(token, rdChildren(token, signerInfos)[0]);
  // si: version, sid, digestAlgorithm, [signedAttrs 0xA0]?, signatureAlgorithm, signature, [unsignedAttrs]?
  const digestAlg = si[2];
  let j = 3;
  let signedAttrs: Der | null = null;
  if (si[j].tag === 0xa0) {
    signedAttrs = si[j];
    j++;
  }
  const sigAlg = si[j++];
  const signatureOct = si[j++];
  return {
    tstInfoBytes,
    signedAttrs,
    digestOid: oidHex(token, rdChildren(token, digestAlg)[0]),
    sigAlgOid: oidHex(token, rdChildren(token, sigAlg)[0]),
    signature: token.subarray(signatureOct.cStart, signatureOct.cEnd),
    certSet,
  };
}

interface ParsedTstInfo {
  hashedMessage: Uint8Array; // messageImprint.hashedMessage
  genTime: string; // ISO 8601, from the GeneralizedTime
}
function parseTstInfo(tstInfo: Uint8Array): ParsedTstInfo {
  const seq = rd(tstInfo, 0);
  const ch = rdChildren(tstInfo, seq);
  // version, policy, messageImprint SEQUENCE, serialNumber, genTime GeneralizedTime(0x18), ...
  const messageImprint = ch[2];
  const miCh = rdChildren(tstInfo, messageImprint); // [ hashAlgorithm SEQ, hashedMessage OCTET STRING ]
  const hashedMessage = tstInfo.subarray(miCh[1].cStart, miCh[1].cEnd);
  const gtDer = ch.find((c, i) => i >= 3 && c.tag === 0x18);
  if (!gtDer) throw new Error('TSTInfo: no genTime');
  const raw = new TextDecoder().decode(tstInfo.subarray(gtDer.cStart, gtDer.cEnd)); // e.g. 20260627123456Z or with frac
  const genTime = generalizedTimeToIso(raw);
  return { hashedMessage, genTime };
}
/** ASN.1 GeneralizedTime (YYYYMMDDHHMMSS[.fff]Z) → ISO 8601. */
function generalizedTimeToIso(g: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z?$/.exec(g);
  if (!m) return g; // surface verbatim if unexpected
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ''}Z`;
}

/** Curve-aware DER ECDSA signature (SEQUENCE{ INTEGER r, INTEGER s }) → raw r‖s, each left-padded to
 *  `size` bytes (P-256→32, P-384→48, P-521→66). Unlike `derToRawEcdsaSig` (P-256 short-form only),
 *  this handles long-form lengths and larger curves — required for ECDSA-SHA512 TSA signers. */
function ecdsaDerToRawSized(der: Uint8Array, size: number): Uint8Array {
  const seq = rd(der, 0);
  if (seq.tag !== 0x30) throw new Error('ECDSA sig: expected SEQUENCE');
  const [rInt, sInt] = rdChildren(der, seq);
  const pad = (d: Der): Uint8Array => {
    let bytes = der.subarray(d.cStart, d.cEnd);
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++; // strip DER sign-padding
    bytes = bytes.subarray(i);
    if (bytes.length > size) bytes = bytes.subarray(bytes.length - size);
    const out = new Uint8Array(size);
    out.set(bytes, size - bytes.length);
    return out;
  };
  return concatBytes(pad(rInt), pad(sInt));
}
const EC_COMPONENT_SIZE = { 'ec-P256': 32, 'ec-P384': 48, 'ec-P521': 66 } as const;

/** Determine the public-key kind from an SPKI (SubjectPublicKeyInfo) DER. */
function spkiKeyKind(spki: Uint8Array): 'rsa' | 'ec-P256' | 'ec-P384' | 'ec-P521' {
  const seq = rd(spki, 0);
  const algId = rdChildren(spki, seq)[0]; // AlgorithmIdentifier SEQUENCE
  const algCh = rdChildren(spki, algId);
  const algOid = oidHex(spki, algCh[0]);
  if (algOid === OID_RSA) return 'rsa';
  if (algOid === OID_EC_PUBKEY) {
    const curveOid = algCh[1] ? oidHex(spki, algCh[1]) : '';
    if (curveOid === OID_EC_P384) return 'ec-P384';
    if (curveOid === OID_EC_P521) return 'ec-P521';
    return 'ec-P256';
  }
  throw new Error(`SPKI: unsupported key algorithm OID ${algOid}`);
}
/** Verify `sig` over `data` against one pinned SPKI, choosing RSA(PKCS1/PSS) or ECDSA + hash. */
async function verifySigAgainstSpki(
  spkiB64: string,
  digestName: string,
  sigAlgOid: string,
  sig: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const spki = b64ToBytes(spkiB64);
  const kind = spkiKeyKind(spki);
  if (kind === 'rsa') {
    if (sigAlgOid === OID_RSASSA_PSS) {
      const key = await crypto.subtle.importKey('spki', ab(spki), { name: 'RSA-PSS', hash: digestName }, false, ['verify']);
      const saltLength = digestName === 'SHA-512' ? 64 : digestName === 'SHA-384' ? 48 : digestName === 'SHA-1' ? 20 : 32;
      return crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, key, ab(sig), ab(data));
    }
    const key = await crypto.subtle.importKey('spki', ab(spki), { name: 'RSASSA-PKCS1-v1_5', hash: digestName }, false, ['verify']);
    return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, ab(sig), ab(data));
  }
  const namedCurve = kind === 'ec-P384' ? 'P-384' : kind === 'ec-P521' ? 'P-521' : 'P-256';
  const key = await crypto.subtle.importKey('spki', ab(spki), { name: 'ECDSA', namedCurve }, false, ['verify']);
  const rawSig = ecdsaDerToRawSized(sig, EC_COMPONENT_SIZE[kind]);
  return crypto.subtle.verify({ name: 'ECDSA', hash: digestName }, key, ab(rawSig), ab(data));
}

/** Result of verifying one ANCHOR's RFC 3161 token. */
interface AnchorTokenResult {
  ok: boolean;
  genTime?: string;
  reason?: string;
}
/**
 * Verify an RFC 3161 token (base64) binds `merkleRootHex` and is signed by a pinned TSA SPKI.
 * Steps: parse CMS → assert messageImprint.hashedMessage == merkle_root (§8.1) → if signedAttrs
 * present, assert the `message-digest` attribute == digest(TSTInfo) and verify the signature over
 * DER(signedAttrs) with the tag re-set to SET-OF (0x31) (the CMS rule); else verify over TSTInfo —
 * against any pinned SPKI → assert the signer cert carries the id-kp-timeStamping EKU.
 */
async function verifyAnchorToken(
  tstB64: string,
  merkleRootHex: string,
  spkis: string[],
): Promise<AnchorTokenResult> {
  let p: ParsedTst;
  let info: ParsedTstInfo;
  try {
    const token = b64ToBytes(tstB64);
    p = parseTimeStampToken(token);
    info = parseTstInfo(p.tstInfoBytes);
  } catch (e) {
    return { ok: false, reason: `malformed RFC 3161 token: ${(e as Error).message}` };
  }

  // (§8.1 / §2.2) messageImprint binding — the timestamped digest IS the root, not a re-hash.
  if (bytesToHex(info.hashedMessage) !== merkleRootHex.toLowerCase()) {
    return { ok: false, reason: `token messageImprint ${bytesToHex(info.hashedMessage).slice(0, 16)}… != ANCHOR merkle_root ${merkleRootHex.slice(0, 16)}…` };
  }

  let digestName: string;
  try {
    digestName = digestNameForOid(p.digestOid);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }

  // (§2.1) Determine the signed bytes. Real TSA tokens sign the DER signedAttributes (re-tagged to
  // SET OF for the signature), with a message-digest attribute == digest(TSTInfo).
  let signedBytes: Uint8Array;
  if (p.signedAttrs) {
    const token = b64ToBytes(tstB64);
    const attrs = rdChildren(token, p.signedAttrs); // each is an Attribute SEQUENCE
    let mdAttr: Uint8Array | null = null;
    for (const a of attrs) {
      const ac = rdChildren(token, a); // [ attrType OID, attrValues SET ]
      if (oidHex(token, ac[0]) === OID_MESSAGE_DIGEST_ATTR) {
        const val = rdChildren(token, ac[1])[0]; // OCTET STRING
        mdAttr = token.subarray(val.cStart, val.cEnd);
      }
    }
    if (!mdAttr) return { ok: false, reason: 'signedAttributes missing message-digest attribute' };
    const tstDigest = await digestBy(digestName, p.tstInfoBytes);
    if (!bytesEqual(mdAttr, tstDigest)) {
      return { ok: false, reason: 'message-digest attribute != digest(TSTInfo) (token does not cover its own content)' };
    }
    // Re-tag the [0] IMPLICIT signedAttrs to SET OF (0x31) for the signature computation (CMS).
    signedBytes = token.subarray(p.signedAttrs.start, p.signedAttrs.cEnd).slice();
    signedBytes[0] = 0x31;
  } else {
    signedBytes = p.tstInfoBytes; // no signed attributes: signature is directly over TSTInfo
  }

  // (§2.3) EKU — the signer certificate must carry id-kp-timeStamping (RFC 3161 §2.3). Scan ONLY the
  // embedded certificate set for the EKU OID (it lives inside an ExtendedKeyUsage extension). We do not
  // fall back to scanning the whole token: with no embedded cert there is nothing whose EKU we can
  // confirm, and scanning the full DER could false-positive on unrelated bytes. (Phase-2 hardening:
  // bind the EKU to the specific signer cert that produced the verifying signature, not the whole set.)
  if (!p.certSet) {
    return { ok: false, reason: 'token embeds no signer certificate (certReq) — cannot confirm the id-kp-timeStamping EKU' };
  }
  if (indexOfSeq(p.certSet, EKU_TIMESTAMPING_TLV) < 0) {
    return { ok: false, reason: 'signer certificate does not carry the id-kp-timeStamping EKU' };
  }

  // Signature must verify against at least one pinned TSA SPKI (the resolved trust anchor).
  for (const spki of spkis) {
    try {
      if (await verifySigAgainstSpki(spki, digestName, p.sigAlgOid, p.signature, signedBytes)) {
        return { ok: true, genTime: info.genTime };
      }
    } catch {
      // wrong key kind / unparseable SPKI for this entry — try the next pinned cert
    }
  }
  return { ok: false, reason: 'token signature does not verify against any pinned TSA certificate (anchorTrust)' };
}

/**
 * `val.checkpoint-merkle.v1` (spec §8.1) — a byte-faithful port of the RIGA producer's
 * `computeMerkleRootFromRows`: leaf = SHA-256(UTF-8(`${sequence_number}|${chain_hash}`)), blocks in
 * ascending sequence order, inner node = SHA-256(left32 ‖ right32), an odd final node promoted
 * unchanged. Returns lowercase hex. Locked against the producer by the shared parity vector
 * (`scripts/fixtures/tsa-merkle-parity-vectors.json` in rigacn; `test/fixtures/` here). Exported so
 * `anchor.test.mjs` can assert parity. NOT the §6.4 membership Merkle (sorted content-hash set).
 */
export async function computeCheckpointMerkleRoot(
  rows: Array<{ seq: number | bigint; hash: string }>,
): Promise<string> {
  if (rows.length === 0) throw new Error('computeCheckpointMerkleRoot: empty input');
  let level: Uint8Array[] = await Promise.all(rows.map((r) => sha256(utf8(`${r.seq.toString()}|${r.hash}`))));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) next.push(await sha256(concatBytes(level[i], level[i + 1])));
      else next.push(level[i]);
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

/** Result of verifying one ANCHOR block (Merkle root + token). */
interface AnchorBlockResult {
  ok: boolean;
  genTime?: string;
  coveredRange?: { from_sequence: number; to_sequence: number };
  reason?: string;
}
/** Pass 4 for a single ANCHOR block: recompute its checkpoint root over the in-band covered range,
 *  then verify its RFC 3161 token (root binding + signature + EKU). */
async function verifyAnchorBlock(block: ValBlock, rows: ChainRow[], spkis: string[]): Promise<AnchorBlockResult> {
  const root = block.merkle_root;
  const cr = block.covered_range;
  const tst = block.tst;
  if (!root || !tst || !cr || typeof cr.from_sequence !== 'number' || typeof cr.to_sequence !== 'number') {
    return { ok: false, reason: 'ANCHOR block missing merkle_root / covered_range / tst' };
  }
  if (block.merkle_alg && block.merkle_alg !== 'val.checkpoint-merkle.v1') {
    return { ok: false, reason: `unsupported merkle_alg '${block.merkle_alg}'` };
  }
  const covered = rows
    .filter((r) => {
      const s = Number(r.sequence_number);
      return s >= cr.from_sequence! && s <= cr.to_sequence!;
    })
    .sort((a, b) => Number(a.sequence_number) - Number(b.sequence_number));
  if (covered.length === 0) {
    return { ok: false, reason: `no in-band blocks in covered_range [${cr.from_sequence}-${cr.to_sequence}]` };
  }
  const recomputed = await computeCheckpointMerkleRoot(covered.map((r) => ({ seq: r.sequence_number, hash: r.chain_hash })));
  if (recomputed !== root.toLowerCase()) {
    return { ok: false, reason: `recomputed checkpoint root ${recomputed.slice(0, 16)}… != ANCHOR merkle_root ${root.slice(0, 16)}…` };
  }
  const tv = await verifyAnchorToken(tst, root, spkis);
  if (!tv.ok) return { ok: false, reason: tv.reason };
  return { ok: true, genTime: tv.genTime, coveredRange: { from_sequence: cr.from_sequence, to_sequence: cr.to_sequence } };
}

/** One row of a chain, in the shape required for verification. */
export interface ChainRow {
  /**
   * The discrete scope key for this row's chain (VAL §4). It is the
   * identifier that partitions one append-only chain from another; a
   * per-scope chain has its own genesis and its own monotonic
   * `sequence_number`. The exact value form is operator-defined per §4.
   */
  scope_key: string;
  sequence_number: number | bigint;
  /**
   * Event name — the per-store column carrying the action/event label that
   * the preimage commits over (VAL §4).
   */
  event_type: string;
  /**
   * RFC 8785 canonical JSON serialization of the event's details payload.
   * MUST be the byte string the trigger computed the hash over — pulled
   * from the `canonical_details` column, NOT recomputed from `details`.
   */
  canonical_details: string;
  previous_hash: string | null;
  chain_hash: string;
}

/**
 * Reconstruct the canonical preimage and SHA-256 it. Returns the
 * lowercase hex string the substrate would have stored in `chain_hash`.
 * Per the VAL wire format (spec §4):
 *
 *   preimage = UTF-8(
 *     scope_key || '|' ||
 *     sequence_number::text || '|' ||
 *     event_type || '|' ||
 *     canonical_details || '|' ||
 *     COALESCE(previous_hash, 'GENESIS')
 *   )
 */
export async function reconstructChainHash(args: {
  scopeKey: string;
  sequenceNumber: number | bigint;
  eventType: string;
  canonicalDetails: string;
  previousHash: string | null;
}): Promise<string> {
  const prevComponent = args.previousHash ?? 'GENESIS';
  const preimage =
    args.scopeKey +
    '|' +
    args.sequenceNumber.toString() +
    '|' +
    args.eventType +
    '|' +
    args.canonicalDetails +
    '|' +
    prevComponent;
  return bytesToHex(await sha256(utf8(preimage)));
}

/**
 * Compute the Merkle root over a membership SET of resource content-hashes
 * (VAL §6.4 `isolation_commitment`). Distinct + lexicographically sorted
 * (bytewise — JS default sort matches PG `COLLATE "C"` on ASCII-hex hashes);
 * leaf = sha256(utf8(content_hash)); pairs concatenated raw-binary; odd-out
 * promotes unchanged. Returns hex of root, or `null` for an empty set.
 *
 * Used by the VAL scope pass to re-derive a committed isolation root from a
 * per-action membership proof's leaves. Producers MUST compute the committed
 * root with byte-identical leaf / concat / sort rules (VAL §6.4) for this
 * re-derivation to match.
 */
export async function computeMembershipRoot(contentHashes: string[]): Promise<string | null> {
  const set = Array.from(new Set(contentHashes.filter((h) => h != null)));
  set.sort(); // bytewise on ASCII-hex; matches PG ORDER BY ... COLLATE "C"
  if (set.length === 0) return null;
  let level: Uint8Array[] = await Promise.all(set.map((h) => sha256(utf8(h))));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(await sha256(concatBytes(level[i], level[i + 1])));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

/** One step of a VAL §6.4 Merkle inclusion proof (sibling node hash + its side). */
export interface MembershipProofStep {
  hash: string; // hex of the sibling NODE hash
  side: 'L' | 'R'; // sibling left of current => sha256(sib||cur); right => sha256(cur||sib)
}

/**
 * Verify a VAL §6.4 membership inclusion proof: recompute the committed root from
 * `(content_hash + proof)` leaf->root and compare to `expectedRoot`. Returns true iff
 * the resource was a committed member of the assignment's permitted set. The scope pass
 * calls this; a false result is the cryptographic isolation refusal.
 *
 * MUST match the producer's membership-proof construction byte-for-byte (VAL §6.4).
 */
export async function verifyMembershipProof(
  contentHash: string,
  proof: MembershipProofStep[],
  expectedRoot: string,
): Promise<boolean> {
  let cur: Uint8Array = await sha256(utf8(contentHash));
  for (const step of proof) {
    const sib = hexToBytes(step.hash);
    cur =
      step.side === 'L'
        ? await sha256(concatBytes(sib, cur))
        : await sha256(concatBytes(cur, sib));
  }
  return bytesToHex(cur) === expectedRoot;
}

/** Result of verifying a contiguous slice of a chain. */
export interface VerificationResult {
  ok: boolean;
  /** Zero-based index of the first row that failed verification, or null on success. */
  firstBadIndex: number | null;
  /** Human-readable reason for the failure, or null on success. */
  reason: string | null;
}

/**
 * Verify a contiguous slice of a single scope's chain. Input MUST be:
 *   - All rows belong to the same scope (same `scope_key`).
 *   - Sorted ascending by `sequence_number`.
 *   - Contiguous: sequence_numbers form an arithmetic progression with step 1.
 *
 * For each row, asserts:
 *   1. Genesis row (sequence_number === 1) has previous_hash === null.
 *   2. Non-genesis row's previous_hash equals the prior row's chain_hash.
 *   3. Row's chain_hash equals the SHA-256 of its reconstructed preimage.
 *
 * Returns the first failure encountered; does not continue past it.
 *
 * Note on partial-chain verification: a slice that does not include the
 * genesis row CAN still be verified by checking the previous_hash linkage
 * (step 2) and per-row preimage (step 3); only step 1 is skipped. The
 * caller must ensure the slice starts at a known-anchored row (e.g., a
 * TSA-anchored sequence_number per the external-anchor spec §8) or
 * chains back to a row they have already trusted.
 */
export async function verifyChain(rows: ChainRow[]): Promise<VerificationResult> {
  if (rows.length === 0) {
    return { ok: true, firstBadIndex: null, reason: null };
  }

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];

    // Cross-row scope consistency (defensive — caller should partition).
    if (i > 0 && rows[i].scope_key !== rows[0].scope_key) {
      return {
        ok: false,
        firstBadIndex: i,
        reason: `scope_key mismatch within slice: '${rows[0].scope_key}' vs '${rows[i].scope_key}'`,
      };
    }

    // Cross-row sequence contiguity.
    if (i > 0) {
      const prev = rows[i - 1];
      const prevSeq = BigInt(prev.sequence_number);
      const thisSeq = BigInt(row.sequence_number);
      if (thisSeq !== prevSeq + 1n) {
        return {
          ok: false,
          firstBadIndex: i,
          reason: `sequence_number gap at index ${i}: prior=${prevSeq.toString()}, this=${thisSeq.toString()}`,
        };
      }
    }

    // Step 1: genesis row.
    const seq = BigInt(row.sequence_number);
    if (seq === 1n && row.previous_hash !== null) {
      return {
        ok: false,
        firstBadIndex: i,
        reason: 'genesis row (sequence_number=1) must have previous_hash=null',
      };
    }

    // Step 2: chain linkage (skip for genesis or for slice-start without prior).
    if (i > 0) {
      if (row.previous_hash !== rows[i - 1].chain_hash) {
        return {
          ok: false,
          firstBadIndex: i,
          reason: `previous_hash linkage broken at index ${i}: row says '${row.previous_hash}', prior chain_hash is '${rows[i - 1].chain_hash}'`,
        };
      }
    }

    // Step 3: preimage reconstruction + SHA-256 match.
    const expected = await reconstructChainHash({
      scopeKey: row.scope_key,
      sequenceNumber: row.sequence_number,
      eventType: row.event_type,
      canonicalDetails: row.canonical_details,
      previousHash: row.previous_hash,
    });
    if (expected !== row.chain_hash) {
      return {
        ok: false,
        firstBadIndex: i,
        reason: `chain_hash mismatch at index ${i}: expected '${expected}', got '${row.chain_hash}'`,
      };
    }
  }

  return { ok: true, firstBadIndex: null, reason: null };
}

// ─────────────────────────────────────────────────────────────────────────────
// VAL passes 2 (lineage) + 3 (scope) + 5 (delegator authority). See spec/07-offline-verifier.md.
// These consume the SAME ChainRow[] as verifyChain, parsing each row's
// canonical_details as a VAL block body (the shape conforming producers emit; §4).
// Rows whose canonical_details carry no `block_type` are non-VAL events (pre-VAL
// or operator-private) and are skipped by passes 2/3/5.
// ─────────────────────────────────────────────────────────────────────────────

/** VAL scope predicate (§6.2). Only the fields the verifier evaluates are typed. */
export interface ScopePredicate {
  subj?: { principal_uri?: string };
  act?: string[];
  res?: {
    resource_type?: string;
    ids?: string[];
    id_glob?: string | null;
    in_workspace?: string | null;
    isolation?: string | null;
    isolation_commitment?: string | null;
  };
  // VAL §6.2/§6.6 temporal window (unix ms). Checked in `satisfies` against the block's
  // `timestamp_local` — the same field the operator's PG trigger enforces preventively.
  win?: { not_before?: number; not_after?: number };
  // VAL §6.2/§6.6 quantitative limits. The §6.6 aggregate over a grant's descendants is the verifier's
  // job (detective) — `max_count` is checked in verifyValChain (cross-block). `max_value`/
  // `max_value_currency` aggregate over SETTLEMENT descendants (operator-deployment-specific).
  lim?: { max_count?: number; max_value?: number; max_value_currency?: string };
}

/** Identity-assurance basis of a self-attested signing key (§5.2). `source` widens with the
 *  profile ladder: `self_asserted`/`kyb_attested` (Profile A/B claim basis) → `eidas_eaa`/`qes`
 *  (Profile C, qualified). The verifier surfaces it verbatim; it never rounds a claim up. */
export interface ValIdentityAssurance {
  source: string;
  subject_claim: string;
}

/** Hardware binding of an enrolled key, bound into the org-root self-attestation so it is
 *  tamper-evident. `device_bound` = verified-attestation single secure element; `syncable` =
 *  verified but account-bound / multi-device (weaker hardware assurance); `unattested` = the
 *  producer obtained no verified hardware attestation at enrollment — the signature still
 *  verifies, but the key's hardware provenance is the client's claim (a software authenticator
 *  is possible). Surfaced verbatim — never rounded up. */
export type ValKeyBinding = 'device_bound' | 'syncable' | 'unattested';

/** A Profile B/C delegator signature carried in `delegator_authority.signature` (and in the
 *  org-root `self_signature`). `alg` selects the verification + profile: `webauthn` → Profile B
 *  (device assertion, verified here); a qualified alg (`qes`/`eidas_qes`/`eidas_eaa`) → Profile C
 *  (qualified e-signature, verified against a QTSP trust list — a future trust-anchor input,
 *  classified here so C requires no shape change). Base64 fields accept base64 or base64url. */
export interface ValDelegatorSignature {
  alg: string;
  public_key: string; // SPKI base64 (the key that signed)
  signature: string; // base64
  client_data_json: string; // base64 (WebAuthn clientDataJSON)
  authenticator_data: string; // base64 (WebAuthn authenticatorData)
  credential_id?: string;
}

/** The enrolled org-root self-attestation embedded in a Profile B/C grant so the verifier can
 *  chain `signature.public_key → this enrolled key → self-attested {org, identity, key_binding}`
 *  entirely from chain bytes. The self_signature signs `orgRootBindingChallenge(...)`, which is
 *  re-derivable from these fields — so relabeling `key_binding` or `identity_assurance` breaks it. */
export interface ValOrgRootAttestation {
  org_id: string;
  signatory_identity_hash: string;
  public_key: string; // SPKI base64 — the enrolled org-root key
  identity_assurance: ValIdentityAssurance;
  key_binding: ValKeyBinding;
  self_signature: ValDelegatorSignature;
}

/** The PERSONAL-scope twin of {@link ValOrgRootAttestation} (§5.2, spec change 0.11.0) —
 *  a natural person's org-free CONSENT key self-attesting
 *  {subject-hash, key, assurance, key_binding}. No org_id: a §4.3 CONSENT is a personal
 *  act, so no organization appears in the signed statement. The self_signature signs
 *  `personalBindingChallenge(...)`, re-derivable from these fields — relabeling
 *  `key_binding` or `identity_assurance` breaks it. */
export interface ValPersonalAttestation {
  signatory_identity_hash: string;
  public_key: string; // SPKI base64 — the enrolled personal key
  identity_assurance: ValIdentityAssurance;
  key_binding: ValKeyBinding;
  self_signature: ValDelegatorSignature;
}

/**
 * Delegator-authority carrier on an ASSIGNMENT's human_attestation (§5.2 / Pass 5).
 * Records the authority basis under which the attesting human could grant the delegated
 * scope. `signature` is the Profile B/C binding slot — absent under Profile A (operator-
 * attested residual trust); present + verified under B (device assertion) / C (qualified).
 * `org_root` carries the self-attestation the signature chains to (Profile B/C linkage).
 */
export interface ValBlockDelegatorAuthority {
  basis?: string;
  capability?: string;
  scope_ref?: string;
  signature?: ValDelegatorSignature;
  org_root?: ValOrgRootAttestation;
  /** Reserved basis `ceremony_session_delegated` (§7.2, 2026-07-01): the operator principal who
   *  attested the delegator's entitlement (sha256 of their operator-namespaced id). Tamper-evident
   *  attestation, NOT offline-provable entitlement — surfaced verbatim in `authorityCarriers`. */
  attested_by?: string | null;
  /** Reserved basis `ceremony_session_delegated`: opaque reference to the single-use ceremony
   *  session that carried the attestation. */
  session_ref?: string | null;
}

// ── Profile B/C signature verification (offline, chain-bytes only) ─────────────
// Ported from the producer's reference signing path. Zero new deps (Node `crypto`).
// What is checked OFFLINE here:
//   - The org-root self-attestation: its self_signature signs a challenge re-derived
//     from {org_id, signatory_identity_hash, public_key, identity_assurance, key_binding}
//     (orgRootBindingChallenge) — fully chain-derivable, so the device_bound/syncable
//     binding + self_asserted subject are tamper-evident.
//   - The delegation signature is a cryptographically valid WebAuthn assertion whose key
//     EQUALS the enrolled org-root key (the grant was signed by the org root).
// NOT checked here (documented limitation): that the delegation challenge binds to a
// specific grant payload — that requires the operator's grant-payload canonicalization as
// a trust-anchor input (like the §7.1(d) policy / QTSP list), a future strengthening. The
// device-bound/syncable org-root verdict does NOT depend on it.

function normB64Url(s: string): string {
  return s.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
/** Normalize a key to compare regardless of base64/base64url encoding. */
function normKey(spkiB64: string): string {
  return bytesToB64url(b64ToBytes(spkiB64));
}

/** Minimal RFC 8785 (JCS) canonical JSON: keys sorted by UTF-16 code unit (JS default
 *  sort, = JCS §3.2.3), leaf primitives via JSON.stringify. Matches the producer's
 *  canonicalJsonStringify for the identifier/string/bool/null vocabulary used here. */
function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(obj[k])).join(',') + '}';
}

/** The challenge the org-root self-attestation signs — re-derivable by any verifier from
 *  the attestation fields (so key_binding / identity cannot be relabeled without breaking it). */
export async function orgRootBindingChallenge(o: ValOrgRootAttestation): Promise<string> {
  return bytesToB64url(
    await sha256(
      utf8(
        jcs({
          identity_assurance: {
            source: o.identity_assurance.source,
            subject_claim: o.identity_assurance.subject_claim,
          },
          key_binding: o.key_binding,
          org_id: o.org_id,
          public_key: o.public_key,
          signatory_identity_hash: o.signatory_identity_hash,
        }),
      ),
    ),
  );
}

/** The challenge a PERSONAL self-attestation signs (§5.2, 0.11.0) — the org-free twin of
 *  {@link orgRootBindingChallenge}: identical construction minus `org_id`. Re-derivable by
 *  any verifier from the attestation fields, so `key_binding` / the self-declared subject
 *  cannot be relabeled without breaking the self-signature. */
export async function personalBindingChallenge(p: ValPersonalAttestation): Promise<string> {
  return bytesToB64url(
    await sha256(
      utf8(
        jcs({
          identity_assurance: {
            source: p.identity_assurance.source,
            subject_claim: p.identity_assurance.subject_claim,
          },
          key_binding: p.key_binding,
          public_key: p.public_key,
          signatory_identity_hash: p.signatory_identity_hash,
        }),
      ),
    ),
  );
}

/** Verify a PERSONAL self-attestation offline: the attestation must be SELF-signed (the
 *  attesting key IS the attested key) over its own re-derived binding challenge. Returns
 *  the honest verdict — never rounds `key_binding` or the assurance source up. Consumers
 *  cross-check `attestation.public_key` against a CONSENT block's embedded signature key
 *  to attribute the bond to the attested subject (a claim RIGA witnessed, never vouched). */
export async function verifyPersonalAttestation(
  attestation: ValPersonalAttestation,
): Promise<{ valid: boolean; reason: string }> {
  if (!attestation?.identity_assurance) {
    return { valid: false, reason: 'personal attestation carries no identity_assurance' };
  }
  if (
    attestation.key_binding !== 'device_bound' &&
    attestation.key_binding !== 'syncable' &&
    attestation.key_binding !== 'unattested'
  ) {
    return { valid: false, reason: 'personal attestation carries no/invalid key_binding' };
  }
  if (attestation.self_signature?.alg !== 'webauthn') {
    return { valid: false, reason: 'personal attestation requires a WebAuthn self-signature' };
  }
  if (normKey(attestation.self_signature.public_key) !== normKey(attestation.public_key)) {
    return { valid: false, reason: 'personal attestation is not self-signed (attesting key != attested key)' };
  }
  const check = await verifyDelegatorSignature(
    attestation.self_signature,
    await personalBindingChallenge(attestation),
  );
  return check.valid
    ? { valid: true, reason: 'personal self-attestation valid (self-signed binding challenge)' }
    : { valid: false, reason: `personal self-attestation invalid: ${check.reason}` };
}

/** Verify a WebAuthn (ES256) delegator assertion against its embedded public key. When
 *  `expectedChallengeB64Url` is given, also require clientDataJSON.challenge to match it. */
export async function verifyDelegatorSignature(
  sig: ValDelegatorSignature,
  expectedChallengeB64Url?: string,
): Promise<{ valid: boolean; reason: string }> {
  try {
    if (!sig || sig.alg !== 'webauthn') return { valid: false, reason: `unsupported alg: ${sig?.alg}` };
    const clientDataJson = b64ToBytes(sig.client_data_json);
    let clientData: { type?: string; challenge?: string };
    try {
      clientData = JSON.parse(new TextDecoder().decode(clientDataJson));
    } catch {
      return { valid: false, reason: 'clientDataJSON not parseable' };
    }
    if (clientData.type !== 'webauthn.get') return { valid: false, reason: `clientData.type=${clientData.type}` };
    if (expectedChallengeB64Url !== undefined) {
      if (!clientData.challenge || normB64Url(clientData.challenge) !== normB64Url(expectedChallengeB64Url)) {
        return { valid: false, reason: 'challenge mismatch (signature is for a different statement)' };
      }
    }
    // WebAuthn signed bytes = authenticatorData || SHA-256(clientDataJSON); the ECDSA-P256
    // signature is over SHA-256(signedBytes). Web Crypto's verify hashes signedBytes itself
    // (hash:'SHA-256'), so we pass signedBytes — and convert the DER signature to raw r‖s.
    const authData = b64ToBytes(sig.authenticator_data);
    const cdjHash = await sha256(clientDataJson);
    const signedBytes = concatBytes(authData, cdjHash);
    const pubKey = await crypto.subtle.importKey(
      'spki',
      ab(b64ToBytes(sig.public_key)),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const rawSig = derToRawEcdsaSig(b64ToBytes(sig.signature));
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, ab(rawSig), ab(signedBytes));
    return ok
      ? { valid: true, reason: 'signature valid against embedded public key' }
      : { valid: false, reason: 'signature does not verify against embedded public key' };
  } catch (e) {
    return { valid: false, reason: `verify error: ${(e as Error).message}` };
  }
}

/** Map a signature's `alg` to its conformance profile (§5.2). Data-driven so Profile C
 *  (qualified e-signatures) is classified without a code change — only its QTSP-anchored
 *  crypto verification is a future addition. */
const QUALIFIED_ALGS = new Set(['qes', 'eidas_qes', 'eidas_eaa']);

/**
 * ADR 0063 — a resolved QES validation verdict consumed by the core (produced caller-side by
 * `@val-protocol/qes-validator`). Structural shape only — the core does NOT depend on that package.
 */
export interface QesVerdict {
  /** True iff the qualified signature validated to ETSI/eIDAS (the only field treated as the gate). */
  qualified: boolean;
  /** Proven natural-person identity (eIDAS minimum dataset), present iff `qualified`. */
  signerIdentity?: {
    given_name?: string;
    family_name?: string;
    date_of_birth?: string | null;
    persistent_id?: string | null;
    country?: string | null;
  } | null;
  /** Opaque reference to the full reproducible validation report. */
  reportRef?: string | null;
  /** Per-signature key (ADR 0063 item 5) = sha256-hex of the delegation `signature.signature` bytes,
   *  as `@val-protocol/qes-validator` emits. When present, the verifier matches THIS report to THIS
   *  signature (not "first qualified report"), so distinct qualified delegations cannot borrow each
   *  other's verdict on a multi-grant / mixed-profile chain. Absent ⇒ legacy unkeyed (single-grant). */
  signatureRef?: string | null;
}

export type TrustChainOutcome =
  | 'authority_verified_org_root_device_bound'
  | 'authority_verified_org_root_syncable'
  | 'authority_verified_org_root_unattested'
  | 'authority_verified_qualified'
  | 'signature_valid_only'
  | 'qualified_unverified'
  | 'invalid';

/** Verify a Profile B/C delegation: the signature is a valid assertion by the enrolled,
 *  self-attested org-root key. Returns the honest outcome (device_bound vs syncable, or
 *  signature_valid_only when the org-root linkage is absent/broken). */
export async function verifyDelegationTrustChain(
  delegationSig: ValDelegatorSignature,
  orgRoot?: ValOrgRootAttestation | null,
  qesVerdict?: QesVerdict | null,
): Promise<{
  signatureValid: boolean;
  linkageVerified: boolean;
  outcome: TrustChainOutcome;
  keyBinding: ValKeyBinding | null;
  subjectAssurance: ValIdentityAssurance | null;
  reason: string;
}> {
  const base = { keyBinding: null as ValKeyBinding | null, subjectAssurance: null as ValIdentityAssurance | null };
  // Profile C (qualified). The qualified signature's ETSI/eIDAS validation is NOT done in this zero-dep
  // core — it is produced caller-side by @val-protocol/qes-validator and supplied as a resolved verdict
  // (ADR 0063), exactly like Pass 4's anchorTrust. With a `qualified: true` verdict ⇒ Profile C VERIFIED;
  // without one ⇒ `qualified_unverified` (classified, never silently upgraded).
  if (QUALIFIED_ALGS.has(delegationSig?.alg)) {
    if (qesVerdict?.qualified === true) {
      return { ...base, signatureValid: true, linkageVerified: true, outcome: 'authority_verified_qualified', reason: `qualified alg '${delegationSig.alg}' verified by qes-validator${qesVerdict.reportRef ? ` (report ${qesVerdict.reportRef})` : ''}` };
    }
    return { ...base, signatureValid: false, linkageVerified: false, outcome: 'qualified_unverified', reason: `qualified alg '${delegationSig.alg}' requires a QES validation verdict (qesValidation not supplied) — Profile C classified, not verified` };
  }
  const sigCheck = await verifyDelegatorSignature(delegationSig);
  if (!sigCheck.valid) {
    return { ...base, signatureValid: false, linkageVerified: false, outcome: 'invalid', reason: `delegation signature invalid: ${sigCheck.reason}` };
  }
  const notLinked = (reason: string) => ({ ...base, signatureValid: true, linkageVerified: false, outcome: 'signature_valid_only' as const, reason });
  if (!orgRoot) return notLinked('signature valid; no org-root attestation embedded');
  if (
    !orgRoot.identity_assurance ||
    (orgRoot.key_binding !== 'device_bound' &&
      orgRoot.key_binding !== 'syncable' &&
      orgRoot.key_binding !== 'unattested')
  ) {
    return notLinked('org-root attestation missing identity_assurance / key_binding');
  }
  const selfCheck = await verifyDelegatorSignature(orgRoot.self_signature, await orgRootBindingChallenge(orgRoot));
  if (!selfCheck.valid) return notLinked(`org-root self-attestation invalid: ${selfCheck.reason}`);
  if (normKey(orgRoot.self_signature.public_key) !== normKey(orgRoot.public_key)) {
    return notLinked('org-root attestation is not self-signed (attesting key != attested key)');
  }
  if (normKey(delegationSig.public_key) !== normKey(orgRoot.public_key)) {
    return notLinked('delegation signed by a key that is not the enrolled org-root key');
  }
  const binding = orgRoot.key_binding;
  const bindingReason =
    binding === 'device_bound'
      ? 'device-bound (verified attestation)'
      : binding === 'syncable'
        ? 'syncable — weaker hardware assurance'
        : 'unattested — hardware provenance claimed, not proven';
  return {
    signatureValid: true,
    linkageVerified: true,
    outcome:
      binding === 'device_bound'
        ? 'authority_verified_org_root_device_bound'
        : binding === 'syncable'
          ? 'authority_verified_org_root_syncable'
          : 'authority_verified_org_root_unattested',
    keyBinding: binding,
    subjectAssurance: { source: orgRoot.identity_assurance.source, subject_claim: orgRoot.identity_assurance.subject_claim },
    reason: `delegation key chains to the enrolled, self-attested org-root key (${bindingReason}); subject "${orgRoot.identity_assurance.subject_claim}" is ${orgRoot.identity_assurance.source}`,
  };
}

/**
 * Capability → permitted-delegable-action policy, supplied to the verifier as a
 * trust-anchor input (§7.1(d)) — obtained and pinned by the verifying party
 * independently of the chain bytes, like the QTSP trust list. Operator-namespaced
 * capability identifiers map to the action names a holder may delegate. Without it,
 * Pass 5 still enforces carrier PRESENCE on v2 ASSIGNMENT bodies but cannot evaluate
 * scope ⊆ authority.
 */
export type DelegatorAuthorityPolicy = Record<string, string[]>;

/** A VAL block body, as carried in a ChainRow's canonical_details JSON. */
export interface ValBlock {
  v?: number;
  block_type?: 'ASSIGNMENT' | 'ACCESS' | 'MUTATION' | 'CONSENT' | 'COMMUNICATION' | 'SETTLEMENT' | 'ANCHOR';
  // ASSIGNMENT:
  // Agent-equity carrier (v3 ASSIGNMENT): the principal this grant authorizes
  // (`agent:<sa>` | `user:<id>`). Every action block rooting here must carry `principal == grantee`.
  grantee?: string;
  scope?: ScopePredicate;
  human_attestation?: {
    method?: string;
    subject_user_hash?: string;
    delegator_authority?: ValBlockDelegatorAuthority;
    // 0.6.0: the root human's DECLARED name carried on the attestation (same {source, subject_claim}
    // shape as the org_root path). Hash-bound in canonical_details since the producer added it; the
    // verifier now SURFACES it as result.rootSubject. `source` stays 'self_asserted' at the floor —
    // a device signature proves key-control, not name-truth.
    identity_assurance?: { source?: string; subject_claim?: string } | null;
  } | null;
  parent_assignment_hash?: string | null;
  // action blocks:
  action?: string;
  principal?: string;
  // VAL §6.6/§8 timestamp_local — operator-supplied unix ms (an operator convention; the spec leaves the unit unspecified), carried ON the block. The §6.6 win check
  // compares it to scope.win.{not_before,not_after}; the operator's PG trigger reads this same field.
  timestamp_local?: number;
  resource?: { content_hash?: string; resource_id?: string; in_workspace?: string };
  membership_proof?: MembershipProofStep[];
  // §7.5 grounding: content-hashes this MUTATION asserts it derived from. The verifier checks each
  // was read via a prior ACCESS by the same principal in this chain (read-before-derive).
  grounded_document_hashes?: string[] | null;
  // §4.4 + ADR 0061: optional hiding bytes-commitment over the document's bytes (Pass 6). Opt-in;
  // re-derived only at evidence time from a disclosed { bytes, nonce }. `value` is 64-char hex.
  bytes_commitment?: { alg?: string; value?: string } | null;
  // §4.3 CONSENT (sign-class): the single signed-artifact hash bound directly by the bond, and the
  // per-action human signature over it (§5.2). The verifier checks the signature's challenge equals
  // the hash of {document_hash, parent_assignment_hash, principal} — so it provably binds the artifact.
  document_hash?: string;
  signature?: ValDelegatorSignature;
  // §8 ANCHOR (operational checkpoint, Pass 4): the checkpoint Merkle root, its construction id
  // (`val.checkpoint-merkle.v1`), the inclusive covered block range, and the in-band base64 RFC 3161
  // TimeStampToken over the root. No `parent_assignment_hash`, no principal (§5.1 exempt).
  merkle_root?: string;
  merkle_alg?: string;
  covered_range?: { from_sequence?: number; to_sequence?: number };
  tst?: string;
}

export interface ValVerificationResult {
  integrity: 'green' | 'red';
  lineage: 'green' | 'red';
  scope: 'green' | 'red';
  /** Property #4 (grounding) re-derived from chain bytes — independent of substrate enforcement. */
  grounding: 'green' | 'red';
  /**
   * Pass 5 (delegator authority, §7.2): every v2 ASSIGNMENT body must carry
   * `human_attestation.delegator_authority`; with a policy supplied (§7.1(d)), the
   * delegated scope.act must be ⊆ the delegator capability's delegable actions.
   * `none` = no ASSIGNMENT in the verified slice engaged the pass.
   */
  authority: 'green' | 'red' | 'none';
  /**
   * Profile B/C signature pass (§5.2): a present `delegator_authority.signature` is a valid
   * device/qualified assertion chaining to the enrolled, self-attested org-root key.
   * `none` = no ASSIGNMENT carried a signature (Profile A); `green` = all present signatures
   * verified + linked; `red` = a present signature failed to verify or link.
   */
  signature: 'green' | 'red' | 'none';
  /** The verified hardware binding of the org-root key (when a Profile-B linkage held).
   *  Surfaced verbatim — `syncable` is never reported as `device_bound`. */
  keyBinding: ValKeyBinding | null;
  /**
   * Conformance profile read from the chain's ASSIGNMENTs (§5.2): the FLOOR — the weakest of
   * A/B/C present. 0.10.0 BEHAVIOR CHANGE (spec amendment 2026-07-01): earlier releases reported
   * the strongest profile present, which let one qualified grant mask a chain of operator-attested
   * ones — the exact over-claim the `rootSubject.source` verbatim rule exists to prevent. A
   * consumer reads `profilesPresent` for the full picture and the per-lineage profile for the
   * grant they rely on; the chain-level letter is the conservative summary.
   */
  conformanceProfile: 'A' | 'B' | 'C' | 'unknown';
  /** 0.10.0 — every profile observed across the chain's ASSIGNMENTs (§5.2 per-lineage model),
   *  ascending. Additive companion to the floor `conformanceProfile`. */
  profilesPresent: Array<'A' | 'B' | 'C'>;
  /**
   * 0.10.0 — the delegator-authority carriers surfaced verbatim, one per ASSIGNMENT that carries
   * `human_attestation.delegator_authority` (§7.2 Pass 5). Answers "who attested entitlement?"
   * from the report alone: `basis` + `capability` are the attested authority claim; `attested_by`
   * / `session_ref` name the attestor for the reserved `ceremony_session_delegated` basis.
   * Surfaced VERBATIM — an attested basis is never presented as proven entitlement.
   */
  authorityCarriers: Array<{
    sequenceNumber: string;
    basis: string | null;
    capability: string | null;
    attested_by?: string | null;
    session_ref?: string | null;
  }>;
  /**
   * 0.11.0 — every §4.3 CONSENT bond itemized: the per-bond INSTRUMENT grade, legible from the
   * report alone. `profile` grades the instrument by `signature.alg` (§5.2: qualified alg ⇒ 'C',
   * webauthn ⇒ 'B', absent/unknown ⇒ 'unknown' — a CONSENT is never signatureless by spec, so
   * 'unknown' co-occurs with a signature violation). DISTINCT from `conformanceProfile` /
   * `profilesPresent`, which grade the chain's ASSIGNMENT roots (per-lineage §5.2 property):
   * a webauthn consent bond on an operator-attested chain reports chain floor 'A' AND a
   * consent bond graded 'B' — both true, surfaced separately, never rounded either way.
   */
  consentBonds: Array<{
    sequenceNumber: string;
    alg: string | null;
    profile: 'B' | 'C' | 'unknown';
    signatureValid: boolean;
  }>;
  /**
   * 0.6.0 — the root human's DECLARED identity, read from the root ASSIGNMENT's
   * `human_attestation.identity_assurance` ({ subject_claim, source }). This is the name the lineage
   * roots in (hash-bound in canonical_details; the verifier re-derives integrity over those bytes).
   * `source` ('self_asserted' | 'kyb_attested' | 'eidas_eaa' | 'qes') is surfaced verbatim so a
   * consumer NEVER reads a self-asserted name as a vouched identity. `null` when the root carries no
   * identity_assurance (pre-0.6.0 / pre-declaration chains). Additive — does not affect any verdict.
   */
  rootSubject: { subject_claim: string; source: string } | null;
  firstLineageViolation: { sequenceNumber: string; reason: string } | null;
  firstScopeViolation: { sequenceNumber: string; reason: string } | null;
  firstGroundingViolation: { sequenceNumber: string; reason: string } | null;
  firstAuthorityViolation: { sequenceNumber: string; reason: string } | null;
  firstSignatureViolation: { sequenceNumber: string; reason: string } | null;
  /**
   * Pass 6 (bytes-binding, §7.2 / ADR 0061): a MUTATION's `bytes_commitment` re-derived from a
   * disclosed { bytes, nonce } (see verifyValChain `options.bytesDisclosures`). OPT-IN and additive:
   * `'bound'` = at least one commitment was disclosed and every disclosed one matched; `'mismatch'`
   * = a disclosed commitment failed to reproduce (the bytes are NOT the committed document);
   * `'not_evaluated'` = no MUTATION carried both a commitment and a matching disclosure. Absence
   * NEVER fails the verdict — bytes-binding is a separate, evidence-time rail.
   */
  bytesBinding: 'bound' | 'mismatch' | 'not_evaluated';
  firstBytesBindingViolation: { sequenceNumber: string; reason: string } | null;
  /**
   * Pass 4 (external anchor, §8): an ANCHOR block's checkpoint Merkle root re-derived over its
   * in-band covered range AND its RFC 3161 token verified against `options.anchorTrust`. OPT-IN and
   * additive: `'verified'` = ≥1 ANCHOR present, a trust anchor was supplied, and every ANCHOR's root
   * + token verified; `'mismatch'` = an ANCHOR was present and a trust anchor supplied but one failed
   * (root mismatch, broken messageImprint binding, or invalid signature) — sticky; `'not_evaluated'`
   * = no ANCHOR block, or no `anchorTrust` supplied. Absence NEVER fails the verdict. Temporal
   * existence only — `anchors[].genTime` is the TSA-attested time; no time-policy is evaluated.
   */
  anchorBinding: 'verified' | 'mismatch' | 'not_evaluated';
  firstAnchorViolation: { sequenceNumber: string; reason: string } | null;
  /** Per verified ANCHOR: the attested `genTime` (ISO 8601) and the covered block range. */
  anchors: Array<{ sequenceNumber: string; genTime: string; covered_range: { from_sequence: number; to_sequence: number } }>;
  /**
   * Pre-carrier (v1) ASSIGNMENT bodies lacking delegator_authority — tolerated (chain
   * bytes are immutable) but counted, so a report states exactly how much of the chain
   * predates the carrier. Conforming producers MUST NOT emit new v1 ASSIGNMENT bodies.
   */
  legacyPreAuthorityAssignmentCount: number;
  /** Count of rows that are not VAL blocks (no block_type) — informational. */
  nonValBlockCount: number;
}

const VAL_ACTION_TYPES = new Set(['ACCESS', 'MUTATION', 'CONSENT', 'COMMUNICATION', 'SETTLEMENT']);
const MAX_LINEAGE_DEPTH = 16;

function parseValBlock(canonicalDetails: string): ValBlock | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonicalDetails);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const b = parsed as ValBlock;
  return b.block_type ? b : null;
}

/**
 * Walk a lineage chain from `startParentHash` up to its root ASSIGNMENT. Returns the
 * ordered ASSIGNMENT scopes on the path (root-most last) and whether the root is
 * human-rooted (Profile A: a non-null `human_attestation`). Fails on a dangling
 * reference, a non-ASSIGNMENT target, an over-deep chain, or a non-human root.
 */
// Walk the lineage from an action block's parent ASSIGNMENT to the human-rooted ASSIGNMENT, collecting
// EVERY ancestor's scope (direct parent → root). Evaluating an action against all of these conjunctively
// IS the §6.7 transitive effective scope (intersection back to root) for subj/act/res/win: the action
// satisfies the intersection iff it satisfies every ancestor, so a sub-assignment that broadens any of
// those cannot grant the surplus. `ancestorHashes` (direct parent → root) lets the §6.6 lim aggregate
// roll up transitively — a descendant counts against every ancestor grant, effective max_count = min.
function walkLineage(
  startParentHash: string,
  index: Map<string, ValBlock>,
): { ok: boolean; scopes: ScopePredicate[]; ancestorHashes: string[]; profile: 'A' | 'unknown'; reason: string | null } {
  const scopes: ScopePredicate[] = [];
  const ancestorHashes: string[] = [];
  let cursor: string | null = startParentHash;
  let depth = 0;
  while (cursor) {
    if (++depth > MAX_LINEAGE_DEPTH) {
      return { ok: false, scopes, ancestorHashes, profile: 'unknown', reason: `lineage exceeds max depth ${MAX_LINEAGE_DEPTH}` };
    }
    const a = index.get(cursor);
    if (!a) {
      return { ok: false, scopes, ancestorHashes, profile: 'unknown', reason: `parent_assignment_hash '${cursor.slice(0, 12)}…' references no ASSIGNMENT in the chain (orphan)` };
    }
    if (a.block_type !== 'ASSIGNMENT') {
      return { ok: false, scopes, ancestorHashes, profile: 'unknown', reason: `parent_assignment_hash resolves to a ${a.block_type}, not an ASSIGNMENT` };
    }
    ancestorHashes.push(cursor);
    if (a.scope) scopes.push(a.scope);
    const next: string | null = a.parent_assignment_hash ?? null;
    if (!next) {
      // root ASSIGNMENT — require human attestation (Profile A).
      if (!a.human_attestation) {
        return { ok: false, scopes, ancestorHashes, profile: 'unknown', reason: 'root ASSIGNMENT has no human_attestation (not human-rooted)' };
      }
      return { ok: true, scopes, ancestorHashes, profile: 'A', reason: null };
    }
    cursor = next;
  }
  return { ok: false, scopes, ancestorHashes, profile: 'unknown', reason: 'lineage terminated without a root ASSIGNMENT' };
}

/** Evaluate §6.6 satisfaction of an action block against one ASSIGNMENT scope. */
async function satisfies(block: ValBlock, scope: ScopePredicate): Promise<{ ok: boolean; reason: string | null }> {
  if (scope.subj?.principal_uri && block.principal && block.principal !== scope.subj.principal_uri) {
    return { ok: false, reason: `principal '${block.principal}' != scope subj '${scope.subj.principal_uri}'` };
  }
  if (scope.act && block.action && !scope.act.includes(block.action)) {
    return { ok: false, reason: `action '${block.action}' not in scope.act [${scope.act.join(',')}]` };
  }
  const res = scope.res;
  if (res?.in_workspace && block.resource?.in_workspace && block.resource.in_workspace !== res.in_workspace) {
    return { ok: false, reason: `resource workspace '${block.resource.in_workspace}' != scope '${res.in_workspace}'` };
  }
  // The cryptographic isolation check (§6.4 / §6.6) applies to ACCESS blocks only —
  // isolation governs which documents an action READS. A MUTATION (record write) is an
  // assertion of fact, not a document read; its document grounding is enforced at write
  // (validate_record_grounding) + recorded as ACCESS blocks. Requiring a membership_proof
  // on a MUTATION would be a category error.
  if (res?.isolation_commitment && block.block_type === 'ACCESS') {
    const ch = block.resource?.content_hash;
    if (!ch || !block.membership_proof) {
      return { ok: false, reason: 'ACCESS under isolation_commitment has no resource content_hash + membership_proof' };
    }
    if (!(await verifyMembershipProof(ch, block.membership_proof, res.isolation_commitment))) {
      return { ok: false, reason: 'membership_proof does not re-derive the committed isolation root (isolation violation)' };
    }
  }
  // §6.6 temporal window: `not_before ≤ timestamp_local ≤ not_after` (where bounds are present).
  // timestamp_local is unix ms (an operator convention; spec §6.6 bounds are unit-agnostic) — the same field the operator's PG trigger enforces preventively.
  if (scope.win && (typeof scope.win.not_before === 'number' || typeof scope.win.not_after === 'number')) {
    const ts = block.timestamp_local;
    if (typeof ts !== 'number') {
      return { ok: false, reason: 'scope.win present but block carries no timestamp_local (§6.6, unverifiable window)' };
    }
    if (typeof scope.win.not_before === 'number' && ts < scope.win.not_before) {
      return { ok: false, reason: `timestamp_local ${ts} is before win.not_before ${scope.win.not_before}` };
    }
    if (typeof scope.win.not_after === 'number' && ts > scope.win.not_after) {
      return { ok: false, reason: `timestamp_local ${ts} is after win.not_after ${scope.win.not_after}` };
    }
  }
  return { ok: true, reason: null };
}

/**
 * VAL offline verifier (§7.2 passes 1–3 + 5) over a single scope's ChainRow slice.
 * Pass 1 reuses verifyChain (integrity). Pass 2 walks every action block's lineage
 * to a human-rooted ASSIGNMENT. Pass 3 evaluates §6.6 satisfaction (incl. the §6.4
 * Merkle isolation check) against the effective scope (intersection over the lineage
 * path — an action must satisfy every ASSIGNMENT scope on its path). Pass 4 (anchor)
 * is out of scope here. Pass 5 (delegator authority) checks every ASSIGNMENT's
 * delegated scope against its delegator's declared authority — carrier REQUIRED on
 * v2 bodies, scope.act ⊆ policy[capability] when `options.delegatorAuthorityPolicy`
 * (the §7.1(d) trust-anchor input) is supplied. As of v0.3.0 the well-known
 * `container_owner` basis is additionally re-derived from chain bytes where the
 * chain permits: scope_ref must equal the ASSIGNMENT's scope.res.in_workspace, and
 * a `user:`-principal COMMUNICATION rooted in it must hash to the attested
 * subject_user_hash (an `agent:` principal carries the Profile-A residual instead).
 * `options` is additive; existing callers are unaffected. Input MUST be the same
 * partitioned, sorted, contiguous slice verifyChain requires.
 */
export async function verifyValChain(
  rows: ChainRow[],
  options?: {
    delegatorAuthorityPolicy?: DelegatorAuthorityPolicy;
    /**
     * ADR 0061 Pass 6 — evidence-time bytes-binding disclosures, one per document the auditor holds.
     * `documentBytesBase64` is the file the auditor produced as evidence; `nonceHex` is the room-side
     * nonce disclosed in the evidence bundle (never on chain). The verifier hashes the bytes itself
     * and recomputes the hiding commitment — it never trusts a supplied hash. Keyed by `resourceId`
     * (the MUTATION's `resource.resource_id`).
     */
    bytesDisclosures?: Array<{ resourceId: string; documentBytesBase64: string; nonceHex: string }>;
    /**
     * §8 Pass 4 — the resolved anchor trust anchor: base64 SPKIs (SubjectPublicKeyInfo) of acceptable
     * RFC 3161 TSA signing certificates. A pinned set in Phase 1 (any-TSA); in eIDAS deployments the
     * caller resolves the QTSP cert from the EU Trusted List (LOTL) and supplies it here already-
     * resolved (identical shape — the verifier never fetches a trust list). Absent ⇒ Pass 4 reports
     * `not_evaluated`.
     */
    anchorTrust?: { tsaCertSpkis: string[] };
    /**
     * ADR 0063 Profile C — resolved eIDAS QES validation verdicts, produced caller-side by
     * `@val-protocol/qes-validator` (which carries the heavy ETSI deps; this zero-dep core only consumes
     * the verdict, exactly like `anchorTrust`). A qualified delegation (`qes`/`eidas_qes`/`eidas_eaa`)
     * with a matching `qualified: true` report verifies Profile C; absent ⇒ `qualified_unverified`
     * (classified, never silently upgraded). Per-signature matching (ADR 0063 item 5): when reports
     * carry `signatureRef` (sha256-hex of the delegation signature bytes, as `qes-validator` emits),
     * each delegation matches ONLY its own report — distinct qualified delegations cannot borrow each
     * other's verdict. Legacy unkeyed reports (no `signatureRef`) fall back to first-qualified for
     * single-grant back-compat.
     */
    qesValidation?: { reports: QesVerdict[] };
  },
): Promise<ValVerificationResult> {
  const result: ValVerificationResult = {
    integrity: 'green',
    lineage: 'green',
    scope: 'green',
    grounding: 'green',
    authority: 'none',
    signature: 'none',
    keyBinding: null,
    conformanceProfile: 'unknown',
    profilesPresent: [],
    authorityCarriers: [],
    consentBonds: [],
    rootSubject: null,
    firstLineageViolation: null,
    firstScopeViolation: null,
    firstGroundingViolation: null,
    firstAuthorityViolation: null,
    firstSignatureViolation: null,
    bytesBinding: 'not_evaluated',
    firstBytesBindingViolation: null,
    anchorBinding: 'not_evaluated',
    firstAnchorViolation: null,
    anchors: [],
    legacyPreAuthorityAssignmentCount: 0,
    nonValBlockCount: 0,
  };

  // Pass 6 disclosure map (ADR 0061). Decoded once; null when the caller supplied none.
  const bytesDisclosures = options?.bytesDisclosures
    ? new Map(
        options.bytesDisclosures.map((d) => [
          d.resourceId,
          { bytes: b64ToBytes(d.documentBytesBase64), nonce: hexToBytes(d.nonceHex) },
        ]),
      )
    : null;

  // Pass 1 — integrity.
  const integrity = await verifyChain(rows);
  if (!integrity.ok) {
    result.integrity = 'red';
    return result; // integrity is prerequisite; no point walking a broken chain.
  }

  // Index VAL blocks by chain_hash.
  const index = new Map<string, ValBlock>();
  const blocks: Array<{ row: ChainRow; block: ValBlock | null }> = rows.map((row) => {
    const block = parseValBlock(row.canonical_details);
    if (block) index.set(row.chain_hash, block);
    else result.nonValBlockCount++;
    return { row, block };
  });

  const profiles = new Set<string>();
  // Grounding index (§7.5 read-before-derive): content-hashes each principal has READ via an
  // ACCESS block earlier in this chain. Populated as we walk in sequence order; a later MUTATION
  // that cites grounded_document_hashes must cite content present here for the same principal.
  const accessByPrincipal = new Map<string, Set<string>>();
  // §6.6 lim.max_count: running count of an ASSIGNMENT's DESCENDANT action blocks, keyed by ancestor
  // hash; the (max_count+1)-th descendant is the violation. Transitive (§6.7): a leaf action increments
  // every ancestor in its lineage, so a grandchild counts against the root grant's max_count.
  const limCounts = new Map<string, number>();

  for (const { row, block } of blocks) {
    if (!block) continue;
    if (block.block_type === 'ANCHOR') continue;

    const seqStr = row.sequence_number.toString();
    const isAction = VAL_ACTION_TYPES.has(block.block_type ?? '');
    const isAssignment = block.block_type === 'ASSIGNMENT';

    // ── Pass 2 — lineage ──
    if (isAction) {
      if (!block.parent_assignment_hash) {
        if (result.lineage === 'green') {
          result.lineage = 'red';
          result.firstLineageViolation = { sequenceNumber: seqStr, reason: `${block.block_type} block has no parent_assignment_hash (orphan)` };
        }
        continue;
      }
      const walk = walkLineage(block.parent_assignment_hash, index);
      if (!walk.ok) {
        if (result.lineage === 'green') {
          result.lineage = 'red';
          result.firstLineageViolation = { sequenceNumber: seqStr, reason: walk.reason ?? 'lineage failure' };
        }
        continue;
      }
      // 0.11.1: the walk contributes NO profile — the walked-to root is a chain block classified
      // in its OWN ASSIGNMENT iteration (signed → B/C, unsigned/failed → A). Adding 'A' here for
      // every successful action walk dragged a cleanly B/C-rooted chain to floor 'A' and stamped a
      // phantom 'A' into profilesPresent (same double-count the 0.10.0 sub-ASSIGNMENT note fixed).

      // ── Pass 3 — scope (effective = satisfy every ASSIGNMENT scope on the path) ──
      // §6.7 effective scope: evaluate the action against EVERY ancestor scope (direct parent → root)
      // — the transitive intersection for subj/act/res/win. The action passes only if it clears each
      // ancestor, so a sub-assignment that broadens any of these cannot grant the surplus; the literal
      // child scope is never trusted alone.
      for (const scope of walk.scopes) {
        const sat = await satisfies(block, scope);
        if (!sat.ok) {
          if (result.scope === 'green') {
            result.scope = 'red';
            result.firstScopeViolation = { sequenceNumber: seqStr, reason: sat.reason ?? 'scope violation' };
          }
          break;
        }
      }

      // ── §6.6 lim.max_count — aggregate over a grant's descendant action blocks (verifier-side,
      // detective), TRANSITIVE per §6.7: a leaf action counts against EVERY ancestor grant in its
      // lineage, so a grandchild is constrained by the root grant's max_count (effective = min over the
      // path). The (max_count+1)-th descendant of any ancestor grant is the violation. ──
      for (const ah of walk.ancestorHashes) {
        const maxCount = index.get(ah)?.scope?.lim?.max_count;
        if (typeof maxCount !== 'number') continue;
        const c = (limCounts.get(ah) ?? 0) + 1;
        limCounts.set(ah, c);
        if (c > maxCount && result.scope === 'green') {
          result.scope = 'red';
          result.firstScopeViolation = {
            sequenceNumber: seqStr,
            reason: `lim.max_count ${maxCount} exceeded: ${c} action blocks in this grant's descendants`,
          };
        }
      }

      // ── Agent-equity — `action.principal == grant.grantee`. The action roots directly in the
      // actor's grant; a v>=3 ASSIGNMENT names its grantee, so the action's principal MUST equal it
      // ("it's THIS actor's own mandate"). v1/v2 grants carry no grantee → grandfathered. ──
      {
        const grant = index.get(block.parent_assignment_hash);
        const grantV = grant?.v ?? 1;
        if (grant?.block_type === 'ASSIGNMENT' && grantV >= 3 && grant.grantee) {
          if (block.principal !== grant.grantee) {
            result.authority = 'red';
            if (!result.firstAuthorityViolation) {
              result.firstAuthorityViolation = {
                sequenceNumber: seqStr,
                reason: `agent-equity: action principal '${block.principal ?? '(none)'}' != grant grantee '${grant.grantee}' (v${grantV} ASSIGNMENT)`,
              };
            }
          }
        }
      }

      // ── Pass 5 (v0.3.0) — `container_owner` ownership re-derivation, chain bytes only.
      // A COMMUNICATION rooted directly in a `container_owner` ASSIGNMENT and performed
      // by a human (`user:` principal) must be performed by the attested owner:
      // sha256(<principal user id>) must equal the root's human_attestation
      // .subject_user_hash. An `agent:` principal has no second chain occurrence of the
      // delegating human to cross-check — it carries the Profile-A operator-attested
      // residual, like every other basis. ──
      if (block.block_type === 'COMMUNICATION' && block.parent_assignment_hash) {
        const parent = index.get(block.parent_assignment_hash);
        const pda = parent?.human_attestation?.delegator_authority;
        if (
          parent?.block_type === 'ASSIGNMENT' &&
          pda?.basis === 'container_owner' &&
          typeof block.principal === 'string' &&
          block.principal.startsWith('user:')
        ) {
          const subjectHash = parent.human_attestation?.subject_user_hash;
          const principalHash = bytesToHex(await sha256(utf8(block.principal.slice('user:'.length))));
          if (!subjectHash || principalHash !== subjectHash) {
            result.authority = 'red';
            if (!result.firstAuthorityViolation) {
              result.firstAuthorityViolation = {
                sequenceNumber: seqStr,
                reason: `container_owner COMMUNICATION principal '${block.principal}' is not the attested container owner (sha256(principal id) != subject_user_hash)`,
              };
            }
          }
        }
      }

      // ── §4.3 CONSENT — per-action signature pass (§5.2 A+/A++). The bond's trust: the embedded
      // `signature` MUST be a valid WebAuthn assertion whose challenge equals the hash of
      // {document_hash, parent_assignment_hash, principal} — so the signature provably binds the
      // signed artifact (D1). A CONSENT with no signature, or one that fails, → signature red.
      // (Lineage + `sign ∈ scope.act` are already checked above via the action-block path.) ──
      if (block.block_type === 'CONSENT') {
        const sig = block.signature;
        if (!sig) {
          result.signature = 'red';
          if (!result.firstSignatureViolation) {
            result.firstSignatureViolation = { sequenceNumber: seqStr, reason: 'CONSENT block carries no per-action signature' };
          }
          result.consentBonds.push({ sequenceNumber: seqStr, alg: null, profile: 'unknown', signatureValid: false });
        } else if (QUALIFIED_ALGS.has(sig.alg)) {
          // 0.11.0 — a QUALIFIED consent signature follows the SAME discipline as qualified
          // delegations (ADR 0063): its ETSI/eIDAS crypto verification is produced caller-side
          // (@val-protocol/qes-validator) and supplied as a per-signature verdict via
          // options.qesValidation. With a matching `qualified: true` verdict ⇒ verified (green);
          // without one ⇒ CLASSIFIED, not verified (signature pass untouched — never red on
          // absence, never green on declaration). Pre-0.11.0 these went red as 'unsupported alg'
          // — a spec-valid Profile-C bond failed the report. The payload binding travels with the
          // verdict (the validator checked the signature over the canonical consent bytes), like
          // the delegation path.
          let qesVerdict: QesVerdict | null = null;
          const reports = options?.qesValidation?.reports;
          if (reports && reports.length) {
            const thisRef = bytesToHex(await sha256(new TextEncoder().encode(sig.signature)));
            const keyed = reports.find((r) => r.signatureRef === thisRef);
            if (keyed) {
              qesVerdict = keyed; // exact per-signature verdict — authoritative
            } else if (reports.some((r) => r.signatureRef != null)) {
              qesVerdict = null; // keyed reports, none for THIS signature ⇒ classified, not verified
            } else {
              qesVerdict = reports.find((r) => r.qualified === true) ?? null; // legacy unkeyed fallback
            }
          }
          const qualified = qesVerdict?.qualified === true;
          if (qualified) {
            if (result.signature === 'none') result.signature = 'green';
          }
          result.consentBonds.push({ sequenceNumber: seqStr, alg: sig.alg, profile: 'C', signatureValid: qualified });
        } else {
          const challenge = bytesToB64url(
            await sha256(
              utf8(
                jcs({
                  document_hash: block.document_hash,
                  parent_assignment_hash: block.parent_assignment_hash,
                  principal: block.principal,
                }),
              ),
            ),
          );
          const v = await verifyDelegatorSignature(sig, challenge);
          if (v.valid) {
            if (result.signature === 'none') result.signature = 'green';
          } else {
            result.signature = 'red';
            if (!result.firstSignatureViolation) {
              result.firstSignatureViolation = { sequenceNumber: seqStr, reason: `CONSENT per-action signature invalid: ${v.reason}` };
            }
          }
          result.consentBonds.push({
            sequenceNumber: seqStr,
            alg: sig.alg ?? null,
            profile: sig.alg === 'webauthn' ? 'B' : 'unknown',
            signatureValid: v.valid,
          });
        }
      }

      // ── Property #4 (grounding, §7.5) — domain-neutral read-before-derive. Walking in sequence
      // order, record each ACCESS's content-hash under its principal; a later MUTATION that cites
      // grounded_document_hashes must cite content the SAME principal already read in this chain.
      // Relaxed linkage (same principal + same chain); assignment co-location is a v0.2 strengthening.
      // This REPLACES the earlier type/scope-flag grounding formulation. ──
      if (block.block_type === 'ACCESS') {
        const ch = block.resource?.content_hash;
        if (ch && block.principal) {
          let seen = accessByPrincipal.get(block.principal);
          if (!seen) {
            seen = new Set<string>();
            accessByPrincipal.set(block.principal, seen);
          }
          seen.add(ch);
        }
      } else if (
        block.block_type === 'MUTATION' &&
        Array.isArray(block.grounded_document_hashes) &&
        block.grounded_document_hashes.length > 0
      ) {
        const seen = accessByPrincipal.get(block.principal ?? '') ?? new Set<string>();
        const ungrounded = block.grounded_document_hashes.filter((h) => !seen.has(h));
        if (ungrounded.length > 0 && result.grounding === 'green') {
          result.grounding = 'red';
          result.firstGroundingViolation = {
            sequenceNumber: seqStr,
            reason: `MUTATION cites ${ungrounded.length} grounded hash(es) with no prior ACCESS by principal '${block.principal ?? '(none)'}' in this chain (first: ${(ungrounded[0] ?? '').slice(0, 12)}…)`,
          };
        }
      }

      // ── Pass 6 (bytes-binding, ADR 0061) — opt-in, evidence-time. A MUTATION carrying a
      // hiding `bytes_commitment` is bound to real file bytes ONLY via a disclosed { bytes, nonce }
      // (room-side nonce, never on chain). The verifier hashes the bytes itself and recomputes the
      // commitment. No commitment or no matching disclosure ⇒ not evaluated (never a failure),
      // per §4.4 optional-field semantics. A mismatch is sticky (a later bind cannot clear it).
      if (block.block_type === 'MUTATION' && block.bytes_commitment?.value && bytesDisclosures) {
        const rid = block.resource?.resource_id;
        const disc = rid ? bytesDisclosures.get(rid) : undefined;
        if (disc) {
          const recomputed = await recomputeBytesCommitment(disc.bytes, disc.nonce);
          if (recomputed === block.bytes_commitment.value.toLowerCase()) {
            if (result.bytesBinding === 'not_evaluated') result.bytesBinding = 'bound';
          } else {
            result.bytesBinding = 'mismatch';
            if (!result.firstBytesBindingViolation) {
              result.firstBytesBindingViolation = {
                sequenceNumber: seqStr,
                reason: `bytes_commitment mismatch for resource ${rid ?? '(none)'} — disclosed bytes+nonce do not reproduce the on-chain commitment`,
              };
            }
          }
        }
      }
    } else if (isAssignment) {
      // ── Pass 5 — delegator authority (§7.2). Applies to EVERY ASSIGNMENT, root or
      // sub, whatever surface minted it. v2 bodies REQUIRE the carrier; v1 bodies without
      // it are pre-carrier legacy (tolerated, counted). With the §7.1(d) policy supplied,
      // the delegated scope.act must be ⊆ what the delegator's capability may delegate. ──
      {
        const da = block.human_attestation?.delegator_authority;
        const v = block.v ?? 1;
        if (!da) {
          if (v >= 2) {
            result.authority = 'red';
            if (!result.firstAuthorityViolation) {
              result.firstAuthorityViolation = { sequenceNumber: seqStr, reason: `v${v} ASSIGNMENT lacks human_attestation.delegator_authority (required as of v2)` };
            }
          } else {
            result.legacyPreAuthorityAssignmentCount++;
          }
        } else {
          if (result.authority === 'none') result.authority = 'green';
          // 0.10.0 — surface the carrier verbatim so the report answers "who attested
          // entitlement?" without reading raw blocks (§7.3). Never a judgement — an
          // attested basis is not presented as proven entitlement.
          result.authorityCarriers.push({
            sequenceNumber: seqStr,
            basis: da.basis ?? null,
            capability: da.capability ?? null,
            ...(da.attested_by !== undefined ? { attested_by: da.attested_by } : {}),
            ...(da.session_ref !== undefined ? { session_ref: da.session_ref } : {}),
          });
          // `container_owner` basis (v0.3.0): chain-internal consistency, policy-
          // independent like carrier presence — the claimed authority must be scoped
          // to the very container this ASSIGNMENT scopes (§7.2 Pass 5).
          if (da.basis === 'container_owner') {
            const ws = (block.scope?.res?.in_workspace as string | null | undefined) ?? null;
            if (!da.scope_ref || da.scope_ref !== ws) {
              result.authority = 'red';
              if (!result.firstAuthorityViolation) {
                result.firstAuthorityViolation = {
                  sequenceNumber: seqStr,
                  reason: `container_owner scope_ref '${da.scope_ref ?? '(none)'}' != ASSIGNMENT scope.res.in_workspace '${ws ?? '(none)'}'`,
                };
              }
            }
          }
          // `ceremony_session_delegated` reserved basis (0.10.0, §7.2 Pass 5 / spec amendment
          // 2026-07-01): an account-less delegation whose entitlement was attested by the
          // ceremony-session creator. Two chain-byte re-derivations, policy-independent:
          //   (a) the claimed authority must be scoped to the very container this ASSIGNMENT
          //       scopes (same shape as container_owner);
          //   (b) the carrier MUST co-occur with a QUALIFIED delegator signature — account-less
          //       identity is cert-carried, so an account-less authority claim without a
          //       qualified instrument has no identity leg to stand on.
          // Entitlement itself stays attested (attested_by/session_ref surfaced verbatim above),
          // never offline-proven.
          if (da.basis === 'ceremony_session_delegated') {
            const ws = (block.scope?.res?.in_workspace as string | null | undefined) ?? null;
            if (!da.scope_ref || da.scope_ref !== ws) {
              result.authority = 'red';
              if (!result.firstAuthorityViolation) {
                result.firstAuthorityViolation = {
                  sequenceNumber: seqStr,
                  reason: `ceremony_session_delegated scope_ref '${da.scope_ref ?? '(none)'}' != ASSIGNMENT scope.res.in_workspace '${ws ?? '(none)'}'`,
                };
              }
            }
            if (!da.signature || !QUALIFIED_ALGS.has(da.signature.alg)) {
              result.authority = 'red';
              if (!result.firstAuthorityViolation) {
                result.firstAuthorityViolation = {
                  sequenceNumber: seqStr,
                  reason: `ceremony_session_delegated carrier without a qualified delegator signature (alg '${da.signature?.alg ?? '(none)'}') — account-less authority requires a qualified instrument`,
                };
              }
            }
          }
          const policy = options?.delegatorAuthorityPolicy;
          if (policy) {
            const permitted = policy[da.capability ?? ''];
            const acts = block.scope?.act ?? [];
            if (!permitted) {
              result.authority = 'red';
              if (!result.firstAuthorityViolation) {
                result.firstAuthorityViolation = { sequenceNumber: seqStr, reason: `unknown delegator capability '${da.capability ?? '(none)'}' — scope ⊆ authority not evaluable` };
              }
            } else {
              const exceeded = acts.filter((a) => !permitted.includes(a));
              if (exceeded.length > 0) {
                result.authority = 'red';
                if (!result.firstAuthorityViolation) {
                  result.firstAuthorityViolation = { sequenceNumber: seqStr, reason: `scope.act [${exceeded.join(',')}] exceeds capability '${da.capability}' delegable set (authority escalation)` };
                }
              }
            }
          }
        }
      }
      // ── Profile B/C signature pass (§5.2) ── A present delegation signature declares the
      // profile (webauthn → B; qualified → C) and must verify + chain to the enrolled,
      // self-attested org-root key. conformanceProfile reflects the DECLARED profile; the
      // `signature` field reflects whether it VERIFIED. Both are read together (like
      // integrity/lineage/...). key_binding (device_bound / syncable / unattested) is the
      // orthogonal hardware axis, surfaced verbatim, never rounded up — 'unattested' still
      // earns B when the signature verifies + links (the letter grades the instrument).
      // 0.10.0: `dsigProfile` records what THIS block's signature classified — under the §5.2
      // per-lineage FLOOR model, a signed root's profile IS B/C, and the root classification
      // below must not also add A for it (harmless under the old max; wrong under floor).
      let dsigProfile: 'B' | 'C' | null = null;
      {
        const dsig = block.human_attestation?.delegator_authority?.signature;
        if (dsig) {
          const oroot = block.human_attestation?.delegator_authority?.org_root ?? null;
          // ADR 0063 item 5 — supply a resolved QES verdict for qualified delegations by PER-SIGNATURE
          // matching: a report whose `signatureRef` == sha256-hex(this signature) is THIS signature's
          // verdict (qualified or not). When reports are keyed but none matches ⇒ no verdict (never
          // borrow another signature's — the old "first qualified" bug). Legacy unkeyed reports fall
          // back to first-qualified (single-grant back-compat). Absent ⇒ classified-not-verified default.
          let qesVerdict: QesVerdict | null = null;
          const reports = options?.qesValidation?.reports;
          if (QUALIFIED_ALGS.has(dsig.alg) && reports && reports.length) {
            const thisRef = bytesToHex(await sha256(new TextEncoder().encode(dsig.signature)));
            const keyed = reports.find((r) => r.signatureRef === thisRef);
            if (keyed) {
              qesVerdict = keyed; // exact per-signature verdict — authoritative
            } else if (reports.some((r) => r.signatureRef != null)) {
              qesVerdict = null; // keyed reports, none for THIS signature ⇒ qualified_unverified
            } else {
              qesVerdict = reports.find((r) => r.qualified === true) ?? null; // legacy unkeyed fallback
            }
          }
          const tc = await verifyDelegationTrustChain(dsig, oroot, qesVerdict);
          if (tc.outcome === 'authority_verified_qualified') {
            // Profile C VERIFIED — a qes-validator verdict proved the qualified signature (eIDAS QES).
            // Earns conformance C + signature green, and surfaces the proven natural-person identity as
            // the root subject (source 'qes'), verbatim — never rounded up.
            profiles.add('C');
            dsigProfile = 'C';
            if (result.signature === 'none') result.signature = 'green';
            const id = qesVerdict?.signerIdentity;
            const claim = id ? [id.given_name, id.family_name].filter(Boolean).join(' ').trim() : '';
            if (claim && !result.rootSubject) {
              result.rootSubject = { subject_claim: claim, source: 'qes' };
            }
          } else if (tc.outcome === 'qualified_unverified') {
            // Profile C: CLASSIFIED (declared). Its crypto verification needs a QES validation verdict
            // (qesValidation) — never a silent default. Conformance reflects C; the signature pass is
            // left unchanged (not green, not red).
            profiles.add('C');
            dsigProfile = 'C';
          } else if (tc.signatureValid && tc.linkageVerified) {
            // Only a VERIFIED + org-root-LINKED signature earns conformance B.
            profiles.add('B');
            dsigProfile = 'B';
            if (result.signature === 'none') result.signature = 'green';
            if (tc.keyBinding && !result.keyBinding) result.keyBinding = tc.keyBinding;
          } else {
            // A present signature that failed to verify or link → flag red and claim NO
            // profile from it (conformance stays A). No over-claim, no silent default.
            result.signature = 'red';
            if (!result.firstSignatureViolation) {
              result.firstSignatureViolation = { sequenceNumber: seqStr, reason: tc.reason };
            }
          }
        }
      }
      // Root ASSIGNMENT must be human-rooted; sub-ASSIGNMENT must walk to one.
      if (block.parent_assignment_hash) {
        const walk = walkLineage(block.parent_assignment_hash, index);
        if (!walk.ok && result.lineage === 'green') {
          result.lineage = 'red';
          result.firstLineageViolation = { sequenceNumber: seqStr, reason: walk.reason ?? 'sub-ASSIGNMENT lineage failure' };
        }
        // 0.10.0: no profile contribution from the walk — the walked-to root is itself a chain
        // block and is classified in its OWN iteration (signed → B/C, else A). Adding 'A' here
        // double-counted signed roots (harmless under the old max; wrong under the floor).
      } else if (!block.human_attestation) {
        if (result.lineage === 'green') {
          result.lineage = 'red';
          result.firstLineageViolation = { sequenceNumber: seqStr, reason: 'root ASSIGNMENT has no human_attestation (not human-rooted)' };
        }
      } else {
        // 0.10.0 floor model: a signed root's profile IS what its signature classified (B/C,
        // recorded in dsigProfile above); only an UNSIGNED (or failed-signature) human-rooted
        // root is Profile A. Under the old max this add was unconditional and harmless.
        if (!dsigProfile) profiles.add('A');
        // 0.6.0 — surface the root human's declared identity (hash-bound in this block's
        // canonical_details, already integrity-checked). First human-rooted root wins; `source`
        // verbatim (never round a self_asserted name up to vouched).
        const ia = block.human_attestation.identity_assurance;
        if (!result.rootSubject && ia?.subject_claim) {
          result.rootSubject = { subject_claim: ia.subject_claim, source: ia.source ?? 'self_asserted' };
        }
      }
    }
  }

  // ── Pass 4 — external anchor (§8). Opt-in: only when a trust anchor is supplied. Each ANCHOR
  //    block (skipped by the main loop) is verified independently against its own covered range +
  //    RFC 3161 token. `verified` requires every present ANCHOR to pass; a single failure is sticky
  //    `mismatch`. Absent trust anchor or no ANCHOR ⇒ `not_evaluated` (never fails the verdict). ──
  const anchorSpkis = options?.anchorTrust?.tsaCertSpkis ?? null;
  if (anchorSpkis && anchorSpkis.length > 0) {
    for (const { row, block } of blocks) {
      if (!block || block.block_type !== 'ANCHOR') continue;
      const seqStr = row.sequence_number.toString();
      const v = await verifyAnchorBlock(block, rows, anchorSpkis);
      if (v.ok) {
        if (result.anchorBinding === 'not_evaluated') result.anchorBinding = 'verified';
        result.anchors.push({ sequenceNumber: seqStr, genTime: v.genTime!, covered_range: v.coveredRange! });
      } else {
        result.anchorBinding = 'mismatch'; // sticky — a later valid ANCHOR does not clear it
        if (!result.firstAnchorViolation) {
          result.firstAnchorViolation = { sequenceNumber: seqStr, reason: v.reason ?? 'anchor verification failed' };
        }
      }
    }
  }

  // Conformance = the FLOOR — the weakest profile declared by the chain's ASSIGNMENTs (§5.2,
  // spec amendment 2026-07-01). 0.10.0 BEHAVIOR CHANGE: earlier releases reported the strongest
  // profile present, letting one qualified grant mask a chain of operator-attested ones — the
  // exact over-claim the rootSubject.source verbatim rule exists to prevent. Never round up:
  // per-lineage detail lives in `profilesPresent`; the chain letter is the conservative summary.
  result.conformanceProfile = profiles.has('A')
    ? 'A'
    : profiles.has('B')
      ? 'B'
      : profiles.has('C')
        ? 'C'
        : 'unknown';
  result.profilesPresent = (['A', 'B', 'C'] as const).filter((p) => profiles.has(p));
  return result;
}
