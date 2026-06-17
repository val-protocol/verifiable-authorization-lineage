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
}

/** Identity-assurance basis of a self-attested signing key (§5.2). `source` widens with the
 *  profile ladder: `self_asserted`/`kyb_attested` (Profile A/B claim basis) → `eidas_eaa`/`qes`
 *  (Profile C, qualified). The verifier surfaces it verbatim; it never rounds a claim up. */
export interface ValIdentityAssurance {
  source: string;
  subject_claim: string;
}

/** Hardware binding of an enrolled key, bound into the org-root self-attestation so it is
 *  tamper-evident. `device_bound` = single secure element; `syncable` = account-bound /
 *  multi-device (weaker hardware assurance). Surfaced verbatim — never rounded up. */
export type ValKeyBinding = 'device_bound' | 'syncable';

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

export type TrustChainOutcome =
  | 'authority_verified_org_root_device_bound'
  | 'authority_verified_org_root_syncable'
  | 'signature_valid_only'
  | 'qualified_unverified'
  | 'invalid';

/** Verify a Profile B/C delegation: the signature is a valid assertion by the enrolled,
 *  self-attested org-root key. Returns the honest outcome (device_bound vs syncable, or
 *  signature_valid_only when the org-root linkage is absent/broken). */
export async function verifyDelegationTrustChain(
  delegationSig: ValDelegatorSignature,
  orgRoot?: ValOrgRootAttestation | null,
): Promise<{
  signatureValid: boolean;
  linkageVerified: boolean;
  outcome: TrustChainOutcome;
  keyBinding: ValKeyBinding | null;
  subjectAssurance: ValIdentityAssurance | null;
  reason: string;
}> {
  const base = { keyBinding: null as ValKeyBinding | null, subjectAssurance: null as ValIdentityAssurance | null };
  // Profile C (qualified) — classified, but its QTSP-anchored verification is a future
  // trust-anchor input. Surface honestly rather than silently passing or failing.
  if (QUALIFIED_ALGS.has(delegationSig?.alg)) {
    return { ...base, signatureValid: false, linkageVerified: false, outcome: 'qualified_unverified', reason: `qualified alg '${delegationSig.alg}' requires a QTSP trust list (not supplied) — Profile C classified, not verified` };
  }
  const sigCheck = await verifyDelegatorSignature(delegationSig);
  if (!sigCheck.valid) {
    return { ...base, signatureValid: false, linkageVerified: false, outcome: 'invalid', reason: `delegation signature invalid: ${sigCheck.reason}` };
  }
  const notLinked = (reason: string) => ({ ...base, signatureValid: true, linkageVerified: false, outcome: 'signature_valid_only' as const, reason });
  if (!orgRoot) return notLinked('signature valid; no org-root attestation embedded');
  if (!orgRoot.identity_assurance || (orgRoot.key_binding !== 'device_bound' && orgRoot.key_binding !== 'syncable')) {
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
  const syncable = orgRoot.key_binding === 'syncable';
  return {
    signatureValid: true,
    linkageVerified: true,
    outcome: syncable ? 'authority_verified_org_root_syncable' : 'authority_verified_org_root_device_bound',
    keyBinding: orgRoot.key_binding,
    subjectAssurance: { source: orgRoot.identity_assurance.source, subject_claim: orgRoot.identity_assurance.subject_claim },
    reason: `delegation key chains to the enrolled, self-attested org-root key (${syncable ? 'syncable — weaker hardware assurance' : 'device-bound'}); subject "${orgRoot.identity_assurance.subject_claim}" is ${orgRoot.identity_assurance.source}`,
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
  human_attestation?: { method?: string; subject_user_hash?: string; delegator_authority?: ValBlockDelegatorAuthority } | null;
  parent_assignment_hash?: string | null;
  // action blocks:
  action?: string;
  principal?: string;
  resource?: { content_hash?: string; resource_id?: string; in_workspace?: string };
  membership_proof?: MembershipProofStep[];
  // §7.5 grounding: content-hashes this MUTATION asserts it derived from. The verifier checks each
  // was read via a prior ACCESS by the same principal in this chain (read-before-derive).
  grounded_document_hashes?: string[] | null;
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
  /** Conformance profile read from the root ASSIGNMENTs (§5.2): highest of A/B/C present. */
  conformanceProfile: 'A' | 'B' | 'C' | 'unknown';
  firstLineageViolation: { sequenceNumber: string; reason: string } | null;
  firstScopeViolation: { sequenceNumber: string; reason: string } | null;
  firstGroundingViolation: { sequenceNumber: string; reason: string } | null;
  firstAuthorityViolation: { sequenceNumber: string; reason: string } | null;
  firstSignatureViolation: { sequenceNumber: string; reason: string } | null;
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
function walkLineage(
  startParentHash: string,
  index: Map<string, ValBlock>,
): { ok: boolean; scopes: ScopePredicate[]; profile: 'A' | 'unknown'; reason: string | null } {
  const scopes: ScopePredicate[] = [];
  let cursor: string | null = startParentHash;
  let depth = 0;
  while (cursor) {
    if (++depth > MAX_LINEAGE_DEPTH) {
      return { ok: false, scopes, profile: 'unknown', reason: `lineage exceeds max depth ${MAX_LINEAGE_DEPTH}` };
    }
    const a = index.get(cursor);
    if (!a) {
      return { ok: false, scopes, profile: 'unknown', reason: `parent_assignment_hash '${cursor.slice(0, 12)}…' references no ASSIGNMENT in the chain (orphan)` };
    }
    if (a.block_type !== 'ASSIGNMENT') {
      return { ok: false, scopes, profile: 'unknown', reason: `parent_assignment_hash resolves to a ${a.block_type}, not an ASSIGNMENT` };
    }
    if (a.scope) scopes.push(a.scope);
    const next: string | null = a.parent_assignment_hash ?? null;
    if (!next) {
      // root ASSIGNMENT — require human attestation (Profile A).
      if (!a.human_attestation) {
        return { ok: false, scopes, profile: 'unknown', reason: 'root ASSIGNMENT has no human_attestation (not human-rooted)' };
      }
      return { ok: true, scopes, profile: 'A', reason: null };
    }
    cursor = next;
  }
  return { ok: false, scopes, profile: 'unknown', reason: 'lineage terminated without a root ASSIGNMENT' };
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
  options?: { delegatorAuthorityPolicy?: DelegatorAuthorityPolicy },
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
    firstLineageViolation: null,
    firstScopeViolation: null,
    firstGroundingViolation: null,
    firstAuthorityViolation: null,
    firstSignatureViolation: null,
    legacyPreAuthorityAssignmentCount: 0,
    nonValBlockCount: 0,
  };

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
      if (walk.profile === 'A') profiles.add('A');

      // ── Pass 3 — scope (effective = satisfy every ASSIGNMENT scope on the path) ──
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
      // integrity/lineage/...). device_bound vs syncable is surfaced verbatim, never rounded up.
      {
        const dsig = block.human_attestation?.delegator_authority?.signature;
        if (dsig) {
          const oroot = block.human_attestation?.delegator_authority?.org_root ?? null;
          const tc = await verifyDelegationTrustChain(dsig, oroot);
          if (tc.outcome === 'qualified_unverified') {
            // Profile C: CLASSIFIED (declared). Its crypto verification needs a QTSP trust
            // list — a future trust-anchor input, never a silent default. Conformance
            // reflects C; the signature pass is left unchanged (not green, not red).
            profiles.add('C');
          } else if (tc.signatureValid && tc.linkageVerified) {
            // Only a VERIFIED + org-root-LINKED signature earns conformance B.
            profiles.add('B');
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
        if (walk.profile === 'A') profiles.add('A');
      } else if (!block.human_attestation) {
        if (result.lineage === 'green') {
          result.lineage = 'red';
          result.firstLineageViolation = { sequenceNumber: seqStr, reason: 'root ASSIGNMENT has no human_attestation (not human-rooted)' };
        }
      } else {
        profiles.add('A');
      }
    }
  }

  // Conformance = the highest profile declared by the chain's ASSIGNMENTs (§5.2): a
  // verified device/qualified binding (B/C) supersedes the operator-attested residual (A).
  result.conformanceProfile = profiles.has('C')
    ? 'C'
    : profiles.has('B')
      ? 'B'
      : profiles.has('A')
        ? 'A'
        : 'unknown';
  return result;
}
