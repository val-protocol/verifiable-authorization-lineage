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

import { createHash } from 'crypto';

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
export function reconstructChainHash(args: {
  scopeKey: string;
  sequenceNumber: number | bigint;
  eventType: string;
  canonicalDetails: string;
  previousHash: string | null;
}): string {
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
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
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
export function computeMembershipRoot(contentHashes: string[]): string | null {
  const set = Array.from(new Set(contentHashes.filter((h) => h != null)));
  set.sort(); // bytewise on ASCII-hex; matches PG ORDER BY ... COLLATE "C"
  if (set.length === 0) return null;
  let level: Buffer[] = set.map((h) => createHash('sha256').update(h, 'utf8').digest());
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(createHash('sha256').update(Buffer.concat([level[i], level[i + 1]])).digest());
      } else {
        next.push(level[i]);
      }
    }
    level = next;
  }
  return level[0].toString('hex');
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
export function verifyMembershipProof(
  contentHash: string,
  proof: MembershipProofStep[],
  expectedRoot: string,
): boolean {
  let cur: Buffer = createHash('sha256').update(contentHash, 'utf8').digest();
  for (const step of proof) {
    const sib = Buffer.from(step.hash, 'hex');
    cur =
      step.side === 'L'
        ? createHash('sha256').update(Buffer.concat([sib, cur])).digest()
        : createHash('sha256').update(Buffer.concat([cur, sib])).digest();
  }
  return cur.toString('hex') === expectedRoot;
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
export function verifyChain(rows: ChainRow[]): VerificationResult {
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
    const expected = reconstructChainHash({
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

/**
 * Delegator-authority carrier on an ASSIGNMENT's human_attestation (§5.2 / Pass 5).
 * Records the authority basis under which the attesting human could grant the delegated
 * scope. `signature` is the RESERVED Profile B/C binding slot — absent under Profile A,
 * where the claim carries the profile's operator-attested residual trust.
 */
export interface ValBlockDelegatorAuthority {
  basis?: string;
  capability?: string;
  scope_ref?: string;
  signature?: unknown;
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
  scope?: ScopePredicate;
  human_attestation?: { method?: string; delegator_authority?: ValBlockDelegatorAuthority } | null;
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
  /** Conformance profile read from the root ASSIGNMENTs (§5.2). */
  conformanceProfile: 'A' | 'B' | 'C' | 'unknown';
  firstLineageViolation: { sequenceNumber: string; reason: string } | null;
  firstScopeViolation: { sequenceNumber: string; reason: string } | null;
  firstGroundingViolation: { sequenceNumber: string; reason: string } | null;
  firstAuthorityViolation: { sequenceNumber: string; reason: string } | null;
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
function satisfies(block: ValBlock, scope: ScopePredicate): { ok: boolean; reason: string | null } {
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
    if (!verifyMembershipProof(ch, block.membership_proof, res.isolation_commitment)) {
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
 * (the §7.1(d) trust-anchor input) is supplied. `options` is additive; existing
 * callers are unaffected. Input MUST be the same partitioned, sorted, contiguous
 * slice verifyChain requires.
 */
export function verifyValChain(
  rows: ChainRow[],
  options?: { delegatorAuthorityPolicy?: DelegatorAuthorityPolicy },
): ValVerificationResult {
  const result: ValVerificationResult = {
    integrity: 'green',
    lineage: 'green',
    scope: 'green',
    grounding: 'green',
    authority: 'none',
    conformanceProfile: 'unknown',
    firstLineageViolation: null,
    firstScopeViolation: null,
    firstGroundingViolation: null,
    firstAuthorityViolation: null,
    legacyPreAuthorityAssignmentCount: 0,
    nonValBlockCount: 0,
  };

  // Pass 1 — integrity.
  const integrity = verifyChain(rows);
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
        const sat = satisfies(block, scope);
        if (!sat.ok) {
          if (result.scope === 'green') {
            result.scope = 'red';
            result.firstScopeViolation = { sequenceNumber: seqStr, reason: sat.reason ?? 'scope violation' };
          }
          break;
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

  if (profiles.size === 1) result.conformanceProfile = [...profiles][0] as 'A';
  return result;
}
