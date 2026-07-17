#!/usr/bin/env node
/**
 * val-demo — mint a live VAL chain and attack it, in your terminal.
 *
 * Act 0  mints a fresh Profile-B chain: a human (Alice) roots two grants with a
 *        P-256 device-style key — one delegating scoped read/write to an agent,
 *        one keeping sign-class authority to herself — then the agent reads a
 *        document, derives a record from it, and Alice signs a consent bond.
 * Act 1  EDITS one committed block            → integrity red (any hash chain catches this).
 * Act 2  REWRITES the whole history           → integrity green… signature red. This is the
 *        attack tamper-evident logging alone does NOT catch — the seam VAL exists for.
 * Act 3  STRIPS the signatures                → everything green, but the profile floor drops
 *        B → A: forgery cannot be hidden, only demoted, and the report says so.
 * Act 4  SILENTLY TRUNCATES the tail          → all green. Honest boundary: a self-held chain
 *        cannot prove completeness — that is §8 external anchoring's job.
 *
 * Every act ASSERTS its expected verdict — the demo doubles as an integration test.
 * Keys are generated in-process and discarded; because a software key carries no verified
 * hardware attestation, the chain honestly declares key_binding: 'unattested' (§5.2 —
 * producers MUST NOT claim device_bound without a verified attestation statement).
 *
 * Flags: --out=<chain.ndjson>  write the pristine chain
 *        --html=<report.html>  write the self-verifying HTML report for it
 */

import { generateKeyPairSync, createHash, createSign, randomBytes, webcrypto, KeyObject } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  verifyValChain,
  reconstructChainHash,
  orgRootBindingChallenge,
  type ChainRow,
  type ValVerificationResult,
  type ValDelegatorSignature,
  type ValOrgRootAttestation,
  type DelegatorAuthorityPolicy,
} from '@val-protocol/chain-verifier';
import { buildHtmlReport } from '@val-protocol/chain-verifier-cli/report';

const g = globalThis as { crypto?: unknown };
if (!g.crypto) g.crypto = webcrypto;

const SCOPE_KEY = 'val-demo';
const WORKSPACE = 'ws-demo';
const AGENT = 'agent:demo-assistant';
const ALICE = 'user:alice-demo';

// §7.1(d) trust-anchor input — what a holder of this capability may delegate.
const POLICY: DelegatorAuthorityPolicy = {
  org_verified_representative: ['read', 'record.append', 'sign'],
};

const b64 = (b: Buffer): string => b.toString('base64');
const sha256hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
const b64url = (b: Buffer): string => b.toString('base64url');

/** Minimal RFC 8785 canonical JSON (sorted keys) for the block bodies this demo mints. */
function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return '{' + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ':' + jcs(obj[k])).join(',') + '}';
}

interface DemoKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

const spkiB64 = (pub: KeyObject): string => b64(pub.export({ format: 'der', type: 'spki' }) as Buffer);

/** A WebAuthn-shaped ES256 assertion over `challenge` — the §5.2 instrument shape. */
function signAssertion(challenge: string, key: DemoKey): ValDelegatorSignature {
  const clientDataJson = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://demo.val-protocol.local', crossOrigin: false }),
    'utf8',
  );
  const authenticatorData = randomBytes(37);
  const signedBytes = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJson).digest()]);
  const s = createSign('sha256');
  s.update(signedBytes);
  s.end();
  return {
    alg: 'webauthn',
    credential_id: 'val-demo-key',
    public_key: spkiB64(key.publicKey),
    authenticator_data: b64(authenticatorData),
    client_data_json: b64(clientDataJson),
    signature: b64(s.sign({ key: key.privateKey, dsaEncoding: 'der' }) as Buffer),
  };
}

interface BodyRow {
  event: string;
  body: Record<string, unknown>;
}

/** Rebuild a full, internally-consistent chain from block bodies (what an operator —
 *  or an attacker WITH database access — can always do: recompute every hash). */
async function buildChain(bodies: BodyRow[]): Promise<ChainRow[]> {
  const rows: ChainRow[] = [];
  let prev: string | null = null;
  for (let i = 0; i < bodies.length; i += 1) {
    const canonical_details = jcs(bodies[i].body);
    const chain_hash = await reconstructChainHash({
      scopeKey: SCOPE_KEY,
      sequenceNumber: i + 1,
      eventType: bodies[i].event,
      canonicalDetails: canonical_details,
      previousHash: prev,
    });
    rows.push({
      scope_key: SCOPE_KEY,
      sequence_number: i + 1,
      event_type: bodies[i].event,
      canonical_details,
      previous_hash: prev,
      chain_hash,
    });
    prev = chain_hash;
  }
  return rows;
}

const deep = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** Rebuild a chain from (possibly mutated) bodies the way a COMPETENT attacker with
 *  store access would: recompute every hash AND re-point each action block's
 *  `parent_assignment_hash` at the rewritten grant's new hash, so the forged chain is
 *  internally consistent. What they cannot re-forge is any signature bound to the old
 *  hashes — that is the point. */
async function rebuildRelinked(bodies: BodyRow[], originalRows: ChainRow[]): Promise<ChainRow[]> {
  const oldToNew = new Map<string, string>();
  const rows: ChainRow[] = [];
  let prev: string | null = null;
  for (let i = 0; i < bodies.length; i += 1) {
    const body = deep(bodies[i].body);
    const parent = body.parent_assignment_hash;
    if (typeof parent === 'string' && oldToNew.has(parent)) {
      body.parent_assignment_hash = oldToNew.get(parent);
    }
    const canonical_details = jcs(body);
    const chain_hash = await reconstructChainHash({
      scopeKey: SCOPE_KEY,
      sequenceNumber: i + 1,
      eventType: bodies[i].event,
      canonicalDetails: canonical_details,
      previousHash: prev,
    });
    oldToNew.set(originalRows[i].chain_hash, chain_hash);
    rows.push({
      scope_key: SCOPE_KEY,
      sequence_number: i + 1,
      event_type: bodies[i].event,
      canonical_details,
      previous_hash: prev,
      chain_hash,
    });
    prev = chain_hash;
  }
  return rows;
}

interface Minted {
  bodies: BodyRow[];
  rows: ChainRow[];
}

async function mint(): Promise<Minted> {
  const alice: DemoKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const subjectHash = sha256hex('alice-demo');
  const assurance = { source: 'self_asserted', subject_claim: 'Alice' };

  // Enrolled self-attestation of Alice's key. HONEST: a software key has no verified
  // hardware attestation, so key_binding is 'unattested' — §5.2 forbids claiming more.
  const orgRootBase = {
    org_id: 'org-demo',
    signatory_identity_hash: subjectHash,
    public_key: spkiB64(alice.publicKey),
    identity_assurance: assurance,
    key_binding: 'unattested' as const,
  };
  const org_root: ValOrgRootAttestation = {
    ...orgRootBase,
    self_signature: signAssertion(await orgRootBindingChallenge(orgRootBase as ValOrgRootAttestation), alice),
  };

  const attestation = (grantRef: string) => ({
    method: 'webauthn',
    subject_user_hash: subjectHash,
    identity_assurance: assurance,
    delegator_authority: {
      basis: 'org_verified_representative',
      capability: 'org_verified_representative',
      scope_ref: WORKSPACE,
      signature: signAssertion(b64url(createHash('sha256').update(grantRef, 'utf8').digest()), alice),
      org_root: deep(org_root),
    },
  });

  // Grant 1 — Alice delegates scoped read + record.append to the agent (v3: names its grantee).
  const grantAgent: BodyRow = {
    event: 'assign',
    body: {
      v: 3,
      block_type: 'ASSIGNMENT',
      grantee: AGENT,
      scope: { act: ['read', 'record.append'], res: { in_workspace: WORKSPACE } },
      human_attestation: attestation('grant:agent'),
    },
  };
  // Grant 2 — sign-class authority stays with Alice herself (actes personnels do not delegate).
  const grantAlice: BodyRow = {
    event: 'assign',
    body: {
      v: 3,
      block_type: 'ASSIGNMENT',
      grantee: ALICE,
      scope: { act: ['sign'], res: { in_workspace: WORKSPACE } },
      human_attestation: attestation('grant:alice'),
    },
  };

  // Two-pass build: action blocks reference grant hashes.
  let rows = await buildChain([grantAgent, grantAlice]);
  const [hAgentGrant, hAliceGrant] = [rows[0].chain_hash, rows[1].chain_hash];

  const docHash = sha256hex('demo-document-v1');
  const access: BodyRow = {
    event: 'read',
    body: {
      v: 1,
      block_type: 'ACCESS',
      parent_assignment_hash: hAgentGrant,
      action: 'read',
      principal: AGENT,
      resource: { content_hash: docHash, resource_id: 'doc-brief', in_workspace: WORKSPACE },
    },
  };
  const mutation: BodyRow = {
    event: 'record.append',
    body: {
      v: 1,
      block_type: 'MUTATION',
      parent_assignment_hash: hAgentGrant,
      action: 'record.append',
      principal: AGENT,
      resource: { content_hash: sha256hex('derived-record-v1'), resource_id: 'rec-1', in_workspace: WORKSPACE },
      grounded_document_hashes: [docHash],
    },
  };
  const consentDocHash = sha256hex('engagement-terms-v1');
  const consent: BodyRow = {
    event: 'sign',
    body: {
      v: 1,
      block_type: 'CONSENT',
      parent_assignment_hash: hAliceGrant,
      action: 'sign',
      principal: ALICE,
      document_hash: consentDocHash,
      signature: signAssertion(
        b64url(
          createHash('sha256')
            .update(jcs({ document_hash: consentDocHash, parent_assignment_hash: hAliceGrant, principal: ALICE }), 'utf8')
            .digest(),
        ),
        alice,
      ),
    },
  };

  const bodies = [grantAgent, grantAlice, access, mutation, consent];
  rows = await buildChain(bodies);
  return { bodies, rows };
}

// ── output helpers ────────────────────────────────────────────────────────────
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';
const tty = process.stdout.isTTY === true;
const paint = (code: string, s: string): string => (tty ? code + s + RESET : s);

function heading(s: string): void {
  process.stdout.write('\n' + paint(BOLD, s) + '\n');
}
function say(s: string): void {
  process.stdout.write(s + '\n');
}
function verdictLine(r: ValVerificationResult): void {
  const chip = (v: string): string =>
    v === 'green' || v === 'verified' || v === 'bound'
      ? paint(GREEN, v)
      : v === 'red' || v === 'mismatch'
        ? paint(RED, v)
        : paint(DIM, v);
  say(
    `  integrity ${chip(r.integrity)} · lineage ${chip(r.lineage)} · scope ${chip(r.scope)} · grounding ${chip(
      r.grounding,
    )} · authority ${chip(r.authority)} · signature ${chip(r.signature)} · profile floor ${paint(BOLD, r.conformanceProfile)}`,
  );
}

let failures = 0;
function expect(cond: boolean, what: string): void {
  if (cond) {
    say('  ' + paint(GREEN, '✔') + ' ' + what);
  } else {
    failures += 1;
    say('  ' + paint(RED, '✘ EXPECTATION FAILED: ') + what);
  }
}

function loadVerifierAsset(): { source: string; version: string } {
  const require = createRequire(import.meta.url);
  let esmPath: string;
  try {
    esmPath = fileURLToPath(import.meta.resolve('@val-protocol/chain-verifier'));
  } catch {
    esmPath = require
      .resolve('@val-protocol/chain-verifier')
      .replace(`${sep}dist${sep}cjs${sep}`, `${sep}dist${sep}esm${sep}`);
  }
  let version = 'unknown';
  try {
    version = (JSON.parse(readFileSync(join(dirname(esmPath), '..', '..', 'package.json'), 'utf-8')) as { version?: string })
      .version ?? 'unknown';
  } catch {
    /* display-only */
  }
  return { source: readFileSync(esmPath, 'utf-8'), version };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const outPath = args.find((a) => a.startsWith('--out='))?.slice('--out='.length);
  const htmlPath = args.find((a) => a.startsWith('--html='))?.slice('--html='.length);

  heading('VAL demo — records prove what your agents did; VAL proves they were allowed to.');
  say(paint(DIM, 'Minting a fresh chain: Alice roots two grants with a P-256 key generated right now;'));
  say(paint(DIM, 'her agent reads a document and derives a record from it; Alice signs a consent bond.'));
  say(paint(DIM, "A software key has no verified hardware attestation, so the chain honestly declares"));
  say(paint(DIM, "key_binding: 'unattested' — §5.2 forbids claiming device_bound without proof."));

  const { bodies, rows } = await mint();
  const ndjson = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';

  heading('Act 0 — verify the pristine chain (offline: chain bytes + pinned capability policy only)');
  const r0 = await verifyValChain(rows, { delegatorAuthorityPolicy: POLICY });
  verdictLine(r0);
  expect(
    r0.integrity === 'green' && r0.lineage === 'green' && r0.scope === 'green' && r0.grounding === 'green',
    'core four properties green',
  );
  expect(r0.authority === 'green', 'delegator authority green (scope ⊆ what the capability may delegate)');
  expect(r0.signature === 'green', "root signatures verify and chain to Alice's enrolled key");
  expect(r0.conformanceProfile === 'B', `conformance floor B — device-key-signed human root (got ${r0.conformanceProfile})`);
  expect(r0.consentBonds.length === 1 && r0.consentBonds[0].signatureValid, 'consent bond itemized, instrument grade B, signature valid');

  heading('Act 1 — EDIT one committed block (change what the agent derived)');
  {
    const t = deep(rows);
    t[3].canonical_details = t[3].canonical_details.replace('rec-1', 'rec-X');
    const r = await verifyValChain(t, { delegatorAuthorityPolicy: POLICY });
    verdictLine(r);
    expect(r.integrity === 'red', 'integrity red — any hash chain catches an in-place edit');
  }

  heading('Act 2 — REWRITE the whole history (recompute every hash, upgrade the key claim)');
  say(paint(DIM, "The attacker controls the store: they relabel Alice's key_binding 'unattested' →"));
  say(paint(DIM, "'device_bound' (claiming hardware assurance never proven) and re-hash the entire chain."));
  {
    const forged = deep(bodies);
    for (const i of [0, 1]) {
      const ha = forged[i].body.human_attestation as { delegator_authority: { org_root: { key_binding: string } } };
      ha.delegator_authority.org_root.key_binding = 'device_bound';
    }
    const t = await rebuildRelinked(forged, rows);
    const r = await verifyValChain(t, { delegatorAuthorityPolicy: POLICY });
    verdictLine(r);
    expect(r.integrity === 'green' && r.lineage === 'green', 'integrity AND lineage GREEN — a tamper-evident log alone calls this rewritten chain intact');
    expect(r.signature === 'red', 'signature red — the self-attestation binding challenge no longer verifies');
    expect(r.conformanceProfile !== 'B', 'the forged chain can no longer claim Profile B');
    say(paint(BOLD, '  ⇒ This is the attack hash-chaining alone does not catch. The seam VAL exists for.'));
  }

  heading('Act 3 — STRIP the signatures (present the chain as if never signed)');
  say(paint(DIM, "The attacker must also DROP Alice's consent bond: its per-action signature binds the"));
  say(paint(DIM, 'original grant hash, and they cannot re-sign it — a consent bond is a lineage pin too.'));
  {
    const stripped = deep(bodies).slice(0, 4);
    for (const i of [0, 1]) {
      const da = (stripped[i].body.human_attestation as { delegator_authority: Record<string, unknown> }).delegator_authority;
      delete da.signature;
      delete da.org_root;
    }
    const t = await rebuildRelinked(stripped, rows);
    const r = await verifyValChain(t, { delegatorAuthorityPolicy: POLICY });
    verdictLine(r);
    expect(
      r.integrity === 'green' && r.lineage === 'green' && r.scope === 'green' && r.signature === 'none',
      'everything still green, signature NONE…',
    );
    expect(r.conformanceProfile === 'A', '…but the floor drops B → A: human-ATTRIBUTED, no longer human-SIGNED');
    say(paint(BOLD, '  ⇒ Forgery cannot be hidden — only demoted. A relying party expecting B rejects this report.'));
  }

  heading('Act 4 — SILENTLY TRUNCATE the tail (drop the consent bond, present the prefix)');
  {
    const t = deep(rows).slice(0, 4);
    const r = await verifyValChain(t, { delegatorAuthorityPolicy: POLICY });
    verdictLine(r);
    expect(r.integrity === 'green', 'integrity green — a valid prefix is a valid chain');
    say(paint(DIM, '  Honest boundary: a self-held chain cannot prove completeness. That is what the §8'));
    say(paint(DIM, '  external anchor is for — an independent RFC 3161 timestamp authority holds the head,'));
    say(paint(DIM, '  so committed history cannot be re-cut after the fact. No record system self-certifies coverage.'));
  }

  if (outPath) {
    writeFileSync(outPath, ndjson);
    say('\npristine chain → ' + outPath + '   (verify: npx @val-protocol/chain-verifier-cli --export=' + outPath + ')');
  }
  if (htmlPath) {
    const { source, version } = loadVerifierAsset();
    writeFileSync(
      htmlPath,
      buildHtmlReport({
        ndjson,
        verifierSource: source,
        verifierVersion: version,
        trust: { delegatorAuthorityPolicy: POLICY },
        generatedAt: new Date().toISOString(),
        title: 'VAL Demo — Verification Report',
      }),
    );
    say('self-verifying report → ' + htmlPath + '   (open it: verification re-runs in your browser)');
  }

  heading(failures === 0 ? 'All acts behaved exactly as the protocol specifies.' : `${failures} EXPECTATION(S) FAILED`);
  say(paint(DIM, 'Spec: https://github.com/val-protocol/verifiable-authorization-lineage — Apache-2.0.'));
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`val-demo error: ${(e as Error).stack ?? String(e)}\n`);
  process.exit(3);
});
