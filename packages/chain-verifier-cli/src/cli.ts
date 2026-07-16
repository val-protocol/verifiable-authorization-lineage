#!/usr/bin/env node
/**
 * val-verify — CLI wrapper for @val-protocol/chain-verifier.
 *
 * Two modes:
 *
 *   File:  val-verify --export=./chain.ndjson
 *          Reads local NDJSON, runs verifier row-by-row, prints
 *          PASS/FAIL per row. On FAIL: prints expected vs observed hash.
 *
 *   URL:   val-verify --audit-export-url=<MCP_URL> \
 *                      --bearer=<TOKEN> \
 *                      --dataroom-id=<UUID>
 *          POSTs MCP tools/call to the URL with name='audit.export',
 *          paginates internally to drain the chain, verifies inline.
 *          No file is written to disk.
 *
 * Exit code: 0 on all rows PASS; 1 on any FAIL.
 *
 * Thin wrapper — under 200 lines. The verification logic lives entirely
 * in @val-protocol/chain-verifier; this CLI does argument parsing, I/O, and
 * per-row output formatting.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  reconstructChainHash,
  verifyValChain,
  ChainRow,
} from '@val-protocol/chain-verifier';
import { buildHtmlReport } from './report.js';

interface Args {
  export?: string;
  auditExportUrl?: string;
  bearer?: string;
  dataroomId?: string;
  html?: string;
  trust?: string;
  limit: number;
  quiet: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { limit: 100, quiet: false, help: false };
  for (const a of argv) {
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--quiet' || a === '-q') out.quiet = true;
    else if (a.startsWith('--export=')) out.export = a.slice('--export='.length);
    else if (a.startsWith('--audit-export-url=')) out.auditExportUrl = a.slice('--audit-export-url='.length);
    else if (a.startsWith('--bearer=')) out.bearer = a.slice('--bearer='.length);
    else if (a.startsWith('--dataroom-id=')) out.dataroomId = a.slice('--dataroom-id='.length);
    else if (a.startsWith('--html=')) out.html = a.slice('--html='.length);
    else if (a.startsWith('--trust=')) out.trust = a.slice('--trust='.length);
    else if (a.startsWith('--limit=')) out.limit = parseInt(a.slice('--limit='.length), 10);
  }
  return out;
}

function printHelp(): void {
  process.stdout.write(`val-verify — verify a VAL audit.export NDJSON chain.

Usage:
  val-verify --export=<path>
  val-verify --audit-export-url=<MCP_URL> --bearer=<TOKEN> --dataroom-id=<UUID> [--limit=N]

Options:
  --export=<path>            Local NDJSON file. One JSON object per line, ASC by
                             sequence_number, all rows from the same scope_key.
  --audit-export-url=<url>   The MCP endpoint URL of a running VAL operator backend
                             (typically https://<host>/api/mcp/records).
  --bearer=<token>           OAuth access token with the operator's audit-export scope.
  --dataroom-id=<uuid>       Workspace to export and verify.
  --limit=N                  Page size for URL mode (default 100, max 1000).
  --html=<path>              Also run the FULL VAL verification (all passes) and write a
                             single-file, self-verifying HTML report: it embeds the chain
                             bytes and the reference verifier, and re-derives every pass in
                             the reader's browser on open — offline, zero operator reads.
  --trust=<path>             JSON file of §7.1 trust-anchor inputs passed to verifyValChain
                             and embedded in the report. Shape (all optional):
                             { "delegatorAuthorityPolicy": {...}, "anchorTrust": {...},
                               "qesValidation": {...}, "bytesDisclosures": [...] }
  --quiet, -q                Suppress per-row PASS lines; print only FAIL lines
                             and the final summary.
  --help, -h                 Show this help.

Exit code: 0 if all rows verify; 1 if any row fails (with --html: also if any
VAL pass is red or an opt-in pass reports mismatch).
`);
}

function parseLine(line: string): ChainRow {
  const parsed = JSON.parse(line);
  return {
    scope_key: parsed.scope_key,
    sequence_number: parsed.sequence_number,
    event_type: parsed.event_type,
    canonical_details: parsed.canonical_details,
    previous_hash: parsed.previous_hash,
    chain_hash: parsed.chain_hash,
  };
}

async function fetchAuditExport(
  url: string,
  bearer: string,
  dataroomId: string,
  limit: number,
): Promise<ChainRow[]> {
  const all: ChainRow[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < 1000; page += 1) {
    const args: Record<string, unknown> = { dataroom_id: dataroomId, limit };
    if (cursor) args.cursor = cursor;
    const body = {
      jsonrpc: '2.0',
      id: page + 1,
      method: 'tools/call',
      params: { name: 'audit.export', arguments: args },
    };
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${bearer}`,
      },
      body: JSON.stringify(body),
    });
    const raw = await resp.text();
    let parsed: unknown = null;
    const sse = raw.match(/^data:\s*(\{.*\})\s*$/m);
    try {
      parsed = sse ? JSON.parse(sse[1]) : JSON.parse(raw);
    } catch {
      throw new Error(`could not parse MCP response (HTTP ${resp.status}): ${raw.slice(0, 200)}`);
    }
    const content = (parsed as any)?.result?.content as Array<{ text: string }>;
    if (!content || content.length < 2) {
      const errText = (parsed as any)?.result?.content?.[0]?.text ?? '<no payload>';
      throw new Error(`audit.export error: ${errText}`);
    }
    const pagination = JSON.parse(content[0].text);
    const ndjson = content[1].text ?? '';
    if (ndjson.length > 0) {
      for (const line of ndjson.split('\n')) {
        if (line.length === 0) continue;
        all.push(parseLine(line));
      }
    }
    cursor = pagination.next_cursor ?? null;
    if (cursor === null) break;
  }
  return all;
}

async function verifyRows(rows: ChainRow[], quiet: boolean): Promise<{ failed: number }> {
  let failed = 0;
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];

    if (i === 0 && BigInt(row.sequence_number) === 1n && row.previous_hash !== null) {
      process.stdout.write(`seq=${row.sequence_number} event=${row.event_type} FAIL\n`);
      process.stdout.write(`  reason: genesis row (sequence_number=1) must have previous_hash=null\n`);
      failed += 1;
      continue;
    }

    if (i > 0) {
      const prevSeq = BigInt(rows[i - 1].sequence_number);
      const thisSeq = BigInt(row.sequence_number);
      if (thisSeq !== prevSeq + 1n) {
        process.stdout.write(`seq=${row.sequence_number} event=${row.event_type} FAIL\n`);
        process.stdout.write(`  reason: sequence_number gap (prior=${prevSeq}, this=${thisSeq})\n`);
        failed += 1;
        continue;
      }
      if (row.previous_hash !== rows[i - 1].chain_hash) {
        process.stdout.write(`seq=${row.sequence_number} event=${row.event_type} FAIL\n`);
        process.stdout.write(`  reason: previous_hash linkage broken\n`);
        process.stdout.write(`  row says:        ${row.previous_hash}\n`);
        process.stdout.write(`  prior chain_hash: ${rows[i - 1].chain_hash}\n`);
        failed += 1;
        continue;
      }
    }

    const expected = await reconstructChainHash({
      scopeKey: row.scope_key,
      sequenceNumber: row.sequence_number,
      eventType: row.event_type,
      canonicalDetails: row.canonical_details,
      previousHash: row.previous_hash,
    });
    if (expected !== row.chain_hash) {
      process.stdout.write(`seq=${row.sequence_number} event=${row.event_type} FAIL\n`);
      process.stdout.write(`  reason: chain_hash mismatch\n`);
      process.stdout.write(`  expected: ${expected}\n`);
      process.stdout.write(`  observed: ${row.chain_hash}\n`);
      failed += 1;
      continue;
    }
    if (!quiet) {
      process.stdout.write(`seq=${row.sequence_number} event=${row.event_type} PASS\n`);
    }
  }
  return { failed };
}

/** Locate the installed @val-protocol/chain-verifier ESM build + version, for embedding
 *  into the self-verifying report. Resolves via the `import` condition where available;
 *  falls back to the `require` resolution with the package's fixed dist/cjs → dist/esm layout. */
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
  const source = readFileSync(esmPath, 'utf-8');
  let version = 'unknown';
  try {
    const pkg = JSON.parse(readFileSync(join(dirname(esmPath), '..', '..', 'package.json'), 'utf-8')) as {
      version?: string;
    };
    version = pkg.version ?? 'unknown';
  } catch {
    /* display-only field — the embedded source is the authority */
  }
  return { source, version };
}

/** Run the full VAL verification (all passes), print the §7.3 summary, and — when
 *  `htmlPath` is set — write the self-verifying HTML report. Returns false on any red
 *  pass or opt-in mismatch. */
async function runValVerification(
  rows: ChainRow[],
  ndjson: string,
  htmlPath: string,
  trustPath: string | undefined,
): Promise<boolean> {
  const trust = trustPath ? (JSON.parse(readFileSync(trustPath, 'utf-8')) as Record<string, unknown>) : null;
  const r = await verifyValChain(rows, (trust ?? undefined) as Parameters<typeof verifyValChain>[1]);

  process.stdout.write('\n── VAL verification (§7.2) ──\n');
  const line = (k: string, v: string, viol?: { sequenceNumber: string; reason: string } | null): void => {
    process.stdout.write(`${k.padEnd(18)} ${v}${viol ? `   (first: seq ${viol.sequenceNumber} — ${viol.reason})` : ''}\n`);
  };
  line('integrity', r.integrity);
  line('lineage', r.lineage, r.firstLineageViolation);
  line('scope', r.scope, r.firstScopeViolation);
  line('grounding', r.grounding, r.firstGroundingViolation);
  line('authority', r.authority, r.firstAuthorityViolation);
  line('signature', r.signature, r.firstSignatureViolation);
  line('anchor', r.anchorBinding, r.firstAnchorViolation);
  line('bytes-binding', r.bytesBinding, r.firstBytesBindingViolation);
  line('profile (floor)', `${r.conformanceProfile}   present: ${r.profilesPresent.join(', ') || '—'}`);

  const { source, version } = loadVerifierAsset();
  const html = buildHtmlReport({
    ndjson,
    verifierSource: source,
    verifierVersion: version,
    trust,
    generatedAt: new Date().toISOString(),
  });
  writeFileSync(htmlPath, html);
  process.stdout.write(`\nself-verifying report → ${htmlPath}\n`);

  const coreOk = r.integrity === 'green' && r.lineage === 'green' && r.scope === 'green' && r.grounding === 'green';
  const extOk =
    r.authority !== 'red' && r.signature !== 'red' && r.anchorBinding !== 'mismatch' && r.bytesBinding !== 'mismatch';
  return coreOk && extOk;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || (!args.export && !args.auditExportUrl)) {
    printHelp();
    process.exit(args.help ? 0 : 2);
  }

  let rows: ChainRow[];
  let ndjson: string;
  if (args.export) {
    ndjson = readFileSync(args.export, 'utf-8').trim();
    rows = ndjson.length === 0 ? [] : ndjson.split('\n').map(parseLine);
  } else {
    if (!args.auditExportUrl || !args.bearer || !args.dataroomId) {
      process.stderr.write('URL mode requires --audit-export-url, --bearer, and --dataroom-id\n');
      process.exit(2);
    }
    rows = await fetchAuditExport(
      args.auditExportUrl,
      args.bearer,
      args.dataroomId,
      args.limit,
    );
    ndjson = rows.map((r) => JSON.stringify(r)).join('\n');
  }

  const { failed } = await verifyRows(rows, args.quiet);
  const passed = rows.length - failed;
  process.stdout.write(`\n── ${passed}/${rows.length} PASS, ${failed} FAIL ──\n`);

  let valOk = true;
  if (args.html) {
    valOk = await runValVerification(rows, ndjson, args.html, args.trust);
  }
  process.exit(failed === 0 && valOk ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`val-verify error: ${(e as Error).message}\n`);
  process.exit(3);
});
