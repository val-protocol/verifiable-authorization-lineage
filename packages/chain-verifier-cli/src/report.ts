/**
 * Self-verifying HTML report for a VAL chain (val-verify --html).
 *
 * The emitted document is a SINGLE self-contained file that embeds (a) the exact
 * chain bytes (NDJSON, base64), (b) the §7.1 trust-anchor inputs supplied at
 * generation time, and (c) the full ESM source of @val-protocol/chain-verifier.
 * On every open, the reader's browser dynamically imports the embedded verifier
 * (via a `data:` module URL) and re-runs all verification passes over the embedded
 * bytes — the report does not ASSERT a verdict, it RE-DERIVES one in front of the
 * reader. No network request is made; the file works on an air-gapped machine.
 *
 * The Node-side CLI never injects a precomputed verdict into the document: a
 * tampered generator could lie in prose, but the pass chips are painted from the
 * in-browser run, and the embedded chain + verifier can each be downloaded and
 * re-verified independently (`npx @val-protocol/chain-verifier-cli --export=…`).
 */

export interface ReportInputs {
  /** Exact NDJSON chain bytes (one JSON row per line) — embedded verbatim, base64. */
  ndjson: string;
  /** Full ESM source of @val-protocol/chain-verifier — embedded, imported via data: URL. */
  verifierSource: string;
  /** Version string of the embedded verifier (display only). */
  verifierVersion: string;
  /** §7.1 trust-anchor inputs passed to verifyValChain (verbatim; null = none supplied). */
  trust?: unknown | null;
  /** Generation instant, ISO 8601 (display only — the verdict is re-derived at open time). */
  generatedAt: string;
  /** Optional report title. */
  title?: string;
}

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64');

/** JSON safe to inline inside a <script> element (escapes `<` so `</script>` cannot occur). */
const scriptJson = (v: unknown): string => JSON.stringify(v).replace(/</g, '\\u003c');

const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a202c;--muted:#5a6472;--line:#e2e6eb;
--green:#0f7b3f;--green-bg:#e7f5ec;--red:#b42318;--red-bg:#fdecea;--neutral:#5a6472;--neutral-bg:#eef1f4;
--accent:#1f3a5f;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#12151a;--card:#1a1f27;--ink:#e8ecf1;--muted:#9aa5b1;
--line:#2a313b;--green:#4ade80;--green-bg:#122b1d;--red:#f87171;--red-bg:#331512;
--neutral:#9aa5b1;--neutral-bg:#232a33;--accent:#8fb4e3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:32px 20px 64px}
header h1{font-size:22px;margin:0 0 4px}header .sub{color:var(--muted);font-size:13px}
.banner{margin:24px 0;padding:18px 20px;border-radius:10px;border:1px solid var(--line);
background:var(--card);font-size:17px;font-weight:600}
.banner.ok{border-color:var(--green);background:var(--green-bg);color:var(--green)}
.banner.fail{border-color:var(--red);background:var(--red-bg);color:var(--red)}
.banner.pending{color:var(--muted);font-weight:400}
.banner .why{display:block;margin-top:6px;font-size:13px;font-weight:400;color:var(--ink)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card h3{margin:0 0 6px;font-size:14px;display:flex;align-items:center;gap:8px;justify-content:space-between}
.card p{margin:6px 0 0;font-size:13px;color:var(--muted)}
.card p.not{font-size:12px;font-style:italic}
.chip{font:600 11px/1 var(--mono);letter-spacing:.4px;padding:4px 8px;border-radius:999px;white-space:nowrap}
.chip.green{color:var(--green);background:var(--green-bg)}
.chip.red{color:var(--red);background:var(--red-bg)}
.chip.neutral{color:var(--neutral);background:var(--neutral-bg)}
.viol{margin-top:8px;font:12px var(--mono);color:var(--red);word-break:break-word}
h2{font-size:16px;margin:32px 0 10px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}tr:last-child td{border-bottom:none}
td.mono,span.mono{font-family:var(--mono);font-size:12px;word-break:break-all}
.tablewrap{overflow-x:auto}
.evidence{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;font-size:13px}
.evidence button{font:600 13px system-ui;padding:8px 14px;border-radius:8px;border:1px solid var(--accent);
background:transparent;color:var(--accent);cursor:pointer;margin:8px 10px 0 0}
.evidence button:hover{background:var(--accent);color:var(--card)}
.evidence code{font-family:var(--mono);font-size:12px;background:var(--neutral-bg);padding:2px 5px;border-radius:4px}
footer{margin-top:36px;color:var(--muted);font-size:12px}
.notice{font-size:12px;color:var(--muted);margin-top:6px}
@media print{body{background:#fff}.card,.banner,table,.evidence{break-inside:avoid;border-color:#bbb}
.evidence button{display:none}.wrap{max-width:none;padding:0}}
`;

/** Browser driver — plain JS, no template literals, no external requests. */
const DRIVER = `
'use strict';
function el(id){return document.getElementById(id)}
function chip(status){
  var cls = status==='green'||status==='verified'||status==='bound' ? 'green'
    : status==='red'||status==='mismatch' ? 'red' : 'neutral';
  var s=document.createElement('span'); s.className='chip '+cls; s.textContent=status.toUpperCase(); return s;
}
function setChip(id,status,violation){
  var h=el(id); h.appendChild(chip(status));
  if(violation){var d=document.createElement('div');d.className='viol';
  d.textContent='first violation at seq '+violation.sequenceNumber+': '+violation.reason;
  h.parentElement.appendChild(d);}
}
function b64decode(b){var bin=atob(b);var u=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return new TextDecoder().decode(u)}
function profilePhrase(p){
  if(p==='C')return 'a qualified-eIDAS-signed human authorization (identity-proofed natural person)';
  if(p==='B')return 'a device-key-signed human authorization (key control cryptographically verified; declared identity)';
  if(p==='A')return 'a human-attributed authorization inside the tamper-evident chain (operator-attested at root — "human-attributed", not "human-signed")';
  return 'a human-rooted authorization';
}
async function main(){
  var payload=JSON.parse(el('val-payload').textContent);
  var ndjson=b64decode(payload.ndjsonB64);
  var VAL;
  try{ VAL=await import('data:text/javascript;base64,'+payload.verifierB64); }
  catch(e){ banner('fail','This report could not load its embedded verifier: '+e.message); return; }
  var rows=[]; var lines=ndjson.split('\\n');
  for(var i=0;i<lines.length;i++){ if(lines[i].length===0)continue;
    var p=JSON.parse(lines[i]);
    rows.push({scope_key:p.scope_key,sequence_number:p.sequence_number,event_type:p.event_type,
      canonical_details:p.canonical_details,previous_hash:p.previous_hash,chain_hash:p.chain_hash}); }
  var opts=payload.trust||undefined;
  var r;
  try{ r=await VAL.verifyValChain(rows,opts); }
  catch(e){ banner('fail','Verification threw: '+e.message); return; }
  el('rowcount').textContent=String(rows.length);
  setChip('p-integrity',r.integrity,null);
  setChip('p-lineage',r.lineage,r.firstLineageViolation);
  setChip('p-scope',r.scope,r.firstScopeViolation);
  setChip('p-grounding',r.grounding,r.firstGroundingViolation);
  setChip('p-authority',r.authority,r.firstAuthorityViolation);
  setChip('p-signature',r.signature,r.firstSignatureViolation);
  setChip('p-anchor',r.anchorBinding,r.firstAnchorViolation);
  setChip('p-bytes',r.bytesBinding,r.firstBytesBindingViolation);
  el('profile-floor').textContent=r.conformanceProfile;
  el('profiles-present').textContent=r.profilesPresent.length?r.profilesPresent.join(', '):'—';
  el('key-binding').textContent=r.keyBinding||'—';
  el('legacy-count').textContent=String(r.legacyPreAuthorityAssignmentCount);
  el('nonval-count').textContent=String(r.nonValBlockCount);
  if(r.rootSubject){el('root-subject').textContent=r.rootSubject.subject_claim+' ('+r.rootSubject.source+')';}
  fillTable('carriers',r.authorityCarriers.map(function(c){return [c.sequenceNumber,c.basis||'—',c.capability||'—',c.attested_by||'—']}));
  fillTable('bonds',r.consentBonds.map(function(c){return [c.sequenceNumber,c.alg||'—',c.profile,c.signatureValid?'valid':'INVALID']}));
  fillTable('anchors',r.anchors.map(function(a){return [a.sequenceNumber,a.genTime,a.covered_range.from_sequence+' – '+a.covered_range.to_sequence]}));
  var coreOk=r.integrity==='green'&&r.lineage==='green'&&r.scope==='green'&&r.grounding==='green';
  var extOk=(r.authority==='green'||r.authority==='none')&&(r.signature==='green'||r.signature==='none')
    &&r.anchorBinding!=='mismatch'&&r.bytesBinding!=='mismatch';
  if(coreOk&&extOk){
    banner('ok','Every action in this chain traces to '+profilePhrase(r.conformanceProfile)
      +' — re-derived offline by this document, with zero reads against the operator.');
  }else{
    var first=r.integrity==='red'?'integrity':r.lineage==='red'?'lineage ('+(r.firstLineageViolation&&r.firstLineageViolation.reason)+')'
      :r.scope==='red'?'scope ('+(r.firstScopeViolation&&r.firstScopeViolation.reason)+')'
      :r.grounding==='red'?'grounding ('+(r.firstGroundingViolation&&r.firstGroundingViolation.reason)+')'
      :r.authority==='red'?'delegator authority ('+(r.firstAuthorityViolation&&r.firstAuthorityViolation.reason)+')'
      :r.signature==='red'?'signature ('+(r.firstSignatureViolation&&r.firstSignatureViolation.reason)+')'
      :r.anchorBinding==='mismatch'?'external anchor ('+(r.firstAnchorViolation&&r.firstAnchorViolation.reason)+')'
      :'bytes-binding ('+(r.firstBytesBindingViolation&&r.firstBytesBindingViolation.reason)+')';
    banner('fail','This chain FAILED verification — '+first+'.');
  }
  wireDownload('dl-chain',ndjson,'text/plain','chain.ndjson');
  wireDownload('dl-verifier',b64decode(payload.verifierB64),'text/javascript','chain-verifier.mjs');
}
function banner(kind,text){var b=el('banner');b.className='banner '+kind;b.textContent=text;
  if(kind==='fail'){var w=document.createElement('span');w.className='why';
  w.textContent='The pass grid below shows each re-derived property; red chips carry the first violating sequence number.';
  b.appendChild(w);}}
function fillTable(id,rowsData){var t=el(id);if(!rowsData.length){t.closest('section').style.display='none';return}
  var tb=t.tBodies[0];rowsData.forEach(function(cells){var tr=document.createElement('tr');
  cells.forEach(function(c,i){var td=document.createElement('td');if(i===0)td.className='mono';
  td.textContent=String(c);tr.appendChild(td)});tb.appendChild(tr)})}
function wireDownload(id,content,mime,name){el(id).addEventListener('click',function(){
  var blob=new Blob([content],{type:mime});var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(function(){URL.revokeObjectURL(a.href)},5000)})}
main();
`;

const PASSES: Array<{ id: string; name: string; proves: string; not: string }> = [
  {
    id: 'p-integrity',
    name: 'Integrity — Pass 1',
    proves: 'Committed blocks were not modified, inserted, deleted, or reordered — every hash recomputed from the §4.3 preimage.',
    not: 'Does not prove every action was captured: coverage is an instrumentation property, not a hashing property.',
  },
  {
    id: 'p-lineage',
    name: 'Lineage — Pass 2',
    proves: 'Every action block walks parent_assignment_hash, hash by hash, to a human-rooted ASSIGNMENT (§5.1, depth ≤ 16).',
    not: 'The strength of the human binding at root is the conformance profile below — read them together.',
  },
  {
    id: 'p-scope',
    name: 'Scope-respect — Pass 3',
    proves: 'Each action fell within its effective granted authority — the transitive intersection down the delegation chain, re-evaluated by this document (§6.6/§6.7), not read back from the operator.',
    not: 'Does not prove what should have been granted — it checks actions against the grant, not the grant against policy intentions.',
  },
  {
    id: 'p-grounding',
    name: 'Grounding — §7.5',
    proves: 'Every MUTATION citing grounded content was preceded by an ACCESS of that content by the same principal, in this chain (read-before-derive).',
    not: 'Does not tie a content-address to a particular file — that is bytes-binding.',
  },
  {
    id: 'p-authority',
    name: 'Delegator authority — Pass 5',
    proves: 'Every v2+ grant carries its delegator-authority basis; with a capability policy supplied, the delegated scope is ⊆ what the issuer could grant (authority escalation fails).',
    not: 'Without a supplied policy, only carrier presence is enforced. An attested basis is surfaced verbatim, never presented as proven entitlement.',
  },
  {
    id: 'p-signature',
    name: 'Root signature — §5.2 (B/C)',
    proves: 'Present delegation signatures are valid assertions chaining to the enrolled, self-attested root key; relabeled attestations break their binding challenge.',
    not: 'NONE means no signature was present (Profile A — operator-attested root). Key control is proven under B; legal identity is the declared name unless C.',
  },
  {
    id: 'p-anchor',
    name: 'External anchor — Pass 4',
    proves: 'Anchored ranges existed no later than the TSA-attested genTime — an independent RFC 3161 authority’s signature, not the operator’s clock.',
    not: 'Temporal existence only; NOT_EVALUATED means no ANCHOR block or no TSA trust anchor was supplied.',
  },
  {
    id: 'p-bytes',
    name: 'Bytes-binding — Pass 6',
    proves: 'A disclosed { bytes, nonce } reproduces the on-chain hiding commitment: the content-address IS the document in hand.',
    not: 'Evidence-time and opt-in; NOT_EVALUATED means no disclosure was supplied with this report.',
  },
];

export function buildHtmlReport(i: ReportInputs): string {
  const scopeKeys = Array.from(
    new Set(
      i.ndjson
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => {
          try {
            return String((JSON.parse(l) as { scope_key?: string }).scope_key ?? '');
          } catch {
            return '';
          }
        })
        .filter((s) => s.length > 0),
    ),
  );
  const title = i.title ?? 'VAL Verification Report';
  const payload = {
    ndjsonB64: b64(i.ndjson),
    verifierB64: b64(i.verifierSource),
    trust: i.trust ?? null,
  };
  const trustNote = i.trust
    ? 'Trust-anchor inputs (§7.1) were supplied at generation time and are embedded verbatim in this document.'
    : 'No §7.1 trust-anchor inputs were supplied: the delegator-authority pass enforces carrier presence only, and anchor / bytes-binding passes report NOT_EVALUATED.';

  const passCards = PASSES.map(
    (p) => `      <div class="card"><h3>${esc(p.name)}<span id="${p.id}"></span></h3>
        <p>${esc(p.proves)}</p><p class="not">${esc(p.not)}</p></div>`,
  ).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>${esc(title)}</h1>
    <div class="sub">Verifiable Authorization Lineage (VAL) — self-verifying report ·
      scope ${esc(scopeKeys.join(', ') || '(unknown)')} · <span id="rowcount">…</span> rows ·
      generated ${esc(i.generatedAt)} · embedded verifier @val-protocol/chain-verifier@${esc(i.verifierVersion)}</div>
  </header>

  <div id="banner" class="banner pending">Re-deriving all verification passes in your browser from the embedded chain bytes…</div>
  <noscript><div class="banner fail">JavaScript is disabled — this report re-derives its verdict locally and cannot do so.
  Download nothing on faith: verify the chain with <code>npx @val-protocol/chain-verifier-cli --export=chain.ndjson</code>.</div></noscript>

  <div class="grid">
${passCards}
  </div>

  <h2>Conformance</h2>
  <div class="tablewrap"><table>
    <thead><tr><th>Chain-level profile (floor — never rounded up)</th><th>Profiles present</th><th>Root key binding</th><th>Root subject (declared, verbatim)</th></tr></thead>
    <tbody><tr>
      <td><span class="mono" id="profile-floor">…</span></td>
      <td><span class="mono" id="profiles-present">…</span></td>
      <td><span class="mono" id="key-binding">…</span></td>
      <td><span id="root-subject">—</span></td>
    </tr></tbody>
  </table></div>
  <p class="notice">A = operator-attested (human-attributed) · B = WebAuthn device-key-signed (key control proven; identity declarative) ·
  C = qualified eIDAS (identity-proofed). The chain letter is the weakest root present (§5.2).</p>

  <section><h2>Authority carriers (§7.2 Pass 5 — verbatim)</h2>
  <div class="tablewrap"><table id="carriers"><thead><tr><th>seq</th><th>basis</th><th>capability</th><th>attested by</th></tr></thead><tbody></tbody></table></div></section>

  <section><h2>Consent bonds (§4.3 — per-instrument grade)</h2>
  <div class="tablewrap"><table id="bonds"><thead><tr><th>seq</th><th>alg</th><th>instrument profile</th><th>signature</th></tr></thead><tbody></tbody></table></div></section>

  <section><h2>External anchors (§8)</h2>
  <div class="tablewrap"><table id="anchors"><thead><tr><th>seq</th><th>TSA genTime</th><th>covered range</th></tr></thead><tbody></tbody></table></div></section>

  <h2>Chain facts</h2>
  <div class="tablewrap"><table><tbody>
    <tr><th>Pre-carrier (v1) legacy ASSIGNMENTs</th><td class="mono" id="legacy-count">…</td></tr>
    <tr><th>Non-VAL rows (operator-private, skipped)</th><td class="mono" id="nonval-count">…</td></tr>
  </tbody></table></div>

  <h2>How this report verifies itself</h2>
  <div class="evidence">
    <p>This file embeds the exact chain bytes and the full source of the open reference verifier.
    When you opened it, your browser imported that verifier and re-derived every pass above from
    the bytes — the verdict was not read from anyone. ${esc(trustNote)}</p>
    <p>Don’t take this document’s word for it either:</p>
    <button id="dl-chain">Download embedded chain (NDJSON)</button>
    <button id="dl-verifier">Download embedded verifier (ESM)</button>
    <p>…then re-verify out-of-band: <code>npx @val-protocol/chain-verifier-cli --export=chain.ndjson</code>
    — or read the verifier source and the <a href="https://github.com/val-protocol/verifiable-authorization-lineage">protocol spec</a>.</p>
  </div>

  <footer>Verifiable Authorization Lineage — an open protocol (Apache-2.0).
  Records prove what your agents did; VAL proves they were allowed to.
  This report makes no claim about capture completeness: coverage is an instrumentation property (§1.2).</footer>
</div>
<script type="application/json" id="val-payload">${scriptJson(payload)}</script>
<script type="module">${DRIVER}</script>
</body>
</html>
`;
}
