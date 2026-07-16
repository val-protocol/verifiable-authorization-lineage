# Control-Framework Crosswalk — Agentic Trust Controls (ATC) & AARM Core

**Status:** informative, non-normative. Pinned to the Vanta Agentic Trust Controls draft as circulated
for public comment (July 2026) and to AARM Core R1–R6. Control IDs and texts in those frameworks are
drafts and may change; this document tracks them and is re-pinned on framework publication.
**Spec references** are to [VAL v0.1](spec/README.md).

Control frameworks decompose outcomes into separately assessable units. VAL composes several of those
units back into **one artifact**: a typed, hash-chained record whose authority content, integrity,
continuity, and external verifiability are properties of the same bytes, re-derivable offline by a
party that does not operate the system that produced them (§2, "Trustless verification"). This
crosswalk states — control by control — what VAL provides, what it partially provides, and what it
deliberately does not address.

## How to read the coverage column

| Mark | Meaning |
|---|---|
| ✅ | The protocol mechanism directly provides the control's outcome, verifiable from chain bytes plus public trust anchors. |
| 🟡 | The protocol provides part of the outcome; the remainder is a deployment/operator responsibility outside the wire format. |
| ⬜ | Deliberately out of scope for VAL (§1.2). VAL coexists with the layer that owns it. |

A ⬜ is not a gap in VAL; it is a boundary. VAL constrains **what is recorded and how it is verified**,
not how runtime decisions are made, how identities are issued, or how systems are monitored (§1.2).

---

## 1. Vanta Agentic Trust Controls

### 1.1 The evidence cluster — where VAL is the implementation

| Control | Requirement (abridged) | VAL mechanism | Coverage |
|---|---|---|---|
| **AID-05** Authority attestation at execution | Record per consequential action: acting identity, originating principal / delegation chain, granted authority, execution context — sufficient to reconstruct why the action was permitted | Every ACCESS/MUTATION block carries `principal`, `parent_assignment_hash`, and a resource clause (§4.4). The delegation chain is walked hash-by-hash to a root ASSIGNMENT carrying the scope predicate and the human designation (§5.1, §5.2). Granted authority is not merely recorded — it is **machine-checkable**: the verifier re-evaluates each action against the effective (intersected) scope (§6.6, §6.7, Pass 3), so "why the action was permitted" is *re-derived*, not read back from the operator's assertion. | ✅ for permitted actions. 🟡 for denied/escalated actions: v0.1 defines block types for actions that occurred; deny/step-up records are operator-private block types (§4.2), not yet standardized. |
| **RBM-03** Tamper-evident action logging | Consequential actions in a tamper-evident log — what was done, under whose authority, on what input — with integrity and sequence protection | §4.3 chain-hash construction: per-`scope_key` monotonic `sequence_number`, `previous_hash` linkage, SHA-256 over an RFC 8785 (JCS) canonical preimage. Modification, insertion, deletion, and reordering of committed blocks each break recomputation (Pass 1). "Under whose authority" is the AID-05 lineage content — same record, not a second log. "On what input" is the grounding property (§7.5, read-before-derive) plus the optional bytes-binding commitment (§7.2 Pass 6). | ✅ for the record and its verifiability. Alerting/response on failed verification is operational (deployment). |
| **RBM-03 (discussion) — verifier independence** | Records verifiable by a party that does not operate the logging plane | The offline verifier's defining property: every asserted property is re-derived from chain bytes plus public trust anchors, with zero reads against the operator (§7.1, §7.2). Profiles B/C remove even the root attribution's dependence on the operator's runtime (§5.2). | ✅ |
| **MAS-03** Delegation-chain authority propagation | Delegated authority explicit and bounded; a sub-agent cannot exceed the delegator's grant; chain reconstructible | Sub-assignments intersect: effective scope = child ∩ parent ∩ … ∩ root, and actions are evaluated against the *effective* scope (§6.7) — delegation is strictly narrowing by construction. Pass 5 additionally checks the issuer *could* grant what was delegated (`scope.act ⊆ policy[capability]` — authority escalation fails the pass, §7.2). The chain is reconstructible from bytes alone: `parent_assignment_hash` is a chain-hash reference, never a foreign key into a mutable table (§5.3); depth is bounded at 16 (§5.1). | ✅ |
| **AID-01** Verifiable agent identity | Distinct, verifiable non-human identity; actions attributable to the responsible agent | Every action block carries a `principal` URI; human and agent principals are distinct namespaces, and attribution is committed into the hash (§4.4). Root human-binding strength is graded and reported honestly via conformance profiles A/B/C — never rounded up (§5.2, §7.3). | 🟡 — attribution content is structural; identity *issuance* is out of scope (§1.2): VAL consumes identity artifacts (DIDs, X.509/eIDAS, WebAuthn keys), it does not mint them. |
| **AID-03 / AID-04** Least-privilege scoping / just-in-time privilege | Task-scoped, time-bounded authority rather than standing access | The scope predicate expresses bounded action vocabulary (`act`), resource clauses including isolation commitments (`res`), validity windows (`win`), and aggregate limits (`lim`) (§6). VAL **proves** a grant was bounded and that actions stayed inside it — evidence for the control, not the enforcement of it. | 🟡 — grant issuance/expiry enforcement is runtime. |
| **GOV-03** Accountability ownership per agent | A named accountable owner per agent | The lineage invariant terminates every action at a human-designated root (§5.1), and the v2 `delegator_authority` carrier records *with what standing* that human granted the scope (§5.2) — accountable ownership as chain evidence, not as registry entry. | 🟡 — the organizational ownership process is out of scope. |
| **HOA-05** Oversight decision logging | Human oversight decisions logged with a stable reference joinable to later outcomes | Sign-class (CONSENT) actions carry a per-action signature bound to `{document_hash, parent_assignment_hash, principal}` (§5.2); every block's `chain_hash` is a stable, tamper-evident join key. | 🟡 — decision-quality sampling and review are organizational. |
| **OUT-02** Content provenance | Output carries provenance of its basis | Grounding: a MUTATION citing `grounded_document_hashes` must cite content the same principal read earlier in the chain — re-derived from bytes (§7.5). Bytes-binding commits the record to the exact document bytes without disclosure (§7.2 Pass 6). | 🟡 — end-user labeling is a product concern. |

### 1.2 In-flight ATC discussion themes

Two control proposals under public discussion in the ATC comment period map directly:

| Theme | VAL mechanism | Coverage |
|---|---|---|
| **Chain-continuity binding** — a record's protection must cover its *position in history*, so a reordered or truncated log is detectable as inconsistent, not merely internally well-formed | v0.1 has **no per-block signature to re-seal** (§4.3): position is committed inside the hash preimage itself (`scope_key \| sequence_number \| event_type \| canonical_details \| previous_hash`). Where cryptographic signatures do exist — the Profile B/C root binding and the per-action CONSENT signature — they bind lineage references (`parent_assignment_hash`), not free-floating content (§5.2). | ✅ by construction |
| **Independently verifiable records / external anchoring** — committed history verifiable against a reference outside the operator's control; checkpoints reveal no record contents | ANCHOR blocks (§8): an independent RFC 3161 timestamp authority signs a Merkle root over a covered block range; the token is carried in-band and committed into the chain. A rewritten history cannot reproduce an earlier TSA attestation over different bytes. Pass 4 verifies root recomputation, `messageImprint` binding, and the TSA's CMS signature against caller-side trust anchors (§8.4). The checkpoint discloses a root — never contents. QTSP-agnostic; eIDAS-qualified where the jurisdiction wants it (§8.3). | ✅ (opt-in per §8.5; cadence RECOMMENDED §8.2) |

### 1.3 Out of scope — owned by adjacent layers

VAL deliberately does not address, and coexists with the layers that do (§1.2, §2 "Interoperable with
adjacent layers"):

- **TUE-01…TUE-09** (deterministic guardrails, allowlisting, parameter validation, sandboxing,
  kill-switch, egress control): runtime enforcement. VAL constrains what is *recorded*, not how
  decisions are *made*. The enforcement point is a natural VAL emission point — the two compose.
- **RII-01…RII-04** (injection resistance, goal integrity), **MEM-01…MEM-04** (memory integrity),
  **ADV-01…ADV-03** (adversarial testing), **RES-01/02** (resource bounds): model-behavior and
  runtime-state controls.
- **RBM-01/02/04–07** (telemetry, drift, monitoring, SOC): observability. A telemetry stream is not an
  authorization lineage; the two answer different questions and should not be conflated.
- **SCP**, remaining **GOV**, **HOA-01…04**, **OUT-01/03**: supply-chain, governance, and product
  controls.

---

## 2. AARM Core (R1–R6)

AARM Core specifies a runtime enforcement plane (R1–R4) with an evidence requirement (R5–R6). VAL is
an evidence protocol: it does not compete with R1–R4 and implements R5 with properties beyond what R5
requires.

| Req | Requirement (abridged) | VAL position |
|---|---|---|
| **R1** Pre-execution interception | Intercept every action before execution | ⬜ Out of scope (§1.2: "the protocol only constrains what is recorded, not how decisions are made"). Complementary: an R1 control plane is a natural VAL producer. |
| **R2** Context accumulation | Maintain intent/session context for policy evaluation | ⬜ Runtime concern. The chain is a durable, verifiable *record* of session history, not the runtime context store. |
| **R3** Policy evaluation with intent alignment | Evaluate actions against policy + intent | ⬜ Runtime concern (FGA/OPA/Zanzibar/etc. — §1.2). |
| **R4** Five authorization decisions | ALLOW / DENY / MODIFY / STEP_UP / DEFER | ⬜ v0.1 block types record actions that occurred (a MODIFY outcome is recorded as the executed, transformed action). DENY/STEP_UP/DEFER receipts are representable as operator-private block types (§4.2) but not standardized in v0.1. |
| **R5** Tamper-evident receipts (action, decision, timestamp, policy context; verifiable against unauthorized modification) | ✅ **Implemented, exceeded.** The receipt is the block: action + resource in `canonical_details` (§4.4); the policy context is the *walkable* granted scope at `parent_assignment_hash` — machine-re-checkable, not a prose snapshot (§6.6, Pass 3); timestamp as `timestamp_local`, upgradeable to a TSA-attested `genTime` under §8. Beyond R5: sequence and continuity protection (§4.3 — R5 protects records individually; VAL protects the *history*), external anchoring (§8), and offline verification by a party that does not trust the operator (§7) — R5 does not say *to whom* receipts must be verifiable; VAL answers: to anyone. |
| **R6** Identity binding (receipt cryptographically bound to agent identity, non-repudiation) | 🟡 Every block carries `principal` committed into the hash; the *cryptographic* binding is graded by conformance profile (§5.2): Profile B/C roots are human-key-signed (WebAuthn device key / qualified eIDAS), sign-class actions carry per-action signatures, Profile A is operator-attested and honestly reported as such — never rounded up (§7.3). v0.1 deliberately defines no per-block agent-key signature (§4.3): when the keyholder is the party under review, per-record signatures add re-signable ceremony, not assurance; VAL binds the *root of authority* and the *history* instead. |

---

## 3. What VAL adds that no control yet requires

Three properties of this protocol are, as of this pinning, ahead of both frameworks:

1. **Re-derivable authorization basis.** Recording "the decision and its basis" still leaves the
   basis as the operator's claim. VAL's scope predicates are decidable (§6), so a verifier
   *re-evaluates* whether each action fell within its granted authority (Pass 3) and whether each
   grant fell within its issuer's authority (Pass 5) — the basis is checked, not trusted.
2. **Human-rooted termination.** Bounding each delegation link (attenuation) is necessary but not
   sufficient: attenuation from a root that had no valid authority attenuates nothing. The lineage
   invariant requires every action to terminate at a human-designated root ASSIGNMENT (§5.1), with
   the root's binding strength honestly graded (§5.2).
3. **Conformance-profile honesty.** A verification report states its own residual trust: the
   chain-level profile is the floor across roots, never rounded up (§5.2, §7.3), so one strong grant
   cannot mask a chain of weaker ones.

---

*Maintained alongside the spec; corrections via the normal [contribution process](CONTRIBUTING.md).*
