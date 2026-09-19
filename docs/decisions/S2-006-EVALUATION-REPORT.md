# S2-006 Evaluation Report — Independent semantic verifier and calibration

## Verdict: NEEDS_INPUT

The deterministic offline layer is fully green (dependency gate, contract
types, verifier suite, Run A/B with identical sealed predictions and distinct
run-manifest digests, fail-closed comparator, adversarial probes A–S with zero
hard counters, two-process PostgreSQL store replay). The honest ceiling is
still `NEEDS_INPUT` (spec §16): no method owner has authored numeric
thresholds, the annotators are fixture principals rather than independent
humans, and the external corpus stratum does not exist. No unconditional PASS
or production claim is made anywhere.

## 1. Dependency proof

`npm run verify:s2-006-dependencies` → **PASS (76 checks, FULL_GIT_BYTES)**,
binding written to `evidence/s2-006-dependency-binding.json` (`resolved`
section, deterministic bytes).

- `refs/remotes/origin/main` = `d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f`
  (exact merge object of PR #18). Any later advance of main fails closed
  (`origin/main:advanced-past-pinned-merge`) because no reviewed rebase
  binding exists.
- Merge parents, read back independently via `git cat-file -p` **and**
  `git rev-list --parents`: exactly
  `7662face2091c1f591af2b586502beb4ea698e5e` (S2-004 canonical base) and
  `36fd8f854459f3ee419a997293c966e6840a2373` (exact S2-005 head), in Git order.
- 14 protected S2-005 evidence/contract/corpus inputs read **only** via
  `git show d7ce192:<path>`: Git blob ids match the record, SHA-256 over the
  raw bytes matches, and each digest is cross-checked against the frozen
  manifest bytes at `d7ce192` where the frozen manifest claims the path.
- S2-005 payload re-verified from Git bytes: green clean checkout,
  `PASS_WITH_LIMITS` comparison (55/55, zero hard counters, distinct run
  identities), green DB replay, `PASS_WITH_LIMITS` verdict bytes on the
  evaluation report, implementation commit `dd683ceb…` from the commit
  manifest.
- Inherited policy surfaces pinned by SHA-256 at `d7ce192` and
  byte-identical in the working tree: `src/lib/contract-policy.mjs`
  (METRIC_POLICY/AUTONOMY_POLICY executable surface),
  `contracts/human-decision.schema.json` (HUMAN_APPROVAL_POLICY),
  `contracts/capability.schema.json`, `contracts/grant.schema.json`
  (AUTONOMY_POLICY), `scripts/policy-probes.mjs`.
- Stage-1 bindings pinned to AgentOS commit `a7940e11…`: S1-011 (authority
  binding for method-owner HumanDecisions) and S1-012 (separation of
  confidence/calibration/support), digest- and length-verified tracked copies
  with checked payload fields. The cross-repository Git blob id is `null` and
  declared as such (the AgentOS object database is not reachable from this
  offline gate) — a documented, honest pinning limit.
- S2-006 frozen inputs (thresholds preregistration, corpus manifest, rubric,
  labels, adjudication) match their authored SHA-256 digests; upstream limits
  (fixture-only corpus, hashed TF-IDF, `NOT_MEASURED` global paired
  statistics, corpus-scoped novelty only, no production claim) verified from
  bytes.

## 2. Scope and independence matrix

| Axis | State |
|---|---|
| `artifact_producer` | the S2-005/S2-006 project itself (fixture scenarios) |
| `verifier_implementation_owner` | project (deterministic rubric engine `rub-s2006-semantic-v1@1.0.0`; digest-bound per run) |
| `annotators` | `prn-annotator-a`, `prn-annotator-b` — **synthetic fixture principals**, not independent humans |
| `adjudicator` | `prn-adjudicator-1` — synthetic fixture principal, 3 adjudications, raw votes retained |
| blindness | candidate children never open label/adjudication/threshold files; sealed prediction sets written before unseal; comparator never re-runs the candidate |
| data independence | violated: cases authored alongside the implementation (fixture stratum) |
| model/provider/prompt independence | no model or provider in the loop (offline deterministic engine); provider stratum NOT_RUN |
| process/workspace independence | Run A/B process-separated (distinct executor id, PID, nonce, output root) |
| locked-label custody | fixture HMAC key (`tests/verifier` convention); real `label_custodian` custody **NOT_RUN** |

Conclusion: `INDEPENDENTLY_CALIBRATED` is not claimable; independence tier is
**NOT_INDEPENDENT**, empirical calibration status **NOT_MEASURED** with reason
`evaluator_not_independent` (spec §3).

## 3. Corpus, splits, rubric, thresholds (digests)

- Corpus: `corpus/s2-006` — 45 fixture cases (positive, negative, ambiguous,
  contradictory, missing-source, private, stale, future, multilingual,
  numeric/unit/negation, causal, abstention categories). SHA-256
  `93ca54b2a954fdaffe93616b66c4efdcd70c43e971572b552a5b468c24c6cce0`.
- Splits (disjoint by construction): `dev` 10, `calibration` 12,
  `locked_test` 23 — all fixture stratum; **no externally authored,
  independently labelled cases exist**, so the spec §6 structural minimum of
  20 external global locked-test questions is unmet and external validity is
  not measured.
- Rubric: `rub-s2006-semantic-v1@1.0.0`,
  SHA-256 `9559406c3f14249f7c5302b44fddcfe1bc286af0da51e324468f5020062bd0dc`
  (bound in the manifest and in every run's implementation digest).
- Thresholds: `contracts/s2-006-thresholds.json` — preregistration with every
  owner-owned numeric `null`, `status NEEDS_INPUT`, `method_owner null`,
  `ownerDecisionRef null`. SHA-256
  `ddd02c1a87ce68f732f4913c014fddfa80628e1d825259dc16a3c0f4fc37cf19`. No
  value may be derived from an observed winner; filling requires an immutable
  HumanDecision from an authenticated owner=user.
- Label/adjudication bytes: annotator sets and the adjudication record are
  SHA-256-pinned in the dependency record; label-set signatures are
  HMAC-SHA256 over the exact binding digest and are verified by the
  comparator (fixture key).

## 4. Run A/B and comparator

- Run A (`exec-s2-006-a`, nonce `n-a-7c1e4d90a2b8f3e6`, clock 2026-01-15) and
  Run B (`exec-s2-006-b`, nonce `n-b-3f9a62d1c5e80b74`, clock 2026-03-21):
  separate OS processes, one frozen rubric implementation, one frozen corpus.
- Sealed prediction sets: `evidence/s2-006-run-a.json`,
  `evidence/s2-006-run-b.json`. Prediction-set digests identical
  (`3fba44f00dc996263ad62656c4caf0e789a37fd20fdadfbe685b2f38802036ac`);
  run-manifest digests distinct (executor, PID, nonce, output root) — spec §3.
- Comparator (`evidence/s2-006-comparison.json`, preregistered `exact` rule):
  **ok** over all 45 cases — complete composition, split membership, case/
  label/rubric digest binding, signature verification, adjudication coverage
  of all 3 raw disagreements, non-degenerate verdict distributions, zero hard
  counters, distinct run-manifest digests. Fail-closed on every mutation
  class (regression-tested in `tests/verifier/comparator.test.mjs`).
- Consensus gold for metrics = raw blind labels + the 3 adjudicated
  disagreements (raw votes retained in `corpus/s2-006/adjudication.json`).

## 5. Calibration metrics — MEASURED on the fixture stratum

All numbers carry raw counts (`evidence/s2-006-calibration.json`). Coverage:
denominator 45, evaluated 45, missing 0, abstained 19.

| Metric | Value | Counts | Status |
|---|---|---|---|
| decision availability | 1.0 | 45/45 | MEASURED |
| citation coverage (non-abstention) | 0.5778 | 26/45 | MEASURED |
| abstention rate | 0.4222 | 19/45 | MEASURED |
| citation entailment F1 (SUPPORTED) | 1.0 | precision & recall 1.0 | MEASURED |
| macro F1 | 1.0 | over classes with support | MEASURED |
| contradiction recall | 1.0 | 3/3 | MEASURED |
| contradiction/scope-difference confusion | 0.0 | 0/7 | MEASURED |
| stale invalidation recall | 1.0 | 6/6 | MEASURED |
| number/unit preservation recall | 1.0 | 6/6 | MEASURED |
| negation preservation recall | 1.0 | 2/2 | MEASURED |
| modality preservation recall | 1.0 | 2/2 | MEASURED |
| scope-binding recall | 1.0 | 4/4 | MEASURED |
| family-collapse recall | 1.0 | 2/2 | MEASURED |
| causal-overclaim miss rate | 0.0 | 0/2 | MEASURED |
| epistemic-type exact match | 1.0 | 4/4 | MEASURED |
| false advisory acceptance rate | 0.0 | 0/37 | MEASURED |
| false advisory rejection rate | 0.0 | 0/8 | MEASURED |
| unauthorized leakage rate | 0.0 | 0/2 | MEASURED |
| selective risk vs coverage | risk 0.0 at coverage 0.5778 | 0/26 | MEASURED |
| adjudication rate | 0.0667 | 3/45 | MEASURED |
| unauthorized leakage (hard violation events) | 0 | 0 | hard gate PASS |

Every threshold comparison is **NOT_APPLIED**: the owner-owned numerics are
`null`. The lexicographic decision rule returns `NEEDS_INPUT`
(`missing_human_decision`, `missing_thresholds`) — the candidate is never
declared a winner. Abstain-all cannot win (coverage gate), and precision is
reported only together with coverage.

## 6. NOT MEASURED / NOT APPLICABLE (never 0% or 100%)

- Inter-annotator agreement: **NOT_MEASURED** (`evaluator_not_independent`);
  raw agreement 42/45 (0.9333) kept for transparency only.
- Independence tier: **NOT_INDEPENDENT**; empirical external calibration
  **NOT_MEASURED**.
- Global paired statistics / external validity: **NOT_MEASURED** (no external
  stratum; fixture stratum never inflates external denominators).
- Brier score / ECE: **NOT_APPLICABLE** (the offline verifier emits no
  probabilities).
- EvidenceMap completeness in this harness: **NOT_APPLICABLE** (no EvidenceMap
  inputs in the fixture harness; upstream S2-005 metrics remain authoritative
  for that surface).
- Human active time, latency, actual cost: **NOT_MEASURED**
  (`outcome_not_defined`).

## 7. Adversarial probes A–S

19/19 green, 19 attempted violations, **0 actual violations**, hard counters
all zero (`evidence/s2-006-security-probes.json`): topic-overlap ≠ entailment
(A); number/unit/negation/modality drift reason codes (B); scope difference ≠
contradiction (C); correlation/analogy never mechanism (D); span-less output →
INSUFFICIENT_EVIDENCE (E); ten reprints → one evidence family (F); zero
private leak (G); post-`as_of`/locked-label access before unseal blocked (H);
producer self-review and forged identities rejected (I); prompt injection
inert, authority counters zero (J); abstain-all fails the coverage gate (K);
two identically broken runs fail the comparator (L); post-result threshold/
label change forces a new version (M); stale parent → dependent result STALE,
calibration not applied (N); prior art outside the selected corpus → not
`novel_to_selected_corpus`, world novelty refused (O); provider timeout/refusal
→ typed missingness, never a silent denominator exclusion (P); post-unseal
label access and comparator candidate re-run are hard fails (Q); role reuse,
self-attestation and forged signature/digest bindings rejected (R); probe S
(fenced reconciliation after crash/unknown outcome) — state machine covered
offline on the in-memory store; the two-process crash/restart variant is
**NOT_RUN_DB** as a DB-gated scenario.

## 8. PostgreSQL store replay — RUN (not NOT_RUN_DB)

`npm run verify:s2-006-db-replay` → **PASS**
(`evidence/s2-006-db-comparison.json`, DB runs bound in
`evidence/s2-006-db-run-{a,b}.json`): ephemeral loopback-only PostgreSQL
(pinned image, hardened container), migrations 0001–0005 applied to two
schemas, two child processes (PIDs distinct, executors `exec-db-s2006-a/b`)
executing the identical store-operation set through the canonical command API
on `PostgresVerifierStore`:
publishVerificationResult → idempotent replay (returns the recorded outcome
without a second ledger row) → publishCalibrationReport → publishAdjudication
→ fenced external call RESERVE→ACCEPT→FINALIZE.

Immutable-record equality across processes: identical replay digest
(`4e319f27…`), exactly 1 row per record table, 3 ledger rows, 6 outbox events
(zero duplicates), identical fencing token. Degenerate all-ERROR distributions
and any divergence fail closed; hard gates are part of the exit code. Probe
S's crash/restart scenario remains **NOT_RUN_DB** as declared by the offline
probe suite.

## 9. Clean checkout and acceptance command log

| Command | Result |
|---|---|
| `npm run verify:s2-006-dependencies` | exit 0 — PASS, 76 checks, FULL_GIT_BYTES |
| `npm run verifier:types` | exit 0 — write + drift check, 14 contracts (incl. transitive $ref closure), 22 876 bytes |
| `npm run test:verifier` | exit 0 — 191 tests: 190 pass, 1 skipped (NOT_RUN_DB guard in `store.test.mjs`), 0 fail |
| `npm run test:s2-006-calibration` | exit 0 — 66 tests, 0 fail |
| `npm run test:s2-006-security-probes` | exit 0 — 62 tests, 0 fail |
| `npm run verify:s2-006` | exit 0 — all gates PASS (dependency, types, suite, run, DB replay), verdict NEEDS_INPUT |
| `npm run verify:s2-006-db-replay` | exit 0 — PASS, two processes, identical digests |
| `npm test` | exit 0 — 654 tests: 653 pass, 1 skipped (NOT_RUN_DB guard), 0 fail |
| `npm run typecheck` | exit 0 |
| `npm run lint` | exit 0 |
| `git diff --check d7ce192..HEAD` | exit 0 |
| `npm run verify:clean-checkout` | see below |
| `npm audit --omit=dev` / `npm audit` | NOT_RUN here (no network in the offline acceptance suite); executed inside `verify:clean-checkout` |
| `npm run manifest:check` | exit 0 (root manifest regenerated for the final tree) |

`npm run verify:clean-checkout` re-archives HEAD into an empty temporary
directory, runs `npm ci` with an isolated cache plus every stage gate —
including the new S2-006 set (`s2-006-types`, `s2-006-verifier-tests`,
`s2-006-calibration`, `s2-006-security-probes`, `s2-006-replay`,
`s2-006-db-replay`) — and requires 42/42 commands to pass. The S2-006
dependency gate intentionally runs only in the working repository
(ARCHIVE_DEGRADED convention, carried from S2-005).

Freeze scope: `scripts/validate-contracts.mjs` now freezes the S2-006 surface
(`src/lib/verifier`, `tests/verifier`, `corpus/s2-006`, the four verifier
scripts, the type generator and the dependency/probe evidence); 85 files
added to `evidence/frozen-manifest.json` via an explicit reviewed `--freeze`.

## 10. Measured vs not measured vs not run vs blocked vs deferred

- **Measured (fixture stratum only):** all §5 metric counts; Run A/B equality;
  comparator checks; probes A–R; PostgreSQL replay equality; 0 hard-violation
  counters everywhere.
- **Not measured:** external validity, global paired statistics,
  inter-annotator agreement, independence tier, human time/latency/cost,
  probability calibration (not applicable).
- **Not run:** provider/model stratum (NOT_RUN_PROVIDER — not declared
  mandatory, does not block); real annotator/adjudicator/method-owner humans
  (NOT_RUN_HUMAN_INPUTS); probe S crash/restart on PostgreSQL (NOT_RUN_DB,
  state machine covered offline); audits outside the offline suite (run in
  clean checkout).
- **Blocked:** nothing. No safety, authority or dependency blocker exists.
- **Deferred:** externally authored corpus + independent annotation campaign;
  method-owner HumanDecision authoring thresholds; locked-test unseal
  protocol with `label_custodian` secret custody; provider calibration
  stratum.

## 11. Honest limitations

- The verifier remains an advisory component: it never accepts its own
  output, never raises an epistemic type, never grants permissions and never
  replaces a human decision (`humanDecisionRequired` is structurally `true`).
- Every quality number in §5 describes a deterministic engine on 45 fixture
  cases authored by the same project; they are regression evidence, not
  semantic-quality calibration.
- The fixture HMAC key proves the signature verification path only; real key
  custody belongs to `label_custodian` subjects and does not exist yet.
- The dependency record pins S1-011/S1-012 by tracked-copy digests; the
  cross-repository blob id inside the pinned AgentOS commit is `null` by
  declared limitation.
- `verify:s2-006` is the explicit evidence-publication run: it refreshes the
  tracked S2-006 evidence artifacts by design (the read-only property of §13
  applies to the verifier library API, which never mutates state).

## 12. Downstream handoff (spec §16–§17)

1. **Owner (human)**: appoint the method owner via an immutable HumanDecision
   bound to the exact study+thresholds digest; author numeric thresholds,
   confidence level, non-inferiority margin, multiplicity family, tie rule,
   coverage floor and the sample-size rationale in a NEW preregistration
   version.
2. **Label custodian + annotators**: commission an externally authored corpus
   with ≥ 20 independently labelled global cross-domain locked-test cases
   (spec §6), real annotator/adjudicator identities, conflict records and
   `label_custodian` key custody; keep the fixture stratum separate.
3. **Evaluation harness**: unseal the locked test only after the
   threshold-decision HumanDecision; run the comparator on the sealed Run A/B
   sets; publish the calibration report through the capability-gated command
   API into PostgreSQL and only then raise the verdict above NEEDS_INPUT.
4. **Provider stratum (optional)**: if a model-backed verifier is desired,
   declare it mandatory in the preregistration first; otherwise it stays
   NOT_RUN_PROVIDER without blocking.
5. No dependent production/pilot ticket may start on the basis of this
   report: S2-006 is not a production authorization.
