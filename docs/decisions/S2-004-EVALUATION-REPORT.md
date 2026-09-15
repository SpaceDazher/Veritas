# S2-004 — Evaluation Report (Claims, Experts and Provenance Graph)

Ticket: `tasks/S2-004` · Branch: `codex/s2-004-claim-provenance-graph`
Canonical base: `origin/main` at `b3fe0ee1b0320ad349265fc5e33327833418e197` (completed S2-003)

## Verdict: PASS_WITH_LIMITS

A bounded local implementation of the versioned typed claim/provenance graph
is complete and green: every hard gate of todo §11 passes on the frozen
96-case corpus with process-separated Run A/B replay, a PostgreSQL-backed
independent replay and the twelve adversarial probes A–L. The verdict is
bounded because semantic quality remains `NOT_CALIBRATED`: there is no
independently produced external gold corpus and no external replay. An
unconditional `PASS` is forbidden by this task without both.

## 1. Dependency gate

`evidence/s2-004-dependency-binding.json` +
`scripts/verify-s2-004-dependencies.mjs` (fail-closed, 32 checks, all from
Git bytes or digest-verified tracked copies):

- `origin/main` is at the S2-003 canonical base `b3fe0ee1…`; closure and
  implementation commits are reachable ancestors.
- S2-003 evidence verified from Git bytes: green clean checkout,
  `PASS_WITH_LIMITS` verdict line in the evaluation report, Run A/B
  comparison with identical decisions and distinct executor identities, DB
  replay comparison, frozen manifest blob.
- The four carried S2-003 limits are byte-verified in the report: live
  private connectors NOT_PROVEN, OCR/ASR fixture-only, near-duplicate
  detection `NOT_CALIBRATED`, candidate lineage requires human confirmation.
- S2-003 contract schemas pinned by blob digest at contractVersion 1.0.0.
- Stage-1 bindings pinned to AgentOS `a7940e113492c83a29533d1e93f2724c36a9bbc1`
  with SHA-256-verified tracked copies: S1-003 (executable SHACL validation,
  `pass`), S1-011 (knowledge promotion gate, `pass_with_limits`), S1-012
  (confidence/provenance semantics, `pass_with_limits`).
- 16 gate tests: the real repository passes; mutations (unreachable commit,
  blob drift, identity collapse, verdict mutation, dropped limit marker,
  branch-pinned Stage-1 commit, drifted/missing tracked copy, payload
  substitution) all fail closed.

## 2. Contracts and implementation

- 10 versioned JSON Schema contracts (1.0.0) + generated TypeScript types
  with drift test; fail-closed ajv validation on every write (39 schema
  tests: canonical fixtures accepted, mutations rejected).
- Memory store (`src/lib/claims/store.mjs`): immutable revisions, projected
  lifecycle, deterministic content-derived ids, digest-bound single-use
  review decisions, producer self-review denied, derived ACL = most
  restrictive input, span-digest evidence binding, `DEPENDS_ON` cycle
  rejection, transitive invalidation with preserved audit trail, idempotent
  operation ledger with conflict-on-mismatch and reconciliation.
- PostgreSQL store (`src/lib/claims/postgres-store.mjs`) with the same
  semantics on migrations 0001–0004 (0004 adds projected claim state, the
  operation ledger, the audit outbox and the polarity/modality/denominator
  columns).
- Deterministic rule-based extraction preserving polarity, units,
  denominators, exclusions, measurement qualifiers, modality and the
  four-time model; quarantine on ambiguity and horizon-less forecasts;
  embedded instructions keep data inert (`policy_blocked`).
- Frozen-artifact integrity: the S2-004 artifacts are sealed into the reviewed
  draft set (`evidence/frozen-manifest.json`, 338 entries) and
  `frozenTargets` in `scripts/validate-contracts.mjs` was extended to cover
  them; §9 records the inherited red gate this closed.

## 3. Frozen corpus (96 cases, todo §10 matrix)

| category | cases |
|---|---|
| atomic extraction | 24 |
| opinion / hypothesis / forecast | 16 |
| numeric / unit / qualifier / time traps | 16 |
| translation / citation / upstream lineage | 12 |
| contradiction / scope | 12 |
| expert lens isolation | 8 |
| invalidation / revision / retraction | 8 |

Every case pins immutable input (segment texts + snapshot time model +
lineage + ACL), an independently authored oracle
(`prn-corpus-annotator`, distinct from producer and extractor) and the
expected abstentions/decisions. The manifest pins SHA-256 of every case and
is verified fail-closed before any run; dev/calibration/locked-test split is
32/32/32.

## 4. Run A/B and PostgreSQL replay

- Run A (`exec-s2-004-a`, clock 2026-01-15, own nonce/pid/output root) and
  Run B (`exec-s2-004-b`, clock 2026-03-21T23:59:59.999Z, own nonce/pid/
  output root) are separate OS processes on the same frozen commit:
  96/96 cases each, decision counts identical, graph digests identical,
  0 decision mismatches.
- PostgreSQL replay: ephemeral hardened podman container, two schemas, each
  run its own child process with a `PostgresClaimGraphStore`
  (`s2-004-db-run-a` / `s2-004-db-run-b`): 96/96, identical decisions and
  graph digests, 0 mismatches.

## 5. Metrics (numerators/denominators/missing, evidence/s2-004-comparison.json)

| metric | value |
|---|---|
| extraction field accuracy | 1236/1236 (0 missing) |
| extraction exact accuracy | 103/103 claims (0 missing) |
| span binding accuracy | 103/103 (0 missing) |
| epistemic-type confusion | 103 match / 0 mismatch |
| qualifier preservation | 88/88, 0 lost |
| negation preservation | 88/88, 0 lost |
| unit preservation | 88/88, 0 lost |
| contradiction precision | 6/6 expected-contradiction pairs marked, 0 false flags (precision 6/6 among flagged) |
| contradiction recall | 6/6 |
| upstream family collapse accuracy | 11/11 lineage cases |
| stale invalidation recall | 8/8 |
| abstention rate | 4/88 text cases (ambiguous fragments → abstention, never guesses) |
| ACL leakage / authority expansion / type auto-promotion / stale survivors / duplicate side effects | 0 / 96 each |

All hard gates of todo §11 are green: no lost negation/unit/qualifier, no
type auto-promotion, no ACL leak, no authority expansion through content, no
stale survivor, no duplicate side effect, corpus complete (96, none missing,
duplicated or excluded), replay determinism proven.

## 6. Adversarial probes A–L

12/12 `DETECTED` (`evidence/s2-004-security-probes.json`), including: ten
reprints collapse to one family (A); exception/unit/nominal-qualifier
preservation with truncated-variant rejection (B); import time never becomes
forecast time (C); physical metaphor stays `ANALOGY`, never a mechanism (D);
parent tombstone transitively stales derivatives with preserved audit (E);
lens re-ranks without touching protected fields and never leaks across users
(F); translation negation-flip detected, original kept, translation
quarantined (G); scope differences are not contradictions (H); prompt
injection stays inert with zero authority counters (I); idempotency-key
reuse with different input conflicts without mutation (J); forged
review/calibration records fail digest/authority binding and never promote
(K); private claims cannot leak into shared aggregates, derived ACL only
tightens (L).

## 7. Honest limitations (carried and declared)

- Semantic quality is `NOT_CALIBRATED`: the oracle was authored alongside
  the implementation by the same project (documented conventions), not by an
  independent external body; no external replay exists. The rule-based
  extractor is corpus-convention-bound, not a general semantic model.
- No claims of objective truth, near-100 % semantic accuracy in the wild,
  production multi-tenant deployment, or source independence under
  `UNKNOWN_LINEAGE`.
- No causality from correlation, analogy or expert authority; a lens is
  ranking-only.
- Live private connectors remain unproven and OCR/ASR remain fixture-level
  (S2-003 limits carried forward).
- Human approval is not claimed anywhere: every reviewer decision in the
  evidence base was produced by the described principals in fixtures.
- S2-005 (synthesis) and S2-006 (independent semantic verifier) are not
  started; they inherit the graph API, the frozen corpus/oracle conventions
  and the `NOT_CALIBRATED` boundary.

## 8. Inputs for S2-005 / S2-006

- Read API surface: `getClaim`, `listClaimHistory`, `listEvidenceMap`,
  `listClaimEdges`, `listExpertLenses`, `getCalibrationRecord`,
  `getInvalidationEvents` — identical semantics in memory and PostgreSQL
  stores.
- Frozen corpus + oracle conventions for independent re-evaluation:
  `corpus/s2-004/manifest.json` (locked digests) and
  `docs/claims/S2-004-CLAIM-GRAPH-CONTRACT.md`.
- Open items for S2-006: independent gold corpus, blind re-annotation,
  calibrated thresholds for near-duplicate merging and contradiction
  precision/recall on externally authored text.

## 9. Frozen draft artifacts: inherited red gate, reseal and command log

### 9.1 The clean-checkout record committed at `3b6f8af` is red, not green

`evidence/clean-checkout.json` as committed in `3b6f8af` records
`exitCode: 1`, `passed: false`, with the step `contracts`
(`node scripts/validate-contracts.mjs`) `FAIL` and the assertion
`Frozen draft files changed: run an explicit reviewed freeze`. The commit
subject of `3b6f8af` ("record green independent clean checkout") therefore
contradicted the record it introduced; the record itself was accurate, and
re-running that command at that HEAD reproduces the failure.

Root cause: S2-004 added or changed files inside targets frozen by
S2-001/S2-002/S2-003 — `contracts/` (10 claim graph schemas), `migrations/`
(`0003_claim_graph.sql`, `0004_claim_graph_state.sql`) and `evidence/external/`
(3 Stage-1 evaluation records) — and changed two frozen S2-003 files
(`scripts/verify-s2-003-dependencies.mjs` and
`tests/ingestion/dependency-binding.test.mjs`, the reachability fix for the
inherited origin/main defect described in §1) without ever running the
reviewed freeze. The sealed manifest therefore held 199 entries against 214
files. The S2-004 dependency gate cannot detect this: it verifies the
historical blob of `evidence/clean-checkout.json` at the S2-003 closure
commit, never the S2-004 record.

### 9.2 Remediation applied on this branch (local; not pushed)

- `frozenTargets` extended with the S2-004 artifacts (`src/lib/claims`,
  `tests/claims`, `corpus/s2-004`, `docs/claims`, the S2-004 runners,
  `evidence/s2-004-dependency-binding.json`,
  `evidence/s2-004-security-probes.json`) — the same coverage rule S2-003
  applied to its ingestion artifacts, so no stage can live outside the gate.
- reviewed freeze applied: 199 → 338 entries, +139 added, 0 removed, 3 updated
  digests (`scripts/validate-contracts.mjs`,
  `scripts/verify-s2-003-dependencies.mjs`,
  `tests/ingestion/dependency-binding.test.mjs`).
- the reseal does not disturb the dependency gates: the S2-003 gate and the
  S2-004 gate both resolve their pinned blobs at their own closure commits
  (`b3fe0ee…`), never at HEAD.
- the todo §13 range check `git diff --check b3fe0ee..HEAD` exposed 12
  trailing-whitespace lines in `migrations/0003_claim_graph.sql` (inherited
  from the implementation commit and invisible to every other gate); they
  were removed in this pass, so the range check now exits 0.

### 9.3 Command log with exit codes (todo §18.8)

| command | exit code | result |
|---|---|---|
| `npm ci` | 0 | clean install |
| `npm run verify:s2-004-dependencies` | 0 | 33 checks, `FULL_GIT_BYTES`, no issues |
| `npm run claims:types` | 0 | 10 contracts, generated types byte-identical |
| `npm run test:claims` | 0 | 108/108 |
| `npm run test:s2-004-security-probes` | 0 | 12/12 `DETECTED`, 0 undetected |
| `npm run verify:s2-004` | 0 | `PASS_WITH_LIMITS`, 0 mismatches (recorded in `evidence/s2-004-comparison.json`); additionally re-executed against the archive by the extended clean-checkout runner at every clean checkout (§9.4) |
| `npm run verify:s2-004-db-replay` | 0 | 96/96, 0 mismatches, identical decisions and graph digests; re-run with `--write` at the post-fix HEAD, so the record pins the updated migration digest and `testedImplementationCommit 54c011f` (the previous record predated the whitespace fix) |
| `npm test` | 0 | 382/382, 0 fail |
| `npm run typecheck` | 0 | 0 diagnostics |
| `npm run lint` | 0 | clean |
| `npm run build` | 0 | clean checkout (locally needs `DATABASE_URL`; a dummy DSN is sufficient and the clean-checkout runner sets it) |
| `npm audit --omit=dev` / `npm audit` | 0 / 0 | 0 vulnerabilities |
| `node scripts/validate-contracts.mjs` before the reseal | 1 | red: frozen manifest drift (§9.1) |
| `node scripts/validate-contracts.mjs` after the reseal | 0 | 34/34 policy probes, 11 schema fixtures, 25 mutations rejected |
| `npm run verify:s2-003-dependencies` | 0 | inherited ingestion gate green after the reseal |
| `npm run manifest:write` / `npm run manifest:check` | 0 / 0 | root manifest resealed to the reseal commit |
| `npm run inventory:write` / `npm run inventory:check` | 0 / 0 | tracked-file inventory resealed |
| `npm run verify:clean-checkout` before the reseal | 1 | `passed: false`, step `contracts` FAIL (§9.1) |
| `npm run verify:clean-checkout` after the reseal | 0 | `passed: true`, all required steps PASS, on a tree identical to HEAD except the record file itself (§14 forbids embedding the container commit; resolve it externally with `git log -1 -- evidence/clean-checkout.json`) |
| `git diff --check` (`b3fe0ee…HEAD`) | 0 | no whitespace errors; the §13 range check initially reported 12 trailing-whitespace lines in `migrations/0003_claim_graph.sql`, fixed in this pass |
| `git status --short` | 0 | clean working tree |

### 9.4 Open items before merge

- **Clean-checkout coverage of the S2-004 stage** — resolved in this pass.
  Until now `verify-clean-checkout.mjs` ran only generic steps plus the
  S2-002/S2-003 stage steps, so a green record certified the generics, not
  the S2-004 stage. The runner now executes the S2-004 steps against the
  archive (dependency gate in `ARCHIVE_DEGRADED` mode, `test:claims`,
  `test:s2-004-security-probes`, `verify:s2-004`, `verify:s2-004-db-replay`),
  and — closing a fail-open hole inherited from the S2-003 era — the S2-003
  steps that were missing from `requiredIds` are gating now as well.
- **identity-suite flake** — root cause unknown, must be tracked. One
  clean-checkout attempt observed a single identity-suite failure (158/159)
  that did not reproduce on re-run (159/159 locally and in the final green
  record). A GitHub issue must be filed when the branch is pushed
  (suggested title: `S2-004: flaky identity suite in clean checkout
  (158/159, no reproduction)`) so the flake cannot silently recur inside a
  gated run.
- **archive-safe binding test** — extending the runner exposed a second
  inherited flaw: `tests/claims/dependency-binding.test.mjs` ran the *real*
  gate against the archive's absent `.git` and failed (107/108), while the
  dedicated `s2-004-dependencies` step passes there by design in
  `ARCHIVE_DEGRADED` mode. The test now mirrors the S2-003 precedent
  (`tests/ingestion/dependency-binding.test.mjs`) and asserts fail-closed
  (`ok: false`, issues non-empty) when no `.git` is present: full repo runs
  and clean archives both pass 108/108.
- `npm audit` with dev dependencies is a hard exit-0 requirement of §13;
  today it passes with 0 advisories, but future CVEs in dev-only packages
  outside this branch's control would force a false `REVISE`. An
  allowlist/override policy for tooling advisories is a spec-level change
  proposed for the next stage.