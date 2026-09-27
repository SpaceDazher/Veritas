# S2-008 — R&D experiment cycle: the deterministic parallel track

## Status of the ticket

| field | value |
| --- | --- |
| issue | [SpaceDazher/Veritas#8](https://github.com/SpaceDazher/Veritas/issues/8) |
| `engineeringStatus` (the ticket) | **`BLOCKED_DEPENDENCY`** |
| `trackStatus` (the deterministic track) | **`FAIL`** — derived by the aggregator, not by this file |
| `assuranceStatus` | `NOT_MEASURED` |
| `realAdapterStatus` | `NOT_RUN_REAL_ADAPTER` |
| `aMvpStatus` | `NOT_RUN` (A-MVP-01..07) |
| base | `bd0e2f5b3873da33440cda5eb6b878c4a9988496` (S2-007 boundary, PR #43) |
| tree | `747a57934cfaf2e04c3322cc3d5f649340f80da0` |
| stage doc | [docs/stages/S2-008.md](../docs/stages/S2-008.md) |
| independent evaluation | [S2-008 Evaluation Report](../docs/decisions/S2-008-EVALUATION-REPORT.md) — carries its own `SUPERSEDED IN PART` banner; its **findings** were confirmed, its **measurements** describe the pre-repair tree |

**The ticket stays `BLOCKED_DEPENDENCY`, and the mechanics are ready.** Those
two sentences are about different things and neither weakens the other. The
mechanics are the fourteen modules, the frozen corpus, the seven harness
scripts, the six test suites and the ten evidence records — all of them present,
all of them run, all of them deterministic. The ticket is not closed, because
none of that is the scope issue #8 asks for.

## What "mechanics ready" means here

It means: every command exists, every gate runs offline, and every gate says
what it found.

```text
npm run s2-008:check-corpus           -> exit 0, corpus not drifted from the fixture
npm run test:s2-008-security-probes -> exit 0, 6/6 probes pass, 6/6 controls flip
npm run s2-008:run -- --label a       -> exit 1, 4 trials, 3 findings against the frozen table
npm run s2-008:replay                 -> exit 1, A3 FAILED, A5 FAILED
npm run verify:s2-008-dependencies    -> exit 1, BLOCKED_DEPENDENCY (index.mjs-absent-at-commit)
npm run verify:s2-008                 -> exit 1, status FAIL, blockingGates [dependency, replay]
npm run test:s2-008                   -> exit 0, 205 tests, 205 pass, 0 fail, 11 suites
```

A non-zero exit here is not a defect in the claim: the gates are fail-closed by
design, and a red gate is the honest reading of this tree. The aggregate status
is `FAIL` and the two blocking gates are named in
`evidence/s2-008-summary.json`.

It does **not** mean any acceptance criterion is closed except the ones the
evidence record says are:

| # | Criterion | state | one-line reason, from the record |
| --- | --- | --- | --- |
| A1 | six negative probes covered | **HELD** | `probes=6/6 notRun=0 broken=0`, six counters `0`; both gates purge their own probe roots first, and the purge is idempotent |
| A2 | fail-closed comparator, controls must flip | **HELD** | all six controls flip on binding **content**; `gate.ok = true` |
| A3 | two process-separated runs, frozen expected-value table | **FAILED** | runs are separated and agree with each other, but each produces 3 table findings (`POSITIVE`/`NULL`/`NEGATIVE` expected, `UNRESOLVED` observed) |
| A4 | observational cannot be read as causal | **HELD** | label seal holds on clean labels, breaks on substituted ones; refusal is the label guard, not a schema rejection |
| A5 | bound to commit SHA + tree SHA + raw run id, survives a repeat run | **FAILED** | every binding and every repeat witness holds, but `git ls-files` reports `tracked_files_of_this_track = 0` |

A3 and A5 fail for two different reasons, and the difference matters for what
happens next:

- **A3 is a real answer, not a broken mechanism.** The mechanism the criterion
  is about is the frozen table, and it is load-bearing: the identical-wrong
  control injects one corruption into **both** runs, leaves their digests equal,
  and still produces findings from both. What fails is the delivered campaign —
  at 8 cases × 5 seeds the frozen design cannot resolve its own preregistered
  noise band, so three trials resolve to `UNRESOLVED` and one is an
  `INFRA_ERROR`. No threshold was widened and no table row was edited to make
  this look decided; both would be a post-result edit of a preregistration,
  which is an `AMENDMENT`, not a fix.
- **A5 is a delivery step.** The mechanism holds: a 40-hex commit SHA, a 40-hex
  tree SHA, a raw run id, a cross-process repeat witness and an in-process
  `--repeat` witness, with only `raw_run_id`, `nonce`, `executor_id`,
  `output_root`, `run.label` and `ledger.snapshot_digest` differing. The
  criterion fails because this track's files are untracked. `git add` of the
  track's paths is the delivery worker's step; no track worker runs git writes.

## What the ticket asked for, and what this is not

Issue #8 asks for an R&D experiment cycle. Read literally, a campaign on a real
project, with real spend, and the task quality of a live executor. None of that
is attempted or claimed here. It stays tracked behind
[#45](https://github.com/SpaceDazher/Veritas/issues/45).

What is built is the deterministic parallel track: the **governance surface** of
the cycle — preregistration before trial one, frozen baseline, seed freezing,
budget reservation, fail-closed decision, six negative probes, six negative
controls, a frozen expected-value table, two process-separated runs and a
cross-process replay — executed entirely offline against authored fixtures.

The two are not substitutes, and the status table above is written so that it
cannot be misread:

- `trackStatus = FAIL` says the **substrate** is real, the gates run, two of
  five criteria do not currently hold, and every limit is named in the
  evidence.
- `engineeringStatus = BLOCKED_DEPENDENCY` says the **ticket** is not closed,
  because nothing here ran a real campaign, spent a real budget or executed
  anything through a really installed adapter.

The precedent is S2-007: `COMPLETE_WITH_LIMITS` of the engineering boundary did
not close issue #7, and the remainder was carried into #45. Same rule, same
reason — and the same reason applies here one stage earlier.

An earlier draft of this file said `trackStatus = PARTIAL` and described a tree
in which the five modules were skeletons, the harness scripts did not exist and
four of six probes reported `not_run`. That tree is gone. The measurement above
is the one on disk; if the two ever disagree, the evidence record wins and this
file is wrong.

## House rules the track obeys

- **Offline and deterministic.** No network, no LLM, no credentials. No
  `Date.now()`, no `Math.random()`, no argument-less `new Date()` in a decision
  path. The clock and the id factory are injected and the bundled default clock
  never advances. Same base ⇒ same outcome.
- **Reuse, never reimplement.** `src/lib/agentboard/**`,
  `src/lib/verifier/canonical-json.mjs` and `src/lib/sloqual/**` are imported.
  `scripts/s2-007-db-replay.mjs` is the replay template. Nothing in that
  boundary was edited to make the track green.
- **The three frozen schemas are the only validation surface.** A fourth was not
  added, and none of the three was edited: the digests agree across the issue
  record, `evidence/frozen-manifest.json`, the commit and the working tree.
- **Fixtures are purged before the run that uses them.** Without the purge a
  repeat run on a permanent base fails on its own leftovers instead of on the
  property.
- **One owner per file.** A needed change outside an ownership list is reported
  (`BLOCKED:`), never made unilaterally.
- **Never weaken a test, delete a negative probe, loosen a threshold or
  catch-and-ignore to get green.** If an assertion is wrong, fix it and record
  why.
- **No secrets in any artefact.** Variable names and locations only.

## Open items this record carries forward

1. `git add` the track's paths, re-run the track on the merged base, and reseal
   `evidence/root-manifest.json`, `evidence/FILE_INVENTORY.md` and the contract
   freeze the way S2-007 did. This is what turns A5.
2. A3 needs a decision, not a workaround: either the frozen design gets more
   cases or a wider band **as a preregistered amendment decided before the next
   run**, or the criterion stays `FAILED` and the honest campaign verdict stays
   `UNRESOLVED`.
3. Two reporting defects outside this record's ownership:
   `src/lib/research/index.mjs` still carries a header claiming every export
   throws `NOT_IMPLEMENTED` (the barrel resolves 87 names), and
   `tsconfig.json` sets `allowJs: false`, so the track is not type-checked.
   Both reported `BLOCKED`.
4. `evidence/probe-registry.json` has 34 pinned entries and no `s2-008` mention.
   Adding one needs an explicit reviewed re-freeze; do not edit that file
   unilaterally.
5. The full acceptance set (`npm test`, `typecheck`, `lint`, `build`,
   `inventory:check`, `manifest:check`, `verify:clean-checkout`) was not run in
   this iteration; only the S2-008 track commands listed above were.
6. Naming: the frozen interface index names the task record
   `tasks/S2-008_PARALLEL_TRACK.md`; this worker was assigned
   `tasks/S2-008_RD_EXPERIMENT_CYCLE.md` by name and wrote that file. Only one
   should survive and the choice is the delivery worker's. Neither file existed
   before this one.
7. Issue #8 itself stays open until #45 delivers the real campaign scope. This
   track is its precondition, not its closure.
