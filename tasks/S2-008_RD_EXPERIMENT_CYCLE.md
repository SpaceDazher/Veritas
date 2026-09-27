# S2-008 — R&D experiment cycle: the deterministic parallel track

## Status of the ticket

| field | value |
| --- | --- |
| issue | [SpaceDazher/Veritas#8](https://github.com/SpaceDazher/Veritas/issues/8) |
| `engineeringStatus` (the ticket) | **`BLOCKED_DEPENDENCY`** — unchanged by the repair |
| `trackStatus` (the deterministic track) | **`NOT_RUN`** — derived by the aggregator, not by this file; `blockingGates []`, `defects []`, `exitCode 3` |
| `assuranceStatus` | `NOT_MEASURED` |
| `realAdapterStatus` | `NOT_RUN_REAL_ADAPTER` |
| `aMvpStatus` | `NOT_RUN` (A-MVP-01..07) |
| campaign decision on this corpus | **`UNRESOLVED`** (a null), matching the frozen declaration; the comparator's `FAIL` verdict is recorded beside it and counts for nothing |
| base | `813f5be66d8ddd936e925cca491063c6409ff7c3`, tree `504f0a1947fd6c19f5a53695c18f322bdd9880fa` |
| stage doc | [docs/stages/S2-008.md](../docs/stages/S2-008.md) |
| independent evaluation | [S2-008 Evaluation Report §0](../docs/decisions/S2-008-EVALUATION-REPORT.md) — the current state; the body below its §0 is the pre-repair measurement, kept as history |

**The ticket stays `BLOCKED_DEPENDENCY`, and the mechanics are ready.** Those two
sentences are about different things and neither weakens the other. The mechanics
are the fifteen modules, the frozen corpus (now seven files: the preregistration in
force, the superseded one beside it, the supersession between them, the appended
supersession ledger, the manifest and the two case files), the seven harness
scripts, the eight `node:test` suites
(246 tests) and the ten evidence records — all of them present, all of them run, all
of them deterministic. The ticket is not closed, because none of that is the scope
issue #8 asks for.

## The first delivery was RED, and that history is part of this record

At base `813f5be` the owner recorded, by hand:

```text
npm run test:research                 -> exit 0 (205 pass)
npm run s2-008:check-corpus           -> exit 0
npm run test:s2-008-security-probes   -> exit 0
npm run verify:s2-008-dependencies    -> exit 0
npm run s2-008:harness                -> exit 1  RESULT properties_held=5/5 verdict=FAIL overall=FAIL
npm run verify:s2-008-replay          -> exit 1  RESULT properties_held=1/2 verdict=FAIL overall=FAIL
npm run verify:s2-008                 -> exit 1  blockingGates [replay, harness]
```

The committed evidence said the same: `git show HEAD:evidence/s2-008-summary.json`
printed `status FAIL`, `exitCode 1`. There was no green-washing to clean up — the
implementation failed loudly, which is the only reason the repair was possible. The
three causes were all in the frozen documents, none in the comparator: a published
multiplicity rule that could **never reject** (`confidence 0.95` over `alpha 0.05`
with `m = 3`, so `1 - c = 0.05 > 0.016667`), an `INFRA` trial inside the measured
campaign (fail-closed ⇒ `VIOLATION` on every run, by construction), and a gate that
counted `verdict_is_pass`, which eight synthetic cases cannot satisfy without
fabricating an effect. The file:line citations and the full root-cause analysis are
in the evaluation report §0.2–§0.3.

**The repair was a redesign of a SYNTHETIC corpus, made before any new measurement
of it.** The eight cases are byte-identical to the first delivery
(`git diff --name-only HEAD -- evidence/s2-008/corpus/cases/` → 0 files), the
published confidence is now **derived** as `1 - alpha / family_size = 0.98333…`
instead of typed, the `INFRA` trial left the measured campaign while keeping its row
and its `VIOLATION`, and the superseded preregistration is preserved whole beside the
one in force as its own document kind (`SUPERSESSION`), carrying the reason and both
digests. This is **not** a hypothesis rewritten after a scientific result: nothing
scientific was measured, and a post-result edit of a hypothesis is an `AMENDMENT`
that P3 proves the track refuses.

## What "mechanics ready" means here

It means: every command exists, every gate runs offline, and every gate says what it
found. Observed with the non-writing forms of the writing gates, so no evidence
record is touched by a reader checking this file:

```text
npm run test:research                              -> exit 0, 246 tests, 246 pass, 0 fail, 11 suites
npm run s2-008:check-corpus                        -> exit 0, preregistration_digest b3ae2a63…, table 8062bc85…,
                                                          superseded 8fab7e83…, expected_campaign_decision UNRESOLVED
npm run test:s2-008-security-probes                -> exit 0, 6/6 probes pass, 7/7 controls flip, six counters 0
node scripts/verify-s2-008-dependencies.mjs --no-write
                                                    -> exit 0, 5 dependency bindings BOUND
node scripts/s2-008-harness.mjs --no-write         -> exit 0, properties_held=5/5 not_run=0 broken=0 verdict=FAIL overall=PASS
node scripts/s2-008-replay.mjs --corpus <copy>     -> exit 0, properties_held=2/2 not_run=0 verdict=FAIL overall=PASS
npm run lint / npm run typecheck                   -> exit 0 / exit 0   (typecheck does not read .mjs — see open item 3)
npm run verify:s2-008                             -> exit 3, status NOT_RUN, blockingGates [], defects []
```

`verify:s2-008` exits **3**, not 0, and that is the honest terminal state: there is
no blocking gate and no defect; the status is `NOT_RUN` because two disclosures
remain — the harness's `A3` is table-derived rather than a measurement (the
cross-process replay's `A3` is the authoritative one), and **the campaign behind
[#45](https://github.com/SpaceDazher/Veritas/issues/45) is `NOT_RUN`**, so this
deterministic track does not decide the ticket's own scope. Both entries were
already in the pre-repair summary. A `NOT_RUN` is never softened into a pass, and the
aggregator's own record says why:
*"engineeringStatus, assuranceStatus and the A-MVP rows are NOT derived from this
gate and never are: a green deterministic track does not convert the ticket's own
scope into done."*

It does **not** mean the campaign succeeded. It does **not** mean any acceptance
criterion is closed except the ones the evidence record says are:

| # | Criterion | state | one-line reason, from the record |
| --- | --- | --- | --- |
| A1 | six negative probes covered | **HELD** | `probes=6/6 notRun=0 broken=0`, six counters `0`, `hardGates.ok`; 7 controls ran and 7 flipped; all 4 frozen corruption variants injected |
| A2 | fail-closed comparator, controls must flip | **HELD** | all controls flip on binding **content**; `controlsFlipVerdict.gate.ok = true`; the `INFRA` row is still a `VIOLATION` |
| A3 | two process-separated runs, frozen expected-value table | **HELD** (was `FAILED` at the first delivery) | `separation=true separate_pids=true findingsA=0 findingsB=0 identical_wrong_both_non_empty=true`; the table was re-derived from the frozen counts by the frozen rule, not tuned to a verdict |
| A4 | observational cannot be read as causal | **HELD** | label seal holds on clean labels, breaks on substituted ones; refusal is the label guard, not a schema rejection |
| A5 | bound to commit SHA + tree SHA + raw run id, survives a repeat run | **HELD** (failed before delivery, when the track was untracked) | `bound_a=true bound_b=true track_tracked=true cross_process=true in_process_repeat=true reconciliation=true crash_classified=PASS` |

A3 and A5 failed at the first delivery for two different reasons, and the difference
matters for what is still open:

- **A3 was a document defect, and it is fixed as one.** The frozen rule could not
  reject anything, so no measurement could have produced a decided answer, and the
  table declared `POSITIVE`/`NULL`/`NEGATIVE` for a corpus whose intervals all
  straddle the `0.75` baseline outside the `0.02` band. The fix derives the
  confidence from the frozen literals, takes the `INFRA` trial out of the measured
  campaign, and re-derives the three measured rows through the comparator's own
  rule. The honest campaign answer is `UNRESOLVED` and the table now says
  `UNRESOLVED`, which is why they agree.
- **A5 was a delivery step, and delivery owns git.** No track worker runs `add`,
  `commit` or `restore`. It is `HELD` because the track is committed at
  `813f5be`, not because anything about the machinery changed.

## What the ticket asked for, and what this is not

Issue #8 asks for an R&D experiment cycle. Read literally, a campaign on a real
project, with real spend, and the task quality of a live executor. None of that is
attempted or claimed here. It stays tracked behind
[#45](https://github.com/SpaceDazher/Veritas/issues/45).

What is built is the deterministic parallel track: the **governance surface** of the
cycle — preregistration before trial one, frozen baseline, seed freezing, budget
reservation, fail-closed decision, six negative probes, six negative controls plus a
named extra, a frozen expected-value table, two process-separated runs and a
cross-process replay — executed entirely offline against authored fixtures.

The two are not substitutes, and the status table above is written so that it
cannot be misread:

- `trackStatus = NOT_RUN` says the **substrate** is real, the gates run, all five
  properties hold on a synthetic corpus, and the two things this track could not
  decide are named rather than averaged away.
- `engineeringStatus = BLOCKED_DEPENDENCY` says the **ticket** is not closed,
  because nothing here ran a real campaign, spent a real budget or executed
  anything through a really installed adapter.

The precedent is S2-007: `COMPLETE_WITH_LIMITS` of the engineering boundary did
not close issue #7, and the remainder was carried into #45. Same rule, same
reason — and the same reason applies here one stage earlier.

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
- **The gate is green on agreement, never on `ALLOW`.** A null campaign is an
  answer; a fabricated decision, a stale evidence file and an unresolved trial are
  all still refused.
- **No secrets in any artefact.** Variable names and locations only.

## Open items this record carries forward

1. **Reseal the delivery.** The repair is uncommitted on the working tree. The
   order is: finish the edits, **commit**, then
   `npm run manifest:write` (with the closure binding), then
   `npm run manifest:check` — `manifest:write` seals at `HEAD` while
   `manifest:check` pins the commit recorded in `evidence/closure-record.json`, so
   on a dirty tree `--write` breaks `--check`. `npm run inventory:write` /
   `inventory:check` likewise. That is the Seal worker's step.
2. **The campaign is `UNRESOLVED`, and that is not a failure to fix.** Eight cases
   per trial cannot resolve a `0.02` band at 98.33 % confidence. The two honest ways
   out are a larger `n` or a wider band, and either one is a preregistered decision
   taken **before** the next run — an `AMENDMENT`, never a post-hoc edit. Not this
   track's to choose, and not this track's to do silently.
3. **Two reporting defects outside this record's ownership.** `tsconfig.json` sets
   `allowJs: false`, so `npm run typecheck` exits 0 without reading a line of
   `src/lib/research/*.mjs` — the track's honest coverage is ESLint, `node --check`
   over the modules and `node --test`. The stale `index.mjs` header from the
   earlier revision is now corrected. `tsconfig.json` is still not this worker's
   file: **BLOCKED**.
4. **`evidence/probe-registry.json` has 34 pinned entries and no `s2-008` mention.**
   Adding one needs an explicit reviewed re-freeze; do not edit that file
   unilaterally.
5. **The aggregator exits 3 by design** and stays there while the real campaign is
   `NOT_RUN`. Do not "fix" that number by widening a threshold or by relaxing the
   two `NOT_RUN` disclosures: the exit code is the track telling the truth about
   scope it cannot decide.
6. **Two names for one question, and one name for two meanings.** The fixture
   derives the measured family from `designed_outcome !== 'INFRA'` and the table
   derives its own from the rows that publish an integer numerator and denominator;
   both are 3 today and `assertTableFrozen` binds the sealed value to the table's,
   so a drift is a refusal rather than a silent pass. Separately,
   `compareParallelTrack` returns a member called `identicalWrongFindings`
   carrying the **clean** findings while the harness's real control returns a member
   of the **same name** carrying the **corrupted** run's findings; a reader of
   `evidence/s2-008-comparison.json` must read `identical_wrong`, not
   `comparison.identicalWrongFindings`. Both are reported, not renamed: the
   comparator is not this worker's file and renaming it is not needed for a
   behaviour to be correct.
7. **Issue #8 itself stays open until #45 delivers the real campaign scope.** This
   track is its precondition, not its closure — and with the repair it is a
   precondition that is now **load-bearing**: the two processes agree with the
   frozen table on every field, the identical-wrong control still produces findings
   on both sides, and all seven controls still flip.
