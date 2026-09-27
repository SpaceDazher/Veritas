# `tests/research/fixtures/` — what the test phase needs

Issue `SpaceDazher/Veritas#8`, track S2-008 (deterministic parallel track). This directory holds **test inputs only**: no module code, no evidence, no judgement. Anything that asserts a property belongs in `tests/research/*.test.mjs`; anything that is a first-class record of a run belongs in `evidence/s2-008-*.json`.

Read the interface first: the interface index handed to the test phase in the
chat workspace (`.bb/` is `.gitignore`d, so it is deliberately not committed
here). This file and your own file are all a worker needs.

## Rules that bind every fixture here

1. **Offline and deterministic.** No network, no LLM, no credentials, no environment lookups. A fixture that reads `process.env` is a fixture that changes between machines.
2. **No process clock.** No `Date.now()`, no `Math.random()`, no argument-less `new Date()`. Time enters a test only through an injected fixed clock; a fixture that bakes "now" into an expected value is a fixture that will pass once and fail forever.
3. **No secrets, ever.** Variable names and locations only. A credential name is acceptable; a credential value is not, in a fixture or in an evidence record.
4. **Deterministic ids are scoped by the run's label + step.** This is what lets a repeat run fail on the property instead of on its own leftovers. Fixtures therefore never assume an exclusive, permanent base.
5. **Every fixture is purged before the run that uses it**, and the purge is idempotent (`purgeRegistry` in `src/lib/research/registry.mjs`; the board precedent is `purgeProbeFixtures` at `src/lib/agentboard/probes.mjs:172`).
6. **A fixture must not weaken its own test.** A fixture whose only job is to make an assertion pass is a deleted negative probe with extra steps. If an assertion is wrong, fix the assertion and record why.

## What the test phase needs, and who owns it

| fixture | owner | needed by | what it must provide | why it is needed |
| --- | --- | --- | --- | --- |
| `ledger-writer-child.mjs` | **W2** | `tests/research/registry.test.mjs` (W2), `tests/research/replay.test.mjs` (W5) | A child process that opens its OWN registry handle with a **distinct raw run id and a distinct nonce**, then writes through the public `registry.mjs` exports only. Takes `--root`, `--label`, `--nonce`, `--expected-revision` and `--no-lock` from `argv`, and prints one canonical-JSON result line on stdout. | The A3 two-writer contention case and the cross-process replay. Under `--no-lock` the advisory lock is skipped entirely, so the revision CAS is the only thing preventing a lost update — if the child can win by racing, the ledger is wrong. It is a child PROCESS on purpose: two in-process handles would share module state and would not exercise the two-writer case at all. |
| a torn journal tail | **W2** (inline in the registry test) | `tests/research/registry.test.mjs` | A journal file whose last line is a partial write: valid JSON prefix, no trailing newline, no `prev_digest` successor. | `recoverTornTail` must truncate to the last COMPLETE record and emit a reconciliation row. A complete-but-uncommitted record must NOT be resurrected, and a partial line must never be returned as a record. |
| an expired budget reservation | **W2** (inline) | `tests/research/preregistration.test.mjs`, `tests/research/replay.test.mjs` | A reservation whose `expires_at` precedes the INJECTED clock reading, plus a live one and an over-limit one. | P4: expiry is a `ReconciliationRequired` with a reconciliation row — never a zero, never a silent skip, never a blind retry. A retry against the expired reservation must be refused too. |
| a post-result hypothesis card | **W2** (from `corpus/s2-008/cases/*.json`) | `tests/research/preregistration.test.mjs` | The SAME `card_id` with a mutated `test_design`, still valid against `contracts/hypothesis-card.schema.json`. | **The P3 proof.** The id does not change and the schema still accepts it, so only the `preregistrationDigest` can catch the rewrite. The test asserts the mutation MUST THROW. A test that merely checks the digest differs is weaker: the throw is the property. |
| a seed set that is not the preregistered one | **W2** (inline) | `tests/research/preregistration.test.mjs` | Four variants: one seed extra, one missing, two reordered, and a different count. | P2. Each must throw `BlockedPolicy('SEED_SUBSTITUTION')`. "The best seed" is not a statistic the verdict may use, because the seeds are preregistered. |
| a substituted-label dataset | **W2** (built by `substituteLabelsControl`, never written to `corpus/`) | `tests/research/causality.test.mjs` (W1), `tests/research/negative-controls.test.mjs` (W3) | An in-memory copy whose labels are replaced while the card text and claims are untouched. | **A4.** A causal claim on observational ground truth MUST fail. Control id `label_substitution`. The substitution must be visible in the record: it names what changed, so a reader can check the failure was caused by the label and not by something else. |
| corrupted run records | **W3** (built by `injectCorruption`) | `tests/research/expected-values.test.mjs`, `tests/research/comparator.test.mjs`, `tests/research/negative-controls.test.mjs` | For each frozen category — a trial status, a counter, a code set, a metric, a provenance field — a corrupted COPY that leaves the original byte-identical. | A2 and A3. The verdict must flip AND the flipped field must be named. The original must stay byte-identical so the control is re-runnable and so "the clean run still passes" is provable. |
| a calibration record with `blind_to_producer: false` | **W1** (validates it) / **W3** (uses it) | `tests/research/comparator.test.mjs` | A contract-valid record with `evaluator_independence.blind_to_producer === false` and `not_measured_reason: 'evaluator_not_independent'`. | P6. A non-independent evaluator resolves the trial to `NOT_MEASURED`, which is a `VIOLATION` — never `ALLOW`, and never 0 %. `evaluator_not_independent` is an exact value of the frozen `not_measured_reason` enum in `contracts/calibration-record.schema.json`. |
| a refused-write snapshot digest | **W2** (inline) | `tests/research/registry.test.mjs` | The `snapshotDigest` captured before and after a `BudgetExceeded` refusal. | P4's "the journal is byte-identical" half. A refusal that changed a single byte is a lie the board cannot detect later. |

## What must NOT be in this directory

- **No generated or copied bulk data.** The four `corpus/s2-008/` files are authored data with stable digests; fixtures reference them, they are not duplicated here.
- **No secrets, tokens, passwords or `.env` material**, in any form.
- **No hard-coded wall-clock instants used as expectations.** Instants are inputs to the injected clock, and the same instant must be written in the fixture and asserted in the test.
- **No probe or control logic.** A fixture provides input; a test asserts; a probe records a boolean fact through `ProbeRecorder`. Keeping them apart is what makes a fixture reusable across P1–P6 and across the replay.
- **No negative control that can be deleted without failing a test.** Each of the six control ids (`holdout_peek`, `seed_substitution`, `budget_opacity`, `label_substitution`, `missing_evaluator`, `corrupted_data`) is hard-gated: a control that does not flip the verdict fails the track.

## What this directory exports (the fixtures worker, S2-008 parallel track)

`index.mjs` is the one import: `import * as F from './fixtures/index.mjs'`. Every module is a
plain data module; none of them decides anything.

| module | provides | needed by |
| --- | --- | --- |
| `fixture-digest.mjs` | the ONE digest convention — `canonicalDigest` in wire form, plus a byte-identity assert | everything, and any test that wants to compare two fixture values |
| `fixture-fixed-clock.mjs` | the one injected instant (`FIXED_CLOCK`, `FIXED_INSTANT_ISO`, `FIXED_CLOCK_NOW_NS`) and a self-check that the two agree | any test that needs "now" without reading the process clock |
| `fixture-run-identity.mjs` | the two A3 run identities (distinct ids, nonces, executors), `ALLOWED_PROCESS_DIFFERENCES` (A5), and a check that the two really are separated | A3, A5 |
| `fixture-preregistration.mjs` | `HYPOTHESIS_CARD` (observational, contract-valid), `PREREGISTERED_*`, `BUDGET_RESERVATION`, `CALIBRATIONS`, `buildPreregistration()` (self-sealing, table digest sealed) | P1–P4, A4, `assertTableFrozen` |
| `fixture-measurement-set.mjs` | `FIXTURE_CASES` (8 cases, per-case agreement labels), `FIXTURE_TRIALS` (4 trials in the shape the table and the comparator read), `CLEAN_RUNS.a` / `.b`, `POOLED_COUNTS`, `FIXTURE_DERIVED_DISAGREEMENTS` | A2, A3, A4 |
| `fixture-expected-values.mjs` | the published document `EXPECTED_VALUE_TABLE` and the object `compareParallelTrack` reads, `EXPECTED_TABLE_ARGUMENT`; `assertFixtureTableMatchesFrozenTable()` runs at import | A2, A3 |
| `fixture-corrupted-variants.mjs` | one builder per corruption class, `EXPECTED_FLIPS` (the before/after a test asserts), `buildIdenticallyWrongControl()` (A3) | A2, A3, A4 |
| `fixture-temp-base.mjs` | `createTempBase()` / `purgeTempBase()` / `writeTempFile()`: a per-(label, step) scratch base, purged before the run, refusing anything it cannot prove it created | A5 |

### Two facts a test author must know before asserting anything

1. **A clean pair is `ALLOW` per trial and `FAIL` per campaign, and both are correct.** The
   frozen table pins trial 3 as `INFRA_ERROR`/`VIOLATION` and pins exactly one unmeasured trial, so
   `scoreRun` always raises `trial_violation` and `scoreMetric` always raises `metric_not_measured`;
   with eight cases the 95% interval also derives UNRESOLVED, so `decision_unresolved` is the third.
   `evidence/s2-008-harness.json` reports the same `FAIL` with the same three codes. A test therefore
   asserts the **axes that move** — table findings, per-trial verdicts, and the failure codes
   `compareParallelTrack` adds — and `CLEAN_CAMPAIGN_VERDICT` says `FAIL` rather than the `PASS` an
   earlier version of this directory wished for.
2. **The design and the derived decision are different, on purpose.** The corpus is designed
   7/8, 6/8, 5/8 (a known effect, a known null on the frozen baseline, a known negative) and the
   table pins that design; the 95% Wilson interval on eight cases derives UNRESOLVED for all three.
   Both are recorded (`outcome` and `derived_outcome` on every trial,
   `FIXTURE_DERIVED_DISAGREEMENTS` in the table document), and neither is presented as the other.

## Naming and shape

- kebab-case filenames, one fixture per file, named for what it provides (`ledger-writer-child.mjs`), not for the test that uses it.
- A child-process fixture reads its inputs from `argv` and writes exactly one canonical-JSON result line to stdout, so the parent can assert on the line without parsing free-form output.
- Every fixture that writes to disk writes only inside its own `results/s2-008/` scratch root, which is purged before the run and is not committed (`.gitignore` entry `results/s2-008/` is owned by D).

## Definition of done for this directory

The test phase is done when: every row above has an owner and a consuming test, no fixture reads a clock or the network, every negative fixture is referenced by an assertion that must fail without it, and `node --test --test-concurrency=1 "tests/research/"` runs green twice in a row from a clean `results/s2-008/` with no fixture left behind.
