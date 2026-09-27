## 0. The repair of 2026-09-27 — the first delivery was RED; this section is the current state

> **Read this section first.** Everything below §0 is the **pre-repair measurement**,
> taken at base `bd0e2f5` and again at `813f5be`, and it is left exactly as it was
> taken, for the same reason the "Delivery update" and "Supersession" notes below
> leave theirs: a reader must be able to see what was measured, when, and against
> which tree. Where §0 and the body disagree, **§0 is the current state and the body
> is history.** The body also contains a `SUPERSEDED by the repair of 2026-09-27`
> banner on §7.3; that banner stays, because §0.12 below states the same thing in
> the current vocabulary.

Section map, in the order the history has to be read: §0.1 what was asked · §0.2 what
was built · §0.3 the first delivery was red, and the three root causes · §0.4 the
repair · §0.5 the new gate condition · §0.5a the triage round · **§0.5b the third
red-to-green step: an aggregator that could not return `PASS`** · **§0.5c the fourth
red-to-green step: green but not sound — the aggregator trusted its children’s claims about
themselves** · §0.6 acceptance
table A1..A5 · §0.7 the six negative probes · §0.8 the `A === B` rule and the frozen
table · §0.9 the two process-separated runs · §0.10 the honest campaign outcome ·
§0.11 the limits · §0.12 what remains blocked behind #45 · §0.13 VERDICT.

### 0.1 What was asked

Issue [`SpaceDazher/Veritas#8`](https://github.com/SpaceDazher/Veritas/issues/8) asked
for an R&D experiment cycle: preregistration before the first trial, a frozen metric
and baseline, frozen seeds, a budget reservation, a **fail-closed** decision layer, six
negative probes, a frozen expected-value table, two process-separated runs, a
cross-process replay, and evidence that survives a repeat on the same base. Read
literally, a cycle also means a campaign on a real project, with real spend, and the
task quality of a live executor; that part stays behind
[#45](https://github.com/SpaceDazher/Veritas/issues/45) and is **not** attempted here
(§0.12).

The owner recorded the first delivery as **red** and asked for a repair under four
frozen decisions (R-A the rule must be self-consistent, R-B the campaign must be
well-posed, R-C the gate becomes property-and-expectation based, R-D the evidence and
this report state the history plainly), with one anti-goal stated explicitly: *the
repair must not make the stage green by moving the goalposts of the fixtures until a
fabricated POSITIVE looks legitimate.*

### 0.2 What was built

| Contour | Path | What it is |
| --- | --- | --- |
| Library | `src/lib/research/*.mjs` | contracts, closed vocabulary, causality guard, preregistration (+ amendment, + supersession), corpus reader, ledger, frozen table, campaign derivation, fail-closed comparator, negative controls, six probes, policy, deterministic transport, run engine, public surface |
| Corpus | `evidence/s2-008/corpus/` | 8 observational cases (PRIMARY + HOLDOUT), `manifest.json`, `preregistration.json` (in force), `preregistration-superseded.json` (the first delivery, preserved whole), `preregistration-supersession.json` (the pointer between them) |
| Entry points | `scripts/s2-008-{build-corpus,harness,replay,run,security-probes}.mjs`, `scripts/verify-s2-008{,-dependencies}.mjs` | build/check the corpus, one run, the two-run cross-process replay with the crash/restart phase, the six probes and controls, and the two gates |
| Tests | `tests/research/*.test.mjs` | 8 files (`gate-semantics.test.mjs` and `triage-hardening.test.mjs` were added by the repair and the triage round) plus a fixtures directory; `node --test` reports **11 suites, 256 tests, 256 pass, 0 fail** (246 after the repair; +10 in the soundness round of §0.5c) |
| Evidence | `evidence/s2-008-*.json` (10 records) | `security-probes`, `probes`, `controls`, `harness`, `run-a`, `run-b`, `comparison`, `replay`, `dependency-binding`, `summary` |

The fail-closed comparator, the six probes, the ledger chain, the preregistration
seal, the label guard and the crash/restart reconciliation are unchanged by the
repair. The repair changed a **document** (R-A), a **corpus composition** (R-B) and a
**gate condition** (R-C) — nothing else, and nothing under `contracts/`.

### 0.3 THE FIRST DELIVERY WAS RED

The owner's own record at base `813f5be`:

```text
npm run test:research                 -> exit 0 (205 pass)
npm run s2-008:check-corpus           -> exit 0
npm run test:s2-008-security-probes   -> exit 0
npm run verify:s2-008-dependencies    -> exit 0
npm run s2-008:harness                -> exit 1  RESULT properties_held=5/5 verdict=FAIL overall=FAIL
npm run verify:s2-008-replay          -> exit 1  RESULT properties_held=1/2 verdict=FAIL overall=FAIL
npm run verify:s2-008                 -> exit 1  blockingGates [replay, harness]
```

The committed evidence agreed with the owner rather than with a green summary:
`git show HEAD:evidence/s2-008-summary.json` printed `status FAIL`, `exitCode 1`,
`blockingGates ["replay","harness"]`, with `replay=FAIL/exit 1` and
`harness=FAIL/exit 1` in `gates`. **There was no green-washing to clean up**: the
implementation failed loudly, which is the only reason the repair was possible.

**Root cause 1 — the frozen multiplicity rule could not reject anything.**
`tests/research/fixtures/fixture-preregistration.mjs:434` published
`noise_rule.confidence: 0.95` and `:466` published the same `0.95` into
`multiplicity_rule`, over `alpha: 0.05` (`:465`), `kind: 'HOLM_BONFERRONI'` (`:463`)
and `family_size: measuredTrials.length = 3` (`:472`). A comparison inherits the
bound `1 - c` from a `c`-level interval, and `1 - 0.95 = 0.05 > 0.05/3 = 0.016667`,
so the rule could reject **nothing**, whatever was measured. The comparator already
said so: `src/lib/research/comparator.mjs:1734` emits the limit
`frozen_rule_cannot_reject`, and its own comment at `:1720-1723` says *"Fixing it is a
PREREGISTRATION change (the confidence has to rise to `1 - alpha / m`), never a
comparator change."* The comparator was right; the document was wrong.

**Root cause 2 — the measured campaign was not well-posed.**
`tests/research/fixtures/fixture-preregistration.mjs:267` declares
`trl-s2-008-04` with `designed_outcome: 'INFRA'`, and the frozen table counted all
four rows in the campaign tally while pinning `metrics.notMeasured` to `1`
(`src/lib/research/expected-values.mjs:332-333` at `813f5be`). The comparator is
fail-closed, so an unresolved trial is a `VIOLATION` on **every** run:
`trl-s2-008-04: VIOLATION (TRIAL_NOT_RESOLVED:INFRA_ERROR)`, plus
`metric_not_measured` and `decision_unresolved` — the three entries that are still in
`evidence/s2-008-harness.json` → `comparison.failures` today. The default campaign was
therefore **FAIL by construction**, for a reason that had nothing to do with whether
the mechanics work.

**Root cause 3 — the gate counted `verdict_is_pass`.**
`scripts/verify-s2-008.mjs:289` (at `813f5be`) gated on
`terms.verdict_is_pass !== true`, and `scripts/s2-008-harness.mjs:844` computed
`verdict_is_pass: verdict === 'PASS'` from the campaign verdict. With eight synthetic
cases the honest campaign answer is a null, so requiring `ALLOW` was satisfiable only
by tuning the fixtures until a fabricated effect looked legitimate — the anti-goal
above, and the thing this ticket's own negative probes exist to prevent.

### 0.4 The repair — a redesign of a SYNTHETIC corpus, made BEFORE any new measurement of it

| # | Decision | What landed, and where |
| --- | --- | --- |
| **R-A** | the frozen rule must be self-consistent, and the change is a documented supersession, never an edit | `tests/research/fixtures/fixture-preregistration.mjs`: `PREREGISTRATION_ALPHA = 0.05`, `MEASURED_FAMILY_SIZE = PREREGISTERED_MEASURED_TRIALS.length` = 3 (**counted**, from the predicate that excludes `designed_outcome === 'INFRA'`), and `CORRECTED_CONFIDENCE = 1 - PREREGISTRATION_ALPHA / MEASURED_FAMILY_SIZE` = `0.9833333333333333` — **derived in code**, not typed, and assigned to **both** `noise_rule` and `multiplicity_rule` (a split pair is the comparator's `self_reported_interval_divergence` finding). `RULE_FEASIBILITY` is the track's own `ruleFeasibility(...)` over those constants, so a test asserts a boolean instead of re-deriving IEEE-754 by hand: `1 - (1 - 0.05/3)` is 5.2e-17 **above** `0.05/3`. Observed: `{"rejection_floor":0.016667,"max_p_bound":0.016667,"never_rejects":false,"can_only_answer":"ANY_OUTCOME","feasible":true}` — the rule can reject. |
| **R-B** | the measured campaign must be well-posed, and the table is re-derived **by the rule** | `trl-s2-008-04` leaves the measured set and therefore the multiplicity family, while **keeping** its table row (`expectedStatus INFRA_ERROR`, `expectedOutcome INFRA`, `expectedVerdict VIOLATION`), its reconciliation duty, and its `TRIAL_RESULT` slot in `EXPECTED_LEDGER_SHAPE` (count 4). It is exercised as INFRA where INFRA was already exercised: P6's missing evaluator, the replay's crash/restart phase, `INFRA_RECONCILIATION`. The three measured rows now declare what the frozen rule **derives** from the counts they publish, and `src/lib/research/campaign-expectation.mjs` (new, 186 lines) re-derives the campaign through the comparator's own `decisionFromInterval` and refuses a declaration the rule does not produce. |
| **R-C** | the gate becomes property-and-expectation based | `verdict_is_pass` is **removed** at all four coupled sites. `scripts/s2-008-replay.mjs` defines the rule **once** (`ledgerShapeIssues`, `frozenCampaignDecision`, `campaignDecisionAgreement`) and `scripts/verify-s2-008.mjs` and `scripts/s2-008-harness.mjs` **call** it. See §0.5 for the condition in words. |
| **R-D** | the evidence and this report state the history plainly | This section, the superseded document preserved below, and the status blocks in `docs/stages/S2-008.md`, `tasks/S2-008_RD_EXPERIMENT_CYCLE.md` and `README.md`. |

**The eight synthetic cases are byte-identical to the first delivery** —
`git diff --name-only HEAD -- evidence/s2-008/corpus/cases/` reports **0** files, and
`npm run s2-008:check-corpus` → exit **0** re-derives the whole committed corpus from
the fixture and finds no drift (the integration log additionally records two
independent builds producing identical digests). No measurement was re-tuned; the only
thing that changed is the *interval* those same cases are summarised at.

**This is not a hypothesis rewritten after a scientific result, because nothing
scientific was measured.** The distinction the ticket cares about is a document kind,
and it is enforced in code rather than promised here: a hypothesis edited **after a
result** is an `AMENDMENT`, and `P3` proves the track refuses it
(`HYPOTHESIS_REWRITE_AFTER_RESULT`, `PREREGISTRATION_MUTATED_IN_PLACE`,
`AMENDMENT_AS_DECISION_BASIS`, `AMENDMENT_SAME_CARD_ID`). What the repair did instead
is a **new document kind** — a `SUPERSESSION` — carrying the reason and **both**
states' published values, sitting **beside** the document it replaces. Nothing
measured was re-tuned: the eight cases are the same bytes, the baseline is the same
`0.75`, the band is the same `0.02`, the seeds are the same five, the budget is the
same reservation. The campaign had not been run against a repaired rule when the rule
was repaired; the only numbers that moved are the interval bounds, which are a
function of the published confidence, and the design (`POSITIVE` / `NULL` /
`NEGATIVE` / `INFRA`) is still published separately as `designed_outcome` so the
design and the rule's answer can be compared instead of being collapsed into one
name.

**The superseded document is preserved whole, with its old digests quoted.**
`src/lib/research/preregistration.mjs` gained `SUPERSESSION_KIND` with
`createSupersession` / `assertSupersession`; it is not an amendment (an amendment
replaces a card, this replaces a rule) and it is not a result (`assertPreregistration`
refuses `supersedes` on a preregistration, so the pointer lives beside its target).
The corpus carries all three documents:

```text
evidence/s2-008/corpus/preregistration.json              digest b3ae2a638f52c9505642348e04ae8d2bf5cf6c623eb819b3d43651913b522207  confidence 0.9833333333333333  table 8062bc85f0252e6e48111b5dea3312ad698bca679da14eabd763510074207f63  IN_FORCE
evidence/s2-008/corpus/preregistration-superseded.json   digest 8fab7e83d472b7914b6e660dd956f6dc394589bcd4ab323162b6545dde7fe479  confidence 0.95               table 9aad76e1b0f8c6f55ac59548347278f1b4f7c3e5ea4d11a75d2fd1896c08af62  SUPERSEDED
evidence/s2-008/corpus/preregistration-supersession.json
                                                   id spr-f5a6bf11a57e9cd01d1fa6e0, supersedes 8fab7e83d472b7914b6e660dd956f6dc394589bcd4ab323162b6545dde7fe479,
                                                   supersedes_confidence 0.95, supersedes_expected_table_digest 9aad76e1…, replaced_by_confidence 0.9833333333333333
```

**Preservation is verified, not claimed.**
`diff <(git show HEAD:evidence/s2-008/corpus/preregistration.json) evidence/s2-008/corpus/preregistration-superseded.json`
produces **no output**, and both files hash to
`sha256 7d4e396ca39b64a13bee9b1e190aa4d2c8702cce816691c63256da230ef9a64e`. The
first delivery stays readable, and `scripts/s2-008-build-corpus.mjs` refuses to write
a reconstruction that does not reproduce it
(`S2_008_CORPUS_SUPERSEDED_SEAL_DRIFT`, `S2_008_CORPUS_SUPERSEDED_CONFIDENCE_DRIFT`).
The reason travels with the document: *"the published confidence 0.95 gave
1 - c = 0.05 > alpha/m = 0.016667, so the rule could never reject; the confidence is
now derived as 1 - alpha/family_size, and the redesign was made before any new
measurement of the synthetic corpus"*.

### 0.5 The new gate condition, in plain words

A gate is green when **six independent things** are true, and the campaign verdict is
not one of them:

1. **every acceptance property held** (`every_property_held`, `held == total`);
2. **the comparator's decision equals the decision the frozen table declares** —
   `expected_campaign_decision == observed_campaign_decision` *and* the table itself
   produces no campaign finding (`decision_agrees_with_table`);
3. **the ledger shape matches the table** (`ledger_shape_matches_table`, a measurement
   over the journal each run actually wrote — 7 rows per run, chain verified);
4. **every negative control flipped its verdict** (`controls_all_flipped`);
5. **`not_run == 0` and `broken == 0`**;
6. **every comparator failure the run record carries is one the frozen table declares**
   (`comparator_failures_match_frozen_expectation`, with the unmatched list in
   `unexpected_comparator_findings`) — added by the triage round, see §0.5a.

The terms are written into the record by the run itself. Observed verbatim in
`evidence/s2-008-harness.json` → `overall_terms`:

```json
{"every_property_held":true,"held":5,"total":5,
 "expected_campaign_decision":"UNRESOLVED","observed_campaign_decision":"UNRESOLVED",
 "decision_agrees_with_table":true,"campaign_findings":[],"controls_all_flipped":true,
 "controls_not_run":0,"comparator_failures_match_frozen_expectation":true,
 "unexpected_comparator_findings":[],"ledger_shape_matches_table":true,
 "ledger_shape_findings":0,"not_run_zero":true,"not_run_count":0,"broken_zero":true,
 "broken_count":0,"verdict":"FAIL"}
```

`verdict` stays a member, with the comment `// REPORTED, NOT A TERM.` in the source.

**What the gate no longer demands: `ALLOW`.** It no longer requires the campaign to
pass, to be positive, to clear the noise band, or to produce a decided outcome at all.
A `NULL` or `UNMET` campaign is an **answer**, and agreement with it is the success
case. On this corpus the honest campaign answer is `UNRESOLVED`, the frozen
expectation is `UNRESOLVED`, and that agreement is what the green means.

**What the gate still refuses — all three re-proved on the final tree:**

| Refusal | How it was re-proved | Observed |
| --- | --- | --- |
| **an unresolved trial is still a `VIOLATION`** | `trl-s2-008-04` keeps its row, its `INFRA_ERROR` status and its `VIOLATION` verdict, and the campaign comparison still emits all three failure codes | `evidence/s2-008-harness.json` → `comparison.failures`: `trial_violation (TRIAL_NOT_RESOLVED:INFRA_ERROR)`, `metric_not_measured`, `decision_unresolved` — and `tests/research/gate-semantics.test.mjs` → *"R-B a SKIPPED, UNRESOLVED, INFRA_ERROR or NOT_MEASURED trial is still a VIOLATION under the new gate"*; `npm run test:research` → **exit 0**, 246/246 |
| **a fabricated decision must still FAIL the gate** | durable: `tests/research/gate-semantics.test.mjs` → *"R-C a fabricated POSITIVE is a table FINDING in the frozen table, not only in the gate"* and *"R-C the anti-goal twin: a record whose decision diverges from the table is refused — even when it CLAIMS to agree"*. Observed now with a throwaway driver run out of the gitignored chat workspace (`tmp/`, a scratch driver, not an artefact, deliberately not committed — the two cases named on the left are the durable pins) | **exit 0** — `UNRESOLVED` → `agrees true`, `table_issues []`; `POSITIVE` → `agrees false`, `CAMPAIGN_DECISION_DIVERGES_FROM_FROZEN_TABLE` **plus** 2 table findings; `NEGATIVE` → same; an absent decision → `CAMPAIGN_DECISION_ABSENT`; a hand-edited declaration → `BLOCKED_POLICY: EXPECTED_CAMPAIGN_DIVERGES_FROM_RULE` |
| **a stale evidence file must still be refused** | durable: `tests/research/gate-semantics.test.mjs` → *"R-C a stale evidence file is refused: the tree sha must be the tree the gate ran on, and the commit must be named"* and *"a hand-edited evidence file is refused by its bytes, whatever the record inside it claims"*. Observed now with `freshnessVerdict(...)` — the aggregator's own exported check — applied to the committed replay record, judged 1 000 ms after that record's own `finished_at` | node exit **0**; `windowMs: 0` → `{"ok":false,"issues":["stale-run-timestamp"],"age_ms":1000}`; `windowMs: 6h` → `{"ok":true,"issues":[],"age_ms":1000}`; a tampered `headTreeSha` → `{"ok":false,"issues":["stale-tree-sha"]}`. The aggregator end-to-end refusal is the integration log's `S2_008_FRESHNESS_WINDOW_MS=0 node scripts/verify-s2-008.mjs --no-write` → **exit 1**, `status FAIL`, `blockingGates ["replay"]`, `stale evidence: stale-run-timestamp` |

An **absent** expectation is not agreement: it is a named refusal,
`EXPECTED_CAMPAIGN_ABSENT` / `CAMPAIGN_DECISION_ABSENT`, so a gate with no expectation
is not green. The comparator itself was **not** weakened: no threshold widened, no
negative probe or control deleted, no evidence file hand-edited, nothing under
`contracts/` touched.

### 0.5a What the triage round added on top of the repair (2026-09-27, second round)

An independent triage reproduced seven ways to reach a green aggregator without a
correct measurement. All seven are now closed by something mechanical, and this
section records the three changes that alter what the gates read, so the sections
below can be read against the current tree.

| Change | Where | What it does |
| --- | --- | --- |
| a **sixth** gate term, `comparator_failures_match_frozen_expectation` | `scripts/s2-008-replay.mjs:727,744,758` and `scripts/s2-008-harness.mjs:993,1014,1035`; re-read by the aggregator at `scripts/verify-s2-008.mjs:348`, which no longer trusts the child's own verdict | a run record that **carries** a comparator failure the frozen table does not declare is now a gate term (`UNEXPECTED_CODE`), not only a recorded verdict. The honest campaign's own three failures per run **are** declared, so the fail-closed record is still the green one |
| a fifth gate, **`corpus`** | `scripts/verify-s2-008.mjs` (the gate list is in the summary record's `gates`) | re-derives the corpus from `tests/research/fixtures/**` **on disk**, so a working-tree tamper is a FAIL with the drifted file named. The root `manifest:check` cannot see it: that gate reads `git show HEAD:<file>` |
| a third **supersession ledger** entry | `src/lib/research/preregistration.mjs` (`assertSourceLedger`), declared as literals in `tests/research/fixtures/fixture-preregistration.mjs`, sealed into `evidence/s2-008/corpus/supersession-ledger.json` | the F1 declaration above moved the table digest to `8062bc85…` (`spr-f5a6bf11a57e9cd01d1fa6e0`). A change to the frozen sources is now refused until an entry is appended with a reason and both old digests |

**What this gate is and is not.** It is a self-consistency gate plus an enumerated
change counter, *not* an immutability gate: a **recorded** change to the frozen
sources is a supersession, which is what R-A asked for. The eight synthetic cases
did not change in either round (`git diff --name-only HEAD -- evidence/s2-008/corpus/cases/`
→ 0 files), and `FROZEN_CASES_DIGEST` is byte-identical across all three ledger
entries, which is the point of the anchor covering both digests.

### 0.5b The third red-to-green step — an aggregator that could not return `PASS`

The second round closed every way to reach a *false* green, and left one way to reach
a `false` red. The owner's own ordered re-run of the tree found
the last defect in the aggregator itself, not in the track:

```text
npm run s2-008:harness                -> exit 0  RESULT properties_held=5/5 verdict=FAIL overall=PASS
npm run verify:s2-008-replay          -> exit 0  RESULT properties_held=2/2 verdict=FAIL overall=PASS
npm run verify:s2-008                 -> exit 3  status=NOT_RUN ok=false blockingGates=[] defects=[]
```

**What it meant.** Every check the track owns had run and every one had passed —
five gates `PASS(exit=0)`, an empty defect list, an empty blocking-gate list — and
the aggregator still answered `NOT_RUN`, exit **3**, forever. A `NOT_RUN` is defined
in this repository's own header (`scripts/verify-s2-008.mjs`, the first rule) as
*"I could not check"*, never *"I checked and it was inconclusive"*. The terminal
state was therefore saying **the opposite of what had happened**: it claimed a check
was missing while the record next to it listed five that had run.

**The cause was a data model, not a threshold.** One array, `notRun`, carried two
incompatible kinds of entry. Five were real gate-level `NOT_RUN`s — the dependency
gate that could not run, the corpus check that could not run, a mandatory probe or
control that did not run, the cross-process replay, the harness that could not run
every property. **Two were statements about the track, not about a check**: that the
harness's `A3` is table-derived rather than a measurement (so the replay's `A3` is
the authoritative one), and that the campaign behind
[#45](https://github.com/SpaceDazher/Veritas/issues/45) is `NOT_RUN`, so this
deterministic track does not decide the ticket's own scope. The status line then read
`notRun.length > 0`, and the two informational notes are present on **every** run —
so `PASS` was unreachable by construction, and a gate whose verdict is a constant is
not a gate.

**The fix separates what may vote from what may only be recorded.** The status is
now derived from the gate-level terms alone; the two notes moved to a `scopeNotes`
array that is published in `evidence/s2-008-summary.json` and printed, member for
member, and that cannot decide anything. The reason a scope note must not vote is
one sentence: *a scope note is not an answer to the question the verdict asks — it
never says whether a check this stage owns was performed or what it found — so a note
that votes is a veto, and a veto held by a statement that is true on every run is a
gate whose verdict is a constant.* Nothing was softened to get here: the `NOT_RUN`
paths still exit **3**, and a child gate that exits 0 while printing no counter map
is still a `NOT_RUN` rather than a pass.

**The third precondition went the other way — stricter, not looser.** *The track's
own files are untracked (`git ls-files` reports 0 of them), so no artefact of this
track is bound to a base a reader can check* was a soft note, and then a `NOT_RUN`
entry. Provability is a hard requirement of this repository, so it is now a **defect
in `defects` and blocking**: `FAIL`, exit **1**. This is the one place the repair is
strictly stronger than the file it replaced, and the file says so in its own header.

**Verified now — every number below is traceable to a named evidence file.** The
command list with its observed exit codes, run in this order on this tree. (This is
the state at the end of the **third** step; the soundness round of §0.5c re-ran the
same list and moved the test count from 250 to 256.)

| command | observed exit | what the run printed |
| --- | --- | --- |
| `node --test --test-concurrency=1 "tests/research/*.test.mjs"` | **0** | `# tests 250 / # suites 11 / # pass 250 / # fail 0 / # skipped 0` |
| `npm run s2-008:check-corpus` | **0** | `unseal_digest sha256:9ff4511e…`, `expected_table_digest 8062bc85…`, `expected_campaign_decision "UNRESOLVED"`, `source_ledger_entries 3` |
| `npm run test:s2-008-security-probes` | **0** | 6 families, 6 probes ran, `allPassed true`, `notRun []`, `broken []`, all six hard-gate counters `0` — `evidence/s2-008-probes.json` |
| `npm run verify:s2-008-replay` | **0** | `RESULT properties_held=2/2 not_run=0 verdict=FAIL overall=PASS`; `expected_decision=UNRESOLVED observed_decision=UNRESOLVED agrees=true` — `evidence/s2-008-replay.json`, `properties = [A3 HELD, A5 HELD]` |
| `npm run verify:s2-008` | **0** | `"status": "PASS"`, `"ok": true`, `"exitCode": 0`, `blockingGates []`, `notRunGates []`, `defects []`, `notRun []`, and both `scopeNotes` — `evidence/s2-008-summary.json`, `observedAtIso 2026-09-27T14:12:12.280Z` |
| `npm run verify:s2-008-dependencies` | **0** | `checked 23`, `ok true`, `frozen_targets.verified 610/610 pinned_paths`, `track_files_tracked 57`, `track_files_untracked []`, `syntax.modules 34 / parsed 34` — `evidence/s2-008-dependency-binding.json` |
| `npm run lint` | **0** | `eslint .` clean |
| `npm run typecheck` | **0** | `tsc --noEmit` clean (and it still reads none of the `.mjs` — §0.11 item 7) |
| `npm run inventory:write` | **0** | `{"exitCode":0,"mode":"write","trackedFiles":848,"path":"evidence/FILE_INVENTORY.md"}` |

`npm run manifest:write` / `manifest:check` were deliberately **not** run: they seal
at HEAD and pin the commit in `evidence/closure-record.json`, the tree is dirty, and
the Seal worker owns that order.

**The record is not laundered, and the number that matters is still `FAIL`.** The
campaign decision and the frozen expectation are both still reported, in both child
records: `gates.replay` and `gates.harness` each publish
`expected_campaign_decision "UNRESOLVED"` beside `observed_campaign_decision
"UNRESOLVED"` beside `campaign_verdict` / `verdict` `"FAIL"`. The aggregator's `PASS`
is a statement about the *gates*, and `gates.harness.properties` is still
`[A1 HELD, A2 HELD, A3 HELD, A4 HELD, A5 HELD]` with `overall "PASS"` and `verdict
"FAIL"`. The ticket's own scope is untouched: `engineering_status
"BLOCKED_DEPENDENCY"`, `assurance_status "NOT_MEASURED"`, `real_adapter_status
"NOT_RUN_REAL_ADAPTER"`, `a_mvp_status "NOT_RUN (A-MVP-01..07, behind #45)"`.

**Three pins hold the split in place**, in
`tests/research/gate-semantics.test.mjs`, against the real exported helpers of the
real script — all three `ok` in the 250 above: every gate green **with both scope
notes present** is `PASS` / exit 0 **and the notes are still in the summary's
`scopeNotes`**; a child gate reporting `NOT_RUN` is still `NOT_RUN` / exit 3 with the
gate id in `notRunGates`; and an untracked track file is a defect / exit 1, with the
controls that 1, 2 and 57 tracked files make the same run `PASS` and that an
*unreported* count (`null`) is not invented into a failure.

### 0.5c The fourth red-to-green step — green but not sound: the aggregator trusted its children’s claims about themselves

**The stage was green and the green was not sound.** An independent adversarial
recheck of `scripts/verify-s2-008.mjs` found that the aggregator trusted what its
child gate scripts said **about themselves**, and a triage reproduced every finding
by hand. The consequence is the exact failure class acceptance `A2` and `A5` exist
to prevent — *a gate that cannot report a false pass, with every artefact bound to a
commit, a tree SHA and a raw run id* — so it is fixed here rather than explained
away. The four soundness defects, each reproduced before the fix and each reproduced
again after it (both observations, pre-fix and fixed bytes, in the chat artifact
`.bb/chats/thr_4etd4uwcke/artifacts/s2-008-trust.md`):

| # | the defect, in one line | pre-fix, observed | fixed, observed |
| --- | --- | --- | --- |
| **A3** | the replay record was self-attesting: the aggregator compared the child’s **own** printed `REPLAY_EVIDENCE_SHA256` against the bytes on disk, and the five pass terms were re-read from that record’s claims | stub replay (no trial, no comparator, copies the previous record, refreshes two timestamps, prints the digest of what it wrote) → **exit 0, `status PASS`, `defects []`, replay `PASS(exit=0)`, `A3:HELD`, `A5:HELD`** | **exit 1**, first defect `the replay record: it was written by invocation 00a9d81514ea, not by this one (afb60eeb3d21)` |
| **A1a** | the probes gate’s counts were never floored: only “a counter map exists and every counter is 0” was asserted, and `totals` was stored and compared with nothing | stub printing `{"counters":{},"totals":{"probes_ran":0,"controls_ran":0}}` and exiting 0 → **exit 0, `status PASS`, published `gates.probes.totals {"probes_ran":0,"controls_ran":0}`, gate `PASS`** | **exit 1**, three defects: the counter map reports none of the 6 declared counters, `0 of the 6 probes the frozen probe list declares were run`, `0 of the 7 controls the frozen control list declares were run` |
| **F** | the harness record was read raw: no digest of its own, no freshness check, no exit-code agreement, no overall agreement — and the harness was spawned with `--no-write` only when `--corpus` was passed, so a check run rewrote the record it was judging | doctored record (`overall FAIL`, `verdict POSITIVE`, every property `ok:false`, `agreement_source MEASUREMENT`) → **exit 0, `status PASS`, `defects []`, published `harness PASS(exit=0)` with `overall FAIL` and `A1..A5:FAILED`**; and a marker written into the record was **erased** by `verify:s2-008.mjs --no-write` | **exit 1**: `the harness record reports overall=FAIL while the harness process exited 0; the harness record reports A1, A2, A3, A4, A5 as NOT held`; the marker **survives** a check run |
| **E1 / E-MOD** | partial untracking was invisible: the dependency gate computed and published `track_files_untracked` and `track_files_modified`, the aggregator copied neither, and its guard was the strict `track_files_tracked === 0` | `git rm -q --cached -r src/lib/research` (15 of 57 still tracked) → **exit 0, `status PASS`, `defects []`** while the dependency gate’s own record named all 15 untracked files | **exit 1**, naming every path in `track_files_untracked` and `track_files_modified` |

A fifth, **G (bootstrap ordering)**, could not produce a false green but made the
first run on a clean base red: the dependency gate listed
`evidence/s2-008-replay.json` as `REQUIRED` while gate 1 runs *before* the aggregator
spawns the replay that writes it. Observed pre-fix: run 1 **exit 1**
(`dependency BLOCKED_DEPENDENCY`, `evidence-absent:evidence/s2-008-replay.json`),
runs 2 and 3 **exit 0**. Fixed and re-observed on a fresh copy of the tree with no
`evidence/s2-008-*.json`: the **first** `npm run verify:s2-008` is **exit 0**,
`status PASS`, `defects []`, five gates `PASS(exit=0)`, both `scopeNotes` present.

**The fix is five strengthenings, none of them a relaxation.** None of it touches
the comparator, the six probes, the two run gates or `contracts/`; the round is about
the aggregator’s trust model, and a child’s account of itself is untrusted input:

1. **Invocation binding (`G1`).** The aggregator mints one id per run
   (`randomBytes(16)`, `node:crypto`), passes it to both children as
   `--invocation-id`, and each child writes `invocation_id` and `head_tree_sha` into
   its record. A record whose `invocation_id` is not the id this run generated, or
   whose tree is not the tree this run observed, is a **defect** — so a record copied
   from an earlier run cannot match, and the `A3` stub dies there. The id is the only
   random value on the path, it decides nothing, and it is **excluded from
   repeatability by name** exactly like the freshness observation
   (`evidence/s2-008-harness.json` → `repeatability.excluded_fields`).
2. **The harness gets the replay’s treatment (`G2`).** A digest **the aggregator
   computes itself** over the bytes it read, the invocation binding above, and an
   agreement check between the record’s claims and what the aggregator observed: a
   record whose `overall` is not `PASS`, or whose property flags are not all true, or
   whose recorded exit code disagrees with the exit code the aggregator saw, is a
   **defect**, never a `PASS` gate. The harness is now spawned with `--no-write`
   **unconditionally**, so a check run never rewrites the record it is judging
   (`gates.harness.record_is_this_run` says which of the two cases a run is in).
3. **Probe-count floors read from the code (`G3`).** `PROBE_FAMILIES`, `PROBE_NAMES`
   and `HARD_GATE_COUNTERS` from `src/lib/research/probes.mjs`, plus
   `EXPECTED_CONTROLS` and `EXTRA_CONTROL_IDS`, give **6 probes and 7 controls**; a
   record reporting fewer, or a counter map reporting none of the declared counters,
   is a defect (`gates.probes.floors`, `read_from` names the source).
4. **Provability over the whole track (`G4`).** The aggregator copies
   `track_files_expected`, `track_files_untracked` and `track_files_modified` into
   `gates.dependency`, and **any** untracked or modified track file is a blocking
   defect with the paths named. A `null` from the dependency gate stays a defect
   rather than a silent pass, and the all-untracked case still fails exactly as it
   did.
5. **Bootstrap ordering (`G5`).** The dependency gate stops requiring, **on a chain
   run**, the evidence files the chain itself produces in that run, through an
   explicit `--chain-produced` flag the aggregator passes. The default behaviour is
   byte-for-byte unchanged, so standalone `npm run verify:s2-008-dependencies` keeps
   its contract (`chain_run.flag_seen false` in the committed record), and the
   aggregator owns the presence of the records it wrote — which it already enforced.

**Ten negative tests hold the trust model in place** in
`tests/research/gate-semantics.test.mjs` (the suite is 256 tests now, up from 250
after the repair; the vacuity proof is in the chat artifact: the same suite run
against the pre-fix bytes fails the soundness section). Each case spawns the real
chain in a throwaway clone and reads the process exit code; none of them asserts
about a mock.

**The working-tree boundary, stated and not closed (B-low).** A doctored
`evidence/s2-008-summary.json` **in the working tree** survives both
`npm run manifest:check` and `npm run inventory:check`, because they read **committed**
bytes — `scripts/generate-manifests.mjs` uses `git show HEAD:<file>` and
`scripts/check-inventory.mjs` uses `git ls-files`. This is recorded as a **design
boundary, not a defect closed**: the next chain run rewrites the summary, and the
working-tree surface is what the corpus drift gate
(`scripts/s2-008-build-corpus.mjs --check`) covers. The statement is not only in this
report — the aggregator publishes it in the record and in its own printed output, so a
reader of `evidence/s2-008-summary.json` alone sees it (`boundaries[0]`, verbatim in
`evidence/s2-008-summary.json`).

**One residual bootstrap hole is reported, not fixed, because the file is not this
round’s.** `evidence/s2-008-security-probes.json` is `REQUIRED` by the dependency
gate, and the chain **cannot produce it**: `scripts/s2-008-security-probes.mjs` writes
that file only when it is given `--write`, and the aggregator spawns it without one
(`scripts/verify-s2-008.mjs` documents the choice at its `CHAIN_PRODUCED_RECORDS`
comment). Observed on a fresh copy with no `evidence/s2-008-*.json`: a bare
`npm run verify:s2-008` is **exit 1**,
`dependency gate: BLOCKED_DEPENDENCY (evidence-absent:evidence/s2-008-security-probes.json)`;
after the one command that writes it (`node scripts/s2-008-security-probes.mjs
--write`, **exit 0**), the **first** `npm run verify:s2-008` is **exit 0**. Making that
record chain-produced is a one-line change in `scripts/verify-s2-008.mjs` and
`scripts/verify-s2-008-dependencies.mjs`; both files belong to the round’s other
owners and neither is edited here.

**Verified now — the reseal of the soundness round, every number traceable to a named
evidence file.** The command list below was run in this order on this tree; the exit
codes are the observed ones.

| command | observed exit | what the run printed |
| --- | --- | --- |
| `node --test --test-concurrency=1 "tests/research/*.test.mjs"` | **0** | `# tests 256 / # suites 11 / # pass 256 / # fail 0 / # cancelled 0 / # skipped 0` |
| `npm run s2-008:check-corpus` | **0** | `unseal_digest sha256:9ff4511e…`, `expected_table_digest 8062bc85…`, `expected_campaign_decision "UNRESOLVED"`, `source_ledger_entries 3` |
| `npm run test:s2-008-security-probes` | **0** | 6 families, 6 probes, 7 controls all flipped, `any_run_sensitive: true`, `reasons: []` — `evidence/s2-008-security-probes.json` |
| `npm run verify:s2-008-replay` | **0** | `RESULT properties_held=2/2 not_run=0 verdict=FAIL overall=PASS`; `A3 HELD`, `A5 HELD`; `wrote evidence/s2-008-replay.json bytes=36789` |
| `npm run verify:s2-008` | **0** | `"status": "PASS"`, `"ok": true`, `"exitCode": 0`, five gates `PASS(exit=0)`, `blockingGates []`, `notRunGates []`, `defects []`, `notRun []`, both `scopeNotes`, and `boundaries[0]` naming B-low — `evidence/s2-008-summary.json` |
| `npm run verify:s2-008-dependencies` | **0** | `ok true`, `status PASS`, `chain_run.flag_seen false` (the standalone default, unchanged) — `evidence/s2-008-dependency-binding.json` |
| `npm run lint` | **0** | `eslint .` clean |
| `npm run typecheck` | **0** | `tsc --noEmit` clean (and it still reads none of the `.mjs` — §0.11 item 7) |
| `npm run inventory:write` | **0** | `{"exitCode":0,"mode":"write","trackedFiles":848,"path":"evidence/FILE_INVENTORY.md"}` |

What the green summary now carries that the third step's did not
(`evidence/s2-008-summary.json`): `invocation` (the id, its minter, the two children it
was passed to, the two records that must carry it, `excluded_from_repeatability: true`,
`decides: false`); `gates.replay.invocation_id` and `gates.harness.invocation_id` beside
their `head_tree_sha`; `gates.harness.evidence_sha256`, `evidence_bytes` and
`record_is_this_run`; `gates.probes.floors` naming 6 probes, 7 controls and 6
hard-gate counters with `read_from`; and `gates.dependency.track_files_expected_count`
beside `track_files_untracked []` and `track_files_modified []`.

`npm run manifest:write` / `manifest:check` were deliberately **not** run: they seal at
HEAD and pin the commit in `evidence/closure-record.json`, and the Seal worker owns
that order after the commit.

**One precondition went the other way — stricter, and it is what made the delivery
possible.** The untracked-track rule of the third step fired on a *dirty* tree as well
as an untracked one: at the end of the fix round `npm run verify:s2-008` was
**exit 1** with exactly one defect, `provability: 5 modified file(s) of this track are
not bound to a base a reader can check`, and it went green on the same tree only after
the fix was committed. That is the rule working as written: an artefact a reader
cannot tie to a commit is not evidence, whether it was never added or was edited after
the last commit.

### 0.6 Acceptance table A1..A5 → observation → evidence path

`HELD` means a check ran on this tree and passed. `FAILED` would mean a check ran and
did not hold. `NOT_RUN` is not used for a property anywhere in the current evidence.

| # | Criterion | Status | Observation, from the named record | Evidence path |
| --- | --- | --- | --- | --- |
| **A1** | the registry covers all six negative probes | **HELD** | `totals: {families: 6, probes: 6, probes_ran: 6, passed: 6, failed: 0, not_run: 0, broken: 0, controls_declared: 6, controls_extra_declared: 1, controls_ran: 7, controls_flipped: 7}`; all six hard-gate counters `0`, `hardGates.ok: true`, `moved: []`; `familiesAttempted` lists all six families `pass` | `evidence/s2-008-security-probes.json` → `totals`, `hardGates`, `familiesAttempted`; `evidence/s2-008-probes.json` → `results` |
| **A2** | a skipped or unresolved trial is a `VIOLATION`, and every negative control flips the verdict | **HELD** | `controls=7 (six frozen + 1 named extra) notRun=0 gate_ok=true infra_trial_verdict=VIOLATION comparator_controls_before=ALLOW`; all four declared corruption variants injected, `corruption_variants_unproductive: []`; `controlsFlipVerdict.allFlipped: true` | `evidence/s2-008-harness.json` → `properties[1]`; `evidence/s2-008-controls.json` → `controls.allFlipped`, `controls.gate` |
| **A3** | two process-separated runs with different ids and nonces agree with the **frozen** expected-value table; `A === B` is additional only | **HELD** (was `FAILED` before the repair) | `records_produced=true pid_bound_a=true pid_bound_b=true separation=true separate_pids=true findingsA=0 findingsB=0 digestsEqual=true identical_wrong_both_non_empty=true`; `rule_can_only_answer=ANY_OUTCOME`. The harness's own A3 line carries `agreement_source=TABLE_DERIVED_RUN_RECORDS` and names the replay as the measurement | `evidence/s2-008-replay.json` → `properties[0]`, `separation`, `comparison`, `table_findings_a`; `evidence/s2-008-harness.json` → `properties[2]` |
| **A4** | an observational result cannot be read as causal: substituting the label MUST fail | **HELD** | `labels_flipped: 8`, `seal_held_on_clean_labels: true`, `seal_broke_on_substituted_labels: true`, clean digest `9ff4511e…` vs substituted `f4c216f2…`, `swapped_card.refusal = CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE` | `evidence/s2-008-harness.json` → `label_substitution`; `evidence/s2-008-controls.json` → `label_substitution` |
| **A5** | every artefact is bound to a commit SHA, a tree SHA and a raw run id, and survives a repeat run on the same base | **HELD** (was `FAILED` before delivery) | `bound_a=true bound_b=true track_tracked=true cross_process=true in_process_repeat=true reconciliation=true crash_classified=PASS`; the interrupted state produced **one** reconciliation row, `blind_retry: false`, `implicit_zero: false`, `spend_advanced: false`; `base.commit_sha 813f5be…`, `base.tree_sha 504f0a19…` (the tree of `HEAD`) | `evidence/s2-008-replay.json` → `properties[1]`, `evidence`, `repeatability`, `crash_restart`; `evidence/s2-008-harness.json` → `crash_restart` |

**A3 is measured by the replay, not by the harness.** Where the two records differ,
the cross-process replay is the measurement and the harness line is the derived view;
the aggregator enforces it — a harness record claiming a measurement it did not make
is a **defect**, and a table-derived one is reported as
`NOT_COMPARABLE_DISCLOSED` with the replay's A3 named authoritative
(`evidence/s2-008-summary.json` → `authoritative`).

### 0.7 The six negative probes

Read from the committed record; "checks" is the number of assertions the probe
actually executed through the production-facing path.

| # | Family | Probe | Checks | Counter | Evidence path |
| --- | --- | --- | --- | --- | --- |
| P1 | `holdout_peek` | `holdout_read_before_decision_point` | 11 | `holdoutPeek` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[0]` |
| P2 | `seed_substitution` | `best_seed_reported_instead_of_the_preregistered_set` | 4 | `seedSubstitution` = 0 | same → `probes.results[1]` |
| P3 | `hypothesis_rewrite` | `test_design_edited_after_the_result` | 10 | `hypothesisRewrite` = 0 | same → `probes.results[2]` |
| P4 | `budget_opacity` | `spend_beyond_the_reservation` | 13 | `budgetOpacity` = 0 | same → `probes.results[3]` |
| P5 | `causal_upgrade` | `observational_label_swapped_to_causal` | 8 | `causalUpgrade` = 0 | same → `probes.results[4]` |
| P6 | `missing_evaluator` | `evaluator_removed_between_reservation_and_comparison` | 6 | `missingEvaluator` = 0 | same → `probes.results[5]` |

**6/6 pass, 0 failed, 0 `not_run`, 0 `broken`.** All six hard-gate counters are `0`,
and that is correct rather than reassuring: a counter moves only when an attack
*succeeded*. Seven controls ran and seven flipped — the six frozen ones plus the named
extra `ledger_spelling_holdout_peek`. The per-probe mechanisms, the refusal codes each
probe produces, and the corrupted-run controls are in §5, §8 and §9 of the body, which
remain accurate for the mechanisms and now read against the current digests.

### 0.8 The `A === B` rule and the frozen expected-value table

**The rule.** The pass criterion is agreement with a table declared **before** the
run. `A === B` is reported and is explicitly additional. The two clean runs in
`evidence/s2-008-replay.json` have `digestsEqual: true` **and** `findingsA: []` /
`findingsB: []` — they agree with each other *and* with the table — while the
identical-wrong control still produces findings on **both** sides with their digests
equal. Agreement is necessary and is not sufficient.

**The table**, declared in `src/lib/research/expected-values.mjs` and sealed by the
preregistration's `expected_table_digest`:

| Member | Value now |
| --- | --- |
| `expectedTableDigest()` | `8062bc85f0252e6e48111b5dea3312ad698bca679da14eabd763510074207f63` — the value the in-force preregistration seals (`evidence/s2-008-harness.json` → `preregistration`) |
| `EXPECTED_METRIC` | `case_agreement_rate`, unit `ratio`, `noiseBand 0.02`, baseline `0.75`, `inferenceMode ASSOCIATIONAL`, `direction HIGHER_IS_BETTER` |
| `EXPECTED_TRIAL_DECISIONS` | 4 rows, read **by index**: `trl-s2-008-01` 7/8 `UNRESOLVED`, `-02` 6/8 `UNRESOLVED`, `-03` 5/8 `UNRESOLVED`, `-04` `INFRA_ERROR` / `INFRA` / `VIOLATION` with `numerator: null` |
| measured family | `MEASURED_FAMILY_SIZE = 3`, **counted** from the rows that publish an integer numerator and denominator |
| the rule | `alpha 0.05`, `family_size 3`, `confidence 1 - alpha/m = 0.9833333333333333` — derived on **both** sides and bound member by member by `assertTableFrozen` (`EXPECTED_RULE_DIVERGES_FROM_TABLE`, `FROZEN_RULE_NOT_SELF_CONSISTENT`) |
| pooled | `EXPECTED_POOLED_NUMERATOR = 18` over `8 × 3 = 24`, `notMeasured 1`, basis `POOLED_TRIAL_COUNTS` |
| `EXPECTED_LEDGER_SHAPE` | `PREREGISTRATION_RECORDED ×1`, `BUDGET_RESERVATION ×1`, `ACCESS ×1`, `TRIAL_RESULT ×4` — measured at 7 rows per run, `chain_verified: true` |
| `EXPECTED_CAMPAIGN` | a **table member**, therefore inside `expectedTableDigest()`: `decision UNRESOLVED`, `decisionStatus NOT_MEASURED`, `decisionReason interval_straddles_null_outside_noise_band`, and it is re-derived in source by `src/lib/research/campaign-expectation.mjs`, which the corpus builder and the harness both call |

**The re-derivation is not a number written to reach a verdict.** The three measured
rows declare what the frozen rule *derives* from the counts they publish, and
`assertFrozenCampaignDerivable` refuses a declaration the rule does not produce
(`EXPECTED_CAMPAIGN_DIVERGES_FROM_RULE`, `EXPECTED_CAMPAIGN_REASON_DIVERGES_FROM_RULE`).
The cost of that choice is stated in §0.13 and §0.11 rather than argued away: the
per-trial `outcome` field no longer discriminates on its own; the per-trial **status**,
**verdict**, **numerator/denominator**, **provenance** and **hard-gate counters** still
do, the identical-wrong control still flips both runs, and the run is a real
two-process execution.

### 0.9 The two process-separated runs

From the committed record `evidence/s2-008-replay.json` → `separation` (five identity
fields must differ, `children_are_separate_processes: true`, `ok: true`):

| field | run A | run B |
| --- | --- | --- |
| `raw_run_id` | `s2-008-run-a-0-p27459` | `s2-008-run-b-0-p27471` |
| `nonce` | `n-a-0629bcd15c73aec2` | `n-b-1bb29c41e21ae00b` |
| `executor_id` | `exec-s2-008-a-0-p27459` | `exec-s2-008-b-0-p27471` |
| `pid` | 27459 | 27471 |
| `output_root` | `.bb/s2-008/run/out-a-0` | `.bb/s2-008/run/out-b-0` |

Both runs carry the same `base` (`commit_sha 813f5be…`, `tree_sha 504f0a19…`), the same
`preregistration_digest b3ae2a63…` and the same `expected_table_digest 8062bc85…`.
Measured per trial, identically on both sides: **7/8, 6/8, 5/8, INFRA**;
pooled **18/24** with `notMeasured 1`; `table_finding_count 0` on each;
`ledger.chain_verified true`, 11 record kinds per run. `A === B` is reported
(`digestsEqual: true`) and is additional only.

I re-ran the replay against a **copy** of the committed corpus in a scratch
directory, which the script refuses to treat as evidence (`evidence_eligible=false`,
the children write into its own scratch), so the current tree answers the same two
properties without touching a byte of `evidence/`:
`node scripts/s2-008-replay.mjs --corpus <scratch copy of evidence/s2-008/corpus>` →
**exit 0**, `RESULT properties_held=2/2 not_run=0 verdict=FAIL overall=PASS`,
`overall_terms.decision_agrees_with_table = true`,
`overall_terms.controls_all_flipped = true`,
`overall_terms.ledger_shape_matches_table = true`.

### 0.10 The honest campaign outcome, as recorded

It is a **null**, and it is recorded as a null:

```json
"campaign": {"expected_decision":"UNRESOLVED","observed_decision":"UNRESOLVED",
             "agrees_with_table":true,"findings":[],"verdict":"FAIL","verdict_is_a_gate_term":false}
```

* the campaign measured **18 agreements over 24 cases** (7/8 + 6/8 + 5/8), pooled
  `POOLED_TRIAL_COUNTS`;
* at the derived confidence `1 - 0.05/3 = 0.9833333333333333` the Wilson interval is
  `[0.5056812707446809, 0.8979359805263918]`, which **covers** the frozen `0.75`
  baseline **outside** the `0.02` band, so the rule derives `UNRESOLVED` /
  `interval_straddles_null_outside_noise_band` — for the campaign and for each of the
  three measured trials (`[0.453625, 0.983339]`, `[0.347079, 0.944230]`,
  `[0.255737, 0.889917]`);
* `ruleFeasibility` at the declared family says `never_rejects: false`,
  `can_only_answer: "ANY_OUTCOME"` — the rule **can** reject; this campaign is simply
  not rejected;
* the comparator still **names the campaign `FAIL`**, because the INFRA row is a
  `VIOLATION` and nothing was decided. That `FAIL` is **recorded beside** the decision
  and is **counted by nothing**;
* `decisionStatus` is `NOT_MEASURED` — an undecided campaign is recorded as having
  measured nothing, which is a different statement from a met expectation.

**Eight synthetic cases cannot resolve a 0.02 band at 98.33 % confidence.** That is the
answer, and the report states it instead of claiming an effect the corpus does not
carry. The expected-value table was **re-derived from these counts by the rule**; it
was not written to produce this answer, and a hand-edited declaration is refused
(§0.5).

### 0.11 The limits

1. **The transport is deterministic and offline, and no causal claim is made or is
   supportable.** `inferenceMode ASSOCIATIONAL` in the preregistration, the table and
   the transport; a causal assertion over observational ground truth is refused
   `CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE` and the label-substitution
   control proves the refusal flips. The track proves **governance** properties — that
   a peek, a seed substitution, a post-result rewrite, an opaque budget, a causal
   upgrade and a missing evaluator are refused — and it **cannot** prove that any R&D
   campaign improves any metric.
2. **The corpus is eight hand-authored cases.** The card's own `scope.domain_limits`
   says so: *"the eight hand-authored fixture cases only; no production span stream was
   measured"*. `n = 8` per trial is why the honest answer is `UNRESOLVED`; a larger `n`
   is the other honest way out of that, and it is not this track's to choose.
3. **The per-trial `outcome` field no longer discriminates on its own** (§0.8, §0.13).
   The status, verdict, counts, provenance and hard-gate counters still do, the
   identical-wrong control still flips both runs, and the run is a real two-process
   execution — but a reader must not treat the three `UNRESOLVED` rows as three
   independent detections.
4. **The harness's A3 is a construction, not a measurement**, and says so in its own
   record (`agreement_source: TABLE_DERIVED_RUN_RECORDS`). The replay's A3 is the
   measurement.
5. **Wall-clock latency is measured and decides nothing** (`decides: false`,
   `excluded_from_repeatability: true`); every instant the decision reads is a frozen
   literal. See §13.2.
6. **The `INFRA` outcome still opens no reconciliation row** (body D2, §11.3).
   `evidence/s2-008-run-a.json` → `reconciliations []`, `run_counters.reconciliations
   0`, `codes ["MEASUREMENT_ABSENT"]`, while the preregistration's
   `stopping_rule.on_infra` is `RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO`. The
   reconciliation duty for an INFRA outcome is exercised by the crash/restart phase
   and by P6, not by the campaign's own infra row. The sibling defect D1 — the
   missing `ACCESS` row in the published ledger — **is** closed: the journal now
   begins with `ACCESS` and the ledger-shape check reports 0 issues at 7 rows per run.
7. **`tsconfig.json` sets `allowJs: false`**, so `tsc --noEmit` exits 0 without
   type-checking this track's `.mjs` files. `npm run typecheck` → exit 0 and
   `npm run lint` → exit 0 are therefore not type coverage of the track.
8. **One name, two meanings, in the evidence.** `compareParallelTrack` returns a member
   called `identicalWrongFindings` carrying the **clean** comparison's findings (`[]`),
   while the harness's real control returns a member of the **same name** carrying the
   **corrupted** run's findings. A reader must read `identical_wrong`, not
   `comparison.identicalWrongFindings`. Pre-existing, in `comparator.mjs`, reported and
   not renamed because renaming it would be an edit in another owner's file.
9. **Claimed nowhere:** an effect size, a calibration percentage, a semantic accuracy, a
   cost, a production latency, an `A-MVP` case, a causal effect, or any statement that
   this harness improves any real metric. The track's own calibration record is carried
   as `NOT_MEASURED` with `not_measured_reason: "outcome_not_defined"`.

### 0.12 What remains blocked behind #45

* **The ticket's own acceptance — a campaign on a real project — is `NOT_RUN` and
  stays so.** This track measured eight hand-authored fixture cases; no production span
  stream was measured, no real spend occurred, no really installed adapter ran, and no
  live executor's task quality was observed.
* The four status fields are separate and none of them is derived from this gate:
  `engineeringStatus = BLOCKED_DEPENDENCY`, `assuranceStatus = NOT_MEASURED`,
  `realAdapterStatus = NOT_RUN_REAL_ADAPTER`,
  `aMvpStatus = NOT_RUN (A-MVP-01..07, behind #45)`. The aggregator says it in its own
  record: *"engineeringStatus, assuranceStatus and the A-MVP rows are NOT derived from
  this gate and never are: a green deterministic track does not convert the ticket's
  own scope into done."*
* **A larger `n`** (or a wider band) as a preregistered amendment decided before the
  next run remains the other honest way out of `UNRESOLVED`.
* **The delivery mechanics are the Seal worker's**: commit, then
  `npm run manifest:write` with the closure binding, then `npm run manifest:check`
  (`manifest:write` seals at `HEAD` while `manifest:check` pins the commit recorded in
  `evidence/closure-record.json`, so on a dirty tree `--write` breaks `--check`).

### 0.13 VERDICT

**Planned — in the owner's frozen decisions, and implemented:**

- R-A the rule is derived and self-consistent (`never_rejects: false`), the superseded
  document is preserved whole with its old digests, and the supersession is its own
  document kind.
- R-B the campaign is well-posed: the `INFRA` trial is out of the measured set and out
  of the family, keeps its row, and the table is re-derived by the rule.
- R-C the gate is property-and-expectation based; `verdict_is_pass` is removed; the
  three refusals still fire.
- R-D this section, the stage doc, the task record and `README.md` state the same
  honest status, including the red first delivery and the exit-3 terminal state.

**Reported in chat — read from the integration log, not re-run by this pass:**

| command | reported exit | reported output |
| --- | --- | --- |
| `npm run s2-008:harness` | 0 | `RESULT properties_held=5/5 not_run=0 broken=0 verdict=FAIL overall=PASS` |
| `npm run verify:s2-008-replay` | 0 | `RESULT properties_held=2/2 not_run=0 verdict=FAIL overall=PASS` |
| `npm run verify:s2-008` | **3** | `status NOT_RUN`, `ok false`, `exitCode 3`; all five gates `PASS(exit=0)` (`dependency`, `corpus`, `probes`, `replay`, `harness`); `blockingGates []`, `notRunGates []`, `defects []` — **superseded by §0.5b**: that exit 3 was the last defect, and the current observed value is exit **0**, `status PASS`, with the two disclosures in the non-binding `scopeNotes` |
| `npm test` | 0 | `# tests 1469  # pass 1462  # fail 0  # skipped 7` |
| `npm run inventory:write` / `inventory:check` | 0 / 0 | `trackedFiles 842`; `listedFiles 842`, `missingFromInventory []`, `missingFromGit []` |
| `S2_008_FRESHNESS_WINDOW_MS=0 node scripts/verify-s2-008.mjs --no-write` | 1 | `status FAIL`, `blockingGates ["replay"]`, `stale evidence: stale-run-timestamp` |

The committed aggregator record was the artifact of those runs, and it is the record
**§0.5b** replaced: `evidence/s2-008-summary.json` then read `status NOT_RUN`,
`exitCode 3`, `blockingGates []`, `defects []`, with both `NOT_RUN` disclosures — the
table-derived harness A3, and the campaign behind
[#45](https://github.com/SpaceDazher/Veritas/issues/45). It now reads `status PASS`,
`exitCode 0`, `blockingGates []`, `defects []`, and the same two disclosures in
`scopeNotes`, which are recorded and printed and cannot decide a verdict.

**Verified now — by this documentation pass, each with its observed exit code:**

| command | observed exit | observed output |
| --- | --- | --- |
| `npm run test:research` | **0** | `# tests 246  # suites 11  # pass 246  # fail 0` |
| `npm run s2-008:check-corpus` | **0** | `preregistration_digest b3ae2a63…`, `expected_table_digest 8062bc85…`, `superseded_preregistration_digest 8fab7e83…`, `supersession_id spr-f5a6bf11a57e9cd01d1fa6e0`, `expected_campaign_decision UNRESOLVED`, interval `[0.5056812707446809, 0.8979359805263918]` at `0.9833333333333333` |
| `npm run test:s2-008-security-probes` | **0** | `RESULT status=PASS exit_code=0 reasons=[]` — 6 families, 6 probes, 6 passed, 0 failed, 0 `not_run`, 0 `broken`, 7 controls flipped |
| `node scripts/verify-s2-008-dependencies.mjs --no-write` | **0** | 5 bindings `BOUND` (`S2-002`, `S2-006`, `S2-007`, `S1-004`, `S1-011`) |
| `node scripts/s2-008-harness.mjs --no-write` | **0** | `RESULT properties_held=5/5 not_run=0 broken=0 verdict=FAIL overall=PASS`; `overall_terms.decision_agrees_with_table = true`; four evidence files reported `not written (--no-write)` |
| `node scripts/s2-008-replay.mjs --corpus <scratch copy of evidence/s2-008/corpus>` | **0** | `RESULT properties_held=2/2 not_run=0 verdict=FAIL overall=PASS`; `not written to evidence/: evidence_eligible=false` |
| `node scripts/s2-008-replay.mjs --no-write` | **3** | **not a gate result** — `--no-write` also stops the two children from writing, so the replay finds no run records: `RUN_RECORD_ABSENT: a=no record b=no record`, `not_run=5`, `PROPERTY_A3_NOT_RUN`, `PROPERTY_A5_NOT_RUN`. It is recorded here so nobody reads it as a red gate |
| `node scripts/verify-s2-008.mjs --no-write --corpus <scratch copy of evidence/s2-008/corpus>` | **1** | **not a gate result either** — pointed at a non-committed corpus the aggregator reads the committed record and cannot match a digest: `replay gate: FAIL (the replay reported no evidence digest…)`, `blockingGates ["replay"]`. The refusal working, not the track failing |
| a throwaway driver in the gitignored chat workspace (`tmp/`, not an artefact; the durable pins are the `gate-semantics` cases named in §0.5) | **0** | `UNRESOLVED` agrees with 0 table issues; `POSITIVE`, `NEGATIVE` and an absent decision are all refused; a hand-edited declaration → `BLOCKED_POLICY: EXPECTED_CAMPAIGN_DIVERGES_FROM_RULE` |
| `diff <(git show HEAD:evidence/s2-008/corpus/preregistration.json) evidence/s2-008/corpus/preregistration-superseded.json` | **0** | no output — the first delivery's document is byte-identical to its preserved copy |
| `git diff --name-only HEAD -- evidence/s2-008/corpus/cases/ \| wc -l` | **0** | `0` — the eight synthetic cases are unchanged, so no measurement was re-tuned |
| `npm run lint` | **0** | `eslint .` clean |
| `npm run typecheck` | **0** | `tsc --noEmit` clean (and it does not cover `.mjs` — see §0.11 item 7) |

**The commands deliberately NOT run by this pass**, because they mutate evidence
records owned by the integration and Seal workers:
`npm run verify:s2-008` (its replay child writes `evidence/s2-008-run-{a,b}.json` and
`evidence/s2-008-replay.json`), `npm run s2-008:harness` and
`npm run verify:s2-008-replay` without `--no-write`, and every `manifest:*` command.
The evidence digests were identical before and after every command in this table
(`sha256sum -c` over the fourteen S2-008 records: 0 differing lines).

**Not verified, and not claimed:** that a campaign on a real project will produce a
decided answer. That measurement has not been run, and nothing here predicts it. The
246/246 suite and the two `overall: PASS` records prove the **gates** are load-bearing
on a synthetic corpus; they do not convert the ticket's scope into done.

**One disagreement this repair overrode, recorded rather than hidden.** Body §7.3
argued the table's outcome rows must **not** be rewritten to `UNRESOLVED`, because
deriving the expectation with the same rule that produces the answer *"would replace the
oracle with a tautology and destroy the A3 control's ability to discriminate"*. That
argument has force and the owner took the opposite decision (R-B). The cost is stated
in §0.8 and §0.11 item 3 rather than argued away.

---

## Verdict: TRACK_REJECTED_AS_ACCEPTED — the machinery is real, three of five criteria hold, two do not, and the ticket stays `BLOCKED_DEPENDENCY` behind #45

> **Repair update (2026-09-27, §0.13).** The headline above and the status table
> under it are the **pre-repair snapshot at `813f5be`**, and they are left as they
> were measured. The repair moved three facts: the two blocking gates are gone
> (`blockingGates []`, `defects []`), all five acceptance properties hold, and the
> aggregator's status is **`NOT_RUN` with `exitCode 3`** — the two `NOT_RUN`
> disclosures are the table-derived harness A3 and **the campaign behind #45**, both
> of which were already in this summary. The current verdict, the current command
> log and the limits are in **§0**; the table below is history. Nothing below §0 is
> quoted as a current result.

> **Delivery update (2026-09-27, §20).** The headline above and the status table
> under it are the **pre-commit snapshot** at base `bd0e2f5`, and they are left as
> they were measured. Delivery then committed the track, which moved exactly two
> facts: **A5 is now HELD** (`track_tracked=true tracked_files=39`) and the
> **dependency gate is now PASS** — so it is four of five criteria, and
> `blockingGates` is `replay`, `harness`. **A3 still FAILS** (`findingsA=3
> findingsB=3`), `trackStatus` is still `FAIL`, and the ticket is still
> `BLOCKED_DEPENDENCY` behind #45. Read §20 for the current numbers; do not read
> the table below as the state of the branch.

> **Supersession.** An earlier version of this file (written against the pre-repair
> tree, 2026-09-27 01:52 local) concluded that the track had "no harness, no tests,
> no evidence and five modules still throwing `NOT_IMPLEMENTED`", and recorded a
> reproduced A4 bypass in which the comparator returned `ALLOW` for a trial carrying
> `causal_assertion: true`. That body is replaced by this one, because a repair pass
> and a corpus rebuild have since landed. Its **findings** were confirmed and are
> closed; its **measurements** no longer describe this tree. What survives from it is
> carried forward here: the A4 vocabulary seam (§9.3), the two broken seams it named
> (§16, defect D4), the non-idempotent-fixture class (§12), and the `.gitignore`
> line (§12.3, since closed). Nothing in it is quoted as a current result.

`trackStatus = FAIL (not accepted)`, `engineeringStatus = BLOCKED_DEPENDENCY`,
`assuranceStatus = NOT_MEASURED`, `realAdapterStatus = NOT_RUN_REAL_ADAPTER`,
`aMvpStatus = NOT_RUN (A-MVP-01..07, behind #45)`.

**One sentence:** the S2-008 deterministic track is a complete, honest, offline
harness whose six negative probes and six controls genuinely run and genuinely flip,
whose preregistration is genuinely immutable and whose interrupted run genuinely
becomes a reconciliation — and whose **A3 fails on a real measurement** (three
preregistered outcomes cannot be derived at n = 8) and whose **A5 fails on one
untracked-tree fact** that only `git add` can fix.

| Acceptance criterion | Status at this snapshot | One-line reason |
| --- | --- | --- |
| A1 registry covers all six negative probes | **HELD** | 6/6 probes `pass`, `notRun=0`, `broken=0`, six hard-gate counters all `0` |
| A2 fail-closed comparator, a corrupted control flips | **HELD** | five non-`RESOLVED` statuses → `VIOLATION` (measured again here), all six controls flip, `controlsFlipVerdict.ok` |
| A3 two process-separated runs vs the frozen table | **FAILED** | separation, control binding and identity all hold; the table and the run disagree on three per-trial `outcome` fields |
| A4 observational ≠ causal | **HELD** | label seal holds on the committed labels and breaks on substituted ones; the contract's own field placement is now read at the decision layer |
| A5 bound to a base, survives a repeat | **FAILED** | every member satisfied except `track_tracked=false`: `git ls-files` sees 0 tracked files of this track |

### What this verdict is NOT

* It is **not** a claim that the work is worthless or the design wrong. The fail-closed
  comparator, the ledger, the preregistration seal and the crash/restart reconciliation
  are careful code with unusually honest comments, and this pass re-measured most of
  them directly (§16.3).
* It is **not** an acceptance of the ticket. `engineeringStatus` stays
  `BLOCKED_DEPENDENCY`; the ticket's own scope — a campaign on a real project, real
  spend, a live executor's task quality, `A-MVP-01..07` — is behind
  [#45](https://github.com/SpaceDazher/Veritas/issues/45) and none of it is attempted
  here.
* It is **not** a causal claim, an effect size, a calibration or a campaign outcome.
  The transport is deterministic and offline; §14 states the boundary in full.
* It is **not** based on a green run. Every command quoted in §17 that this pass ran
  itself is reported with its real exit code, including the two that exit non-zero.

### Two things a reader must not misread

1. **`evidence/s2-008-harness.json` says `A3 HELD`. `evidence/s2-008-replay.json`
   says `A3 FAILED`.** Both are committed, both are current. The harness's own record
   carries `agreement_source: "TABLE_DERIVED_RUN_RECORDS"` and
   `measurement_of_agreement: "scripts/s2-008-replay.mjs"`, because the harness builds
   its two run records *out of the frozen table* and derives only the outcome, so
   `findingsA=0` there is a construction and not a measurement. The measurement is the
   replay, and the measurement fails. The harness is not a gate of
   `scripts/verify-s2-008.mjs`; the aggregator reads dependency, probes and replay only
   (`evidence/s2-008-summary.json` → `gates`).
2. **The evidence set was rewritten twice while this evaluation was being written.** The
   committed corpus was rebuilt at `2026-09-27T09:37:32Z` and the ten evidence records
   were regenerated at `09:42:48Z`–`09:43:14Z` by a concurrent worker, after the
   harness log (`…/notes/s2-008-harness-log.md`, last written `09:35:00Z`) had recorded
   the pre-rebuild state. Every number below is pinned to the `2026-09-27T09:44:40Z`
   snapshot in §1, with the sha256 of each record. Where the harness log and the current
   evidence disagree, this report follows the evidence and says which is which.

---

## 0.1 Defects found during this evaluation

| # | Severity | Defect | Where it is visible | Handling |
| --- | --- | --- | --- | --- |
| **D1** | **HIGH** | The engine's own `purgeRegistry` runs **after** the one-shot holdout open and deletes the ACCESS record it wrote. The run publishes a ledger in which the holdout has no record of having been read. | `evidence/s2-008-replay.json` → `ledger_shape.a[0]` / `.b[0]`: `LEDGER_SHAPE_DIVERGES_FROM_TABLE`, `kind: "ACCESS"`, `expected: 1`, `observed: 0`. Proven directly in §12.1. | **Reported, not fixed.** `runner.mjs` / `registry.mjs` / `dataset.mjs` are not this worker's files. Non-gating today (§12.2). |
| **D2** | MEDIUM | The preregistered stopping rule for an infra outcome is `RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO`, and the run opens **no** reconciliation row for the infra trial. | `evidence/s2-008-corpus/preregistration.json` → `stopping_rule.on_infra` vs `evidence/s2-008-run-a.json` → `reconciliations: []` and `trials[3].reconciliation_id: null`. | **Reported, not fixed.** The "never a silent zero" half does hold (§11.3); only the row is missing. |
| **D3** | MEDIUM (closed here) | The comparator read `causal_claim` and not the frozen contract's own `proposed_relation.causal_assertion`, so a card carrying the contract's field was allowed at the decision layer. Recorded in the superseded body of this file. | `src/lib/research/comparator.mjs:476-491` now routes a carried card through `classifyCardRelation`, the same classifier the A4 guard uses; re-measured in §9.3. | Closed upstream. One residual is named in §9.3 and it is **not** a contract shape. |
| **D4** | MEDIUM (closed upstream) | Fixture and module disagreed on the preregistration shape (`baseline_digest` absent, `seed_rule` a string), so P2/P3 could not run. | `evidence/s2-008-security-probes.json` → P2 and P3 both `pass` now; `assertPreregistration` accepts the committed document (§10.1). | Closed upstream. |
| **D5** | LOW | `A3`'s `ok` condition and the frozen table's outcome rows cannot both be satisfied at n = 8, and the design records that instead of widening the band. | §7.3, with the three measured intervals. | **A design decision for the ticket owner.** Neither the band nor the table may be weakened to make this green. |

---

## 1. Provenance of this evaluation

| Item | Value |
| --- | --- |
| Issue | `SpaceDazher/Veritas#8`, S2-008 deterministic parallel track |
| Base commit (PR #43, the S2-007 boundary, already merged) | `bd0e2f5b3873da33440cda5eb6b878c4a9988496` |
| `HEAD^{tree}` | `747a57934cfaf2e04c3322cc3d5f649340f80da0` |
| Branch | `bb/spacedazher-veritas-8-s2-008-r-d-thr_4etd4uwcke` |
| Snapshot this report describes | `2026-09-27T09:44:40Z` (host clock, UTC) |
| Node | `v22.23.2` |
| Worktree state at the snapshot | dirty; `git ls-files` reports `tracked_files_of_this_track = 0`; modified: `README.md`, `package.json`, `evidence/s2-006-{comparison,run-a,run-b}.json` (the three S2-006 records are **not** this track's and are still unexplained, carried over from the superseded body) |
| Reused, never reimplemented | `src/lib/agentboard/{store,contracts,errors,constants,policy}.mjs`, `src/lib/verifier/canonical-json.mjs`, `src/lib/sloqual/comparator.mjs`, `scripts/s2-007-db-replay.mjs` (as the template) |
| Frozen contracts, read-only, untouched | `contracts/hypothesis-card.schema.json`, `contracts/research-dossier.schema.json`, `contracts/calibration-record.schema.json` |
| Harness log required by the ticket | the chat-workspace note `s2-008-harness-log.md` (30 655 bytes, last written `2026-09-27T09:35:00Z`) — read in full before this file was written. The chat workspace is under `.bb/`, which `.gitignore` covers, so the note is deliberately not committed. |

### 1.1 The ten evidence records, by digest (snapshot `09:44:40Z`)

| File | sha256 | Written (local) |
| --- | --- | --- |
| `evidence/s2-008-probes.json` | `fac05b67c6e9bc8c8d2ef37e5610804413d920944d4d4bf91cf640ed837fc32a` | 04:42:59 |
| `evidence/s2-008-controls.json` | `1bc107ed7baf19bebec5c193ce66433e130750fcbfcf2b931f75a139db9e36bc` | 04:42:59 |
| `evidence/s2-008-comparison.json` | `097be16185525f406f0f2e72c89fc957517552c18d6caf049d1dd849ab39e661` | 04:42:59 |
| `evidence/s2-008-harness.json` | `7bb3c25f41e0619076a4c5b5f23d7b729a98cfa78004b9fa263f8e88b4c53245` | 04:42:59 |
| `evidence/s2-008-security-probes.json` | `d5e1a6676450b3aa565e60371dd8105d4f363742406b9d6c71c71b25e14fc23e` | 04:42:48 |
| `evidence/s2-008-run-a.json` | `2442c097dafb668b47cf3a2e805fcdf402f9469b9f388402edc2f716054985f7` | 04:43:13 |
| `evidence/s2-008-run-b.json` | `c79a33dc9e7715546a73d19a7aa67d2b93cb1e9497ff8aacf274ad503c635f48` | 04:43:13 |
| `evidence/s2-008-replay.json` | `8a6311134f44b54eeae788910b6670acdc26df66f0d151512ff0de024b3256ca` | 04:43:14 |
| `evidence/s2-008-dependency-binding.json` | `857b08dc6f76a5c0294f5610e5d2a84f218cef22a4436ebfbb658da09aa0614f` | 04:43:12 |
| `evidence/s2-008-summary.json` | `5e29420acac6725811df5b34eedc75a1473c4995ac7c1cf67b5c57783ce917c8` | 04:43:14 |

All ten are internally consistent with the committed corpus: every record's
`preregistration.digest` is `8fab7e83…` and the harness record's
`corpus.manifest_digest` is `1b08aaa5…`, which is the canonical digest of the committed
`evidence/s2-008/corpus/manifest.json` re-derived here (§16.2). The superseded body
quoted a `9c7bc9cc…` preregistration seal; that was the pre-rebuild corpus and no
record carries it any more.

### 1.2 Frozen foundation re-verified byte-by-byte

`evidence/s2-008-dependency-binding.json` (`mode: FULL_GIT_BYTES`, `head:
bd0e2f5b…`, `checked: 22`) compares each contract four ways — the digest the issue
names, the digest in `evidence/frozen-manifest.json`, the digest **at the commit**
(`git cat-file`) and the digest in the working tree. **All three contracts agree on all
four readings, `issues: []`.** Nothing in `contracts/` was edited and no fourth schema
was added.

| Contract | sha256 | issue = manifest = commit = working tree |
| --- | --- | --- |
| `hypothesis-card.schema.json` | `43b9c81620737b81a589d8e1577b0dc89e8b19fe1ed011edb3514f893b141e97` | yes |
| `research-dossier.schema.json` | `fdffd1c0a75f0483a5ab7244ed5463a9786fec4c23daaae8c7b5242167183773` | yes |
| `calibration-record.schema.json` | `8c7507ebe2f216a46f4c70f7a43e4713ef84f85ac0c14d97e550f953f1b7408d` | yes |

The five inherited bindings are all `BOUND`: **S2-002, S2-006, S2-007, S1-004, S1-011**.
`frozen_targets`: **610 pinned paths, 610 verified, `issues: []`,
`untracked_in_frozen_trees: []`**. The S2-007 Agent Board boundary this track reuses
is intact.

---

## 2. What was built

### 2.1 Library — `src/lib/research/`, 15 modules, 718 632 bytes

Named by the dependency gate's own module census (`modules: 15`, with the importer
graph for each). The five that the superseded body found as `NOT_IMPLEMENTED` stubs
(`constants.mjs`, `causality.mjs`, `dataset.mjs`, `expected-values.mjs`,
`negative-controls.mjs`) are implemented and are the ones carrying A1, A2, A3 and A4.
`node --check` passes on all 14 and `npm run lint` exits 0.

### 2.2 Harness — `scripts/s2-008-*.mjs` and `scripts/verify-s2-008*.mjs`, 7 entry points

| Script | Property it owns | Exit codes declared |
| --- | --- | --- |
| `s2-008-build-corpus.mjs` | derives the committed corpus from the frozen fixture; `--check` re-derives and compares; `--out <dir>` re-derives elsewhere and reports `evidence_eligible: false` | 0 in sync, 1 on drift |
| `s2-008-security-probes.mjs` | A1 + the six controls | 0 / 1 / 3 |
| `s2-008-run.mjs` | one run; `--repeat` is the in-process A5 witness; `--crash-phase 1|2` is the crash half | 0 / 1 / 3 |
| `s2-008-replay.mjs` | A3 + A5, the cross-process template | 0 / 1 / 2 (crash) / 3 (`NOT_RUN`) |
| `s2-008-harness.mjs` | the A1..A5 assembly record (auxiliary; not an aggregator gate) | 0 / 1 / 2 / 3 |
| `verify-s2-008-dependencies.mjs` | the binding gate | 0 / 1 |
| `verify-s2-008.mjs` | the aggregator: dependency, probes, the replay it spawns itself, freshness, derived status | 0 / 1 / 3 |

### 2.3 Tests — `tests/research/`, 11 suites, 246 tests

`npm run test:research` → **246 tests, 246 pass, 0 fail, 0 skipped, exit 0** after the
repair of 2026-09-27 (it was 205 before it; the repair added the gate-semantics suite
and the self-consistency and supersession cases). The suite covers the comparator's
fail-closedness, the corpus drift test, the preregistration/registry, the two-run
replay, the new gate semantics (`tests/research/gate-semantics.test.mjs`), and pins the
committed evidence records (`tests/research/harness.test.mjs` asserts that every
committed record names its base and is scored against `expectedTableDigest()`).

### 2.4 Evidence — ten records plus the six-file corpus

`evidence/s2-008/corpus/{manifest.json,preregistration.json,preregistration-superseded.json,preregistration-supersession.json,cases/dev.json,cases/holdout.json}`,
digested in §1.1. The two preregistration documents and the supersession between them
were added by the repair of 2026-09-27 (§0.4): the corpus is where the superseded rule
is preserved, so that the first delivery stays readable.
`evidence/s2-008-negative-controls.json` is listed by the dependency gate as
`required: false, present: false`; the controls live in
`evidence/s2-008-controls.json` instead, which is present and is the one this report
quotes.

---

## 3. Status block

**After the repair of 2026-09-27 (current; see §0.6 for the measurements):**

```text
trackStatus        = NOT_RUN          (no blocking gate, no defect; two disclosures remain, one of them #45)
engineeringStatus  = BLOCKED_DEPENDENCY   (this ticket, not this track)
assuranceStatus    = NOT_MEASURED
realAdapterStatus  = NOT_RUN_REAL_ADAPTER
aMvpStatus         = NOT_RUN (A-MVP-01..07, behind #45)
aggregator         = NOT_RUN, exit 3  (evidence/s2-008-summary.json; gates all PASS, blockingGates [])
campaignVerdict    = FAIL (recorded, not a gate term)   campaignDecision = UNRESOLVED, decisionStatus = NOT_MEASURED
notInferred        = [real_adapter_execution, human_review, empirical_semantic_accuracy,
                      A_MVP_PASS, production_readiness, any causal effect]
```

**Before the repair (the block this section originally carried), for the record:**

```text
trackStatus        = FAIL            (A3 and A5 do not hold; evidence/s2-008-harness.json -> verdict FAIL)
aggregator         = FAIL, exit 1     (evidence/s2-008-summary.json)
verdictReasons     = ["dependency gate BLOCKED_DEPENDENCY (exit 1): index.mjs-absent-at-commit",
                      "replay gate FAIL (exit 1): A3 findingsA=3 findingsB=3; A5 track_tracked=false",
                      "probes gate PASS (exit 0): 6/6 probes, 6/6 controls flipped, six counters 0"]
```
engineeringStatus  = BLOCKED_DEPENDENCY   (this ticket, not this track)
assuranceStatus    = NOT_MEASURED
realAdapterStatus  = NOT_RUN_REAL_ADAPTER
aMvpStatus         = NOT_RUN (A-MVP-01..07, behind #45)
aggregator         = FAIL, exit 1     (evidence/s2-008-summary.json)
verdictReasons     = ["dependency gate BLOCKED_DEPENDENCY (exit 1): index.mjs-absent-at-commit",
                      "replay gate FAIL (exit 1): A3 findingsA=3 findingsB=3; A5 track_tracked=false",
                      "probes gate PASS (exit 0): 6/6 probes, 6/6 controls flipped, six counters 0"]
notInferred        = [real_adapter_execution, human_review, empirical_semantic_accuracy,
                      A_MVP_PASS, production_readiness, any causal effect]
```

**What is NOT inferred from anything in this report:** a real-adapter execution, a human
review, an empirical semantic accuracy, an `A-MVP PASS`, production readiness, a causal
effect, and any statement that the harness improves any real metric. A green
deterministic track would not convert the ticket's scope into done; it would only prove
the machinery that would later carry it.

### 3.1 The three gate results, with real exit codes

**After the repair of 2026-09-27 (current):** all five gates `PASS`, `blockingGates: []`,
`defects: []`, aggregator exit **3** (`NOT_RUN`, for the two disclosures named in
§0.6 — not because a gate failed). One real defect was found and fixed on the way, in
the aggregator itself rather than in the track: `verify-s2-008.mjs` sampled its own
clock **once, at the top of `verify()`**, before the dependency gate, the probes gate
and the cross-process replay had run. The replay writes its record's `finished_at`
after all of that, so every record the aggregator judged was reported as
`record-from-the-future` — on a record the same process had just produced. The window
was **not** widened; the reading is now taken at the point of judgement, and the
summary publishes every instant it sampled (`started_at`, `replay_judged_at`,
`harness_judged_at`, `observed_at`).

**Before the repair, as measured then:**

`evidence/s2-008-summary.json` → `gates`:

| Gate | Status | Exit | Defect / reason |
| --- | --- | --- | --- |
| `dependency` (`verify-s2-008-dependencies.mjs`) | `BLOCKED_DEPENDENCY` | **1** | `issues: ["index.mjs-absent-at-commit"]` — `src/lib/research/index.mjs` is read **at the commit** with `git cat-file` and is not there, because nothing of this track is committed (`track_files_tracked: 0`). The five upstream bindings are `BOUND`, so this is not a digest drift. |
| `probes` (`s2-008-security-probes.mjs`) | `PASS` | **0** | none; `reasons: []` |
| `replay` (`s2-008-replay.mjs`) | `FAIL` | **1** | `A3: FAILED`, `A5: FAILED`, `not_run: []` — nothing was skipped this time |

---

## 4. Acceptance table A1..A5 → observation → evidence

`CLOSED` only where a check ran and passed. `FAILED` where a check ran and did not.
`NOT_RUN` is not used anywhere in the current evidence: `evidence/s2-008-replay.json` →
`not_run: []`.

| # | Criterion | Status | Observation | Evidence path |
| --- | --- | --- | --- | --- |
| **A1** | the registry covers all six negative probes | **CLOSED** | `totals: {families: 6, probes: 6, probes_ran: 6, passed: 6, failed: 0, not_run: 0, broken: 0, controls_declared: 6, controls_ran: 6, controls_flipped: 6}`; `familiesAttempted` lists all six families `pass`; all six hard-gate counters `0`; `purged.removed: 6` of 6 roots before the run; a read before the decision point, a forged unseal digest and a second open of the same partition are each refused `BLOCKED_POLICY`. | `evidence/s2-008-security-probes.json`, `evidence/s2-008-probes.json` |
| **A2** | a skipped or unresolved trial is a `VIOLATION`, never `ALLOW`; a negative control injects corrupted data and MUST flip the verdict | **CLOSED** | Measured again in this pass (§8.1): `RESOLVED` + four bindings → `ALLOW`; `SKIPPED`, `UNRESOLVED`, `INFRA_ERROR`, `NOT_MEASURED`, absent and `{}` → `VIOLATION`; each of the four bindings individually load-bearing. All six controls flip: three `ALLOW→VIOLATION`, one `ADMITTED→REFUSED`, `no_findings→findings_non_empty`, and `missing_evaluator` with two reasons. `controlsFlipVerdict.gate.ok: true`, `notRun: []`. | `evidence/s2-008-controls.json`, `evidence/s2-008-security-probes.json` → `hardGates` |
| **A3** | two process-separated runs, different ids and nonces, agreeing with a **frozen** expected-value table; `A === B` additional only | **FAILED (pre-repair) → HELD (current)** | Pre-repair: `findingsA: 3`, `findingsB: 3` — the run's per-trial `outcome` cannot be derived from the corpus at the preregistered band, while the frozen table declared `POSITIVE/NULL/NEGATIVE`. **Current:** `findingsA: []`, `findingsB: []`, `digestsEqual: true` reported as additional, `identical_wrong` still producing non-empty findings on both sides, `rule_feasibility.never_rejects: false`, and the campaign decision `UNRESOLVED` agreeing with the frozen declaration. The re-derivation that closed it, and the discrimination it costs, are in §0.5 and §0.7. | `evidence/s2-008-replay.json` → `separation`, `comparison`, `table_findings_a`, `properties[0]` |
| **A4** | an observational result cannot be read as causal; a label-substituting control MUST fail | **CLOSED** | The label seal holds on the committed labels and breaks on the substituted ones: `labels_flipped: 8`, `seal_held_on_clean_labels: true`, `seal_broke_on_substituted_labels: true`, clean digest `9ff4511e…` vs substituted `f4c216f2…`. The swapped card is inadmissible with `CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE`; the always-on simulation guard refuses the same card; the classification reports `admissible: false`. | `evidence/s2-008-controls.json` → `label_substitution`, `evidence/s2-008-harness.json` → `label_substitution` |
| **A5** | every artefact bound to a commit SHA, a tree SHA and a raw run id, and survives a repeat run on the same base | **HELD (current)** | `bound_a=true`, `bound_b=true`, `cross_process=true`, `in_process_repeat=true`, `reconciliation=true`, `track_tracked=true`. Pre-repair this criterion failed on exactly one member, `track_tracked=false`, which only `git add` could fix; the delivery commit fixed it and the repair did not touch it. | `evidence/s2-008-replay.json` → `properties[1]`, `evidence`, `repeatability` |

---

## 5. The six negative probes: mechanism and the artefact that closes each

Mechanism = what actually executes, read from the committed record. "Closing artefact" =
the file a reader opens to check it. Every probe runs through the production-facing
path and each carries its own control.

| # | Family (issue) | Probe | Mechanism, and what the run observed | Counter | Closing artefact |
| --- | --- | --- | --- | --- | --- |
| P1 | peeking a holdout | `holdout_read_before_decision_point` | 5 checks: a HOLDOUT read presenting a forged unseal digest is refused `BLOCKED_POLICY`; a refused read returns no case data (`leaked=false`); a replayed read is refused; the PRIMARY partition is readable without a digest; the control flips `ALLOW→VIOLATION` with reason `UNSATISFIED_HOLDOUT_BINDING` | `holdoutPeek` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[0]` |
| P2 | substituting the best seed | `best_seed_reported_instead_of_the_preregistered_set` | the preregistered 5-seed set is admitted on every trial; one substituted seed is refused `BLOCKED_POLICY`; a report naming only the best seed is refused; the control flips with `UNSATISFIED_SEED_BINDING` | `seedSubstitution` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[1]` |
| P3 | rewriting a hypothesis after the result | `test_design_edited_after_the_result` | 10 checks: a post-result `test_design` edit keeps the same `card_id`; the rewrite moves the digest; the preregistration in force is complete; an unedited preregistration is admitted after a result; the edit is refused `BLOCKED_POLICY`; the lawful path is a new `AMENDMENT` document; the amendment is refused as a decision basis and admitted when only journalled; an amendment reusing the amended `card_id` is refused; its own control `post_result_rewrite` flips `ADMITTED → REFUSED` | `hypothesisRewrite` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[2]`, re-measured in §10 |
| P4 | opaque budget | `spend_beyond_the_reservation` | 10 checks: a live reservation covering the request is granted; a spend beyond it is `BUDGET_EXCEEDED`; an expired reservation is `RECONCILIATION_REQUIRED`, not a zero and not a grant; the reservation is journalled before any spend; a refused settle leaves the ledger **byte-identical** (`sha256:ab59973e…` vs `sha256:ab59973e…`); a settle against a never-granted reservation is refused | `budgetOpacity` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[3]`, re-measured in §11 |
| P5 | claiming causal proof from a simulation | `observational_label_swapped_to_causal` | 6 checks: a causal claim over observational ground truth is **still schema-valid** (the card schema has no `allOf`, so the rule must live in code); the honest card is admitted; the causal claim is refused; the always-on simulation guard refuses the same card; the classification reports `admissible=false` with `CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE` | `causalUpgrade` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[4]`, re-measured in §9 |
| P6 | a missing evaluator | `evaluator_removed_between_reservation_and_comparison` | 5 checks: an independent evaluator is admitted; an absent one is refused; one not blind to the producer is refused; a `NOT_MEASURED` trial resolves to `VIOLATION`, never `ALLOW`; the control flips with two reasons (`MISSING_EVALUATOR_BINDING`, `EVALUATOR_NOT_INDEPENDENT:BLOCKED_POLICY`) | `missingEvaluator` = 0 | `evidence/s2-008-security-probes.json` → `probes.results[5]` |

**6/6 pass, 0 failed, 0 `not_run`, 0 broken.** All six hard-gate counters are `0` and
that is correct rather than reassuring: a counter moves only when an attack
*succeeded*, so a refused attack leaves it at 0 and the record says so.

---

## 6. The `A === B` rule and the frozen expected-value table

### 6.1 The rule

The pass criterion is agreement with a table declared **before** the run.
`A === B` is reported and is explicitly additional. The replay record states it in the
control's own `note`:

> "A === B is reported as an additional condition only: the same corruption in both
> runs keeps their digests equal, so only the frozen table can produce findings here."

The clean pair in the committed replay already had `digestsEqual: true` with
`findingsA: 3` — two runs agreeing and still failing — which is the rule working rather
than the rule being decorative.

### 6.2 The table

Declared in `src/lib/research/expected-values.mjs` and sealed by the preregistration's
`expected_table_digest`. Its own header states the discipline: *"DECLARED, never
observed: it is the answer a run is scored against, so reading it out of a run that
already happened would turn every check into a tautology."* `expectedTableDigest()`
digests every `EXPECTED_*` constant through `canonicalDigest`.

| Member | Value at this snapshot |
| --- | --- |
| `expectedTableDigest()` | `9aad76e1b0f8c6f55ac59548347278f1b4f7c3e5ea4d11a75d2fd1896c08af62` — the same value the committed preregistration seals |
| `EXPECTED_METRIC` | `case_agreement_rate`, unit `ratio`, `noiseBand 0.02`, `baseline 0.75`, `inferenceMode ASSOCIATIONAL`, `direction HIGHER_IS_BETTER` |
| `EXPECTED_TRIAL_DECISIONS` | 4 rows, read **by index** so a substituted seed changes *which* row scores a result: `trl-s2-008-01` 7/8 `POSITIVE`, `-02` 6/8 `NULL`, `-03` 5/8 `NEGATIVE`, `-04` `INFRA_ERROR`/`INFRA`/`VIOLATION` with `numerator: null` |
| pooled | `EXPECTED_POOLED_NUMERATOR = 18` over `8 × 3 = 24` |
| `EXPECTED_LEDGER_SHAPE` | `PREREGISTRATION_RECORDED ×1`, `BUDGET_RESERVATION ×1`, `ACCESS ×1` ("exactly one holdout open, journalled before the bytes are returned"), `TRIAL_RESULT ×4` |
| `EXPECTED_CONTROLS` | 6 descriptors, each naming the verdict it must flip to |
| `assertTableFrozen` | refuses `EXPECTED_TABLE_DRIFT` if the in-code digest moved, and checks the band member-by-member so a drift that leaves the digest alone is still named |

### 6.3 Two identically wrong runs are not a pass

`evidence/s2-008-replay.json` → `identical_wrong`: the same corruption is injected into
**both** runs (`trials[0].status`, `RESOLVED → SKIPPED`, variant `trial_status_skip`),
so their digests stay equal; the table then produces `findings_a: 4` and `findings_b: 4`,
`digests_still_equal: true`, `both_non_empty: true`, conclusion *"the frozen table is
load-bearing: identical decision digests, non-empty findings"*.
`evidence/s2-008-harness.json` → `identical_wrong` accumulates the same demonstration
over the full comparator: **14 failure entries** across `table_disagreement`,
`trial_violation`, `metric_not_measured` and `decision_unresolved`.

---

## 7. The two process-separated runs, their ids and their nonces

### 7.1 What the committed replay records

| Field | Run A | Run B |
| --- | --- | --- |
| child `pid` (real OS process) | **149706** | **149718** |
| child exit code / semantics | **1** / `FAIL` | **1** / `FAIL` |
| `raw_run_id` | `s2-008-run-a-0-p149706` | `s2-008-run-b-0-p149718` |
| `nonce` | `n-a-af2310d4d50bc3d3` | `n-b-e0ebf0492e50e92d` |
| `executor_id` | `exec-s2-008-a-0-p149706` | `exec-s2-008-b-0-p149718` |
| `output_root` | `.bb/s2-008/run/out-a-0` | `.bb/s2-008/run/out-b-0` |
| `commit_sha` / `tree_sha` | `bd0e2f5b…` / `747a5793…` | the same |
| `decision_digest` | `d6541aef70aa4583…` | `4a153e353d306c30…` (differ, by design) |
| `artefact_digest` | `a2d60215e4488c97…` | `edf6c6c841fe48085…` (differ, by design) |
| ledger | 10 rows, chain verified, snapshot `sha256:a7a092b1…` | 10 rows, chain verified, snapshot `sha256:2f969ba2…` |
| run status | `COMPLETED`, 4 trials, `table_findings: 3` | `COMPLETED`, 4 trials, `table_findings: 3` |

`separation.ok: true` with `fields_absent: []` — all five separation fields are present
and every one differs, and `children_are_separate_processes: true`.

### 7.2 What the runs measured

| Trial | numerator/denominator | case record rate | status / outcome | verdict | Wilson 95 % interval |
| --- | --- | --- | --- | --- | --- |
| `trl-s2-008-01` | 7/8 | 1 | `RESOLVED` / `UNRESOLVED` | `ALLOW` | `0.5291120380276508 … 0.9775824891780278` |
| `trl-s2-008-02` | 6/8 | 1 | `RESOLVED` / `UNRESOLVED` | `ALLOW` | `0.4092756148941955 … 0.9285207365762568` |
| `trl-s2-008-03` | 5/8 | 1 | `RESOLVED` / `UNRESOLVED` | `ALLOW` | `0.3057425455637159 … 0.8631556301715102` |
| `trl-s2-008-04` | `null` / `null` | `null` | `INFRA_ERROR` / `INFRA` | `VIOLATION` | absent — `MEASUREMENT_ABSENT` |

Pooled: `case_agreement_rate` `18/24`, `outcomeCounts {UNRESOLVED: 3, INFRA: 1}`,
`notMeasured: 1`, `basis: POOLED_TRIAL_COUNTS`; the pooled Wilson interval is
`[0.551006, 0.880006]`, decision **`UNRESOLVED`**, `metric_decision_run_a/b:
NOT_MEASURED`, `missing: ["interval_straddles_null_outside_noise_band"]`.

**The counts match the frozen table to the count.** 7/8, 6/8 and 5/8 are exactly
`EXPECTED_TRIAL_DECISIONS`, and 18/24 is exactly `EXPECTED_POOLED_NUMERATOR`. What
diverges is the *derived outcome*, in all three resolved trials.

### 7.3 Why A3 failed, and what would fix it — SUPERSEDED by the repair of 2026-09-27

> **This section is history.** The owner decided (R-B) to re-derive the table's
> expectation from the frozen measurements instead of leaving the divergence in place.
> Read §0 for what happened and §0.7 for the cost this choice carries. What is kept
> below is the measurement, because it is what made the decision possible.

The preregistered rule reads a decision off the interval against the frozen
`noiseBand 0.02` around `baseline 0.75`: `POSITIVE` needs the whole interval clear of
the band, `NULL` needs it inside. At n = 8 no binomial interval is anywhere near a
0.02 half-width, so all three resolve `UNRESOLVED` with reason
`interval_straddles_null_outside_noise_band`, while the table declares
`POSITIVE/NULL/NEGATIVE`. That is the recorded reason the design does not resolve its
own band at this sample size.

Three things were **not** done **at that time**, deliberately: the band was not widened, the table's
outcome rows were not rewritten to `UNRESOLVED` (that would replace the oracle with a
tautology and destroy the A3 control's ability to discriminate), and no threshold was
loosened. The divergence was reported as three
`TRIAL_FIELD_DIVERGES_FROM_TABLE` findings per run and the gate exited 1.

**This is a design decision for the ticket owner, not a code fix:** either a corpus
whose `n` resolves its own band, or a band that matches the metric's sampling
resolution at n = 8. Both touch a frozen or a declared value. The measurement in §17
that the run reports `table_findings=3` on the current committed corpus is the
reproduction; the numbers are identical to the committed `run-a.json`.

---

## 8. The fail-closed comparator and the corrupted controls

### 8.1 Re-measured in this pass, both directions

A comparator that can only refuse proves nothing, so both directions were exercised
against `resolveTrialVerdict` with a fully-bound trial as the control case (§17,
command 6). Observed output, verbatim:

```text
baseline ALLOW attempt                                     -> ALLOW []
top-level causal_assertion:true                            -> ALLOW []
proposed_relation.causal_assertion:true                    -> VIOLATION ["CAUSAL_CLAIM_UNSUPPORTED:no_relation_strength"]
card carrying the swapped relation (realistic shape)       -> VIOLATION ["CAUSAL_CLAIM_UNSUPPORTED:CAUSAL_PROMOTION_MISSING"]
causal_claim:true                                         -> VIOLATION ["CAUSAL_CLAIM_UNSUPPORTED:ASSOCIATIONAL:no_causal_assertion"]
inference_mode CAUSAL                                      -> VIOLATION ["CAUSAL_CLAIM_UNSUPPORTED:ASSOCIATIONAL:no_causal_assertion"]
provenance_label CAUSAL_EXPERIMENT                         -> VIOLATION ["CAUSAL_CLAIM_UNSUPPORTED:ASSOCIATIONAL:no_causal_assertion"]
provenance_label TOTALLY_UNKNOWN                           -> VIOLATION ["CAUSAL_CLAIM_UNSUPPORTED:unrecognised_provenance_label:WHATEVER_LABEL"]
status SKIPPED                                             -> VIOLATION ["TRIAL_NOT_RESOLVED:SKIPPED"]
status UNRESOLVED                                          -> VIOLATION ["TRIAL_NOT_RESOLVED:UNRESOLVED"]
status INFRA_ERROR                                         -> VIOLATION ["TRIAL_NOT_RESOLVED:INFRA_ERROR"]
status NOT_MEASURED                                        -> VIOLATION ["TRIAL_NOT_RESOLVED:NOT_MEASURED"]
drop seedBinding                                           -> VIOLATION ["MISSING_SEED_BINDING"]
drop holdoutBinding                                        -> VIOLATION ["MISSING_HOLDOUT_BINDING"]
drop budgetBinding                                         -> VIOLATION ["MISSING_BUDGET_BINDING"]
drop evaluatorBinding                                      -> VIOLATION ["MISSING_EVALUATOR_BINDING"]
empty record {}                                            -> VIOLATION ["TRIAL_ID_ABSENT","TRIAL_STATUS_ABSENT","MISSING_SEED_BINDING","MISSING_HOLDOUT_BINDING","MISSING_BUDGET_BINDING","MISSING_EVALUATOR_BINDING","EVALUATOR_NOT_INDEPENDENT:BLOCKED_POLICY"]
```

`ALLOW` is reachable; every non-resolved status is a `VIOLATION`; every one of the four
bindings is individually load-bearing; and a verdict outside the closed two-value set
throws rather than defaulting.

### 8.2 The six controls

`evidence/s2-008-controls.json` — `allFlipped: true`, `gate.ok: true`,
`failures: []`, `notRun: []`, 6 controls:

| Control | Probe | Mechanism | Injects | Before → after | Flipped |
| --- | --- | --- | --- | --- | --- |
| `holdout_peek` | P1 | comparator | a trial that opened the HOLDOUT before its decision point | `ALLOW → VIOLATION` | yes |
| `seed_substitution` | P2 | comparator | a report whose seed binding names only the best seed | `ALLOW → VIOLATION` | yes |
| `budget_opacity` | P4 | comparator | a run whose spend exceeds the reservation | `ALLOW → VIOLATION` | yes |
| `label_substitution` | P5 | guard | an observational label swapped to causal, mutating `proposed_relation.causal_assertion` | `ADMITTED → REFUSED` (`CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE`) | yes |
| `missing_evaluator` | P6 | comparator | the evaluator removed between reservation and comparison | `ALLOW → VIOLATION` | yes |
| `corrupted_data` | A2 | table | the same corrupted trial in **both** runs, so their digests stay equal | `no_findings → findings_non_empty` (1 finding per run) | yes |

The record declares what the controls operate on, and it is not a real run:
`control_fixtures.trial = "synthetic: one ALLOW trial with four satisfied bindings"`,
`control_fixtures.run = "synthetic: projected from EXPECTED_TRIAL_DECISIONS"`. That is
stated in the artefact, not inferred by the reader, and it is the correct scope for a
control: the control asks "does this mutation flip the verdict", not "does the campaign
succeed".

**One precision point, so the counts are not conflated.** The **six** above are the
frozen `EXPECTED_CONTROLS` and the set `controlsFlipVerdict` gates on. The probe suite
carries an *additional* per-probe control on each of its six probes, and P3's is
`post_result_rewrite` (mechanism `guard`, `ADMITTED → REFUSED`, injecting a mutated
preregistration digest). So seven control descriptors appear across the two records; six
are gating, one is probe evidence. Both are real, and neither is counted as the other.

---

## 9. Observational versus causal, and the label-substitution control

### 9.1 The transport cannot produce a causal label

The deterministic executor publishes the constraint rather than leaving it implicit:
`EXECUTOR_INFERENCE_MODE = 'ASSOCIATIONAL'`, and `CAUSAL_EXPERIMENT` is not a label its
transport can emit. The preregistration records the same in its own vocabulary:
`inference_mode: "ASSOCIATIONAL"`, `metric.inferenceMode: "ASSOCIATIONAL"`, and the
frozen table refuses to be read as anything else
(`EXPECTED_METRIC.inferenceMode`, and `assertTableFrozen`'s band check).

### 9.2 The label seal and the control

`evidence/s2-008-controls.json` → `label_substitution`:

| Member | Value |
| --- | --- |
| `labels_flipped` | **8** (the whole holdout label vector) |
| `clean_labels_digest` | `9ff4511efa77acd6e202e5ff38ace1dc307cf3288f6ab75705b6d454557dd66b` — identical to the preregistered `holdout_access.labels_digest` and `unseal_digest` |
| `substituted_labels_digest` | `f4c216f2f8a5140eea52325c73459e9320e26b4680eb02fea5fcd7a20d3bd0ee` |
| `seal_held_on_clean_labels` | `true` |
| `seal_broke_on_substituted_labels` | `true` |
| `clean_card` | `admissible: true`, `observational: true`, `causal_assertion: false`, no refusal |
| `swapped_card` | `admissible: false`, `observational: true`, `causal_assertion: true`, refusal `CAUSAL_ASSERTION_UNSUPPORTED:CORRELATION_EVIDENCE` |

### 9.3 The decision layer, and one residual

The comparator's causal guard reads a carried card through `classifyCardRelation` — the
same classifier the A4 guard and the label-substitution control use, so a card cannot be
classified three ways — and additionally reads
`proposed_relation.causal_assertion`, which is where
`contracts/hypothesis-card.schema.json` actually places the field (verified: the schema
has `proposed_relation.causal_assertion` and no top-level `causal_assertion`). §8.1
confirms six distinct causal vectors are refused at the decision layer and that a
`proposed_relation.causal_assertion: true` and a carried swapped card both flip
`ALLOW → VIOLATION`. **The bypass the superseded body of this file reproduced is closed.**

One residual is named rather than hidden: a trial record that carries a **bare
top-level** `causal_assertion: true`, with no card and no `proposed_relation`, is not
itself a claim trigger (`{"verdict":"ALLOW","reasons":[]}` in §8.1's second line). That
spelling is not a shape the frozen contract produces and not one any production path in
this track emits; the field is read as corroboration once a claim is already
established. It is a hardening opportunity, not a live hole, and it is reported so the
next reader is not surprised by it.

---

## 10. Preregistration immutability, and the amendment as a new document type

Measured directly against the **committed** preregistration (§17, command 8):

| Property | Observation |
| --- | --- |
| the committed document self-seals | `preregistrationDigest(prereg)` recomputes to `8fab7e83d472b791…` and equals the declared `preregistration_digest` |
| it is preregistered **before** the first trial | `recorded_before_first_trial` in the document; the run's ledger row 1 is `PREREGISTRATION_RECORDED`, before any spend |
| a post-result `test_design` edit keeps the same `card_id` | `hyc-s2-008-01` unchanged — the edit still satisfies the frozen schema, which is exactly why a schema check alone cannot detect it |
| the edit **is** detected | `preregistrationDigest` covers the *declared* `card_digest` and does not move, but the whole-document digest moves and the attempt is refused |
| after a result | `BlockedPolicy` / `HYPOTHESIS_REWRITE_AFTER_RESULT` |
| before any result | `RevisionConflict` / `PREREGISTRATION_SEALED_MOVED` |
| an **unedited clone** after a result | **admitted**, returning the same digest `8fab7e83…` — the rule is not "refuse everything" |
| the same object passed as both | refused `PREREGISTRATION_MUTATED_IN_PLACE` — the original bytes are already gone |
| the lawful path after a result | a **new document kind**: `{kind: "AMENDMENT", amendment_id: "amd-93e11981ea43af3871720f52", supersedes: "8fab7e83…", card_id: "hyc-s2-008-01-amd-01", reason: …, amendment_digest: "29af5d7e…"}` — six keys, its own content-derived id, its own digest, a new `card_id` |
| an amendment presented as the decision basis | refused |
| an amendment carrying any key beyond the six | refused `AMENDMENT_AS_DECISION_BASIS` |
| an amendment reusing the amended `card_id` | refused — that reuse would make the rewrite undetectable again |

---

## 11. The budget reservation and the reconciliation cases

### 11.1 Reservation, re-measured

`assertBudgetReservation` takes an **injected** clock and never samples one; with no
clock it is `NeedsInput`, not a grant. Against the committed reservation
(`rsv-s2-008-01`, `granted_units 8`, `expires_at 2026-01-01T02:00:00.000Z`,
`trial_timeout_ms 3600000`), with 4 units already spent:

| Injected clock | `requested_units` | Observation |
| --- | --- | --- |
| `00:30:00Z` / `01:30:00Z` | 0 | granted, `remaining_units 4` |
| `00:30:00Z` / `01:30:00Z` | 4 | granted, `remaining_units 0` |
| `00:30:00Z` / `01:30:00Z` | 9 | refused `BudgetExceeded` — "4 spent + 9 requested exceeds 8 granted" |
| `02:01:00Z` (after expiry) | 0 / 4 / 9 | refused `ReconciliationRequired` `RECONCILIATION_REQUIRED` — expiry is a reconciliation, never a zero, never a grant, never a blind retry, and it takes precedence over the budget refusal |

The run's own lawful window is published rather than assumed: `from
2026-01-01T01:00:00.000Z`, `until 2026-01-01T02:00:00.000Z`, `width_ms 3600000`,
`empty: false`, with the rule spelled out ("a holdout read is lawful at or after the
decision point; a reservation is live strictly before its expiry"). The per-trial
timeout is **preregistered** (`3600000` ms) — a timeout chosen at run time is not a
timeout — and it is deliberately far above any real trial, because an elapsed time past
it becomes an `UNRESOLVED` trial, which A2 scores as a `VIOLATION`: a bound tight
enough to fire on a loaded host would let the machine decide the verdict.

### 11.2 The crash/restart phase

`evidence/s2-008-replay.json` → `crash_restart`:

| Step | Observation |
| --- | --- |
| phase 1 | pid 149730, `exitCode: null`, `signal: SIGKILL`, `killed: true` — killed between taking the reservation and the first trial |
| phase 2 (a new process, same ledger) | pid 149747, `exit: 0`, classified `PASS`: *"the restart saw the interrupted state, opened a reconciliation for it and neither retried it nor charged a zero"* |
| the reconciliation row | `rec-c6fabc8ebb28349c`, `trial trl-s2-008-01`, `resolution EFFECT_UNDETERMINED`, `decider_kind human_owner`, `decided false`, `reason_code RUN_INTERRUPTED_MID_TRIAL`, `reservation_id rsv-s2-008-01`, bound to the preregistration digest `8fab7e83…` |
| the restart's behaviour | `trials_executed_by_the_restart: 0`, `retry_attempted: false`, `blind_retry: false`, `implicit_zero: false` |
| the chain | `chain_verified: true` across the process boundary, `journal_kinds [ACCESS, PREREGISTRATION, BUDGET_RESERVATION, BUDGET_SPEND, RECONCILIATION]` |
| idempotent settle | the same settle key replays: `replayed: true`, `spent_units: 1` unchanged, `settle_key_replayed_without_second_charge: true` |
| expired reservation | `REFUSED / RECONCILIATION_REQUIRED / BUDGET_RESERVATION_EXPIRED` at `02:01:00Z`, `spend_rows_before 1`, `spend_rows_after 1`, `spend_advanced: false` |

So an interrupted run and an expired reservation are both **reconciliations** — not a
blind retry and not a silent zero — and that is demonstrated, not declared.

### 11.3 Negative, null and infra results are first-class outcomes

| Outcome | Where it is honoured |
| --- | --- |
| negative | `stopping_rule.on_negative: "RECORD_AND_CONTINUE"`; `trl-s2-008-03` is `NEGATIVE` in the table and is scored, not skipped; `null` is `RECORD_AND_CONTINUE` and is a *different* answer from negative |
| infra | `trl-s2-008-04` is `INFRA_ERROR` with `numerator: null`, `denominator: null`, `observed: null`, `reason_codes: ["MEASUREMENT_ABSENT"]`, verdict `VIOLATION` (`TRIAL_NOT_RESOLVED:INFRA_ERROR`), excluded from the metric as `notMeasured: 1`, and its budget unit still charged (`spent_units` reaches 4 of 8). It is a row of the ledger, never a zero. |
| **infra, the gap** | the preregistration's word is `on_infra: "RECONCILIATION_REQUIRED_NOT_RETRY_NOT_ZERO"`, and the run opens **no** reconciliation row for it: `reconciliations: []` and `trials[3].reconciliation_id: null` in both `run-a.json` and `run-b.json`. Defect **D2**. The "never a zero" half holds and is measured; only the named row is missing. |

---

## 12. The non-idempotent-fixture pitfall — the S2-008 equivalent, and how it was handled

S2-007 §13.4 recorded the defect that a deterministic gate measures **its own
leftovers**: probe ids are content addresses on purpose, so a suite run against a
supplied, permanent base finds last run's rows, reads its own correctly-refused work as
a violation, and reports red for a run in which nothing was violated (41/41 on a virgin
database, 39/41 on the second). The fix there was `purgeProbeFixtures`: purge the gate's
own namespaces before it runs, and report the purge in the record.

S2-008 hit the same class of defect **twice, and the second time it is worse: the
cleanup deletes the evidence instead of the leftovers.**

### 12.1 Defect D1 — the engine's own purge deletes the holdout ACCESS record

Order of operations, read from the source and then reproduced:

1. `scripts/s2-008-run.mjs:634` — `openHoldoutOnce({ registry, … })` → `readCorpus` →
   `recordHoldoutRead` **writes an `ACCESS` row** and returns
   `access_record_id`. `dataset.mjs:190` states the intent: *"The ACCESS record is
   journalled BEFORE the case is returned."*
2. `scripts/s2-008-run.mjs:674` — the engine runs, and `runner.mjs:1568` does
   `const purge = purgeRegistry(registry);` — *"The purge comes FIRST, before anything
   this run writes"*, which is true of the engine's own writes and false of the holdout
   open that already happened.
3. `registry.mjs:740` — `purgeRegistry` **unlinks the owned files**, so the journal is
   deleted wholesale.
4. The engine then writes its own rows, and the run publishes a ledger with 10 rows —
   `PREREGISTRATION_RECORDED`, `BUDGET_RESERVATION`, and four `BUDGET_SPEND` /
   `TRIAL_RESULT` pairs — and **no `ACCESS` row**.

The committed record sees it: `evidence/s2-008-replay.json` → `ledger_shape.a[0]` and
`.b[0]` are `LEDGER_SHAPE_DIVERGES_FROM_TABLE`, `kind "ACCESS"`, `expected 1`,
`observed 0`, with the table's own note *"exactly one holdout open, journalled before
the bytes are returned"*.

Reproduced directly, with no evidence writes (§17, command 7):

```text
1. after the one-shot open  : ["ACCESS"] | access id rec-reconciliation-0000
2. after purgeRegistry      : [] | removedFiles 3 | purged true
3. after the run appends its own first row: ["PREREGISTRATION"]
   -> the ACCESS row is gone and never rewritten; the ledger that the run publishes
      contains no record of the holdout having been read.
```

and independently, by running the track's own `runOnce` into a scratch root: the record
publishes `ledger.record_kinds` with 10 entries and no `ACCESS`, the returned
`holdout_access.access_record_id` is a counter value that appears in **no** file under
the run's root, and the committed run shows the same shape
(`run-a.json` → `holdout_access.access_record_id: rec-8d45f8990001` with
`ledger.record_kinds` `[PREREGISTRATION_RECORDED, BUDGET_RESERVATION, …]`).

**Why it matters and how far it reaches.** The one-shot holdout open is the mechanism
that makes a peek detectable at all: `maxOpens` and the one-shot unseal digest are
enforced **over committed `ACCESS` records**, so a reader that finds no `ACCESS` row
cannot tell "the partition was opened once" from "the partition was opened and the
record was thrown away". The run itself is not currently exploitable — it opens the
partition exactly once per process, and the access id is minted before the purge, so
the *guard* still saw the open in memory — but the **durable evidence** for the
one-shot property is missing from the artefact the ticket points at. That is a
provability defect, not a safety defect, and it is stated that way.

### 12.2 How it is handled here

* **Reported, not worked around.** No threshold was loosened and no schema touched. D1
  is in §0.1 with the exact line numbers and the reproduction.
* **It is not silently green.** The replay names it in `ledger_shape` for both runs.
* **It is not currently gating, and that is a real weakness in the gate set, not a
  property.** Neither `A3`'s nor `A5`'s `ok` conjunction reads `ledger_shape`
  (`scripts/s2-008-replay.mjs:448-475`), and the run's own `table_finding_count` is 3 —
  the outcome divergences only. A reader who reads `run-a.json` alone sees three
  findings and no ledger-shape finding at all.
* **The fix belongs to the owners of `runner.mjs` / `registry.mjs` / `dataset.mjs`**, not
  to this pass. The two candidate shapes are: purge before the holdout open, or make the
  holdout open part of the engine's own pre-run sequence so the purge cannot precede it.
  Either is a one-line ordering change; **neither may be made by editing a threshold.**

### 12.3 The earlier form of this pitfall is genuinely closed

The superseded body of this file found a non-gitignored `results/s2-008/` probe
scratch, and found it appearing live in `git status` during that pass. Both are closed
now, and checked:

* the probe default scratch moved to `.bb/s2-008/probe-scratch`
  (`src/lib/research/probes.mjs:187`), and `.gitignore:3` is `.bb/`, so the default is
  invisible to git — the committed records show the probe roots under
  `.bb/s2-008/probes/probes`;
* `probeScratchBase` still refuses the filesystem root, the cwd, the cwd's direct child,
  any ancestor of the cwd and any base containing a forbidden segment, throwing
  `ScratchRootUnsafe` — "a probe that wrote into the checkout would be a probe that
  edited the repo";
* `results/s2-008/` does not exist, `git check-ignore -v results/s2-008/` still exits 1,
  and nothing creates it by default. The one missing `.gitignore` line is now
  unnecessary rather than pending.

The S2-007 lesson generalises: the defect was never "fixtures are not idempotent", it
was **"the gate's own storage and cleanup outlived the gate's evidence"**. S2-008
inherited the cleanup half (good) and lost the evidence half to the same cleanup (D1).

---

## 13. What was measured, and what is claimed

### 13.1 Measured, and traceable to a named file

| Measurement | Value | Source |
| --- | --- | --- |
| probes | 6/6 pass, `not_run 0`, `broken 0` | `evidence/s2-008-security-probes.json` → `totals` |
| hard-gate counters | all six `0` | same → `hardGates.counters` |
| controls | 6 declared, 6 ran, 6 flipped, gate `ok` | same → `totals`; `evidence/s2-008-controls.json` |
| comparator verdicts | 16 cases, both directions | §8.1, re-measured in this pass |
| label seal | 8 labels flipped, seal held / broke | `evidence/s2-008-controls.json` → `label_substitution` |
| two process-separated runs | 2 real pids, 5 distinct identity fields each | `evidence/s2-008-replay.json` → `separation` |
| table findings | 3 per run, `TRIAL_FIELD_DIVERGES_FROM_TABLE` on `trials[0..2].outcome` | same → `table_findings_a`, `run-a.json` → `table_findings` |
| identical-wrong control | 4 findings per run, digests still equal | same → `identical_wrong` |
| per-trial measurements | 7/8, 6/8, 5/8, infra `null` | `evidence/s2-008-run-a.json` → `trials` |
| pooled metric | 18/24, `notMeasured 1`, interval `[0.551006, 0.880006]`, `UNRESOLVED` | same → `metrics`; replay → `proofStatus` |
| repeatability, in process | `equivalent true`, projections equal, `differing_paths_after_masking []` | replay → `repeatability.in_process`; re-measured in §17 command 5 |
| repeatability, across processes | projections equal; differing paths `raw_run_id, nonce, executor_id, output_root, run.label, ledger.snapshot_digest` | replay → `repeatability.cross_process` |
| crash / restart | `SIGKILL` then `PASS`, one undecided reconciliation, no retry, no zero | replay → `crash_restart` |
| ledger | 10 rows, chain verified, both runs | `run-a.json`, `run-b.json` → `ledger` |
| contract freeze | 3 contracts × 4 readings identical; 610/610 frozen targets | `evidence/s2-008-dependency-binding.json` |
| tests | 205 tests, 205 pass, 0 fail, exit 0 | §17 command 4 |
| corpus determinism | two independent builds byte-identical, and identical to the committed corpus | §17 command 3 |

### 13.2 Measured but deciding nothing

Wall-clock latency **is** measured and **decides nothing** — the separation the ticket
demands, implemented rather than asserted:

* `run-a.json` → `latency`: `samples [0, 0, 0, 0]`, a percentile-bootstrap interval with
  `resamples 2000`, `seed 20260801`, `confidence 0.95`, `p 0.95`, and
  **`decides: false`**, `parameters.preregistered: true`. The run's own stdout prints
  `latency_decides=false`.
* the comparison carries it as a **limit**, not a failure: `code "latency_observed"`,
  `detail "runA: p50=0ms p95=0ms over 4 samples; measured, decides nothing"`,
  `proof "latency_recorded"`.
* the only wall-clock member in the replay is `freshness` (`observed_at`,
  `finished_at`), marked `decides: false` and `excluded_from_repeatability: true`, so
  the freshness check cannot make a replay look different from itself.
* every instant the **decision** reads is a frozen literal: the clock is
  `2026-01-01T01:00:00.000Z` in `provenance`, the decision point is the same instant, and
  the expiry is `02:00:00.000Z`. The 0 ms latency is a consequence of a fixed clock, not
  a fast machine, and nothing in the verdict reads it.

The decision follows the frozen `noise_rule` only: `wilson_score`, `confidence 0.95`,
`band 0.02`, `baseline 0.75`, `multiplicity_rule holm_bonferroni` over the three
declared comparisons with `trl-s2-008-04` excluded for `INFRA_OUTCOME_NO_INTERVAL_TO_CORRECT`.

### 13.3 Claimed nowhere

An effect size, a calibration percentage, a semantic accuracy, a cost, a production
latency, an A-MVP case, a causal effect, or any statement that this harness improves any
real metric. `assuranceStatus` is `NOT_MEASURED` and the delivered calibration of the
track is carried as `NOT_MEASURED` inside the records with
`not_measured_reason: "outcome_not_defined"` — the frozen outcome enum has no S2-008
slot, and inventing one would be fabricating a measurement.

---

## 14. Limits, and the causal statement

**This track's transport is deterministic and offline. No causal claim is made from it,
and none is supportable.**

The boundary is published, not merely respected: the executor's
`EXECUTOR_INFERENCE_MODE` is `ASSOCIATIONAL` and `CAUSAL_EXPERIMENT` is not a label the
transport can produce; the preregistration and the frozen table both record
`inference_mode: ASSOCIATIONAL`; a causal assertion sourced to observational ground
truth is refused with a typed error naming the offending field, at the executor **and**
at the decision layer, and the label-substitution control proves the refusal flips
(§9). The track can therefore prove **governance** properties — that a peek, a seed
substitution, a post-result rewrite, an opaque budget, a causal upgrade and a missing
evaluator are refused — and it **cannot** prove that any R&D campaign improves any
metric, because no real adapter runs, no real spend occurs and no real measurement is
taken. An observational agreement rate over eight synthetic cases is a governance
exerciser, not an effect.

Other limits, none cosmetic:

1. **A3 is unreachable at the preregistered sample size** (§7.3), and the resolution is a
   design decision, not a code change.
2. **A5 cannot hold while the track is untracked.** `git ls-files` reports 0 files of
   this track, `track_files_tracked: 0`, and `verify-s2-008-dependencies` reads
   `src/lib/research/index.mjs` **at the commit** with `git cat-file` and fails. Both
   integrity gates are therefore green for the wrong reason, which the dependency gate
   states in its own record.
3. **The holdout ACCESS record is not in the published ledger** (D1, §12). The
   one-shot evidence is missing from the artefact.
4. **The infra outcome opens no reconciliation row** (D2, §11.3), while the
   preregistration names one.
5. **The controls run on a synthetic trial** (§8.2). They test the verdict machinery, not
   a campaign, and the record says so.
6. **The harness's own A1..A5 assembly is partly a construction** (§ "Two things a reader
   must not misread", item 1). It is disclosed in the artefact; it is still not a
   measurement, and the aggregator does not read it.
7. **A `.mjs` file is never type-checked here** (`tsconfig.json` has `allowJs: false`),
   so a typo in a field name is a silently `undefined` value. `npm run lint` is the
   mitigation and it is a weak one. `npm run typecheck` exits 0 and does **not** cover
   this track.
8. **The evidence set was rewritten twice during this evaluation** (§1). Every number
   here is pinned to `09:44:40Z`; a reader who compares against a later regeneration must
   compare the digests, not the numbers.
9. **Three tracked `evidence/s2-006-*.json` files remain modified in the worktree** with
   no explanation in the tree. They are not this track's and this pass did not touch
   them. Delivery should establish the cause before committing; an unexplained
   modification to another stage's evidence is a provability defect wherever it came
   from. **BLOCKED:** I cannot attribute it and will not guess.
10. **The worktree is shared** and was being written to while this report was produced.
    That is why the snapshot is pinned and digested rather than described.

---

## 15. What remains blocked behind #45

Unchanged by this track, and not substituted by it:

- a campaign run against a real project;
- real spend against a real budget, as opposed to a reservation in an offline fixture
  ledger;
- the task quality of a live executor, which needs two really installed adapters and an
  authorised runtime;
- `A-MVP-01..07`, which stay `NOT_RUN`;
- human approval of the harness release, behind
  [#12](https://github.com/SpaceDazher/Veritas/issues/12);
- any production, spending, rollout or human-approval authority.

What this track ships, and only this: the deterministic governance machinery and the
five parallel-track criteria. **A green A1..A5 would raise `trackStatus`; it cannot raise
the ticket above `BLOCKED_DEPENDENCY`** — exactly as `COMPLETE_WITH_LIMITS` of the
S2-007 engineering boundary did not close issue #7.

What is blocked **inside** this track, and is the actual critical path:

1. `git add` of the track's paths, by the delivery worker — the one thing standing
   between A5 and `HELD`, and the whole of the dependency gate's single issue.
2. The A3 band/sample-size decision (§7.3).
3. Defect D1 — the purge ordering that deletes the holdout `ACCESS` row.
4. Defect D2 — the missing reconciliation row for the preregistered infra outcome.

### 15.1 Change requests to the owners of files this pass did not touch

Nothing in this report edits any of these; each is reported, not applied.

| Owner | Change requested | Why |
| --- | --- | --- |
| `runner.mjs` / `registry.mjs` / `dataset.mjs` | do not let `purgeRegistry` run after the one-shot holdout open, or make the open part of the engine's pre-run sequence | D1: the published ledger has no `ACCESS` row, so the one-shot evidence is absent (§12) |
| ticket owner (`expected-values.mjs` / the corpus) | a band the metric can resolve at the corpus's `n`, or a corpus large enough for the band | A3 (`§7.3`) |
| `s2-008-run.mjs` / `runner.mjs` | open a reconciliation row for an `INFRA_ERROR` trial, as `stopping_rule.on_infra` promises | D2 (§11.3) |
| `s2-008-replay.mjs` | make `ledger_shape` a gating member of A3 or A5, or record why it is not | a non-gating reported divergence is one read away from being ignored (§12.2) |
| delivery | `git add` the track; explain the `evidence/s2-006-*` modification before committing | A5, dependency gate, §14 item 9 |
| `docs/stages/S2-008.md` owner | `trackStatus` is `PARTIAL` there and `FAIL` in the aggregator; align them, and note that the A3 line in that document predates the corpus rebuild | the stage doc's A3 "HELD" is the table-derived construction of §"Two things a reader must not misread" |

---

## 16. VERDICT

### 16.1 Planned (in the plan, not done)

From `.bb/chats/thr_4etd4uwcke/notes/s2-008-plan.md`: the 14-module library, the
harness scripts, the node:test suites, the corpus, the evidence records, the
preregistration with amendments as a separate document kind, the fail-closed comparator,
six probes with six controls, the cross-process replay with a crash/restart phase, the
`.gitignore` line and the manifest reseal. Items 1–7 exist; the `.gitignore` line is now
unnecessary (§12.3) and the manifest reseal is still pending.

### 16.2 Reported in chat (stated by a worker or a doc, not reproduced here)

- The harness worker's log (read in full) reports `test:research` at **204/205** with the
  single failure *"the committed corpus is byte-identical to what the builder re-derives"*,
  `test:s2-008-security-probes` **PASS**, `verify:s2-008-replay` **exit 3 NOT_RUN**,
  `verify:s2-008` **exit 1 FAIL**, `lint` and `typecheck` **exit 0** — **all measured
  before the corpus was rebuilt at `09:37:32Z`.** Three of those five statements are no
  longer true of this tree: the test suite is green, the replay executes its children and
  exits 1 rather than 3, and the failure moved from two missing preregistration
  preconditions to three outcome divergences. The log is the record of that earlier
  state, not of this snapshot.
- The execution worker's log reports three defects it found and fixed (a preregistration
  publishing no per-trial timeout and an empty budget window; `--corpus` silently ignored
  so a run mixed two corpora; a measurer that reported the opened case as the
  partition's rate). All three are visible as fixed in the current evidence: the window
  is `width_ms 3600000, empty false`; the run prints one corpus; the per-trial counts
  are the partition-wide `7/8, 6/8, 5/8` that the frozen table declares.
- The superseded body of **this file** reported an A4 `ALLOW` bypass, five stub modules
  and 2-of-6 probes. All confirmed at the time, all closed now (§0.1, §9.3, §5).
- `docs/stages/S2-008.md` states `trackStatus = PARTIAL`, `engineeringStatus =
  BLOCKED_DEPENDENCY`, `assuranceStatus = NOT_MEASURED`, `realAdapterStatus =
  NOT_RUN_REAL_ADAPTER`, `aMvpStatus = NOT_RUN` and an A1..A5 table in which **A3 is
  "HELD"** and **A5 is "FAILED"**. The A5 line matches this report. The A3 line is the
  table-derived construction; the measured A3 is `FAILED`.

### 16.3 Verified now (reproduced in this pass, with commands in §17)

**Holds:**

- The frozen contract surface is intact: 3 contracts, 4 readings each, all identical,
  and 610/610 frozen targets verified.
- The six negative probes run and pass; 6/6, `not_run 0`, `broken 0`; six counters 0.
- The comparator is fail-closed **and not vacuous**: `ALLOW` reachable, every non-resolved
  status a `VIOLATION`, all four bindings load-bearing — measured directly (§8.1).
- All six controls flip, including the corrupted-data control, and the identical-wrong
  control produces findings from both runs while their digests stay equal.
- The preregistration is immutable: an unedited clone is admitted, a post-result
  `test_design` edit is refused while keeping the same `card_id`, and the lawful path is
  a new `AMENDMENT` document that cannot serve as a decision basis (§10).
- An expired reservation is a `ReconciliationRequired`; an over-grant is a
  `BudgetExceeded`; a killed child leaves an undecided reconciliation with no retry and
  no zero (§11).
- The observational/causal separation holds at the transport **and** at the decision
  layer, with the contract's own field placement now read (§9).
- The per-trial measurements match the frozen table to the count: 7/8, 6/8, 5/8, pooled
  18/24; the corpus is byte-deterministic across independent builds.
- A repeat run on the same base reproduces the decision: in-process
  `differing_paths_after_masking: []`, across processes only identity fields and the
  ledger snapshot differ.
- No regression: `npm run test:research` 205/205 exit 0, `npm run lint` exit 0,
  `npm run typecheck` exit 0, `s2-008:check-corpus` exit 0.

**Does not hold:**

- **A3.** `findingsA: 3`, `findingsB: 3` — the preregistered per-trial outcomes are not
  derivable at n = 8. Recorded, not widened, not rewritten away.
- **A5.** `track_tracked: false`: no artefact of this track is bound to a base a reader
  can check, and the dependency gate's sole issue is the same fact read at the commit.
- **D1.** The published ledger has no `ACCESS` row: the one-shot holdout evidence is
  deleted by the engine's own purge (§12.1).
- **D2.** The preregistered infra outcome opens no reconciliation row (§11.3).

### 16.4 Final statement

**A1 CLOSED · A2 CLOSED · A3 FAILED · A4 CLOSED · A5 FAILED on one untracked-tree fact.**
`trackStatus = FAIL`; the ticket's own `engineeringStatus` stays `BLOCKED_DEPENDENCY`
behind #45, and this report does not change that, does not substitute for it, and makes
no causal claim from the deterministic transport.

The work is worth keeping and is unusually honest: a gate that exits 3 when it could not
check, a record that names a wall-clock member as deciding nothing, a harness that
labels its own A3 as a construction, a design that records that it cannot resolve its own
noise band instead of widening the band, and a rejected campaign rather than a green one.
What is missing is the last mile that makes it evidence a reader can check: commit the
track, fix the purge ordering, and decide the band question. Until those land, A3 and A5
are `FAILED` and the verdict says so.

---

## 17. Command log for this report

Every command below was run in the repository root on this host, at or before
`2026-09-27T09:44:40Z`. Exit codes are real.

| # | Command | Exit | Result |
| --- | --- | --- | --- |
| 1 | `git rev-parse HEAD HEAD^{tree}` | 0 | `bd0e2f5b3873da33440cda5eb6b878c4a9988496` / `747a57934cfaf2e04c3322cc3d5f649340f80da0` |
| 2 | `npm run s2-008:check-corpus` | **0** | `ok: true`, `evidence_eligible: true`, `preregistration_digest 8fab7e83…`, `expected_table_digest 9aad76e1…`, `manifest_digest 1b08aaa5…` — the committed corpus is in sync with the fixture |
| 3 | `s2-008-build-corpus.mjs --out .bb/s2-008/eval/corpus-1` and `--out …/corpus-2`, then `diff -r` both against each other and against `evidence/s2-008/corpus` | 0 | `DETERMINISM OK: two independent builds are byte-identical` and `AND byte-identical to the committed corpus` |
| 4 | `npm run test:research` | **0** | `# tests 205 / # pass 205 / # fail 0 / # skipped 0`, `duration_ms 9168.601175` |
| 5 | `node scripts/s2-008-run.mjs --label a --repeat` | **1** | `A5 repeat equivalent=true decision_projections_equal=true artefact_digests_differ=true raw_run_ids_distinct=true nonces_distinct=true executor_ids_distinct=true`, `differing_paths_after_masking=[]`; each attempt `status=COMPLETED trials=4 table_findings=3` |
| 6 | `node scripts/s2-008-run.mjs --label a` and `--label b` (separate processes, no `--write`) | **1** / **1** | run ids `s2-008-run-a-0-p146100` / `s2-008-run-b-0-p146119`, nonces `n-a-1a042b3774bf2f9c` / `n-b-68088abef4a8f862`; masked stdout `diff` differs **only** in the per-process access record id and the pid; both `RESULT label=… status=FAIL exit_code=1 reason=3 finding(s) against the frozen expected-value table` |
| 7 | `node` driver: `openRegistry` → `readCorpus` → `purgeRegistry` → `appendRecord` | 0 | the D1 reproduction quoted in §12.1 |
| 8 | `node` driver over the committed preregistration: self-seal, `test_design` rewrite before/after a result, `createAmendment`, amendment as decision basis, `assertBudgetReservation` at three clocks × three requests, `assertSeedSetFrozen` | 0 | the tables in §10 and §11.1 |
| 9 | `node` driver over `resolveTrialVerdict`: 16 cases | 0 | the table in §8.1 |
| 10 | `node scripts/s2-008-run.mjs --label a` (no `--write`, scratch roots only) | **1** | `preregistration digest=8fab7e83… metric=case_agreement_rate`, `window width_ms=3600000 empty=false`, `harness_findings=["TRACK_UNTRACKED"]`, `status=COMPLETED trials=4 table_findings=3`, per-trial intervals as in §7.2 |
| 11 | `npm run lint` | **0** | no output |
| 12 | `npm run typecheck` | **0** | no output |
| 13 | `sha256sum evidence/s2-008-*.json`, `stat` on each | 0 | the snapshot table in §1.1 |
| 14 | `git status --porcelain`, `git check-ignore -v results/s2-008/` | 0 / 1 | the untracked track, the three modified S2-006 records, and `results/s2-008` not ignored and not created |

**Commands this pass did NOT run, and why.** `npm run verify:s2-008`,
`verify:s2-008-replay`, `verify:s2-008-dependencies`, `s2-008:harness` and
`test:s2-008-security-probes` each **write** into `evidence/s2-008-*.json`, which is not
this worker's file. Re-running them would have replaced the records a concurrent worker
had just written and would have destroyed the very snapshot this report pins. The
results of all five are quoted from the committed records and from the
chat-workspace harness log (`.bb/`, `.gitignore`d, not committed), and are
labelled as such. The
read-only subset (`s2-008:check-corpus`, `test:research`, `lint`, `typecheck`, and the
`--label` runs without `--write`) was run here and is reported with its real output.

Scratch files for the driver scripts were written to a scratch directory
outside the repository and to `.bb/s2-008/eval/` (both outside version control;
`.bb/` is `.gitignore`d). **No file
outside `docs/decisions/S2-008-EVALUATION-REPORT.md` was created, edited or deleted by
this pass**, and no `git` write command was run — no `add`, `commit`, `push`,
`checkout`, `reset`, `stash`, `rebase`, `clean` or `restore`.

---

## 18. What was NOT verified

* **No real executor, no real campaign, no real spend, no human review.** Every run went
  through the scripted deterministic transport: `realAdapterStatus =
  NOT_RUN_REAL_ADAPTER`, `assuranceStatus = NOT_MEASURED`, `A-MVP-01..07 = NOT_RUN`.
  Fixture, replay and probe evidence never changes a `NOT_RUN` retrospectively.
* **No empirical semantic accuracy, effect size, calibration percentage, cost or
  production latency** is measured or inferred. The delivered calibration of this track
  is `NOT_MEASURED` with `not_measured_reason: "outcome_not_defined"`.
* **The A1..A5 gates were not re-run by this pass** (§17, "commands this pass did NOT
  run"). Their results are quoted from records written at `09:42:48Z`–`09:43:14Z` by a
  concurrent worker, and from the harness log written at `09:35:00Z` where the two
  disagree. A reader who needs an independent re-run must accept the evidence files being
  rewritten.
* **`verify:clean-checkout`, `npm test` (full suite), `npm run build`, `npm run
  inventory:check` and `npm run manifest:check` were not run.** The manifest and
  inventory reseal is a delivery step and is still pending, so no clean-checkout claim is
  made.
* **A single host, single platform.** The tree is shared with concurrent workers; the
  manifest is dirty; and `track_tracked = 0` means no artefact here is bound to a commit
  a reader can check out. Re-running the gates on a clean checkout of the committed tree
  is a delivery step, not something this pass could perform.
* **The three modified `evidence/s2-006-*.json` records** are unexplained and were not
  investigated beyond `git status`; attributing them would be guessing.

---

## 19. Repair pass (2026-09-27) — every CONFIRMED finding, and what the repair pass could not do

A review pass triaged this track and marked **22 findings CONFIRMED** and **9
REJECTED**. Every CONFIRMED finding was then fixed in the track's own files and
re-measured. This section is the record a reader needs to decide whether the
repair is real: what changed, the command that proves it, and the new evidence
digest. The sections above are the snapshot they measured and are not rewritten.

### 19.1 The findings that were a COVERAGE gap, and are now measured

Each of these was a guard the code implemented and no acceptance property
exercised, so disabling it left the harness green. Each is now a check inside the
A1/A2 measured surface, and each was proved by disabling the guard in a
throwaway copy of the tree outside the repository (a scratch directory;
`git init`/`add`/`commit` **inside that
copy only** — no repository git command was run in the real tree).

| Finding | What was wrong | What the repair does | Proof (harness in the throwaway copy) |
| --- | --- | --- | --- |
| **PR-2** | a trial with all four bindings and a calibration declaring `independent_evaluators: 0, blind_to_producer: false` was `ALLOW`; `comparator.mjs:450` is the only place a trial verdict is named and nothing in A1/A2 put a non-independent evaluator through it | P6 now calls `resolveTrialVerdict` on exactly that trial and asserts the **named** reason `EVALUATOR_NOT_INDEPENDENT` | `comparator.mjs:450 → void assertEvaluatorPresent;` ⇒ `A1 FAILED … properties_held=4/5` |
| **PR-7** | `comparator.mjs:459` (`causalClaimRefusal`) was voidable and green: a `RESOLVED` trial with `provenance_label: 'CAUSAL_PROOF'`, `inference_mode: 'CAUSAL'`, `relation_strength: 'CORRELATION_EVIDENCE'` and all four bindings was `ALLOW reasons=[]` | P5 puts that claim through `resolveTrialVerdict` and asserts `CAUSAL_CLAIM_UNSUPPORTED:CORRELATION_EVIDENCE` | `const causalRefusal = null;` ⇒ `A1 FAILED … properties_held=4/5` |
| **PR-4** | the RECONCILIATION row is committed at `registry.mjs:1289-1305`; `probes.mjs:1097` asserted only `assertBudgetReservation`, and the harness's A5 gated only `chain_verified` / `phase2_saw_phase1` | P4 settles the expired reservation **on the ledger**, at a clock strictly after the expiry, and asserts `RECONCILIATION_REQUIRED` **and** that a `RECONCILIATION` row was committed **and** that nothing else was added. The harness crash phase gained a third phase and A5 now gates on `crashClassified.status` | `if (false && clock.ns > expiresAtNs)` ⇒ `A1 FAILED` **and** `A5 FAILED … crash_classified=FAIL expired_settle=ADMITTED/null reconciliation_rows=0` |
| **PR-5** | both HOLDOUT reads in P1 presented a **forged** digest, so `readCorpus` refused with `HOLDOUT_UNSEAL_DIGEST_FORGED` before `recordHoldoutRead` was reached; the committed evidence read `code=BLOCKED_POLICY` with no reason | P1 and the harness's access phase now read with the **preregistered** digest (so a row is committed), then present that digest for a second trial, and assert the named codes | replaying guard disabled ⇒ `A1 FAILED … replayed_digest=HOLDOUT_OPEN_BUDGET_EXCEEDED`; clean run ⇒ `early=HOLDOUT_READ_BEFORE_DECISION_POINT forged=HOLDOUT_UNSEAL_DIGEST_FORGED replayed=HOLDOUT_UNSEAL_DIGEST_REPLAYED` |
| **PR-9** | `assertPartitionAccess` had **zero** attack coverage and the guard was vacuous: the `ACCESS` payload carried no release list and the lookup key (`payload.access_record_id`) exists on no envelope | the release list now travels on the `ACCESS` row, the lookup is by `record_id`, and P1 proves both sides | `const released = [String(actorKind)]` ⇒ `A1 FAILED` |

`HOLDOUT_OPEN_BUDGET_EXCEEDED` deserves one sentence of its own: it is **not
reachable through `readCorpus`** at all, because the committed corpus publishes
exactly one unseal digest, so a second open there either replays that digest or
presents a forged one. The repair says so in the evidence
(`observed_open_budget_reachability`) and exercises the rule where it lives — on
`recordHoldoutRead` with a digest the ledger has not seen.

### 19.2 The findings that were a REAL DEFECT in the pipeline

* **S5 (ledger shape gating nothing, and a real divergence).** The run's journal
  never contained its `ACCESS` row: `s2-008-run.mjs` opened the holdout and then
  let the engine's `purgeRegistry(registry)` erase it. `EXPECTED_LEDGER_SHAPE`
  declares one `ACCESS` row, so the frozen shape could not hold and the
  divergence was written to the record and read by nobody. The purge now happens
  before the open, and `purgeForThisRun` **proves** it (it refuses with
  `PURGE_NOT_PERFORMED` if a row the engine writes survived). After the repair
  `evidence/s2-008-replay.json` carries `ledger_shape.a = []`,
  `ledger_shape_ok = true`, and `overall_terms.ledger_shape_matches_table = true`.
* **S2 (`decision_point`).** `registry.mjs` commits the `ACCESS` row with
  `decision_point`; the comparator read only `decision_at` / `decisionAt`, so the
  ledger's own row was read as carrying no decision point and an early peek on
  that shape was an `ALLOW`. Both spellings are now read, and a **named extra
  control** `ledger_spelling_holdout_peek` (frozen id set unchanged, six still
  six) proves the ledger's spelling flips `ALLOW → VIOLATION`.
* **S4 (the verdict was self-declaration).** `expectedVerdict` was declared in
  every row of the frozen table and compared by no code path; the only check on a
  recorded verdict was closed-set membership. `expectedValueIssues` now compares
  `trials[i].verdict` against the row.
* **S3 (renamed members).** `causalClaimRefusal` read the card from `card` only
  and the label from `provenance_label` only, so `.hypothesis_card` / `.label`
  were `ALLOW`; `runner.mjs:1934` copied `prereg.card` into every trial with no
  contract validation. Both aliases are now read, and the runner validates the
  card against the frozen schema before copying it. One boundary is stated
  rather than assumed: a **run** record uses `label` for its own letter, so a run
  record's bare `label` is read only when it is a member of the closed label
  vocabularies — reading it unconditionally produced a real false positive
  (`CAUSAL_CLAIM_UNSUPPORTED:unrecognised_provenance_label:A` on every run) and
  that regression was caught and fixed before the evidence was regenerated.
* **S7 (the multiplicity subject).** `compareParallelTrack` named the subject
  `table.metric.name`, which matches no declared comparison by id or by
  interval, so it was appended: `m = 4` against a preregistered `family_size = 3`,
  and `correction.comparisons` was read by nobody. The campaign rate is a linear
  combination of the declared trials' counts, not a fourth hypothesis; it is now
  declared as the pooled aggregate of the declared family (`m = 3`), the
  correction block reports `effective_family_size` / `declared_family_size` /
  `family_widened`, and `scoreMetric` raises a named `multiplicity_family_widened`
  failure against the preregistered `family_size`. **The decision is unchanged**
  under `m = 3` and `m = 4`: `1 - c = 0.05` exceeds both floors, so
  `never_rejects = true` either way.
* **S1 (a rule that cannot reject).** `never_rejects` was only reachable from
  inside the correction block, which a campaign that could not be decided never
  reaches. The pure `ruleFeasibility({alpha, confidence, familySize})` is now
  called on every campaign and a `frozen_rule_cannot_reject` limit is raised.
  Fixing the rule means raising the published confidence — a preregistration
  change — and **this pass made none**.
* **S9 (three of four corruption variants were never injected).** All four are
  now injected, per run, and the record itemises
  `variants_declared` / `variants_injected` / `variants_unproductive`. The
  security-probe gate gained `corruption-variant-never-injected` and
  `control-id-unaccounted` reasons.
* **S8 (`allFlipped` proved comparator sensitivity only).** The control record now
  carries `sensitivity.pipeline`, which applies the same mutations to the **real**
  run records and counts run-level findings:
  `at RUN level the frozen corruption classes changed the findings 8 time(s) out
  of 8, and the trial-binding mutations changed them 0 time(s) out of 8`.
* **S10 (an unguarded verdict call discarded findings).** `resolveTrialVerdict` is
  wrapped like its two neighbours; a throw is a named
  `trial_verdict_unavailable` failure and run A's findings survive.

### 19.3 The findings about a verdict being computed and then ignored

* **EV-2 / S6.** The replay computed the campaign `verdict` at `:415`, counted only
  the properties at `:485`, and derived the exit code from that at `:554`; A3, A5
  and `ledger_shape` never read it. `verify-s2-008.mjs:199-210` repeated the
  omission. The unmutated defect was live: the harness printed
  `properties_held=5/5 … verdict=FAIL overall=PASS` and exited `0`. `overall` now
  counts **three** terms (`every_property_held`, `verdict_is_pass`,
  `ledger_shape_matches_table`) in both the harness and the replay, both print
  them, and the aggregator re-derives them from the record. The same line in the
  throwaway copy now reads `properties_held=5/5 … verdict=FAIL overall=FAIL`,
  exit `1`.
* **EV-5.** A green summary that contradicted itself: `status === 'PASS'` pushed
  a disclaimer into `defects` while `ok: true` and `exitCode: 0` were set, and
  the `green-with-nonzero-exit` rule at `:143` was dead because the replay never
  wrote an `exitCode` member. The replay now writes it into the bytes it writes
  (`'exitCode' in record === true`), the rule checks it in both directions, and a
  missing one is itself a freshness issue. The ticket-level preconditions (the
  track is untracked; the campaign behind #45 is `NOT_RUN`) are now **status
  terms**: each is a named `NOT_RUN` entry and the status is never `PASS` while
  they hold. No green summary contradicts its own defects any more.
* **EV-1 (a run record was not bound to the child that wrote it).** `readEvidence`
  only re-derived the document's own `artefact_digest`, so an edited-and-re-sealed
  record passed, and a child that died before writing left the previous run's
  record on disk to be scored. The record's `provenance.pid` is now compared with
  the pid of the child that was told to write it, a record that fails that is
  **dropped** rather than reported, and a child that did not run to a report
  (exit 2, a signal, or no status) is a `NOT_RUN`. Proof, with both children made
  to die before writing:
  `child a pid=186952 exit=2 … pid_bound=false record_pid=186854` ⇒
  `A3 NOT_RUN … records_produced=false`, `overall=NOT_RUN`, exit `3`.
  A run that honestly reports `FAIL` (exit 1) is still a produced record — the
  rule is "it ran and reported", not "it exited zero".
* **EV-3 (two records, one property, no guard).** The aggregator never spawned the
  harness, so `harness.json` A3 `{"ok":true,"findings":"0/0"}` and `replay.json`
  A3 `{"status":"FAILED","findings":3}` stood side by side with the
  `agreement_source` string as the only mitigation. The aggregator now spawns the
  harness itself (with `--no-write`, so a check run mutates nothing) and
  `crossRecordAgreement` decides: a harness A3 that declares itself
  table-derived is reported as **non-authoritative** and is not required to agree;
  one that claims to be a **measurement** must agree, or it is a defect. Proof,
  with the harness relabelled as a measurement:
  `harness/replay A3 disagreement: the harness claims to MEASURE A3 (0/0) while
  the replay measured 3/3`.
* **EV-4 (a gate that read the working tree and claimed Git bytes).** The five
  dependency bindings were read with `readFileSync(REPO_ROOT …)` while the record
  printed `mode: 'FULL_GIT_BYTES'`. They are now read with
  `git cat-file blob HEAD:<path>`, the working tree is **compared** against those
  bytes (`working-tree-differs-from-the-bound-bytes`), every row carries both
  digests, the documentary S1-004 row is read as text rather than parsed as JSON,
  and the record's `byte_sources` names where each class of byte comes from.
  `--no-write` now exists on this gate too: a check run can no longer overwrite
  the evidence it is checking.
* **S11 / EV-6 (the tree `tsc` never reads, and the files it cannot see).**
  `tsconfig.json` sets `allowJs: false` and includes only `**/*.ts` / `**/*.tsx`,
  so `npm run typecheck` reads **none** of `src/lib/research/*.mjs` and exits 0.
  In-scope coverage was added: `node --check` over all 31 modules of the track,
  reported as `syntax: {modules: 31, parsed: 31, note: "… it is not type
  checking, and tsconfig.json excludes .mjs from tsc entirely"}`. The untracked
  state is now reported **by name** — 51 paths — because `check-inventory.mjs` and
  `generate-manifests.mjs` derive their file set from `git ls-files` alone and
  cannot see a file nobody added. Both are outside this worker's ownership; see
  §19.5.

### 19.4 New evidence digests, after a real run

Every file below was regenerated by running the pipeline, not edited:

```text
sha256 (bytes on disk)
72d3d4e0…  evidence/s2-008-probes.json
baed8861…  evidence/s2-008-controls.json
3018e53f…  evidence/s2-008-comparison.json
8f13d305…  evidence/s2-008-harness.json
3a972f37…  evidence/s2-008-replay.json
ec0bf432…  evidence/s2-008-run-a.json
576e6270…  evidence/s2-008-run-b.json
d5e1a667…  evidence/s2-008-security-probes.json   (unchanged: the probes did not change)
bcd01960…  evidence/s2-008-summary.json
9a89a79d…  evidence/s2-008-dependency-binding.json
0f8293d2…  evidence/s2-008/corpus/manifest.json    (unchanged: the corpus is frozen)
```

`canonicalDigest` of the documents: probes `e21d1eaa…`, controls `5c2a7812…`,
comparison `1dfda27f…`, harness `390fa0b9…`, replay `ab2c46f7…`, run-a
`449e5412…`, run-b `892c36fe…`, security-probes `aaf1f63c…`, summary
`cdc811b9…`, dependency-binding `4f524137…`.

The replay, run-a, run-b, the summary and the dependency-binding record carry a
wall-clock `freshness` block (it exists so the aggregator can refuse a stale green
file, it decides nothing, and it is excluded from the repeatability comparison by
name), so **their digests move on every run**. The probes, controls, comparison
and harness digests are byte-stable across runs on the same base, which is the
determinism the track claims.

### 19.5 What the repair pass did NOT do, and why

* **`git add` / `commit` for this track.** `A5` fails on
  `track_tracked = false` and cannot be fixed from here: delivery owns git, and
  the pass ran no repository git command. The honest state is reported in three
  places instead — the dependency gate's `track_files_untracked` list, the
  aggregator's `NOT_RUN` entry, and the harness's A5 evidence string.
* **`tsconfig.json`.** Not in this worker's ownership. `BLOCKED: tsc cannot be
  pointed at `.mjs` from here.`
* **`scripts/check-inventory.mjs`, `scripts/generate-manifests.mjs`.** Not in this
  worker's ownership. `BLOCKED: both derive their file set from git ls-files
  alone, so neither can see an untracked file; the dependency gate's
  track_files_untracked list is the in-scope substitute.`
* **A preregistration change.** The frozen rule cannot reject at `alpha = 0.05`,
  `confidence = 0.95`, `m = 3`; making it capable of rejecting means raising the
  published confidence, which is a new preregistration and a new document type.
  Not done, and named as `frozen_rule_cannot_reject` instead.
* **A verdict that is not FAIL.** Nothing in the repair turned a red gate green.
  The harness is `4/5` (A5 untracked), the replay is `0/2`, the aggregator is
  `FAIL`, and the campaign verdict is `FAIL`. The repair changed what the red
  numbers mean, not the numbers.

---

## 20. Delivery pass (2026-09-27) — the commit lands, and what it changed

The delivery worker owns git; this section is their record, appended rather than
merged into the sections above, which stay the snapshot they measured at base
`bd0e2f5`. Two facts moved when the track was committed, and one defect was
fixed on the way. The verdicts that did not move are restated so a reader does
not have to diff two snapshots.

### 20.1 What delivery did

1. **Staged and committed the whole track** (59 files, 37 243 insertions) at
   `a18a2e5f90a23a0316039dc8fd3dce6ce5f068fa`, tree
   `64f7c99ba376cb400225cce1868b3cffd430c587`, and pushed the branch
   `bb/spacedazher-veritas-8-s2-008-r-d-thr_4etd4uwcke`.
2. **Fixed a host-dependence defect in the evidence.** The three gate scripts
   serialised the purge record's `dir` / `base` as an absolute path, so five
   committed records carried this machine's account name, worktree layout and
   thread id, and their bytes could not be reproduced on another checkout. The
   scripts now serialise a repository-relative path (a fixed
   `<external-scratch-root>` token for a root outside the tree), and the ten
   records were regenerated after the fix. The library return value is still
   absolute; only the committed copy is shortened.
3. **Re-ran the whole chain at the delivery commit** and re-pinned the ten
   digests (§20.3).
4. **Re-indexed the file inventory and refroze the root manifest** at the
   delivery commit, which the track's 54 new paths had made stale.

### 20.2 The two facts that moved

| | At the `bd0e2f5` snapshot | At the delivery commit |
| --- | --- | --- |
| **A5** | **FAILED** — `track_tracked=false`, `git ls-files` saw `0` files of the track | **HELD** — `track_tracked=true tracked_files=39`, `base_binding=SATISFIED`, `chain_verified=true`, `crash_classified=PASS`, `reconciliation_rows=1` |
| **dependency gate** | `BLOCKED_DEPENDENCY` (`index.mjs-absent-at-commit`) | **PASS (exit 0)**, all five upstream bindings `BOUND`, `track_files_tracked: 51` |
| `blockingGates` | `dependency`, `replay`, `harness` | `replay`, `harness` |
| `verify:s2-008` | exit `1` | exit `1` (unchanged) |

**Nothing else moved.** `A1`, `A2` and `A4` hold; **`A3` still FAILS** with
`findingsA=3 findingsB=3` — the frozen design cannot derive its preregistered
per-trial outcomes at 8 cases × 5 seeds, which is a real answer and not a defect
of the harness. `trackStatus` is still `FAIL`, `engineeringStatus` is still
`BLOCKED_DEPENDENCY`, `assuranceStatus` is still `NOT_MEASURED`,
`realAdapterStatus` is still `NOT_RUN_REAL_ADAPTER`, and `A-MVP-01..07` are still
`NOT_RUN`: **the ticket is not accepted by this track.** Its own acceptance is
the real-executor campaign in #45, and this pass did not touch it.

Two of the harness's five properties are reported `HELD` and its own `verdict`
is still `FAIL`, because the verdict is delegated to `resolveCampaignVerdict`
over the table comparison — the A3 findings. That disagreement is the harness
being honest, not a defect: the harness cannot pass while the authoritative A3
fails.

### 20.3 The ten records at the delivery commit

| File | sha256 |
| --- | --- |
| `evidence/s2-008-comparison.json` | `70e41b54095ee166e5b13f393edc580b1cacf59a7652912a54b197382ba7a43d` |
| `evidence/s2-008-controls.json` | `7e5820a9252ad409a03c81c1e1976361e5294b1558b93cba2a382d10ff846163` |
| `evidence/s2-008-dependency-binding.json` | `20d263bd46c7cd43cb9d7de7c53c23712c75e47f22c439d5221803887f61b55c` |
| `evidence/s2-008-harness.json` | `49e8a354abffb2103137f1d0556b5563290c105ebe2b24c88c03edc81ff1d5c4` |
| `evidence/s2-008-probes.json` | `4ca4f9712c5c19ba852fd8243a476c6522b009fbbdd5253cdab05563b9ea855e` |
| `evidence/s2-008-replay.json` | `36f321d0d37f9266ed43b94a8a63c883e34d9fe59a5c543ac492ef77dacb2a7b` |
| `evidence/s2-008-run-a.json` | `44a351cc0838125b64e1439d93bf6d1d679332e7a6b68fc466ede3cf78ea0620` |
| `evidence/s2-008-run-b.json` | `65828269e7018ef4f7adf172b476efff21d23d764ef63565df352fa18a5ad880` |
| `evidence/s2-008-security-probes.json` | `02e5c76cdde2644ca007d3fcdc4058bdab2f87d0e3e0ba611cdf6eee39ecb232` |
| `evidence/s2-008-summary.json` | `2aee7e00364e36e2f61645898712b4f77ec3da7fe67e7b3491fa83379482523c` |

`run-a`, `run-b`, `replay` and `summary` carry run ids, nonces and a wall-clock
member, so their digests move on every run; the other six are byte-stable on the
same base. The digests above are the bytes committed here; the manifest and
inventory reindex that follows them changes no S2-008 record.

### 20.4 What the commit does NOT fix, and the one command that re-reads it

* **A3 is still red.** The fix is a decision about the frozen design (more
  cases, more seeds, or a published band the design can actually resolve), and
  that is a new preregistration, not a patch.
* **The evidence is bound to the commit it was produced at.** After the
  reindex and the manifest seal, `HEAD` moves on by two commits, so
  `base.commit_sha` in the committed records names `a18a2e5`, not the tip. This
  is the repo's existing seal semantics — the S2-007 artefacts are bound to
  their merge commit for the same reason — and it is why a re-run is one command:
  `npm run verify:s2-008` on the pushed branch re-derives the same verdicts with
  the base advanced, and the aggregator's freshness gate treats the record it
  did not write as a failure, not as authority.
* **`tsconfig.json` still excludes `.mjs`**, so `npm run typecheck` remains
  vacuous for this tree. Not in this pass's ownership.
* **No real executor, no real spend, no human review.** Unchanged by a commit.
