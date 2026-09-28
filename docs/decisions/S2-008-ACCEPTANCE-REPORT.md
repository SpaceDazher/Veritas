# S2-008 — the real campaign: acceptance report

**Verdict: the campaign ran, and the answer is a null with two real negatives
inside it.** This report is the owner's handover: what was asked, what was frozen
before any measurement, what every seed and every outcome was, what decided it,
what is still unknown, and — verbatim — what was not measured.

| | |
| --- | --- |
| ticket | [SpaceDazher/Veritas#8](https://github.com/SpaceDazher/Veritas/issues/8) |
| question | Do commit-message features agree with a message-independent MAJOR label on the newest 25% of the real Veritas history? |
| real project | **Veritas**, this checkout, commit `13243186b1573398fc327e245ebd2e5a90a2ced0`, 502 real commits |
| campaign decision | **`UNRESOLVED`** — the pooled interval straddles the frozen baseline |
| per-arm | `NEGATIVE`, `UNRESOLVED`, `NEGATIVE` |
| decision digest | `5e925f4d407318d9a24e45d2d472134cd3cce199601b4c3550cc627acaeca0bc` (run A **and** run B) |
| real adapter | `REAL_ADAPTER_AVAILABLE` — a digest-pinned installed executor in the S2-002 A-MVP-04 isolation profile |
| monetary spend | **zero** |
| independent evaluation | `AGREES`, 0 findings |
| negative probes | **7 / 7 HELD** |
| the track's own gate | `npm run verify:s2-008` → `PASS`, exit 0, `blockingGates []`, `defects []` |

---

## 1. The question, and the real project behind it

**Real project.** The Veritas repository's own git history, read from this
checkout with `git log` and `git show`. 502 real commits between 2026-09-09 and
2026-09-28. Every label comes from a real diff and every subject from a real
message. Nothing in the corpus is authored.

**The label is a function of the tree alone.** A commit is `MAJOR` iff its diff
touches at least one path under `src/lib/`, `contracts/` or `migrations/`. The
rule never reads the message. This is proved, not asserted:

```
node scripts/s2-008-campaign-prepare.mjs --selftest
  labels_digest                                f5e14fab623121fb13c931990843cd0f11c88fad2ea1b6ba9248651a27754701
  label_vector_digest_under_constant_subject   f5e14fab623121fb13c931990843cd0f11c88fad2ea1b6ba9248651a27754701
  stable true   verdict HELD
```

Re-labelling all 376 dev commits after replacing every subject with a constant
returns the identical label-vector digest. The independent evaluation re-derived
all 502 labels from the git trees and found **0 mismatches**.

**The question.** For a real commit, does a message-side feature agree, more
often than the majority-class baseline, with the message-independent MAJOR
label?

**Type: `CORRELATION_EVIDENCE`, and no promotion is attempted.** A message and a
diff are written at the same instant, so `temporal_ordering.established` is
`false` **by construction** — that is a fact about a retrospective association,
not a hedge. The card names two confounders (a low MAJOR base rate; partitions
that are temporal successors, not exchangeable), two alternative explanations,
and three falsifiers. The card was validated by `contracts/hypothesis-card.schema.json`
alone; no fourth schema was added and none of the three frozen contracts was edited.

**The split is temporal**, and the corpus is a function of a **pinned commit**,
never of `HEAD`. The first attempt read `HEAD` and the digests moved the moment
the freeze was committed — a moving target, not a corpus.

| partition | commits | period | MAJOR |
| --- | --- | --- | --- |
| dev (PRIMARY) | 376 | 2026-09-09 → 2026-09-26 | 45 (11.97%) |
| holdout (HOLDOUT) | 126 | 2026-09-26 → 2026-09-28 | 12 (9.52%) |

The base rate moved 2.4 points between the partitions, which matters in §5.

---

## 2. What was frozen BEFORE the adapter existed

The freeze is commit `2e68423`, and at that commit **every `agreement_by_trial`
map in the corpus is empty**. That emptiness is the proof that no outcome existed
before the freeze. The corpus is reproducible with
`node scripts/s2-008-campaign-prepare.mjs --check` → `mismatches []`.

| frozen item | value |
| --- | --- |
| metric | `case_agreement_rate`, `HIGHER_IS_BETTER` |
| baseline | `0.8803191489361702` = 331/376, the dev majority class, with its digest over the dev case ids, labels and the label rule |
| noise band | `0.06969570950743816` |
| band derivation | the half-width of the preregistered interval at the preregistered confidence for `n = 126`, evaluated at the **dev** baseline — a *precision floor*, not an effect threshold |
| seeds | 3, fixed list `[20260926, 20260927, 20260928]`, digest `42704357…` |
| seed selection | `best_seed_selection: FORBIDDEN`; the point estimate is the observed rate (which no seed can move) and the interval is the **HULL** of all three, so no seed is ever chosen for being narrow |
| stopping rule | `FIXED_TRIALS`, 3 trials, `early_stop: false` |
| sequential rule | `NO_INTERIM_ANALYSIS_NO_PEEK_FIXED_TRIPLES_ALPHA_CORRECTED_ONCE_OVER_THE_FROZEN_FAMILY` |
| multiplicity | `holm_bonferroni`, `alpha = 0.05`, family 3, `confidence = 1 - alpha/m = 0.98333…` **derived, never typed** |
| per-trial timeout | `120000 ms` (`budget_reservation.trial_timeout_ms`) |
| budget | 12 units of `isolated_executor_launches`, expiry `2026-09-28T23:59:59.000Z` |
| holdout access | `max_opens: 1`, one-shot unseal `21c83ae0…`, released to `EVALUATOR` only |

`ruleFeasibility` on those constants: `never_rejects: false`,
`can_only_answer: "ANY_OUTCOME"`. **The rule is able to decide.** A rule that
could not would make the campaign undecidable by construction, and that is
checked from the published constants before the run, not inferred from an
`UNRESOLVED` afterwards.

**Ordering is proved by the registry journal, not by a clock.** In every run:
`PREREGISTRATION` at row 0, first `TRIAL_EXECUTION` at row 4, the single `ACCESS`
row at row 21, `access_rows: 1`, `ordering_holds: true`.

### 2.1 One supersession, and what it did not touch

The first campaign run is preserved as **ABORTED**, not deleted:
`evidence/s2-008-campaign/run-aborted-1.json`. It produced **no effect size**, so
nothing could be outcome-driven. Two defects, both in the apparatus:

1. **The resampler collapsed bootstrap multiplicity.** Each resample was encoded
   as a membership bitmask, so a case drawn three times counted once. The proof
   is arithmetic: an observed rate of `115/126 = 0.9127` came back with a
   resample mean of `0.5779` — a ratio of `0.633 = 1 − e⁻¹`, which is exactly the
   expected fraction of *distinct* cases drawn in 126 draws with replacement.
   Every interval that run produced described a distribution the adapter never
   drew.
2. **The budget was opaque in practice.** 6 units were reserved and 9 launches
   were made while charging none of them.

A third defect surfaced while superseding: **the first freeze sealed no
`expected_table_digest`**, so the track's own `createSupersession` **refuses** to
carry the supersession (`SUPERSESSION_TABLE_DIGEST_ABSENT`). The refusal is
recorded in `preregistration-supersession.json` rather than worked around by
editing the old document, which is preserved whole and recovered from commit
`2e68423`. The supersession is carried instead by the chained source-ledger entry
(`spr-s2-008c-01`, `37050753…`) and by that record. The in-force document now
seals its own table digest, so the *next* supersession is carryable.

**Everything scientific is byte-identical across the supersession**, and the report
states the check rather than the claim: `card_digest`, `metric`, baseline
`value` and `baseline_digest`, `band`, `seed_rule.seeds` and `seeds_digest`,
`family_size`, `alpha`, `confidence`, `direction`, `null_value`, `trial_list`,
`holdout_access`, `stopping_rule` and `sequential_rule` all compare **SAME**.
What moved: the budget ceiling `6 → 12`, the now-present `expected_table_digest`,
and the two-process bootstrap. **The band was not moved to make an arm clear it.**

---

## 3. The real adapter

| | |
| --- | --- |
| kind | a genuinely installed executor inside the S2-002 A-MVP-04 digest-pinned isolation profile |
| base image | `docker.io/library/node@sha256:25330af3…` (registry digest, unchanged) |
| adapter image | `sha256:30d48be42e8db50524ed711f8167609556add9ebb744e0416fe7cb5bf5d2f7a7` |
| bootstrap image | `sha256:2c063dfa6af6afb4cf0c4491967b3ad152fe66413a95c80210fb2a547dce0f56` |
| pin is a pin | identical content built twice with `--timestamp 0` → identical `Id` **and** `Digest` (`identical: true`, `context_digest ba3f1ae1…`) |
| axes enforced | network `deny_all` (`--network=none`), filesystem read-only root + `/tmp` tmpfs, environment allowlist of 4 names with nothing inherited, process ceilings 32 pids / 256 MB / 0.5 CPU |
| start proof | exit 0 **and** a banner carrying the container's own pid (`1`) and runtime version, a payload that parses, and the pin re-checked by `assertImageMatchesPin`; host pid 550556 ≠ container pid 1 |
| launches | 10 per run: 9 blind predictions (3 arms × 3 frozen seeds) + 1 post-reveal bootstrap |

**The blindness is structural, not a promise.** The predictor is handed
`cases/holdout.blind.json` (case ids and subject lines, no labels), it refuses an
input carrying a `label` member (`BLIND_INPUT_CARRIES_LABEL`), and the image it
runs in contains that blind file and nothing else. Labels arrive only at the
decision point, in a different process.

**Two processes, and why.** A bootstrap needs the agreement vector, which is a
function of the label. So the predictor answers first, blind; the evaluator opens
the holdout once; the seeded bootstrap runs afterwards in its own launch on the
agreement vectors. It never predicted anything, so handing it the agreement costs
the experiment nothing.

---

## 4. Every seed, every outcome

All three seeds, for all three arms, all reported, none selected. Every
resample mean sits on its own measured rate, and a trial whose interval does not
is refused rather than published (`INTERVAL_DISJOINT_FROM_ITS_OWN_DATA`).

| trial | arm | agreeing | measured | seed | resample mean | interval | **outcome** | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `trl-s2-008c-01` | `arm-scope-present` | 35/126 | 0.2778 | 20260926 | 0.2782 | 0.1825–0.3810 | **NEGATIVE** | ALLOW |
| | | | | 20260927 | 0.2774 | 0.1905–0.3810 | | |
| | | | | 20260928 | 0.2784 | 0.1905–0.3730 | | |
| | | *hull* | | | | **0.1825–0.3810** | | |
| `trl-s2-008c-02` | `arm-type-feat-fix` | 115/126 | 0.9127 | 20260926 | 0.9126 | 0.8492–0.9683 | **UNRESOLVED** | ALLOW |
| | | | | 20260927 | 0.9138 | 0.8492–0.9683 | | |
| | | | | 20260928 | 0.9129 | 0.8492–0.9683 | | |
| | | *hull* | | | | **0.8492–0.9683** | | |
| `trl-s2-008c-03` | `arm-type-chore` | 51/126 | 0.4048 | 20260926 | 0.4043 | 0.3016–0.5079 | **NEGATIVE** | ALLOW |
| | | | | 20260927 | 0.4041 | 0.3095–0.5079 | | |
| | | | | 20260928 | 0.4039 | 0.3016–0.5079 | | |
| | | *hull* | | | | **0.3016–0.5079** | | |

`bestSeedDisclosure` → `count: 3, disclosed: true, selection: null`.

**The four outcome classes, and where each one is evidenced.**

| class | in the measured family? | evidence |
| --- | --- | --- |
| **POSITIVE** | **no** | No arm cleared the baseline. Manufacturing one would have been fabrication; the record says the campaign produced none. |
| **NEGATIVE** | **yes, 2 of 3** | `trl-s2-008c-01`, `trl-s2-008c-03` — significantly *below* the frozen baseline, after correction. |
| **NULL** | **no** | No interval landed inside the band. The `NULL` path is exercised in the probe suite and is reachable by the frozen rule. |
| **INFRA** | **no** | No infrastructure failure occurred. It is exercised for real by probe P1 (a digest-pinned image absent from the host) and by the aborted run's own predictor defect, both of which produced `INFRA_ERROR`/`INFRA` and **never** a zero. |
| UNRESOLVED | yes, 1 of 3 | `trl-s2-008c-02`: its interval straddles the baseline outside the band. |

**All seven probes HELD** (`evidence/s2-008-campaign/probes.json`):

| probe | plants | result |
| --- | --- | --- |
| P1 | a real launch of a pinned image not on this host | `INFRA_ERROR`/`INFRA`, no reconciliation, no zero |
| P2 | a measured trial with the evaluator deleted | `VIOLATION`, reason names the missing evaluator |
| P3 | an observation with no measurement | `UNRESOLVED` + `MEASUREMENT_ABSENT` reconciliation |
| P4 | `elapsed_ms 120001` vs the preregistered `120000` | `UNRESOLVED` + `TIMEOUT` reconciliation |
| P5 | a **real SIGKILL** mid-campaign, then a **real restart** with no purge | restart sees phase-1 rows; trial not re-run, not retried, not zeroed; `RECONCILIATION` row opened; chain verified |
| P6 | a settle against an already-expired reservation | typed refusal, **spend did not advance**, second presentation idempotent |
| P7 | `TRIAL_STARTED` with no `TRIAL_RESOLVED` | gap countable; `metricsSummary` **refuses** a fully-missing run (`TRIALS_ABSENT`) instead of reporting 0, and a partly-missing run reports `notMeasured 1` with the denominator still 126 |

Two probes first reported **BROKEN against a correct engine** — P4 asserted
`TIMEOUT_EXCEEDED` where the engine emits `TIMEOUT`, and P7 looked for a typed
code where the board reports the class in the message. **The assertions were the
defect; the behaviour was not touched.**

---

## 5. The decision, and what decided it

Nothing but the frozen rule. Wall clock was measured (`latencyRecorded`, every
block `decides: false`) and is **excluded from the decision**; the verifier's own
`assertNoWallClockInVerdict` enforces that no timestamp reaches the hashed
projection.

**Per arm** — baseline `0.8803191489361702`, band `0.06969570950743816`, so the
band is `[0.810623, 0.950015]`:

- `trl-s2-008c-01`, interval `[0.1825, 0.3810]`: excludes the baseline, clears the
  band → Holm → `pUpper 0.016667 ≤ floor 0.016667` → rejected → the effect points
  the **other** way → **`NEGATIVE`** (`significant_effect_in_the_other_direction`).
- `trl-s2-008c-02`, interval `[0.8492, 0.9683]`: straddles the baseline and is not
  inside the band → **`UNRESOLVED`** (`interval_straddles_null_outside_noise_band`).
  Its point estimate `0.9127` is *above* the baseline; the interval simply does not
  exclude it. The preregistered rule says UNRESOLVED, so that is what it says.
- `trl-s2-008c-03`, interval `[0.3016, 0.5079]`: → **`NEGATIVE`**, same path.

**Pooled**: `201/378 = 0.531746`, interval `[0.182540, 0.968254]` (the union of the
family intervals — conservative for a linear combination of the family means, and
its width is the between-arm heterogeneity, which is the honest number) →
straddles the baseline → **`UNRESOLVED`**.

**So: the campaign decided nothing about the hypothesis.** That is a null result
and it is reported as one. The `FAIL` verdict the comparator prints beside it is
a recorded outcome, not a gate term, and the gate is green on *agreeing with the
frozen declaration*, exactly as this track intends.

**The two negatives are the informative part.** Both arms that predict `MAJOR`
more often than the base rate *lost* to the majority-class baseline, and they lost
decisively. The obvious alternative explanation — "the arms only lost because the
base rate is low and they over-predict the rare class" — is **ruled out by
measurement, not by argument**: the holdout is *more* balanced than dev (9.52% vs
11.97% MAJOR, a 2.4-point move), and the arms still lost. And on the dev
partition, where the baseline was measured, all three arms were already below it
(`0.1303`, `0.8670`, `0.3457`).

### 5.1 Two things about the frozen rule that the independent evaluation found

1. **Every rejection in this campaign is a boundary rejection.** The confidence is
   derived as `1 − α/m`, so the worst-case p bound *equals* the Holm threshold:
   margin `5.2e-17`. The rejections hold only because the comparator decides a
   bound landing exactly on the threshold in the comparison's favour, via a
   documented `1e-12` relative epsilon. **A one-ULP change in the published
   confidence flips all three outcomes.** That is a property of the frozen rule,
   not of the data, and it is the rule this campaign was preregistered under.
2. **The decision rests on a slightly optimistic interval.** The percentile
   bootstrap interval is *narrower* than the continuity-corrected Wilson interval
   at the same confidence for all three arms — the known under-coverage of the
   percentile bootstrap at `n = 126`. Recorded as a limitation of this run, not
   asserted away.

---

## 6. Independent evaluation

`evidence/s2-008-campaign/evaluation.json` — **verdict `AGREES`, 0 findings.** It
does not check the campaign's decision; it re-derives it from the primary
evidence and compares:

- the **labels** re-derived from the git trees: 0 mismatches in 502 cases, and
  the re-derived label-vector digest equals the corpus's (`8e279e8f…`);
- the **agreement counts** recomputed from the corpus labels and the arm rules
  **restated in the evaluation file**: `35/126`, `115/126`, `51/126` — all three
  agree with the run;
- the **interval** cross-checked against a continuity-corrected Wilson score
  **written out in that file rather than imported**, because reusing the
  machinery's own statistics is the same opinion twice;
- the **decision** recomputed from the preregistration's own constants with the
  frozen rule written out;
- the **one-shot holdout re-proved** on a throwaway registry: one `ACCESS` row
  permitted, a second open refused with `HOLDOUT_UNSEAL_DIGEST_REPLAYED`, a forged
  digest refused with `HOLDOUT_UNSEAL_DIGEST_FORGED`.

One correction belongs here: the evaluation's first version dropped the label when
mapping a case, so its independent count was `0` for every arm and it disagreed
with the run *for the wrong reason*. That was a bug in the evaluation, and it is
named rather than quietly fixed.

---

## 7. Reproducibility, bound to commit, tree and raw run id

| | run A | run B |
| --- | --- | --- |
| commit SHA | `0ac485bd099ee5566bc90bfea8c4052e6a70139f` | *same* |
| tree SHA | `8cbb2f9e4872edfda8ffa51434eed1ec219991b8` | *same* |
| raw run id | `s2-008-campaign-a-550556` | `s2-008-campaign-b-549854` |
| decision digest | `5e925f4d407318d9…` | `5e925f4d407318d9…` |
| verdict projection digest | equal | equal |
| campaign decision | `UNRESOLVED` | `UNRESOLVED` |

**Same base, same verdict digest, different raw run ids, different processes.**
Both runs are bound to a commit SHA, a tree SHA and a raw run id, and each
carries the adapter's image digest, the container argv, the container's own pid
and the registry's chained head digest.

---

## 8. What is still unknown

1. **Whether any arm is better than the baseline in general.** One repository, one
   checkout, one 19-day window, 126 holdout cases. `trl-s2-008c-02`'s point
   estimate is *above* the baseline and the interval does not exclude it; that arm
   is the one worth more data, and more data is a preregistered decision, not a
   post-hoc one.
2. **Whether the two negatives generalise.** They are decisive *on this corpus*.
3. **The base rate is the mechanism, and it was not decomposed.** The arms lost by
   different amounts; whether that is entirely explained by their `MAJOR`-prediction
   frequency is not measured here, only bounded.
4. **`arm-type-chore` is not a complement of the others.** Its rule differs from
   `arm-type-feat-fix` in the predicted direction as well as the pattern, so the
   family is three hypotheses of different shapes rather than three tests of one.
5. **The rule's boundary margin (§5.1) is a latent fragility**, not a measured
   property of any arm.
6. **One process, one host, one podman.** The reproducibility witness is two runs
   on one host. Cross-host reproduction is not demonstrated.

---

## 9. What is NOT measured — verbatim

> **The executor in this campaign is a deterministic installed program, not a
> model-calling agent. No model and no paid service is involved anywhere in this
> campaign.**
>
> — `evidence/s2-008-campaign/run-a.json`, `adapter.NOT_A_MODEL_CALL`

That is the leg the ticket's own words tie to spend, and **no explicit
authorisation was given**, so it was not attempted. Concretely, the following are
**not measured and not claimed**:

- **the task quality of a live, model-calling executor.** Nothing here says
  anything about whether a real agent does this task well. The predictor is three
  regexes over a subject line;
- **any model quality, latency or cost.** No tokens, no API, no bill;
- **`realAdapterStatus` as the ticket means it.** A-MVP-04's own record says
  "**No model call is made.** … paying for a call would not evidence a
  `--network=none` flag", and this campaign did not change that;
- **whether the governance surface behaves the same under a slow, flaky, paid
  executor.** The per-trial timeout and the P4 probe prove the *rule*; they do not
  prove a real executor hits it.

The command that would begin that leg, for whoever holds the authorisation, is
`scripts/s2-002-isolation-run.mjs`'s real-executor path with a provider granted;
it needs a credential, a budget and an owner's explicit go-ahead, and it is not
run, scheduled or approximated here.

---

## 10. What was owned and what was not

**Touched** (all mine): `corpus/s2-008-campaign/**`,
`scripts/s2-008-campaign-*.mjs`, `evidence/s2-008-campaign/**`, this report.
Plus two mechanical steps on the acceptance base: a merge of `main` into the #8
tip (the research track and the A-MVP-04 executor were developed on divergent
sides of `e90dd12`, and a real-adapter campaign needs both) and the resulting
reseal of the four derived records.

**Not touched**: `src/lib/research/**`, `scripts/s2-008-run.mjs`,
`s2-008-replay.mjs`, `s2-008-security-probes.mjs`, `verify-s2-008.mjs`,
`verify-s2-008-dependencies.mjs`, `src/lib/agentboard/**`, `contracts/**` (the
three frozen digests are byte-identical to the #8 tip), and every other branch.
The campaign imports the machinery; it never reimplemented it.

**Regression check on the base**: `test:research` 260/260 · `lint` exit 0 ·
`typecheck` exit 0 · `validate-contracts` exit 0 · `check-corpus` exit 0 ·
`security-probes` exit 0 · `harness --no-write` 5/5, `overall=PASS` ·
`verify:s2-008` **PASS, exit 0, `blockingGates []`, `defects []`**.

---

## 11. The one line for the owner

The campaign is real, zero-spend, reproducible and honestly null: two of three
message features are **significantly worse** than a frozen majority-class
baseline on a real 126-commit temporal holdout, and the third is undecided. The
paid, model-calling leg is **not measured**, and the exact words are in §9.
