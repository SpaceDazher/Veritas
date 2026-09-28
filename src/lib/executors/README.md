# `src/lib/executors/` — the S2-007R real-executor tree

Issue `SpaceDazher/Veritas#45` (S2-007R). This tree drives a **genuinely
installed** `codex` or `pi` process across the `veritas.adapter/1.0.0` boundary.

## Why this tree exists at all, and why it is here

`src/lib/agentboard/` is a FROZEN target of S2-007. Round 1 of this ticket wrote
the real transport inside it, which would have forced a reviewed re-freeze of the
whole S2-007 unit (610 files, every digest bound to it) for an additive change
that never belonged in the boundary module. Decision **D1** of
`.bb/chats/thr_mgkk7cb5t6/notes/SPEC.md` places the real executors in a new tree
precisely so the frozen unit is not re-opened. This directory is that tree, and
it is **outside every frozen target**: no file here is hashed into
`evidence/frozen-manifest.json`, and a change here needs no re-freeze.

The boundary module `src/lib/agentboard/adapters.mjs` is NOT edited. Its header
states in prose that `createTestTransport` and `createReplayTransport` are its
only constructors and that `adapter_kind` + `real_adapter_provenance.status` are
its own literals; this tree speaks the same ten-method interface and builds its
own `AdapterRegistration`, so that claim stays exactly as written and a third
constructor never appears inside the frozen file.

## The invariants this tree exists to hold

1. **The honesty status is derived, never passed.** `REAL_ADAPTER_AVAILABLE` is
   reachable only from a run record this process minted from a process it
   actually spawned and observed (`evidence-writer.mjs`), and that record is
   re-derived from the filesystem and bound field-by-field to the raw process
   log. A registration, a probe, a fixture, a stub and a replay are all refused.
   **What this invariant is worth in practice is bounded by D-3 below, and the
   bound is now published rather than described as narrow.**
2. **The argv is an allowlisted array; the prompt is data.** No shell, ever.
   `assertArgvAllowed` re-validates the final array immediately before `spawn()`.
3. **The effective tool set is the intersection**, taken from the cross-check's
   own `effective_tools` (`claim ∩ grant`) and reduced to executor-native names.
   A skill bundle is a recorded part of the configuration and can only *ask* for
   authority; an ask outside the intersection is refused and recorded.

Plus, from the owner's later decision (issue #45, D3 revised):

4. **Isolation is recorded, never claimed.** A model-calling executor cannot run
   inside a proven profile on this host (measured:
   `evidence/s2-007r-host-unisolated.json`). A real run is therefore bound to the
   **HOST_UNISOLATED floor** (`sbx-host-unisolated-v1`), which is NOT in
   `PROVEN_SANDBOX_PROFILE_IDS` and never will be, and is admitted only by a
   complete named human permit that `policy.assertLiveExecutionAuthorized`
   adjudicates. This tree refuses to drive a run bound to a profile whose
   controls it cannot enforce, rather than naming them.

And from round 3, after round 2 measured the three lifecycle defects this ticket
exists to catch:

5. **Configuration surface invariant — the surface is a required, validated
   argument, and the axis is decided by the argv, before any process exists.**
   `createRealExecutorTransport({ configuration })` refuses an absent or unknown
   surface (`CONFIGURATION_UNKNOWN`) rather than defaulting it, so no run is
   silently a B cell. `resolveConfigurationSurface` validates against the closed
   `CONFIG_SURFACES` table and refuses a flag the allowlist does not already
   carry (`CONFIGURATION_FLAG_NOT_ALLOWLISTED`); there is no free-form
   passthrough and no shell string on that path. The two ends differ in the
   surface and nothing else — same model pin, same derived tool allowlist, same
   timeout, same prompt, same project, same grant — and a provider whose ends
   select the same command is `EXCLUDED_FROM_COMPARISON` with the measurement
   that decided it, never reported as "no difference observed".
6. **Lifecycle-proof invariant — a kill is a kill, it is proved, and nothing is
   left pending.** A deadline this transport enforced IS a kill, so it carries
   the same three-way proof (`TERMINATED | SURVIVORS_REMAINING | UNVERIFIED`) an
   explicit cancel does, on the terminal event, and a kill that cannot be proved
   `TERMINATED` is reported `UNKNOWN` / `RECONCILIATION_REQUIRED` rather than as
   a definite `TIMEOUT`. The child's exit is WAITED FOR before the survivor
   accounting, and when the two readings disagree BOTH are published
   (`pre_accounting_reading`, `accounting_reading`, `readings_disagree`): the
   observer's first answer is never overwritten. Every timer this module arms is
   destroyed in a `finally` on every path, so a finished run cannot hold the
   event loop open.

## What the round-3 records say about invariants 5 and 6

Both invariants hold **as designed** in the code and neither has yet been
exercised by a governed run. Stating that separately is the point.

| invariant | what the code does | what the round-3 records show |
| --- | --- | --- |
| 5 — configuration surface | the surface is required and validated; the axis decision is structural and per provider | the **decision** is measured: `configurationAxisFor(codex).distinguishable = false` with the 27-flag `codex exec --help` measurement quoted in place, and `distinguishable = true` for pi. The **comparison** is not: all eight round-3 crossings carry `invocation.configuration: "A"`, `configuration_surface_flags: []`, and identical normalised argv digests per provider (codex `6b0130c7…` ×4, pi `4b874a27…` ×4) — including the two cells the comparison labels configuration `B`. No B invocation was ever executed, so the invariant is armed and unexercised. |
| 6 — lifecycle proof | every kill carries the proof, the child is reaped before accounting, both readings are published, every timer is cleared | the proof is now **published where round 2 published none**: the timeout arm reached a terminal `RECONCILIATION_REQUIRED` *with* a `SURVIVORS_REMAINING` proof, where round 2 had `cancelProof === null`. The proof itself is still `SURVIVORS_REMAINING` on the cancel and timeout arms, and the independent later reading contradicts the observer on the cancel arm (the survivor pid is no longer resolvable 2 s later). So the invariant holds *procedurally* — the proof exists, both readings are published — while the measurement it was added to fix is still `NOT_RUN`. |

The per-round disclosure of the second row lives three records away from the
crossing (in the comparison's `config_delta_reason`, not in the crossing), which
is why it is repeated here: **a cell labelled configuration `B` in the round-3
run set contains only configuration-A argv.**

## The configuration axis (round 3)

Round 2 measured `argv_identical: true` for both providers across configurations
A and B, because the transport took no surface argument and pi's argv always
carried the `--no-*` flags: a comparison would have differenced a cell with
itself, which is worse than no comparison. The axis now exists:

* `CONFIG_SURFACES` in `constants.mjs` is the closed table of the two ends.
  **A** (`HOST_DEFAULT_CONTEXT_SURFACE`) passes no suppression flag at all, so
  whatever the host has installed is what the executor sees; **B**
  (`LIMITED_BUILD`) suppresses skills, extensions, prompt templates, context
  files and themes. Same model pin, same derived tool allowlist, same timeout,
  same prompt, same project, same grant.
* `resolveConfigurationSurface` (in `internals.mjs`) validates the surface and
  refuses a flag the allowlist does not already carry
  (`CONFIGURATION_FLAG_NOT_ALLOWLISTED`). There is no free-form passthrough and
  no shell string on this path; `assertArgvAllowed` re-checks the final array
  immediately before `spawn`.
* `configurationAxisFor(provider)` decides STRUCTURALLY, before any process
  exists, whether the provider may be compared. Measured on this host: pi
  documents all five suppression flags (distinguishable), codex 0.157.1 exposes
  no context-surface switch in the 27 flags of `codex exec --help` (so its pair
  is EXCLUDED with that reason). **A structural decision is a decision about the
  code, not an observation of a run**: no B cell has been executed on this
  checkout, and the comparison is `NOT_RUN` with both providers `REFUSED`
  (`NEEDS_INPUT / COMPARISON_INPUT_MISMATCH:config_delta:none!=none`).
* Both digests are published in every raw process log: the raw one is the exact
  argv the OS received, the normalised one folds out the per-run project copy,
  the evidence root, the injected containment roots and the run id — nothing
  else. **A comparison asserts on the normalised digest.** Round 2 nearly
  mis-read a per-run `--output-last-message` path as a configuration
  difference; that is the false positive this pair of digests exists to prevent.

## The three lifecycle defects (round 3)

| defect | fix | what proves it |
| --- | --- | --- |
| `TRANSPORT_PUBLISHES_NO_TERMINATION_PROOF_ON_TIMEOUT` — a timeout produced `TIMEOUT` with `cancelProof === null` | a deadline this transport enforced IS a kill, so it runs the same `terminateGroup` + `proveTermination` and the proof travels on the terminal event; a kill that cannot be proved `TERMINATED` is reported as `UNKNOWN` / `RECONCILIATION_REQUIRED`, never as a definite `TIMEOUT` | the round-3 timeout arm carries the proof a cancel does: terminal `RECONCILIATION_REQUIRED` with `SURVIVORS_REMAINING: PROCESSES_SURVIVED_THE_GROUP_KILL` published, where round 2 had none |
| `TRANSPORT_TIMER_NEVER_CLEARED` — a 4 s run kept the process alive 5m01 s | the deadline timer is cleared in `finally` on every path, and the only way to wait in this file is `boundedRace`, which destroys its timer in a `finally` on the losing path too | `the event loop is not held open after the run settles` (a real child, a granted 8 s deadline, measured wall clock) |
| `CANCEL_PROOF_IS_A_REAPING_RACE` — the observer was asked about a child that had not been reaped, so a dead child was counted as a survivor | the exit is WAITED FOR before the survivor accounting, and when the two readings disagree both are published (`pre_accounting_reading`, `accounting_reading`, `readings_disagree`) — the observer's first answer is never overwritten | `a reap race records BOTH readings and never overwrites the observer answer` |

## The one-owner rule

**One file, one owner. No file in this repository has two owners.**

That is the rule the ticket was planned under (SPEC §2, "one owner per file"), and
this tree is where it is easiest to break, because every module here is written
against a document another module will write. The rule is a *naming* rule before it
is a process rule, and it is enforced by where things live:

| kind | who may write it | what it decides |
| --- | --- | --- |
| this tree (`src/lib/executors/**`) | owner A (transport), owner C (measurement) | how a real child is spawned, observed and measured |
| `scripts/s2-007r-*.mjs`, `scripts/verify-s2-007r*.mjs` | owners B, C, D, E | what a run, a comparison, a probe and a verdict mean |
| `evidence/s2-007r-*.json` | exactly one writer each — the script that names it in its own header | the published claim |
| `evidence/root-manifest.json`, `frozen-manifest.json`, `FILE_INVENTORY.md`, `closure-record.json`, `commit-record.json` | the orchestrator only | what is sealed |

Consequences that are not negotiable while this tree exists:

* **A measurement never writes a status, and a status never writes a measurement.**
  `measure.mjs` is pure; it cannot read the clock, the filesystem or a process, and
  it decides nothing about provenance. `evidence-writer.mjs` decides what a run
  record *means* and never measures a thing.
* **A second writer of an evidence record is a defect, not a merge conflict.** If a
  new module needs a field, the owning script adds it; the other module reads it.
* **A change here never needs a re-freeze, and must never be used as the reason for
  one.** Editing a frozen target to make something in this tree work is the failure
  mode the whole tree exists to avoid: it converts an additive change into a
  reviewed re-freeze of 610 files.
* **The stage record is not the tree's to edit.** `docs/stages/S2-007R.md` and the
  evidence records it criticises have different owners, and none of them is this
  tree. A finding about someone else's file is reported, never patched in place,
  because a silent patch is the exact shape of the false claim this repository
  exists to prevent.

## Files

| file | role | SPEC §2 name |
| --- | --- | --- |
| `constants.mjs` | the literal tables: version, provider set, argv allowlist, the canonical-argument tables' regexes, the provenance statuses, the floor-tier profile id and the digest of the absence-of-controls record | `constants.mjs` (files 2) |
| `internals.mjs` | shared shape/digest helpers and `assertArgvAllowed`; no authority, no clock, no state | **not in the plan** — see the deviation record below |
| `failure-map.mjs` | the fail-closed mapping of an executor's own output (codex exit 1 + `turn.failed`; pi exit **0** + `stopReason:"error"` + `402:`) and `extractUsage` | `failure-map.mjs` (file 5) |
| `evidence-writer.mjs` | `assertRealRunEvidence` — the only declared path to `REAL_ADAPTER_AVAILABLE` — and the observation registry (**bounded by D-3**) | `evidence-writer.mjs` (file 10) |
| `registration.mjs` | `createRealRegistration` — `adapter_kind:'real'` as this file's own literal — and the minted-registration registry | `registration.mjs` (file 3) |
| `transport.mjs` | `createRealExecutorTransport`: the ten `async` methods, the process-group lifecycle, the raw process log, the isolation truth | `transport-core.mjs` + `codex-transport.mjs` + `pi-transport.mjs` + `process-group.mjs` (files 4, 6, 7, 8) — **merged, see below** |
| `measure.mjs` | the seven measurements, pure and recomputable from a raw run record alone | `measure.mjs` (file 9) |

One SPEC file in this plan is deliberately **absent** from this tree rather than
merged into it: `real-probes.mjs` (SPEC §2 file 11) — see D-5.

## Deviation record (SPEC §2 file plan)

**One deviation, stated rather than hidden.** (D-3 to D-6 are the round-3 audit
findings and the remaining SPEC-vs-implementation gaps; they are recorded below
under their own numbers, and they are the reason a reader should not treat
invariant 1 as an impossibility proof.)

**D-1 — `transport-core.mjs`, `codex-transport.mjs`, `pi-transport.mjs` and
`process-group.mjs` are ONE module, `transport.mjs`, instead of four.**

*Reason.* `createRealExecutorTransport` is a single factory over **one live child
process**: ~30 closures share one mutable `state` object (the child handle, the
process group, the captured stdout/stderr, the event list, the raw-log slot, the
fence). Splitting it by provider would mean two factories over one state, i.e. a
shared-state contract that is *harder* to verify than one cohesive module and that
cannot be checked by a type. Splitting out the process group would mean a handle
object crossing a module boundary on every signal, which is exactly where a
`pids_before_kill.length === 0` bug hides. The two providers differ in exactly
two pure places — `buildArgv` and the output readers — and both of those are
already data-driven (`PROVIDER_ARGV_ALLOWLIST[provider]`,
`failure-map.mjs` keyed by provider), so the shared module is not "one code path
that guesses"; it is one lifecycle with two argv tables.

*What is given up:* a reader cannot open `pi-transport.mjs` to see the pi argv
and find only the pi argv. The mitigation is that both are in
`PROVIDER_ARGV_ALLOWLIST` (`constants.mjs`) with the measured reason each flag
exists, and `assertArgvAllowed` refuses a token that is not in that table, so a
provider's surface is a closed, reviewable set.

*Why the other seams were NOT merged.* `constants.mjs`, `failure-map.mjs`,
`evidence-writer.mjs` and `registration.mjs` are pure with respect to the live
process, which is precisely the property that makes them independently checkable:
`evidence-writer.mjs` decides what a run record *means* and must stay readable
without reading the transport, and `failure-map.mjs` is recomputable from the
executor's own bytes. They are split as the plan names them.

**D-2 — `internals.mjs` is not in the plan.** The plan's six pure seams share
thirteen shape/digest helpers and the argv allowlist. `internals.mjs` holds
those and nothing else, so no module re-declares them. It is deliberately *not*
part of any documented surface: a caller that needs a helper should import the
module that owns the decision, not this one.

**D-3 — the two object-identity registries are tree-public, and the evidence one
is FORGEABLE by any importer. This is the most important line in this file.**
`evidence-writer.mjs` exports `mintObservedRunEvidence` and the last check in
`assertRealRunEvidence` is `OBSERVED_RUN_EVIDENCE.has(raw)` — a module-level
`WeakSet` any importer can satisfy. Verified from the source in round 3: the
`WeakSet` is declared at `evidence-writer.mjs:20`, the mint is exported at `:23`,
and the membership test is the final gate at `:272`.

The header's stated threat model is that "a record reconstructed from JSON is not
in the registry" and that this is "the fact no file on disk can carry". Both
sentences are true and the model is the wrong one: a hand-written log file on
disk is exactly what a forger supplies, and once the caller mints, every other
check (binary basename, realpath, sha256, log↔record agreement, argv allowlist,
non-zero observed exit) passes. The round-3 honesty audit
(`.bb/chats/thr_mgkk7cb5t6/notes/honesty-audit-round3.md`) demonstrated exactly
that: a `/tmp` log describing a crossing that never happened was minted, accepted
as `run-forged-crossing`, and a `REAL_ADAPTER_AVAILABLE` registration follows from
it — **zero processes, zero board commands**. The same audit saw 8 of 10
adversarial attempts refused (`exit 0`, `exit_observed: false`, `/bin/false`, an
unobserved record, a proven profile, no permit).

So the honest statement about invariant 1 is: it stops a *careless* caller and
every replay, fixture and stub path, and it does **not** stop a caller inside this
tree that writes its own log. The gate that would close it needs something a
forged document cannot produce, and the mint's own process-identity is not it.
**No record published by this ticket uses the hole** — all eight round-3
crossings are `governed: false, is_a_run: false, `board_commands_called: 0`, and
the eight registration corroborations name a log whose bytes recompute — but the
limitation belongs to the gate, not to the run, and it is recorded here instead of
being described as a narrow residual exposure.

**D-4 — `assertNoCallerWidening` does not exist.** SPEC §2 file 3 named it
("throws `NotRunRealAdapter NOT_RUN_REAL_ADAPTER` for any caller
`adapter_kind`/status") and it is nowhere in this checkout — not in `src/`, not
in `scripts/`, not in `tests/`. What landed is `createRealRegistration` plus a
`MINTED_REGISTRATIONS` registry (`registration.mjs`) plus
`isMintedRegistration`. The behaviour is fail-closed and the derivation is sound:
`adapter_kind` is this file's own literal, `status` starts at
`CANONICAL_PROVENANCE_STATUS` and is raised only when `assertRealRunEvidence`
returns for a record whose provider matches. A caller's `adapter_kind: 'test'` or
its own `real_adapter_provenance.status` is silently ignored. What is lost is
auditability: a record cannot distinguish "nobody asked for a widening" from
"somebody asked and was ignored", and the SPEC's promise that it throws was not
kept.

**D-5 — `real-probes.mjs` (SPEC §2 file 11) is not in this tree.** The probe
family, its `COUNTER_MAP` and `runRealProbes` live in
`scripts/s2-007r-probes.mjs` (owner D), which is where the gate runs them from
and where the record is written. Nothing was lost except the plan's placement:
the counters are the seven imported `HARD_GATE_COUNTERS` and `probes.mjs` was
never edited, which is what SPEC D10 required.

**D-6 — `scripts/s2-007r-real-adapter-run.mjs` and
`scripts/s2-007r-comparison-run.mjs` (SPEC §2 files 13 and 14) were never
written.** The driver is `scripts/s2-007r-run.mjs` and the measurement set is
`scripts/s2-007r-measurement-set.mjs`; both are declared in `package.json` under
their real names. The consequence is visible in every published summary: the
frozen gate list in `scripts/verify-s2-007r.mjs` still expects the mandatory npm
scripts `s2-007r:real-run` and `s2-007r:comparison`, so the `real-adapter-run`
and `comparison` gates answer `NOT_RUN` with the reason "the mandatory npm script
is not declared in package.json". Declaring those two names here would be either
a script that cannot run or a `repointed` finding that blames `package.json` for
a defect living in the gate list, so they stay absent and the two gates stay
fail-closed. **The reconciliation belongs to the owners of the gate list and of
those two entry points, not to `package.json` and not to this tree.**

## Determinism and secrets

* No `Date.now()`, no `new Date()` without the injected clock, no `Math.random()`,
  no `process.hrtime` anywhere in this tree. The only real timer is the
  enforcement of the caller-authorized `budget_grant.timeout_ms`.
* A raw log records the exact argv (which carries the brief in cleartext, because
  both CLIs take the prompt as a trailing positional — the log says so), the cwd,
  the exit status, and digests of stdout/stderr. It never records an environment
  value and never records the executor's output text. Credentials are named by
  variable name and file location (`CREDENTIAL_VARIABLES`) and are never read.

## What this tree produced, and what it did not

Published state at the S2-007R record, stated here so a reader of this README
does not have to open six JSON files to learn it. Everything below was re-derived
from the bytes on disk for this README, not carried over from a previous round:

* **two registrations really did reach `REAL_ADAPTER_AVAILABLE`**, one per
  installed provider, each from a child this process spawned and observed (exit 1,
  pid == pgid, `POSIX_GROUP`, 65-event gap-free stream from 1, binary and raw-log
  digests recomputed and matching);
* **still zero governed runs**: the round-3 cells refused every
  `tasks.claim` with `BLOCKED_SANDBOX` because the permit did not reach the
  per-edge guard, and `agentboard_run` / `agentboard_execution_event` hold 0 rows
  in all four schemas. All eight crossings are recorded as
  `governed: false, is_a_run: false, board_commands_called: 0`. The orchestrator
  has since changed that guard path — `policy.assertAdapterCoversTask` now calls
  `assertLiveExecutionAuthorized` and `commands.guardContextFor` forwards the
  server-resolved permit — so `READY→CLAIMED`, `CLAIMED→RUNNING` and
  `RUNNING→IN_REVIEW` are reachable again. That is the orchestrator's change in
  the frozen core; this tree neither reverts nor repeats it, and until the driver
  is re-run every record still says `NOT_RUN_REAL_ADAPTER`;
* the strongest evidence in the ticket is a **boundary observation**, not a run:
  measurement 7 planted two authority-expansion attempts, both were refused with
  typed errors (`CAPABILITY_MISMATCH / ADAPTER_CLAIM_NOT_REGISTERED` and
  `BLOCKED_POLICY / BOUNDARY_ARGUMENT_NOT_CANONICAL:capabilities`) and the
  effective tool and capability sets were unchanged — `planted 2 / refused 2 /
  granted 0`, value `0`. Its second sub-observable (argv allowlist == request
  allowlist) is `NOT_RUN`, so the row is `PARTIAL`, not `MEASURED`;
* the A/B axis is implemented and its decision is measured structurally, but
  **no B cell was ever executed** and the comparison is `NOT_RUN` with both
  providers `REFUSED`; the three lifecycle defects are fixed and the timeout arm
  now publishes a proof it did not publish in round 2, while the cancel and
  timeout arms are still `SURVIVORS_REMAINING`.

The status fields therefore stay where they are until a re-run moves them:
`realAdapterStatus` `NOT_RUN_REAL_ADAPTER` in every record,
`engineeringStatus` `PARTIAL` in the per-case record and `REVISE` in the
aggregator, `assuranceStatus` `NOT_MEASURED`, `aMvpStatus` `NOT_CLAIMED`. The
permit that admits the floor tier is neither a review nor an acceptance, and the
budget grant approves no acceptance criterion.

Full detail, with the measurement methods, the per-case table and the eleven
residual limitations:
[docs/stages/S2-007R.md](../../../docs/stages/S2-007R.md). The blocker and the two
sides of the tier decision:
[2026-09-26-s2-007r-host-unisolated-tier.md](../../../docs/decisions/2026-09-26-s2-007r-host-unisolated-tier.md).

## Verification

```
node --test tests/agentboard/real-executor.test.mjs        # 75 tests, 1 skipped (opt-in real provider)
node --test --test-concurrency=1 "tests/agentboard/*.test.mjs"
node --test tests/identity/contracts.schemas.test.mjs
npx eslint src/lib/executors tests/agentboard/real-executor.test.mjs
npm run s2-007r:authorize        # the permit, with its own body digest
npm run s2-007r:run              # the real run driver (spawns REAL codex/pi)
npm run s2-007r:lifecycle        # the three process-lifecycle arms (spawns REAL pi)
npm run test:s2-007r-probes      # the five mandatory negative probes
npm run verify:s2-007r           # the aggregation gate
```

Two entry points of this ticket are deliberately NOT in `package.json`, and the
aggregator reports their gates `NOT_RUN` because of it: the frozen gate list in
`scripts/verify-s2-007r.mjs` expects `s2-007r:real-run` and `s2-007r:comparison` to
name `scripts/s2-007r-real-adapter-run.mjs` and
`scripts/s2-007r-comparison-run.mjs`, two files that were never written (D-6).
Declaring those names would either be a script that cannot run, or a `repointed`
finding that blames `package.json` for a defect that lives in the gate list.
Every entry point that **does** exist is declared, one to one: eight npm scripts
for eight `scripts/s2-007r*.mjs` files, with no dangling declaration and no
undeclared file. Until their owners reconcile it, the real entry points are
declared under the names in the block above and the two gates stay fail-closed.

The opt-in test (`VERITAS_S2_007R_REAL=1`) is skipped by default on purpose: it
starts a real installed provider and costs a real model call. A suite that could
reach `REAL_ADAPTER_AVAILABLE` by itself would be the defect, not the coverage.

Last measured on this checkout, with the orchestrator's guard change in place:
`node --test --test-concurrency=1 "tests/agentboard/*.test.mjs"` → 426 tests,
425 pass, 0 fail, 1 skipped (the opt-in real-provider test).
