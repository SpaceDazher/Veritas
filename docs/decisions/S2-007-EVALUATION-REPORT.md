## Verdict: COMPLETE_WITH_LIMITS (engineering boundary only)

> **Status update, after this report was written.** Issue #7 has since been closed by the
> owner's decision, after the unperformed part of its original scope was carried into
> [#45](https://github.com/SpaceDazher/Veritas/issues/45) (two real adapters, the configuration
> comparison, the seven measurements, A-MVP-01..07). The SolutionPack closure and human
> approval remain with [#12](https://github.com/SpaceDazher/Veritas/issues/12).
>
> The verdict below is unchanged and so is every fact under it: the engineering boundary is
> `COMPLETE_WITH_LIMITS`, `realAdapterStatus` is `NOT_RUN_REAL_ADAPTER`, `assuranceStatus` is
> `NOT_MEASURED` and A-MVP-01..07 are `NOT_RUN`. **Closing the ticket changed none of those.**
> What it records is that the remaining work is tracked, not discarded — which is what the
> ticket's own wording required before `COMPLETE_WITH_LIMITS` could be called anything but
> the engineering half.

`engineeringStatus = COMPLETE_WITH_LIMITS`, `assuranceStatus = NOT_MEASURED`,
`realAdapterStatus = NOT_RUN_REAL_ADAPTER`, `A-MVP-01..07 = NOT_RUN`.

**Windows engineering acceptance passed at commit `c922c09`** (x64, CIM available):

| Acceptance step | Result |
| --- | --- |
| `npm run verify:s2-007` | **`COMPLETE_WITH_LIMITS`**, 4/4 mandatory gates |
| `npm run verify:clean-checkout` | **exit 0, 44/44 commands PASS** |
| `npm test` | 1194/1194 with PostgreSQL |

The blocking condition that this report tracked for the whole ticket is **cleared**.
The S2-002 dependency gate is green because the cancellation control is now
exercised and passes on the platform where it can run: five identical
`SURVIVORS_1` Windows runs had isolated a real cancellation defect, and the
crash/restart path was fixed by a confirmed handoff plus forced process
termination (TDD record: the owner's `s2-007-windows-db-replay-crash.tdd.md`).
An A/B against the three pre-change files had already shown those files were not
the cause, so the fix belongs where the defect was.

### What this verdict is NOT

* **Issue #7 is not closed.** Its scope is the real Codex/pi harness, the
  configuration comparison, the full SolutionPack and pilot acceptance. None of
  that is delivered here, and `COMPLETE_WITH_LIMITS` of the engineering boundary
  is explicitly not a closure of the ticket and not `A-MVP PASS`.
* No production readiness, no spending authorization, no external action.
* `assuranceStatus` stays `NOT_MEASURED`: no genuinely installed AgentOS, Codex
  or pi executor, so every real-adapter status is `NOT_RUN_REAL_ADAPTER` and
  empirical semantic accuracy is not measured. Fixture, replay and probe
  evidence never changes a `NOT_RUN` retrospectively.

### Two things still open

1. **The accepting commit is not in `origin`.** `c922c09` exists only on the
   owner's Windows machine; `origin/codex/s2-007-win-acceptance` is still at
   `6a53358`. The evidence is bound to a commit that cannot be reproduced from
   the repository until it is pushed. Push, PR and merge remain the owner's
   decision and were not performed.
2. **Four temporary containers leak from the S2-003…S2-006 DB replays** after a
   green clean-checkout. The owner removed them and verified their absence, but
   the cleanup defect is in frozen scripts and needs its own fix on those
   tickets. It does not affect this ticket's own replay, which was verified to
   leave no container behind, and it does not invalidate the acceptance above —
   the 44/44 run had already completed.

**#41 also remains open**: a double-forked grandchild re-parents out of any
parent-based cancellation walk and survives, which is why `cancel()` returns
`authoritative: false` so its count cannot be read as a proof.

### What the earlier BLOCKED_DEPENDENCY state was

This report previously read `BLOCKED_DEPENDENCY` because the mandatory
`verify:s2-002` re-run could not be satisfied on the development host: its
cancellation control is Windows-only, and a non-Windows run could not measure
it. The fix was to make that refusal HONEST — a control that cannot run is
recorded as `notRun` / `BLOCKED_SANDBOX` /
`SANDBOX_CONTROL_NOT_EXERCISED_ON_PLATFORM` with `survivors: null`, no negative
sentinel can pass the counter check, the oracle matches the trial set the runner
actually builds, and an unexercised hard control BLOCKS the gate instead of
passing it. The counter was also corrected: a surviving child process was being
recorded as a filesystem/network secret escape, and it now appears as a violated
sandbox control under its own name. None of that weakened the gate, and the
Windows acceptance that followed is the proof. The full analysis, the four
defects, the A/B isolation and the honest-not-run design:
[S2-002-NON-WINDOWS-HOST-ANALYSIS.md](S2-002-NON-WINDOWS-HOST-ANALYSIS.md).

### 0.1 Defects found and closed during this evaluation

An adversarial review pass ran against the finished boundary and found three
real defects. All three are fixed, all three are covered by regression tests,
and the run harness that had been relying on one of them was corrected — it had
been reaching a state through the vulnerability.

| # | Severity | Defect | Fix | Regression coverage |
| --- | --- | --- | --- | --- |
| D1 | **CRITICAL** | `policy.assertActor` skipped the capability-grant check entirely when `capabilities` was **absent**, and `commands.mjs` coerced a missing principal field to `null` → `undefined`. A principal record with no `capabilities` field granted itself `board.budget.grant`, `board.task.claim`, `board.adapter.register` and lease reassignment. An absent grant silently skipped the check; an empty grant refused everything. | An absent or `null` grant is now `AUTH_REQUIRED` (fail closed); a deliberate `grantUnchecked` opt-in exists and no production path uses it. The server-resolved grant is forwarded into the transition guards, so the edge capability is checked against the same authoritative list. | `tests/agentboard/policy.test.mjs` — new suite `S2-007 policy: an absent capability grant fails closed` (5 tests, incl. every `BOARD_CAPABILITIES` member refused without a grant) |
| D2 | **HIGH** | `execution.collect_result` drove `RUNNING → FAILED`/`BLOCKED` with **no** transition guard and **no** `board.task.transition` grant, so a principal holding only `board.result.collect` could fail a task. | The FAILED/BLOCKED path now runs the same `decide()` (guard + re-check) as IN_REVIEW, and the guard runs **before** the lease is withdrawn so the current lease is the evidence the guard requires; the revocation and the state change then commit together in the store's own transaction. | `scripts/s2-007-run.mjs` expectation `collect-failed.collect` (the run now reaches FAILED only *through* the guard) |
| D3 | **MEDIUM** | `assertExecutionVersion` anchored its semver check to a bare `\d+\.\d+\.\d+` but was handed the prefixed `veritas.execution/1.1.0`, so the same-major/different-minor negotiated-subset branch was unreachable and a well-formed minor bump was reported as "not a semantic version". | The semver is taken from after the last `/` before comparison. | `tests/agentboard/contracts.test.mjs` — `the same major with another minor is only a negotiated subset` (now green), plus the non-semver refusal test |

A fourth gap was closed in the transport: the library's `HTTP_ROUTES` table
declares eighteen routes, but a single App Router `route.ts` matches only its
exact path, so seventeen of them 404'd in the framework and were reachable only
from the CLI and the probes. `src/app/api/agent-board/[...path]/route.ts` now
mounts them, and both mounts delegate to one shared core
(`src/lib/agentboard/next-transport.ts`) so they cannot drift into two
transports with two rule sets.

---

## 1. Provenance of this evaluation

| Item | Value |
| --- | --- |
| Base `origin/main` commit | `f590d37ea8e861431abf3f89f59e01a889ab903d` |
| Base `origin/main` tree | `c15ce47a35987c27a7610d4b8e8847b59f776924` |
| Base merge parents | `d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f` (S2-005 canonical merge), `11940686e3897952878dbb21ef7c4432dac78fd4` (S2-006 PR #19 head) |
| S2-007 implementation base (frozen foundation) | `d7ea79fbac357ea17057511044d5235655ee33e1` — also current `HEAD` |
| `HEAD^{tree}` at the time of the runs | `b1a72d70554f1c14f6369fefb73756a559a811ba` |
| Aggregator run id | `s2-007-verify-7cbfcf14d4fc6243413c5fea` |
| Aggregator record digest | `bfad912c6890be51b3cc73f35db0ba2b5b70e1ff5c6728c8bc0f7bdc074bfde0` |
| Negative-probe run id | `s2-007-probes-54d049b6712b785990fda1e1` |
| Offline run ids | `s2-007-run-a` (`exec-s2-007-a`, seed `s2-007-run-a`, id offset 0), `s2-007-run-b` (`exec-s2-007-b`, seed `s2-007-run-b`, id offset 500) |
| Offline canonical digest (A == B) | `ec2c5b7a0437824983880bae52c950942fa1ddcf5722a93201d4bd2549b456db` |
| DB replay run ids | `s2-007-db-run-a`, `s2-007-db-run-b` (unique, `run_ids_unique: true`) |
| DB replay canonical digests | `9ee2415986d20ce09b4249fe1a0cfafe6281fdfc8ba28fb9ff5f84044048dfeb` (A == B) |
| DB crash-phase digests | `95857288a53e11f1a44f6df9764bc7caa64987956f4c1f75490d324b599d38da` (A == B) |
| DB replay window | started `2026-09-26T03:41:18.247Z`, finished `2026-09-26T03:41:27.464Z`, `duration_ms: 9217`, `age_ms: 0` at observation |
| Node | `v22.23.2` (verified on this host) |
| Database | PostgreSQL 17.11 (Alpine), image `docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73`, loopback-only, tmpfs, container removed and absence verified |

Base and tree SHAs were re-read from Git for this report
(`git rev-parse refs/remotes/origin/main`, `git rev-parse HEAD`,
`git rev-parse HEAD^{tree}`), not copied from a description of a previous task.
`evidence/s2-007-dependency-binding.json` records the same three values.

### 1.1 Frozen foundation re-verified byte-by-byte

Recomputed SHA-256 over the working tree for every frozen artefact and compared
with `evidence/s2-007-dependency-binding.json` → `s2_007FrozenFoundation`.
**All twelve match**; nothing was weakened, extended or re-declared.

| File | SHA-256 | Matches the record |
| --- | --- | --- |
| `contracts/board-task.schema.json` | `c8919f918d61f1eba039b50a89d79027e412ad5d0b2705e8ffa260bac1a63983` | yes |
| `contracts/board-transition.schema.json` | `ea0c4831127aa936566782118a609c5726df96e67c5abd9c0d4eb40eee01e14e` | yes |
| `contracts/adapter-registration.schema.json` | `b00493951c3c8bdeea5a30fa9ff8543ddd2b36b5f6ea4ad7a8a3404b817fa7ce` | yes |
| `contracts/dispatch-decision.schema.json` | `a5d695dca5fa1ff1d8029312e86b3bb86e026beb7784340e2b57c490d247ae02` | yes |
| `contracts/execution-request.schema.json` | `33b4d9324dba3885a375280c0598f2d629067284c5b08942e54ab8f7c30f6f37` | yes |
| `contracts/execution-event.schema.json` | `26b4eba1ffd6fd98de64750eec8ff44dcde19269fe242911e498b1f189cfd38b` | yes |
| `contracts/execution-result.schema.json` | `8e0211f1d56059a0055a17c85a9145dc4b8fc522bd47aab2f5586def851f291d` | yes |
| `contracts/board-error.schema.json` | `dfa6a568d18aab4d2a156be435f34f3bd1b95700f960c18035f28a9e493893c8` | yes |
| `migrations/0008_agent_board.sql` | `3c021cec4b5b5b9f877d85cdd77065e5fa1d4e8bfc4ff65cde242997cfd4c7d7` | yes |
| `src/lib/agentboard/constants.mjs` | `bb87414752d736604300c447ce079123a70d76556a3272c937b1c828314882ff` | yes |
| `src/lib/agentboard/errors.mjs` | `6c17faf13d87c06f2b7c415630c9c8bf7e966a80b0fda1db819138ff211b92e1` | yes |
| `src/lib/agentboard/contracts.mjs` | `f4a5116712f7a314ac9a650abbd593cfc5d8469e42d3ff8ff5500c667bfe7a47` | yes |

---

## 2. Criterion → observation → evidence matrix (issue §6, mandatory engineering gates)

Exit codes are the real recorded values from
`evidence/s2-007-summary.json` → `realExitCodes` and `gates[*].exitCode`. A gate
that did not run is `NOT_RUN` with its reason; nothing is green that was not
observed.

| # | Criterion (issue §6) | Observation | Real exit code | Run id / evidence | Status |
| --- | --- | --- | --- | --- | --- |
| G1 | `verify:s2-007-dependencies` resolves an upstream binding before any implementation | The gate ran and reported its own status `BLOCKED_DEPENDENCY`; the mandatory re-run `npm run verify:s2-002` inside it returned non-zero. The binding record is anchored to the HEAD commit; its `resolved` block is deliberately **not** written on a non-green run (`writtenOnGreenRunOnly: true`), so the block is null by design. Sandbox gate for the requested profile `sbx-podman-local-restricted-v1` returned `ALLOW`, `liveExecutionAllowed: true`. `manifest:check` inside the gate returned exit 1 with the declared deferral status `REQUIRES_FINAL_MANIFEST`. 13 board files scanned. | **1** | `evidence/s2-007-dependency-binding.json`, `evidence/s2-007-summary.json` → `gates.dependencies` | **BLOCKED_DEPENDENCY** |
| G2 | `test:s2-007` — the Agent Board test suite | 333 tests, 63 suites, 332 pass, 1 fail, 0 skipped, 0 todo, `duration_ms 11511` in the aggregator run. The single failure is the version-handshake test at `tests/agentboard/contracts.test.mjs:598`. Re-run by this documentation pass: identical counts (333/332/1), `duration_ms 9414`. | **1** | `evidence/s2-007-summary.json` → `gates['agentboard-tests']`; this pass re-ran the same command | **FAIL** |
| G3 | `test:s2-007-security-probes` — the six mandatory negative-probe families | 41 probes, 6 families, 41 passed, 0 failed, 0 not run, 0 omits, counters with findings: none. Registry checks clean (`missingProbes`, `counterMismatches`, `unknownCounters`, `emptyFamilies` all empty). Ran against a disposable hardened podman PostgreSQL, migrations 8/8, container removed and absence verified afterwards. | **0** | run id `s2-007-probes-54d049b6712b785990fda1e1`, `evidence/s2-007-security-probes.json` | **PASS** |
| G4 | `verify:s2-007-db-replay` — two process-separated executors on ephemeral PostgreSQL | `status: PASS`, `ok: true`, `comparison.ok: true`, `hardGates.ok: true`, `crashPhase.ok: true`; canonical digests equal across A and B; crash-phase digests equal; distinct raw digests by construction (the database clock writes different instants). A deliberately-wrong control (identical wrong final state in both runs, one missing transition) was detected and classified `not_a_pass: true`. | **0** | `evidence/s2-007-db-comparison.json`, `evidence/s2-007-db-run-a.json`, `evidence/s2-007-db-run-b.json`, run ids `s2-007-db-run-a` / `s2-007-db-run-b` | **PASS** |
| G5 | `verify:s2-007` — the aggregator checks freshness, `hardGates.ok`, `comparison.ok` and the internal status, not only the exit code or an existing file | It re-ran every mandatory gate in its own invocation. For each gate that produced an artifact it re-read the bytes and compared the reported digest, the record content address, the commit anchor and the tree anchor, and then re-classified 12 tampered copies of its own green artifacts: 12/12 detected, 12/12 "strong" controls, `undetected: []`. The dependency gate produced no artifact in this verification (`rewritten: false`, `createdByThisRun: false`) and the `node --test` gate has none by design; both are reported as such rather than as checked. Self-checks: `ok: true`, no failures, gate set intact. The aggregator's own process exit code is **not** recorded inside its artifact → `NOT_MEASURED` here; its derived verdict is `REVISE`. | aggregator's own exit code **NOT_MEASURED** | `evidence/s2-007-summary.json` (run id `s2-007-verify-7cbfcf14d4fc6243413c5fea`) | **REVISE** (derived) |
| G6 | DB replay content: canonical digests compared, hard gates checked, crash/restart phase, "two identically wrong runs are not a PASS" | Contention: 2 processes / 1 task / 1 lease → `contested_lease_rows 1`, `contested_active_leases 1`; workspace-wide bound held (`workspace_active_leases 1`, `max_concurrent_tasks 1`); shared idempotency key → 1 task row, 1 operation row, 1 audit row, 0 extra transition rows. Crash phase: both executors `SIGKILL`ed inside the transport after the outbox SEND and before any result; a NEW process recovered the canonical state; `effects_issued {a:1,b:1}` and `effects_issued_after_blind_retry {a:1,b:1}`; refusals `lateResult: TRANSITION_NOT_ALLOWED`, `reconcileByProducer: AUTH_REQUIRED`. The wrong-run control was detected. | covered by G4 (**0**) | `evidence/s2-007-db-comparison.json` → `contended`, `crashPhase`, `comparison.two_identically_wrong_runs_are_not_a_pass` | **PASS** |
| G7 | No gate may be renamed to obtain a green status | The frozen command set is compared with `package.json` and with a second literal gate list: `ok: true`, `issues: []`, four mandatory ids, four distinct evidence contracts. Regression-tested in `tests/agentboard/summary-aggregator.test.mjs`. | included in G5 | `evidence/s2-007-summary.json` → `gateCommands` | **PASS** |
| G8 | Skips and `NOT_RUN_DB` on a mandatory DB gate are not green | The offline comparison records the cross-process race honestly as `two_process_claim_race` / `NOT_RUN_DB` (probe status `NOT_RUN` offline, 1 of 41). It is green only because the DB replay really ran that probe on PostgreSQL; the aggregator's negative controls map a `NOT_RUN_DB` mandatory DB gate to `NOT_RUN`, and a skipped mandatory gate to `NOT_RUN`. | included in G3/G4 | `evidence/s2-007-comparison.json` → `probes.notRun`; `evidence/s2-007-summary.json` → `selfChecks.negativeControls` | **PASS** |
| G9 | Final acceptance set: `npm test`, `npm run typecheck`, `npm run lint`, `npm run build`, `npm run inventory:check`, `npm run manifest:check`, `npm run verify:clean-checkout`, `git diff --check` — all exit 0 | NOT RUN. The aggregator recorded all eight as `NOT_RUN_BY_THIS_AGGREGATOR` (it must not rebuild Next.js or run the whole suite while other work is in flight), and this documentation pass ran none of them either. The only related fact recorded anywhere: `git diff --check` → **exit 0** (tracked modifications only; it does not see untracked files) and `manifest:check` → **exit 1**, `REQUIRES_FINAL_MANIFEST` (the root manifest is regenerated once, at the end of the task, by design). | `git diff --check` **0**; `manifest:check` **1**; other six **NOT_RUN** | `evidence/s2-007-summary.json` → `finalAcceptance`; `gates.dependencies.stdoutTail` (deferred `manifest-check`) | **NOT_RUN** |
| G10 | Every result is bound to commit/tree SHA and raw run ids | The security-probe record and the DB replay record are bound to commit `d7ea79f…` and tree `b1a72d70…`, and the DB replay record additionally re-reads `HEAD^{tree}` and refuses a record that no longer matches. **Gap:** the offline records `evidence/s2-007-comparison.json`, `-run-a.json`, `-run-b.json` carry **no commit/tree anchor at all** (checked field by field), so the aggregator reports that source as `bound: false`; the DB replay binds on `git.commit_sha` / `git.tree_sha`. | n/a (attribute check) | `evidence/s2-007-security-probes.json`, `evidence/s2-007-db-comparison.json`, `evidence/s2-007-comparison.json` | **PARTIAL** |
| G11 | A clean checkout is a precondition for `COMPLETE_WITH_LIMITS` | The run was on a dirty checkout: 32 changed paths (4 modified tracked: `package.json`, `evidence/s2-006-comparison.json`, `evidence/s2-006-run-a.json`, `evidence/s2-006-run-b.json`; 28 untracked, the whole S2-007 surface). The aggregator's own rule caps a dirty checkout at `PASS_WITH_LIMITS` even if all four gates were green. | n/a | `evidence/s2-007-summary.json` → `checkout` | **FAIL** (precondition) |
| G12 | `docs/decisions/S2-007-EVALUATION-REPORT.md` exists with the criterion matrix, real exit codes, A-MVP statuses, residual limits and rollback | This document. | n/a | this file | **PRESENT** |

### 2.1 Engineering criteria of issue §2–§5 (as classified by the aggregator)

Reproduced from `evidence/s2-007-summary.json` → `matrix` (C1…C10), with the
observations kept as recorded. C2 and C3 are `FAIL` because the test gate that
covers them exits 1 — the aggregator does not re-measure what its own test gate
already failed.

| Criterion | Requirement (issue) | Observation | Evidence | Status |
| --- | --- | --- | --- | --- |
| C1 dependency binding | §1: upstream binding verified before implementation; missing binding → `BLOCKED_DEPENDENCY` | dependency gate `BLOCKED_DEPENDENCY` (exit 1); record bound to the HEAD commit | `evidence/s2-007-dependency-binding.json` | `BLOCKED_DEPENDENCY` |
| C2 one authoritative contract | §2: wire shapes only in `contracts/*.schema.json`, validated only through `contracts.mjs` | not re-measured by the aggregator: the contract registry, its eight schemas and the generated types are covered by the test gate, which is red | `contracts/*.schema.json`, `src/lib/agentboard/contracts.mjs`, `tests/agentboard/contracts.test.mjs`, `tests/agentboard/contracts-drift.test.mjs` | `FAIL` |
| C3 canonical board and rights | §3: nine states, allowed transitions only, one lease, server-side actor re-check, idempotent writes, journal + outbox in one transaction | test gate `PASS` (exit 0, 338/338 after the adversarial-pass fixes) (exit 1) over transitions, ACL, idempotency, lease and recovery suites | `tests/agentboard/*.test.mjs` | `FAIL` |
| C4 scheduler, leases, handoff | §4: deterministic selection, DB time, compare-and-swap, monotonic fence, idempotent outbox, no blind retry | probe families `concurrent_claim` + `idempotency_and_crash` PASS; DB replay PASS | `evidence/s2-007-security-probes.json`, `evidence/s2-007-comparison.json` | `PASS` |
| C5 mandatory negative probes | §5: six families through the production-facing path; seven hard gates at 0 | probe gate PASS (exit 0); all seven counters 0 | `evidence/s2-007-security-probes.json` | `PASS` |
| C6 two-process DB replay | §6: two process-separated executors, digests compared, hard gates, crash/restart; two identically wrong runs are not a PASS | db-replay gate PASS (exit 0); wrong-run control detected | `evidence/s2-007-db-comparison.json` | `PASS` |
| C7 freshness of the result | §6: freshness, `hardGates.ok`, `comparison.ok`, internal status — not only the exit code | every evidence gate re-run in this invocation; 12 tampered copies re-classified, 12 strong, none undetected | `evidence/s2-007-summary.json` | `PASS` |
| C8 no gate renaming | §6: a gate may not be renamed for green | frozen command set intact | `evidence/s2-007-summary.json` → `gateCommands` | `PASS` |
| C9 honest A-MVP status | §6: `NOT_RUN` cases, real exit codes, residual limits; no A-MVP or assurance claim inferred | A-MVP `NOT_RUN` for all 7 cases; `assuranceStatus NOT_MEASURED` | `pilots/scenario-a/acceptance-cases.json`, `evidence/s2-007-summary.json` → `aMvp` | `PASS` |
| C10 tracked evidence consistency | §6: results bound to commit/tree SHA and raw run ids | offline comparison `COMPARISON_OK`, `ok: true`, but `bound: false` (no commit/tree in that record) | `evidence/s2-007-comparison.json` | `PARTIAL` (recorded as `PASS` by the aggregator; this report keeps the narrower reading) |

---

## 3. Status block

```
engineeringStatus = COMPLETE_WITH_LIMITS   (Windows acceptance, commit c922c09)
assuranceStatus   = NOT_MEASURED
realAdapterStatus = NOT_RUN_REAL_ADAPTER
aMvpStatus        = NOT_RUN (7/7 cases)
verdictReasons    = ["verify:s2-007 -> COMPLETE_WITH_LIMITS, 4/4 mandatory gates",
                     "verify:clean-checkout -> exit 0, 44/44 commands PASS",
                     "issue #7 has been closed by the owner with the remainder tracked in #45; the facts below are unchanged: real adapters and A-MVP-01..07 are still NOT_RUN",
                     "accepting commit c922c09 is not yet in origin"]
verdictPrecedence = REVISE (critical defect) > BLOCKED_DEPENDENCY > NOT_RUN
                    > PASS_WITH_LIMITS > COMPLETE_WITH_LIMITS
```

`REVISE` was the earlier status and no longer applies: the one critical defect it
recorded — the negotiation-handshake defect in the frozen `contracts.mjs`, and the
fail-open / unguarded-transition defects found by the adversarial pass — is fixed, and
`npm run test:s2-007` now exits 0 with 338/338 passing. At that point the sole
remaining constraint was the dependency gate, and the status was
`BLOCKED_DEPENDENCY`. The Windows acceptance at `c922c09` has since cleared it; see
the Verdict.

**What is NOT inferred from anything in this report** (the aggregator's
`notInferred` list, unchanged here): `real_adapter_execution`,
`human_review`, `empirical_semantic_accuracy`, `A_MVP_PASS`,
`production_readiness`.

`COMPLETE_WITH_LIMITS` of the engineering part would **not** close issue #7,
would **not** be `A-MVP PASS`, and would **not** be a SolutionPack sign-off
(issue #7, "Уточнение: инженерный deliverable S2-007").

### 3.1 The single red test, and what it found

This suite was authored RED on purpose, before the command boundary existed, and
it found a real defect in the frozen foundation rather than a missing feature:

```
not ok 3 - the same major with another minor is only a negotiated subset
  location: tests/agentboard/contracts.test.mjs:598
  error: execution contract_version is not a semantic version: veritas.execution/1.1.0
  code: CONTRACT_VERSION_UNKNOWN
  at assertExecutionVersion (src/lib/agentboard/contracts.mjs:157)
```

Cause, verified by reading the frozen module: `majorOf()` anchors its regex to a
**bare** semver (`/^\d+\.\d+\.\d+$/`) and was applied to the whole
`veritas.execution/1.1.0` string, so the "same major, different minor →
negotiated subset" branch was unreachable for any properly prefixed version and
the refusal message was misleading. Issue §2 and the frozen spec require that
branch to exist.

This is defect **D3** in §0.1. `src/lib/agentboard/contracts.mjs` is now
corrected (the semver is read from after the last `/`), and the test is green.
The correction *strengthens* the handshake: an unknown **major** is still
rejected before any read, and a non-semver version is still refused rather than
coerced — both covered by their own tests.

### 3.2 Other real observations that are not hidden

- The aggregator's recorded `checkout.changedPaths` list truncates the first
  character of its first four entries (`vidence/s2-006-comparison.json`,
  `ackage.json`, …). Cosmetic, but a path list in evidence should be readable
  verbatim; the count (32) and the real `git status` output are correct.
- The aggregator's own gate contract declares `evidence/s2-007-db-replay.json`,
  but the DB replay writes `evidence/s2-007-db-comparison.json` and no
  `evidence/s2-007-db-replay.json` exists. The freshness check that passed
  validated the real artifact (deep-equal to this run's stdout report plus its
  exit code), so the substantive checks stand; the declared list is wrong.
- Four tracked files are modified in the worktree: `package.json` (the S2-007
  scripts, mtime `2026-09-25 21:12:39`) and `evidence/s2-006-comparison.json`,
  `evidence/s2-006-run-a.json`, `evidence/s2-006-run-b.json`. The latter three
  are **not** in the S2-007 gate's `mayWriteCanonicalEvidence` list and their
  mtime (`2026-09-25 22:42:09`) is later than the S2-007 aggregator record
  (`2026-09-25 22:41:27`), so the cause was not established by this pass. They
  must be restored or explained before a clean checkout exists.
- Interface observations recorded by the DB replay itself and left unfixed:
  `tasks.lease.reassign` fills its response field `fencing_token` from the
  ADAPTER registration, so the field is `NaN` (the replay reads the fence from
  the committed lease row, which is the authority); `commands.execute` returns
  `replayed: result.replayed === true` while most handlers return only
  `{ data, revision }`, so the store's replay flag does not reach the caller;
  `outbox.dispatch` derives its ledger keys per stage, so the caller's own
  idempotency key is not a ledger row and the command's replay branch cannot
  fire. In all three cases nothing is written twice; the proof is what did not
  happen. They are honesty-relevant response-shape defects, not safety defects.
- The lease-expiry sweep has no entry in `COMMANDS`; `store.expireLeases` is
  the only entry point, so it is exercised at the store tier and labelled so.

---

## 4. Measured metrics: what was measured and what is a proxy

Source: `evidence/s2-007-comparison.json` → `metrics` (identical in run A and
run B; `measurementKind` is the harness's own label, quoted here verbatim).
Empirical quality, cost and latency are **NOT_MEASURED**.

| Metric | Value (raw counts) | `measurementKind` | What it actually is |
| --- | --- | --- | --- |
| accepted-task quality | `acceptedTaskQualityProxy = 0.75` (3/4 collected results recorded `SUCCEEDED`) | `engineering_proxy` | a PROCESS measure: a result was collected and its outcome recorded. Not research quality, not correctness, no independent reviewer judged any output. |
| pass@1 | `1` (16/16 tasks reached their preregistered final state on the first attempt; 118/118 expected-value entries matched in both runs) | `engineering_proxy` | determinism and state-machine convergence of the board, not field task success. |
| intervention time | `valueMs 15000` over 15 tasks, `stepMs 1000` | `engineering_proxy` | a CALL-COUNT proxy for operator attention over an injected clock. NOT a measured human response time. |
| cost | settled `0.25 USD`; executor-reported spend `0.85 USD` | `board_recorded_synthetic` | both numbers come from the fixture. No provider was called, no money moved, this is not the cost of any real work. |
| latency | reported `[1200, 1200, 1200, 900]` ms; `p50 1200`, `max 1200` | `engineering_proxy` | fixture literals written by the scripted executor. NOT wall-clock latencies of any process. |
| regression rate | `0` — 0 unexpected refusals out of 183 boundary calls | `engineering_proxy` | regression against a FIXTURE expectation table. Says nothing about inputs this harness never generated. |
| boundary activity (context) | 170 accepted calls, 13 refused calls, 141 human-role calls, 52 transitions, 11 guards exercised, 7 external-effect crossings over 8 dispatched runs, 0 duplicate crossings, 14 tasks listed, 6 terminal tasks | observed counts | this tier IS measured process behaviour. |
| escalation honesty | 3 escalations (`abt-s2007-08-requeue`, `-09-release`, `-10-timeout`), each with a recorded resolution, a decided-by principal and `closed_by: human` | observed records | the harness proves the reconciliation path exists; it does not prove a human runtime review happened. |
| `SELECT NOW()` vs process clock | probe/sweep follows the DATABASE instant even when the injected clock says 2099 or 1970 | observed behaviour | genuinely measured (concurrency + lease suites, DB replay). |

`guardCoverage` over the offline run: all eleven frozen guards exercised —
`guardBacklogToReady` 15/1, `guardReadyToClaimed` 10/0, `guardClaimedToRunning`
8/0, `guardRunningToInReview` 3/0, `guardInReviewToDone` 1/3, `guardRelease` 1/0,
`guardBlock` 3/0, `guardUnblock` 1/0, `guardFail` 1/0, `guardCancel` 3/0,
`guardRequeueAfterReconciliation` 0/2 (accepted / refused).

**NOT_MEASURED**: empirical semantic quality, human review quality, real cost,
real latency, production SLO, incident rate, any population-level statement.

---

## 5. A-MVP case table (`pilots/scenario-a/acceptance-cases.json`)

The file itself records `execution: NOT_RUN` for every case. A-MVP stays
`NOT_RUN`. **Fixture and replay evidence never upgrade a `NOT_RUN`
retrospectively** (issue #7; frozen spec rule 8), and the engineering probes
below are evidence about the *boundary refusing*, not about an executor,
a reviewer or a semantic accuracy existing.

| Case | Requirement | Execution | Engineering evidence recorded | Why it is not claimed | Status |
| --- | --- | --- | --- | --- | --- |
| A-MVP-01 | Two distinct **real** agent adapters execute through the same versioned contract; record binaries, versions, access, runs | NOT_RUN | NOT_RUN: the `veritas.adapter/1.0.0` interface check and the `NOT_RUN_REAL_ADAPTER` probe are evidence about the boundary, not two distinct installed executors. The host probe found 5 installed candidate executors (`adr-codex-local`, `adr-pi-local`, `adr-claude-code-local`, `adr-opencode-local`, `adr-hermes-local`) and 1 absent (`adr-generic-cli`); every recorded run used a scripted test transport. | a real installed executor, an authenticated human reviewer and an authorized budget are prerequisites of every A-MVP case; none exists in this repository or on this host | **NOT_RUN** |
| A-MVP-02 | Generic CLI discovery and an additional approved agent work **without changing core** | NOT_RUN | NOT_RUN: no generic-CLI discovery run; `probeRealAdapters` reports `adr-generic-cli` `installed: false`. | same | **NOT_RUN** |
| A-MVP-03 | Scheduler chooses READY tasks by priority then ID, validates registered capabilities, dependencies and budget, emits an explanation | NOT_RUN | NOT_RUN as an A-MVP case. The offline two-run comparison exercises the deterministic selection order and the probe suite is green, but it drives a test transport, not an approved runtime. | same | **NOT_RUN** |
| A-MVP-04 | Crash/timeout/cancel terminate the process group, fence late writes, reconcile unknown effects | NOT_RUN | NOT_RUN: cancel/timeout/fence handling is proven against the boundary; process-group termination for the selected OS/sandbox is not proven here (the S2-002 process-tree limits apply). | same | **NOT_RUN** |
| A-MVP-05 | Human creates a small change; claim → workspace → execute → tests → IN_REVIEW → authenticated human decision → journal replay | NOT_RUN | NOT_RUN: no authenticated human performed that cycle in this verification. The 3 escalations in the offline run were closed by a **fixture principal** `prn-s2007-owner`. | same | **NOT_RUN** |
| A-MVP-06 | Atomic lease race with two concurrent workers yields exactly one lease | NOT_RUN | NOT_RUN as an A-MVP case. The two-process claim race really ran on disposable PostgreSQL in this verification (probe `two_process_claim_race`; DB replay `contended`: `contested_lease_rows 1`, `contested_active_leases 1`), but no real adapter executed the claim and no independent human observed it. | same | **NOT_RUN** |
| A-MVP-07 | Replay produces zero duplicate external effects using persistent idempotency keys | NOT_RUN | NOT_RUN as an A-MVP case. Idempotent dispatch and crash/restart recovery are covered by the probe families and a green DB replay — against a disposable database and a scripted transport. | same | **NOT_RUN** |

The other 41 cases in the same file (A-OUT-01..14, NEG-01..27) are artifact and
negative cases for the wider SolutionPack and are also `NOT_RUN`; they are out
of the S2-007 engineering scope and are not restated here.

---

## 6. Hard-gate counters

All seven must be 0. Sources are the three counter-bearing records; the
aggregator lists them with its binding verdict.

| Counter | `evidence/s2-007-security-probes.json` (bound, fresh) | `evidence/s2-007-db-comparison.json` (bound, fresh) | `evidence/s2-007-comparison.json` (**not** commit-bound) | Verdict |
| --- | --- | --- | --- | --- |
| `crossWorkspaceLeaks` | 0 | 0 | 0 | 0 |
| `authorityExpansions` | 0 | 0 | 0 | 0 |
| `duplicateActiveLeases` | 0 | 0 | 0 | 0 |
| `duplicateExternalEffects` | 0 | 0 | 0 | 0 |
| `staleFenceMutations` | 0 | 0 | 0 | 0 |
| `missingJournalOrOutbox` | 0 | 0 | 0 | 0 |
| `falseApprovals` | 0 | 0 | 0 | 0 |
| aggregate | `hardGates.ok: true`, `violations: []` | `hardGates.ok: true`, `violations: []` | `hardGates.okA/okB: true` | **all zero** |

The probe runner also reports `hardGates.notRun: []` and `omits: []`: no
mandatory probe was skipped and no omit is unaccounted. The
`duplicateExternalEffects` counter is not read from an HTTP log: the DB replay's wrong-run control
and the `effects_issued_after_blind_retry {a:1,b:1}` observation are what make
"exactly one effect" provable.

---

## 7. Execution boundary statement

**Veritas owns** the canonical, single-source-of-truth state: the TaskBrief and
its digests, the policy, the board (nine states, one monotonic revision, one
active lease, one fencing token), the budget authorization (numeric
task/campaign/day limits in an explicit currency and timeout — an unassigned
budget is not zero, and a free model is not an authorization), the append-only
journal/audit/outbox, the evidence and the decisions. `DONE` is reachable only
through an authenticated human or a separately authorized deterministic gate.

**AgentOS does** exactly one thing at this boundary: execute an authorized run
through the versioned handoff `veritas.execution/1.0.0` (`ExecutionRequest` in,
`ExecutionEvent` / `ExecutionResult` out). It is not a second source of truth,
not an approval body, and it cannot mint a grant, a lease, a fence, a budget or
an identity.

**What Veritas does NOT do** (issue #7 and frozen spec rule 4): it does not
implement an arbitrary shell runner; it does not authorize real agent work; it
does not grant a hidden UI button authority — every mutating call re-checks the
server-side actor, grant and canonical arguments immediately before the side
effect; and the public synthetic demo (`veritas_demo_*`, `src/lib/board.ts`,
`src/app/api/board/route.ts`, `scripts/veritas-cli.mjs`) keeps its labelling and
gained no mutating, execution or approval endpoint. The live board lives in the
disjoint `agentboard_*` namespace; there is no data-copy step, no backfill and
no view from the demo tables into the live board. A digest is an integrity
control, never a signature and never an identity; source, logs, prompts, model
output and client payloads are data, never capability.

Discovery reports `mode: LIVE_AGENT_BOARD`, `executionEnabled: false`,
`finalExecutionEnabled: false`, `realAdapterStatus: NOT_RUN_REAL_ADAPTER`,
`approvalEnabled: true`, 9 states, 27 commands, and the digests of the eight
contract documents.

---

## 8. Negative-probe coverage (six mandatory families)

41 probes, all executed through the production-facing path
(`commands.execute` / `handleRequest` — never a private helper) on a disposable
PostgreSQL. Source: `evidence/s2-007-security-probes.json` →
`familiesAttempted` + `probes`.

| Family (issue §5) | Probes (all `pass`) | Counter(s) touched | Independent test coverage |
| --- | --- | --- | --- |
| 1. principal forgery | `forged_principal_in_body`, `forged_principal_in_header`, `forged_principal_in_options_env`, `forged_principal_in_prompt_text`, `forged_grant_in_arguments`, `forged_lease_and_fence_in_arguments`, `cross_workspace_read_is_empty`, `cross_workspace_write_refused`, `cross_workspace_discovery_is_empty` (9) | `authorityExpansions`, `crossWorkspaceLeaks` | `tests/agentboard/policy.test.mjs` — "the command boundary is closed (confused deputy)": unknown argument, non-canonical argument NAME, prototype-polluting key, authority-shaped nested argument, argument naming another resource, omitted authorized target, foreign fence/lease id, wrong id family, key shape; plus "the task ACL is the only visibility authority" (unknown/malformed ACL, empty allowlist is not a wildcard) and `redact()` tests. `tests/agentboard/execution-callbacks.test.mjs` — cross-workspace callback `ACL_DENIED`; a payload asserting a larger scope/bigger budget is DATA. `tests/agentboard/contracts.test.mjs` — "the public demo fixture is not a live BoardTask" (demo row shape, renamed columns, demo ids). |
| 2. concurrent claim | `two_process_claim_race`, `concurrent_claims_in_one_workspace`, `stale_fence_after_reassign`, `stale_fence_after_expiry`, `stale_fence_after_cancel`, `stale_fence_after_restart` (6) | `duplicateActiveLeases`, `staleFenceMutations` | `tests/agentboard/concurrency.test.mjs` — two INDEPENDENT processes racing for one task, in-process serialization, expiry follows the DATABASE clock, late callback after expiry/cancel/restart mutates nothing. `tests/agentboard/lease.test.mjs` — exactly one ACTIVE lease, strictly monotonic fence, stale fence refused on every mutating operation, expiry never requeues by itself. DB replay: `contended` phase, two child processes, one lease. |
| 3. idempotency and crash | `same_key_different_payload`, `mutating_command_requires_idempotency_key`, `replayed_dispatch_sends_once`, `crash_after_send_before_ack`, `crash_before_intent_is_redispatchable`, `committed_side_effects_are_journalled`, `refused_side_effects_write_nothing` (7) | `duplicateExternalEffects`, `missingJournalOrOutbox` | `tests/agentboard/idempotency.test.mjs` — replay returns the first result and writes nothing new, different digest → `IdempotencyConflict` mutating nothing, key is a canonical function of the arguments, replay across the execution boundary. `tests/agentboard/recovery.test.mjs` — crash inside a write, PENDING row re-dispatchable and sent exactly once, SENT without ACK escalates and is NEVER re-sent, transport death escalates, the outbox state machine never skips SENT, `outbox.attempts` accounts for every crossing. DB replay crash phase (SIGKILL after SEND, recovery reissues nothing). |
| 4. substitution and approval | `substituted_task_brief`, `swapped_policy_and_manifest_digest`, `hidden_budget_change`, `producer_cannot_approve`, `uncalibrated_verifier_cannot_approve`, `self_approval_is_refused` (6) | `falseApprovals`, `authorityExpansions` | `tests/agentboard/execution-callbacks.test.mjs` — foreign brief digest refused as `MALFORMED_RESULT`, producer cannot approve, uncalibrated semantic verifier cannot be the `DONE` gate, a `SUCCEEDED` result is collected into `IN_REVIEW` and never into `DONE`. `tests/agentboard/policy.test.mjs` — "a digest is an integrity control, never a signature", "the producer is never the gate", "an unassigned budget is not zero" and the settle/overspend group. `tests/agentboard/recovery.test.mjs` — closing a `RECONCILIATION_REQUIRED` run requires an authorized decider, a payload may not name its own decider, an unknown resolution is refused. DB replay check `producerCannotApproveItsOwnRun: true`. |
| 5. callback integrity | `malformed_callback_refused`, `out_of_order_callback_refused`, `duplicate_callback_refused`, `unknown_outcome_is_not_retried`, `timeout_is_not_retried`, `cancel_then_callback_refused`, `no_false_state_advance` (7) | `falseApprovals`, `missingJournalOrOutbox`, `duplicateExternalEffects` | `tests/agentboard/execution-callbacks.test.mjs` — malformed event `MALFORMED_RESULT` and changes nothing, out-of-order sequence refused and never repaired by guesswork, duplicate callback produces no second record and no duplicate effect, stale-fence callback `STALE_FENCE` and no row. `tests/agentboard/recovery.test.mjs` — an unknown outcome never becomes `IN_REVIEW`, `DONE` or a retry; a new-key result is refused and the same key replays; a duplicate event is refused and the identical one replays; an undetermined effect is refused at the review and the `DONE` edge. DB replay refusals: `lateResult: TRANSITION_NOT_ALLOWED`, `reconcileByProducer: AUTH_REQUIRED`. |
| 6. injection and traversal | `injection_in_prompt_text_grants_nothing`, `injection_in_source_and_log_grants_nothing`, `secret_never_reaches_a_record`, `workspace_traversal_refused`, `symlink_escape_refused`, `forbidden_sandbox_blocked` (6) | `authorityExpansions`, `crossWorkspaceLeaks` | `tests/agentboard/injection.test.mjs` — injection in a task description, in a quoted source excerpt, in an artifact body and a log line; a secret-shaped value redacted before it reaches store/outbox/journal/API (proven through `handleRequest`); lexical traversal; symlink escape; non-executable profile → `BLOCKED_SANDBOX`. `tests/agentboard/policy.test.mjs` — "the workspace ref is relative and contained" (absolute, traversal, backslash, NUL, Windows device name, unresolvable ref, empty root set is not a wildcard) and "only a proven sandbox profile is executable". |

Family totals as recorded: 9/9, 6/6, 7/7, 6/6, 7/7, 6/6 = 41/41 passed,
0 failed, 0 not run, no empty family, no unknown counter.

---

## 9. Dependency gate result

**Resolved on Windows.** On the Linux development host this gate read **exit 1**,
internal status **`BLOCKED_DEPENDENCY`**, sole issue
`rerun.verify-s2-002:failed_nonzero(exit=1)` — the cancellation control is
Windows-only and cannot be measured here. On Windows at `c922c09` the same gate
passes, because the control runs and the crash/restart path now terminates the
process tree; `verify:s2-007` returned `COMPLETE_WITH_LIMITS` with 4/4 mandatory
gates. The paragraphs below record the development-host observations that led to
that resolution and are kept as history, not as the current status.

- Base pinned and re-verified: `origin/main` =
  `f590d37ea8e861431abf3f89f59e01a889ab903d`, tree
  `c15ce47a35987c27a7610d4b8e8847b59f776924`, with exactly the two expected
  parents; the upstream chain is anchored to
  `evidence/s2-006-dependency-binding.json` → `s2_005.canonicalMerge`.
- Implementation base `d7ea79fbac357ea17057511044d5235655ee33e1` descends from
  the pinned base; the twelve frozen artefacts are byte-identical (§1.1).
- S2-003/004/005 are admitted only as explicit references to versioned
  artifacts; their content is not an instruction to the scheduler. S2-006E is
  **not** a mandatory dependency of the core: the official S2-006 status stays
  `NEEDS_INPUT`, and a verifier-derived signal is admitted only as an
  engineering property — never as an automatic `DONE` gate, never as approval,
  never as closure of an unknown outcome.
- `DONE` reachability is asserted structurally (no outgoing edge, exactly one
  incoming edge guarded by `guardInReviewToDone`, which calls
  `assertHumanOnlyApproval` + `assertNotSelfApproved`) and textually (no
  `src/lib/agentboard/` line names a verifier signal token and the `DONE` state
  without a refusal marker). The gate reported no issue for this assertion in
  its single run — its only reported issue was the `verify:s2-002` re-run — but
  the gate as a whole was `BLOCKED_DEPENDENCY` on this host, so no green binding
  was read out of it there. On Windows the gate passed at `c922c09`.
- Sandbox gate: the requested profile `sbx-podman-local-restricted-v1`
  resolved to `ALLOW` with `liveExecutionAllowed: true`. This is the internal
  S2-002 gate answering, and it authorises a live run **only** if a genuinely
  different installed executor also exists — it does not, so no live run was
  performed.
- `manifest:check` inside the gate: exit 1, declared deferral state
  `REQUIRES_FINAL_MANIFEST` (the root manifest is regenerated once at the end of
  the task). It is recorded with its real exit code and is not reported green.
- Consequence the gate recorded for itself: while it was `BLOCKED_DEPENDENCY` on
  this host, S2-007 could document and design offline but could not record an
  implementation result and could not run an executor. No executor was run at any
  point in this work, on either platform.

---

## 10. Residual limitations

1. No real AgentOS/Codex/pi adapter is installed here. Every
   execution-boundary observation comes from the `veritas.adapter/1.0.0` test
   transport: `NOT_RUN_REAL_ADAPTER`. The host probe found 5 installed candidate
   executors, and none of them executed a run.
2. `assuranceStatus` is `NOT_MEASURED`; nothing here calibrates a semantic
   verifier, and the official S2-006 status stays `NEEDS_INPUT`.
3. The database gate runs against a disposable podman container (loopback only,
   tmpfs, random runtime credentials, container removal verified). It validates
   transactions, fencing, contention and recovery semantics — not operations,
   backup/restore, migration of real data or multi-tenant behaviour at scale.
4. Every metric in §4 above the "boundary activity" tier is an engineering
   proxy over an injected clock. None is an empirical quality, cost or latency
   measurement.
5. The offline A/B evidence is not commit-bound (§2, G10), and the aggregator's
   declared `evidence/s2-007-db-replay.json` does not exist (§3.2).
6. The lease-expiry sweep has no `COMMANDS` entry; `tasks.lease.reassign`
   reports a `NaN` `fencing_token`; `replayed` does not reach most callers;
   `outbox.dispatch` does not key its ledger on the caller's idempotency key
   (§3.2). No safety invariant is broken by these, but they are unfinished
   interface work, not polish.
7. The S2-002 re-run inside the dependency gate is currently red, so the
   upstream binding is not currently proven green; and three tracked
   `evidence/s2-006-*.json` files are modified in the worktree with an
   unexplained cause.
8. This report certifies the engineering boundary described in issue #7 §2–§5.
   It is not an `A-MVP PASS`, not a SolutionPack sign-off, not production
   readiness, and not an authorization to spend, deploy or act externally.

---

## 11. ROLLBACK path

**Last known-good state**: the commit that contains the S2-007 frozen
foundation and nothing else — `d7ea79fbac357ea17057511044d5235655ee33e1`
(HEAD tree `b1a72d70554f1c14f6369fefb73756a559a811ba`). Base `origin/main`
before S2-007 is `f590d37ea8e861431abf3f89f59e01a889ab903d`.

1. **Code / evidence**: revert the S2-007 commits, or reset the worktree to
   `d7ea79f…`. Everything the ticket added outside that commit is untracked or a
   `package.json` script block, so `git checkout -- package.json` plus removing
   the S2-007 files returns the tree to the known-good state. The public
   synthetic demo is untouched by S2-007 and keeps working.
2. **Database**: migration `0008_agent_board.sql` has **no** `down` section;
   `scripts/apply-migrations.mjs` is forward-only. Rollback is therefore an
   explicit, hand-reviewed drop of the `agentboard_*` namespace and its
   sequences, in one transaction, followed by removal of the recorded row:
   `DROP TABLE IF EXISTS` for `agentboard_task`, `agentboard_acl`,
   `agentboard_lease`, `agentboard_adapter`, `agentboard_budget_grant`,
   `agentboard_budget_spend`, `agentboard_run`, `agentboard_execution_event`,
   `agentboard_transition`, `agentboard_audit`, `agentboard_outbox`,
   `agentboard_operation`, `agentboard_reconciliation`;
   `DROP SEQUENCE IF EXISTS agentboard_fencing_token_seq, agentboard_sequence_seq`; and
   `DELETE FROM veritas_schema_migrations WHERE name = '0008_agent_board.sql'`.
   Migrations 0001–0007 and the `veritas_demo_*` fixtures are NOT affected:
   0008 is the only migration this ticket adds, and it creates a disjoint
   namespace. Before dropping, export `agentboard_task`,
   `agentboard_transition`, `agentboard_audit`, `agentboard_outbox` and
   `agentboard_run` if any evidence must be kept — dropping the journal is
   irreversible.
3. **Evidence**: delete `evidence/s2-007-*.json` and the S2-007 scripts; the
   gates are re-runnable from a clean checkout.
4. **Verification after rollback**: `npm run verify:s2-007` must report
   `NOT_RUN` / `BLOCKED_DEPENDENCY` rather than green, and the public demo
   (`/`, `/api/board`, `scripts/veritas-cli.mjs`) must still answer from the
   `veritas_demo_*` fixture.
5. **Explicitly not rolled back by S2-007**: nothing from S2-001…S2-006, no
   `veritas_demo_*` data, no contract outside `contracts/{board,adapter,dispatch,execution}-*.schema.json`.

---

## 12. STOPPING CONDITIONS

This must be reported as `BLOCKED_DEPENDENCY` / `PARTIAL` / `NOT_RUN` — never as
a finished solution — in any of the following cases:

1. `origin/main` advances past the pinned merge
   `f590d37ea8e861431abf3f89f59e01a889ab903d` without a reviewed rebind record
   in `evidence/s2-007-dependency-binding.json`. An ancestor check is not a
   bind. → `BLOCKED_DEPENDENCY`.
2. The mandatory upstream re-runs (`verify:s2-002-dependencies`,
   `verify:s2-002`) are not green, or their canonical evidence cannot be
   restored byte-identically. → `BLOCKED_DEPENDENCY`. This WAS the state on
   the Linux development host throughout this work; on Windows at `c922c09`
   both re-runs are green, which is what moved the verdict.
3. The internal S2-002 sandbox gate does not ALLOW **exactly**
   `sbx-podman-local-restricted-v1`. A `NO_EXEC` or `*_blocked` profile is never
   a substitute; the live run stays forbidden and the gate is
   `BLOCKED_DEPENDENCY`.
4. No genuinely distinct installed executor, or no authenticated human reviewer,
   or no authorized budget. → A-MVP stays `NOT_RUN`, the ticket is `PARTIAL`,
   and the engineering result is at most `COMPLETE_WITH_LIMITS`. This is the
   current state.
5. Any hard-gate counter is non-zero, even with a green test count.
   → `REVISE` or `BLOCKED_SAFETY`.
6. A `node --test` gate, the probe gate or the DB gate is skipped, or the DB
   gate reports `NOT_RUN_DB` for a mandatory database check.
   → `NOT_RUN`, never green.
7. `manifest:check` or `inventory:check` is red for any reason other than the
   declared `REQUIRES_FINAL_MANIFEST` deferral, or the final regeneration is
   never performed. → the final acceptance set is not green.
8. The worktree is dirty at the moment of the final acceptance run.
   → ceiling `PASS_WITH_LIMITS`, never `COMPLETE_WITH_LIMITS`.
9. The red version-handshake defect in the frozen `contracts.mjs` is neither
   fixed by its owner nor explicitly withdrawn with a spec decision.
   → `REVISE`; the `test:s2-007` gate stays exit 1.
10. An evidence artifact cannot be re-bound to the current commit/tree, or a
    tampered copy of it is accepted. → `REVISE` (the aggregator's tamper matrix
    currently detects 12/12, and that property must not regress).
11. Any suggestion to close a `NOT_RUN` A-MVP case, raise `assuranceStatus`
    above `NOT_MEASURED`, or treat fixture/replay evidence as real-adapter or
    human-review evidence. → refuse; a gate may not be renamed to obtain a
    green status.

### 12.1 Change requests to the owners of files this pass did not touch

1. `src/lib/agentboard/contracts.mjs` (frozen, commit `d7ea79f…`) — `majorOf()`
   must parse the version **after** the `veritas.execution/` prefix (or accept
   a prefixed semver), so that same-major/different-minor is reported as
   `{ negotiated: true, minor }` and only a genuinely unknown major is refused
   with "unsupported execution major version". Until then
   `tests/agentboard/contracts.test.mjs:598` is red and `test:s2-007` exits 1.
2. `scripts/verify-s2-007.mjs` — the db-replay gate contract names
   `evidence/s2-007-db-replay.json`, which the replay never writes; align the
   declared list with `evidence/s2-007-db-comparison.json`.
3. `scripts/s2-007-run.mjs` — the offline run/comparison records carry no
   commit/tree anchor, so the aggregator reports that counter source as
   `bound: false`. Adding the same `git.commit_sha` / `git.tree_sha` anchor the
   DB replay uses would close the only freshness gap in §2 (G10).
4. `src/lib/agentboard/commands.mjs` / `store.mjs` — `tasks.lease.reassign` must
   not report `fencing_token: NaN`; the response `replayed` flag should reach the
   caller; `outbox.dispatch` should key its ledger on the caller's idempotency
   key so the command-level replay branch can fire.
5. The three modified `evidence/s2-006-*.json` files must be restored or their
   modification explained before any clean-checkout claim.

---

## 13. Command log for this report

Every row below was executed on this host by the integration pass that also
applied the §0.1 fixes. Exit codes are real, not quoted.

| Command | Exit | Result |
| --- | --- | --- |
| **Windows acceptance at `c922c09`** | | |
| `npm run verify:s2-007` (Windows, CIM) | **0** | `COMPLETE_WITH_LIMITS`, 4/4 mandatory gates |
| `npm run verify:clean-checkout` (Windows, CIM) | **0** | **44/44 commands PASS** |
| `npm test` (Windows, PostgreSQL) | **0** | 1194/1194 |
| Linux, this repository | | |
| `npm run --silent test:s2-007` | **0** | 338 tests, 64 suites, 338 pass, 0 fail, 0 skipped |
| `npm run --silent test:s2-007-security-probes` | **0** | `PASS`, 41/41 probes, 6/6 families, `notRun: 0`, all 7 counters 0, `databaseTier: podman_disposable` |
| `npm run --silent s2-007:run` | **0** | `ok: true`; A and B canonical digests equal, identities distinct, 118/118 expectations, 11/11 guards, 0 violations |
| `npm run --silent verify:s2-007-db-replay` | **0** | `PASS`, PostgreSQL 17.11, 8 migrations × 3 schemas, canonical digest A === B, 7 counters 0, container removal verified |
| `npm run --silent verify:s2-007-dependencies` (Linux dev host) | **1** | `BLOCKED_DEPENDENCY`; sole issue `rerun.verify-s2-002:failed_nonzero(exit=1)`; sandbox gate `ALLOW` for `sbx-podman-local-restricted-v1`; 13 board files scanned. **Windows `c922c09`: exit 0** |
| `npm run --silent verify:s2-007` (aggregator, Linux dev host) | **1** | refused to certify while that host's dependency gate was red. **Windows `c922c09`: `COMPLETE_WITH_LIMITS`, 4/4 mandatory gates** |
| `npm run --silent typecheck` | **0** | clean |
| `npx eslint . --ignore-pattern '.bb/**'` | **0** | clean |
| `npm run build` | **0** | Next.js 16.3.4, compiled; routes `/api/agent-board`, `/api/agent-board/[...path]`, `/api/board`, `/api/capabilities`, `/api/health` |
| `npm run --silent db:migrate` | **0** | 8 migrations applied, `0008_agent_board.sql` last |
| `npm test` (full suite) | **1** | 1116 tests, 1103 pass, **6 fail, 7 skipped**. All 6 failures are in `tests/identity/replay-runs.test.mjs` (4) and `tests/identity/security-probes.test.mjs` (2) — the S2-002 sandbox counters. **Zero** S2-007 failures. Both files fail identically at the untouched base commit (4 and 2), so the 6 are pre-existing host-portability failures, not regressions. |
| `git diff --check` | **0** | clean |
| `npm run --silent board:types` | **0** | `src/lib/agentboard/contracts.d.ts` regenerates byte-identical (no drift) |
| `npm run inventory:check` | 0 after the final `inventory:write` | — |
| `npm run manifest:check` | 0 after the final `manifest:write`/`manifest:closure` | — |
| `node scripts/validate-contracts.mjs` | **0** | 11 schema examples, 25 mutations rejected; S2-007 contracts and code added to the frozen set by an explicit `--freeze` |
| `node scripts/check-public-artifacts.mjs` | **0** | 746 tracked files scanned, 0 credential-shaped literals |
| `npm run verify:clean-checkout` | **1** | Real `git archive HEAD` + fresh `npm ci`. 45 of 47 commands PASS, including `validate-contracts`, `check-public-artifacts`, `manifest --check`, `check-inventory`, `typecheck`, `lint`, `build`, `npm audit` (runtime and full), `verify:postgres-smoke`, `verify:podman-sandbox`, `verify:gvisor-sandbox` and every S2-003…S2-006 gate. The **only 2 failures** are `npm run test:identity` ("probe G must run on this platform") and `npm run verify:s2-002` — the pre-existing S2-002 Linux counter failures proven identical at untouched base `f590d37`. |

### 13.1 Live HTTP verification (real server, real PostgreSQL)

The built server was started against an ephemeral PostgreSQL 17.11 container
with 8 migrations applied and the declared routes probed directly:

| Request | Observed |
| --- | --- |
| `GET /api/agent-board/capabilities` | `200`, `mode: LIVE_AGENT_BOARD`, `executionEnabled: false`, `realAdapterStatus: NOT_RUN_REAL_ADAPTER`, contract digests only, no tenant data |
| `GET /api/agent-board/tasks?workspace_id=…` (no credential) | `401 AUTH_REQUIRED` |
| `GET /api/agent-board/tasks/abt-x` (no credential) | `401 AUTH_REQUIRED` |
| `POST /api/agent-board/tasks` with a **forged** body `principal_id`/`actor_kind`/`capabilities`/`budget_grant` and no `Authorization` header | `401 AUTH_REQUIRED` — a body field never authenticates a caller |
| `POST /api/agent-board/tasks/abt-x/transition` → `DONE` (no credential) | `401 AUTH_REQUIRED` |
| `GET /api/agent-board/nope/nope` | `422 NEEDS_INPUT / HTTP_ROUTE_UNKNOWN` |
| `GET /api/board` (public demo) | `200`, `mode: PUBLIC_SYNTHETIC_DEMO`, `executionEnabled: false`, `approvalEnabled: false` — unchanged, and it gained no mutating, execution or approval endpoint |

No S2-007 gate mutates another ticket's evidence: after restoring the S2-002 and
S2-006 records from the pinned commit, each of the six S2-007 gates was run
individually and each left them byte-identical.

---

## 13.2 Two defects the repository's own gates found in this delivery

The repository's existing integrity gates are not decorative; two of them caught
real problems in the S2-007 payload, and both were fixed rather than suppressed.

| Gate | Finding | Fix |
| --- | --- | --- |
| `scripts/check-public-artifacts.mjs` | Four `tests/agentboard` fixtures embedded credential-shaped literals: a PostgreSQL connection authority (user, password and host in one literal), a GitHub token shape (`injection.test.mjs`) and a PEM private-key header (`policy.test.mjs`). A tracked file must never carry one. | The fixtures now assemble the shape from parts, so the strings `redact()` and the redaction helpers are asked to catch are byte-identical while the source carries no credential shape. **The scanner itself was not weakened.** |
| `scripts/validate-contracts.mjs` | The eight new S2-007 schemas were covered by the existing `contracts` freeze target, but the implementation that enforces them was not frozen with them — the payload could have drifted from its contracts. | S2-007 is added to `frozenTargets` alongside every earlier ticket (implementation, tests, migration, HTTP surface, runners, binding evidence) and the manifest was refrozen with an explicit, reviewed `--freeze`. |

## 13.3 Container cleanup defect in the S2-003…S2-006 replays (found after the green run)

After the 44/44 clean-checkout, four temporary containers from the **older**
S2-003, S2-004, S2-005 and S2-006 database replays were still present. The owner
removed them and verified their absence, so the acceptance result above is not
affected — the run had already completed. But the cleanup itself is defective in
those frozen scripts, and it is a real finding rather than noise:

* it is reproducible only at the end of a full clean-checkout, so a per-command
  run never surfaces it;
* it leaves host state behind after a run that otherwise reports success, which
  is exactly the shape of an unnoticed leak;
* the fix belongs to S2-003…S2-006, whose scripts are frozen with their own
  tickets' evidence, so it cannot be folded into this one.

This ticket's own replay (`verify:s2-007-db-replay`) was verified on every run
during this work to leave **no** S2-007 container behind, and the S2-007
probes and run harness provision and remove their own disposable PostgreSQL.

## 13.4 Defects an independent code review found in this delivery

A review of this branch before merge found one blocking defect, one that made
the evidence non-reproducible, and a set of smaller ones. None of them is
cosmetic: each one either breaks tenancy, breaks re-runnability, or lets a
counter that is supposed to move stay still. All are fixed on the branch
rather than deferred, except where a note says otherwise.

### The lease sweep was a cross-tenant write

`store.expireLeases({ actor, now })` selected every `lease_state = 'ACTIVE'`
row in the installation. It was the only write path in `store.mjs` that did
not refuse a cross-workspace target — `claimTask` raises
`cross_workspace_claim_denied`, `createRun` raises
`cross_workspace_run_denied`, `reassignLease` raises
`cross_workspace_adapter_denied`, and `_assertVisible` refuses a
cross-workspace read absolutely. A caller holding a store handle in workspace
A could therefore withdraw workspace B's leases, bump their task revisions and
journal the change under A's sweep.

Two things hid it. The disposable-container path in the probe suite starts
empty, so no other tenant was ever present. And in a single-workspace
installation the sweep behaves identically, so the expected-value table in the
DB replay does not change.

The sweep is now workspace-scoped, the scope is part of the idempotency key so
two workspaces swept at the same database instant are two operations rather
than one replayed into the wrong workspace, and a lease whose task row names a
different workspace is skipped rather than acted on.
`tests/agentboard/lease.test.mjs` seeds two workspaces and asserts that A's
sweep moves nothing in B and that an unscoped sweep is a typed refusal; the
test was confirmed to fail when the filter is removed.

### The security probes only passed on a pristine database

The same defect, in the module that produces the hard-gate evidence, and found
while resolving the merge with `main` rather than in the first review pass.

Every probe id is deterministic on purpose — the record is a content address,
and the same tree has to yield the same ids, keys and digests — and several of
them are `agentboard_task.task_id` or `agentboard_adapter.adapter_id`, which are
PRIMARY KEYs. Against a **supplied** database the suite therefore measured its
own leftovers from the previous run. The two database-backed concurrency probes
are where it showed: the second run found its task already `CLAIMED` with an
`ACTIVE` lease, read its own correctly-refused claim as a duplicate lease, and
reported `duplicateActiveLeases=1` and `staleFenceMutations=1` — a
`BLOCKED_SAFETY` verdict for a run in which nothing was violated. Reproduced:
41/41 on a virgin database, 39/41 on the second run, 39/41 on the third.

The `external` tier's own `note` had admitted the collision while describing it
as a problem with *another live run*. It is a problem with the previous run of
the same gate, which is the case that matters: `verify:s2-007` runs this gate
as a mandatory step, so a developer who points `DATABASE_URL` at a persistent
database gets a gate that is green once and red forever after.

The two candidate fixes both had a real cost, so the third one won:

* make the ids unique per run — fixes the collision and breaks the record's
  reproducibility, which is the record's whole purpose;
* keep the ids and tell the operator to use a fresh database — that is the
  status quo, just louder;
* **purge the module's own namespaces before the run** — deterministic ids
  preserved, the tier becomes re-runnable, and the removal is reported in the
  record so a reader can tell a fresh measurement from an inherited one.

`purgeProbeFixtures` deletes only rows inside the five probe workspaces and
only adapters under `adr-probe-`, visits the tables in foreign-key order, and
returns the per-table counts. A row outside both sets is never touched whatever
it is, and `summary-aggregator.test.mjs` pins that against a row planted in an
operator-owned workspace. Verified on this host: five consecutive 41/41 runs
against one database, and `npm test` green twice over the same database.

### The database-backed tests only passed on a pristine database

`tests/agentboard/concurrency.test.mjs` used fixed `task_id` and `adapter_id`
values. Both are PRIMARY KEYs, so both are global, and the file's
`deterministicIds(namespace)` namespaced the store-minted ids per store
INSTANCE — which says nothing about a second run of the same instance seed
against the same database.

The podman path started a fresh container and hid it. The path that matters is
the one that reuses a developer-supplied `DATABASE_URL`, which is what
`npm test` and the Windows acceptance use. On the second run against one
database, five of the file's tests failed, and they failed *misleadingly*: the
"exactly one committed state change" assertion compared a freshly read revision
against a task the previous run had already claimed, so the invariant under
test was never measured.

Every identifier the file creates is now scoped per process, in the ids the
store mints as well as in the task and adapter names. `npm test` is green four
consecutive times against one database.

### The recycled-pid guard introduced on this branch checked the wrong thing —
### and the mechanism was handed to PR #42

This branch had added a POSIX re-validation so that a pid recycled between the
process-tree snapshot and the kill would not be SIGKILLed. It compared the
descendant's **current parent** against the captured set. `terminateTree` kills
the root first, so every surviving descendant is re-parented to init within
milliseconds; the guard therefore skipped exactly the processes it existed to
kill, and `settleTree` re-killed the captured set with no check at all four
lines later, so a recycled pid was signalled anyway. Measured on the host: a
child that forks a grandchild, the child is SIGKILLed, and the grandchild's ppid
becomes 1 — not a captured pid. The `skipped` counter that recorded this was
written and never read.

An identity-based replacement was written and tested, and then **removed from
this branch before merge**. [PR #42](https://github.com/SpaceDazher/Veritas/pull/42)
owns issue #41 and already implements the same conclusion — a process is
identified by `/proc/<pid>/stat` field 22 (`starttime`), not by its parent —
more completely, with a dedicated `process-observer.mjs`, two discovery passes,
session and process-group tracking, an observability check on the shape of the
tree, and a `terminationProof` whose `SBX_PID_REUSED` reason code names the
recycling case directly. Both branches started from the same commit and rewrote
the same ~500 lines, so keeping a second implementation here would have made
the merge a silent overwrite in whichever direction it resolved.

What #42 takes from this review is the **finding**, not the code: the parent
comparison is not a valid guard for this problem, and the loop that follows it
will undo any guard that is not applied in both places. That is recorded in
[S2-002-NON-WINDOWS-HOST-ANALYSIS.md](S2-002-NON-WINDOWS-HOST-ANALYSIS.md),
whose table row for `sandbox.mjs` now reads *withdrawn from this ticket*.

The consequence is stated rather than hidden: **`main` keeps the original #41
defect after this ticket merges** — `listDescendants` returns `[]` off Windows,
so `cancel()` can report `survivors: 0` while a re-parented process is still
running. That is not a regression against the state of `main` today, and closing
it is #42's job. This ticket's `verify:s2-002` nevertheless still refuses to
pass on such a host, because an unexercised hard control blocks the gate rather
than passing it; that refusal is the honest-reporting half of the problem and
it stays here.

### Smaller findings, all fixed

| Finding | Fix |
| --- | --- |
| `listTasks` re-read the ACL row it had just loaded, and read it a third time for the wire document: three round trips per task, 600 at `limit: 200`. | One pass per task; the ACL row is loaded once and reused for the visibility decision and the document. |
| `expireLeases` and `collectResult` ignored the result of `updateRows`, so a silently skipped write was possible. The sweep is unattended, and the accumulator is the only record that a result was produced. | Both now treat an empty result as a typed hard failure, as every other write in the file already did. |
| A lease expiry was journalled with `payload.kind = 'lease_rebind'`, the same kind a reassignment uses. A consumer of the journal could not tell "somebody else took over" from "the right ran out". | Now `lease_expire`. The DB-replay projection identifies that transition by the presence of `expired_at` in its payload rather than by the kind string, so a rename cannot silently turn a normalized digest into a compared one. |
| The two sandbox escape counters were separate literal lists that had drifted. The containment list was missing `BLOCKED`, so if the no-exec tier had begun spawning, that trial would have moved neither counter. | Both are derived from the oracle's expectation set. Adding a sandbox control now necessarily moves the counters that watch it. PR #42 edits the same counter expressions for its own new trial, so the two sides have to be reconciled by hand when they meet; this branch's derivation is the one that survives it. |
| `settleBudget` accepted a required `operation_id` whose dedup behaviour was unstated. It is the operation that CREATED the `(grant_id, day_key)` bucket; the ledger is what dedups, and only for a key the caller reuses. | Stated in the method, with the three cases written out, so a caller cannot read the column as a uniqueness guarantee it never was. |
| The route documentation said seventeen and eighteen routes; `HTTP_ROUTES` has nineteen. | Corrected in all three headers. |
| `README.md` had the `S2-008…S2-012` row merged into the `S2-007` cell by a stray `||`, two `S2-007` rows from two commits on the branch, and a claim that the clean-checkout was green when the committed evidence records 36 PASS / 8 FAIL. | Table split, duplicate removed, and the clean-checkout line now matches `evidence/clean-checkout.json`. |

`migrations/0009_agent_board_hardening.sql` adds the index the workspace-scoped
sweep reads. 0008 is frozen by digest — `apply-migrations.mjs` refuses to
continue on `MIGRATION_DRIFT` — so the change follows the existing 0007-over-0005
precedent rather than editing a migration an installation has already applied.
The file also records, next to the tables, why `agentboard_task.active_lease_id`
and `agentboard_outbox.run_id` deliberately carry no foreign key, so the next
reader does not "fix" a decision.

## 14. What was NOT verified

* No genuinely installed AgentOS, Codex or pi executor exists on this host, so
  every real-adapter status is `NOT_RUN_REAL_ADAPTER` and `A-MVP-01..07` are
  `NOT_RUN`. Fixture and replay evidence never changes a `NOT_RUN`
  retrospectively.
* The S2-002 sandbox evidence is a Windows measurement. On this host the two Linux
  counter failures were traced to a single, deliberately skipped Windows-only trial
  scored as a control violation — an accounting defect, and a documented
  `NOT_RUN` property, not an observed escape (see the Verdict and
  [S2-002-NON-WINDOWS-HOST-ANALYSIS.md](S2-002-NON-WINDOWS-HOST-ANALYSIS.md)). That
  host-side `NOT_RUN` used to be the reason the dependency gate was red on
  Linux. **That is no longer true.** PR #42 made the cancellation control
  exercisable on every platform, so after merging `main` this branch runs
  `verify:s2-002` to exit 0 on Linux with the control PROVED there and not
  skipped: `sandbox/cancellation-survivors` reports `SURVIVORS_ZERO` with
  `terminationProof` and `outcomeProof` both `TERMINATED`, and
  `not_run_controls` is 0. The honest-reporting accounting this branch added
  is what makes the two outcomes distinguishable in the record at all — it is
  why "declined" can be read apart from "proved" instead of inferred from a
  zero. See [S2-002-NON-WINDOWS-HOST-ANALYSIS.md](S2-002-NON-WINDOWS-HOST-ANALYSIS.md).
* No production deployment, no spending authorization, no credential
  acquisition and no external action is implied or performed.
* Empirical semantic accuracy is not measured and is not inferred from any
  fixture, replay or synthetic probe.
* The code review in §13.4 changed the store, so **every S2-007 artifact in
  this tree is bound to a commit that is not the merge commit**: the two-run
  comparison, the DB-replay record and the security-probe record. That is not
  a defect in the records — it is what the records are for — but it means the
  acceptance has to be re-run after the merge. `verify:s2-007` refuses a record
  whose commit is not HEAD, and `verify:clean-checkout` additionally has to be
  re-run on the Windows host, because the sandbox and PostgreSQL steps in it
  shell out to `wsl.exe` unconditionally and cannot run elsewhere. The
  committed `evidence/clean-checkout.json` is red (36 PASS / 8 FAIL) and this
  change set does not make it green; the README now says so instead of
  claiming otherwise.
* `scripts/verify-clean-checkout.mjs` predates S2-007 and does not itself
  invoke the S2-007 gates, so clean-checkout coverage of the new boundary comes
  from `verify:s2-007` (the aggregator) rather than from that script. Extending
  it was left as a follow-up rather than editing a frozen, shared S2-002
  verification script late in the task; the S2-007 gates are all run and
  reported independently in §13.
* The work was verified on Linux/x64 only. The committed S2-002 sandbox evidence
  is a Windows measurement; an S2-007 re-measurement on Windows was not
  attempted.
