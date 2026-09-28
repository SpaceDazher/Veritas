# S2-007R: final disposition — engineering COMPLETE_WITH_LIMITS, ticket CLOSED as PARTIAL

- Date: 2026-09-27
- Decided by: the repository owner, in the BB thread that runs #45
- Subject: the closing disposition of issue #45
- What this document is: a record of a DECISION and of the final measured state
- What this document is **not**: evidence, and it upgrades no status

## The decision

Issue #45 is **CLOSED as PARTIAL**. The engineering contour of the ticket is
finished and gated; the acceptance criteria that require a human reviewer, an
isolated execution environment, or a work item outside this ticket are not met,
and they are handed to #47 with an owner and an unblock condition each. The
issue's own rule is that `A-MVP PASS`, production readiness and the final
SolutionPack acceptance are not established by engineering evidence, and nothing
here claims them.

## The final measured state

| field | value |
| --- | --- |
| `engineeringStatus` | `PARTIAL` (all four mandatory gates PASS; the residual is the list below) |
| `realAdapterStatus` | `REAL_ADAPTER_AVAILABLE` — on eight own corroboration checks plus an independent host probe |
| `assuranceStatus` | `NOT_MEASURED` — fixed; no independent human review, no empirical semantic accuracy |
| `aMvpStatus` | `NOT_CLAIMED` — fixed; no named operator accepted a bounded pilot |
| A-MVP-01..07 | **1 PASS**, 5 `NOT_RUN`, 1 `PARTIAL` |

Mandatory gates: `dependencies` PASS, `real-adapter-run` PASS, `comparison` PASS,
`probes` PASS. All seven hard-gate counters are 0. Five of five negative probes
pass with no deferred arm.

## The five acceptance criteria, final state

1. **`A-MVP-01..07 = PASS` on a real run** — **not met.** A-MVP-01 is PASS on
   eight governed runs; the other six are `NOT_RUN` and A-MVP-04 is `PARTIAL`.
2. **`realAdapterStatus` lifted from `NOT_RUN_REAL_ADAPTER` on evidence** —
   **met.** It required eight own checks (the record exists, is bound to this
   commit and tree, carries one minted corroboration per installed provider, both
   digests recompute from the bytes on disk, the log names the same run, the
   executor minted a session id, and no scripted transport is involved) AND a fresh
   host probe finding the named executables installed.
3. **Seven measurements published with a method** — **partially met.** Four are
   `MEASURED`: `accepted_task_quality` 0/8, `pass_at_1` 0/8, `regression_rate`
   0/32, `latency` 6.5 s median. Three are `NOT_RUN` for stated reasons: `cost`
   (pi reports USD, codex reports no billing, and a sum across two bases is not a
   number), `intervention_time` (the event stream carries no terminal event, so the
   window has no endpoints), and the row of `skills_authority_expansion` (its gates
   are computed from per-cell crossing records, and the plant is refused BEFORE any
   crossing — the refusal itself is measured and published in full under
   `authority_probe.measurement_7.real_run_plant`: planted 1, refused 1, granted 0,
   `CAPABILITY_MISMATCH / SKILL_AUTHORITY_EXPANSION_REFUSED`).
4. **`assuranceStatus` reported separately and honestly** — **met.**
5. **No `A-MVP PASS` without a named operator** — **met.** No such claim is made,
   and this decision does not make one.

## What went from red to green in the closing pass, and why

Three controls were refusing to look at themselves:

* **The dependency gate was ours.** It answered
  `constants.mjs:frozen-foundation-working-tree-drift` because this ticket edited
  six frozen paths under the owner's own decision and registered none of them. The
  gate has a mechanism for a legitimate change — a REVIEWED deviation naming the
  commit, matching bytes and a reason. All six are registered that way, so the gate
  verifies them rather than ignoring them.
* **The real-adapter gate asked the wrong question.** The shared S2-007 classifier
  requires a NON-ZERO executor exit and reads an empty pid list as unobserved; both
  are right for the failure-path evidence they were written for and neither can be
  satisfied by a run that succeeded. A gate of this ticket's own now answers one
  question — did distinct installed executors cross the boundary — and the shared
  classifier's verdict is published verbatim beside it with the two disagreements
  named.
* **The plant was not in a run.** The skills authority measurement used a file the
  measurement step wrote into a scratch workspace, so it was a boundary observation
  with no run behind it. The driver plants it into a governed run's own workspace
  now, and the transport refuses it on that run before any crossing.

## What remains, and where it goes

The remainder was handed to **#12 (S2-012)**, which already owns pilot
acceptance and the operator's approval, and #47 was closed on that transfer
(2026-09-28). #12 is where the items below are tracked; this document is their
engineering record.

* **A-MVP-05** — an authenticated human reviewer who is not the producer. This is
  structurally unreachable in an agent run and is the work #12 was created for.

* **A-MVP-02 (c)** — the tracked diff of this ticket touches `contracts/`,
  `src/lib/agentboard/` and `src/lib/identity/`, because the owner's
  `HOST_UNISOLATED` decision did. Either the case is restated for a sanctioned
  exception, or it stays `NOT_RUN`.
* **A-MVP-03** — the *derived* dispatch decision must select the adapter. It does
  not: the plan excludes the candidate and the claim binds one explicitly.
* **A-MVP-04 isolation clause** — `NOT_RUN` by construction. Closing it needs three
  S2-002 capabilities: a digest-pinned image containing the node runtime and the
  executors, a network allowlist replacing `--network=none`, and a secret-handle
  mechanism in the profile.
* **A-MVP-06, A-MVP-07** — the two-process lease race and the crash/restart replay
  against a real PostgreSQL and a real crossing. Not executed.
* **`cost`, `intervention_time`** — see criterion 3; each needs a decision or a
  board change, not a measurement fix.

## One environment limitation recorded, not worked around

The `tests/agentboard/concurrency.test.mjs` suite (8 tests) could not run in the
closing pass: rootless podman lost `/run/user/1000` mid-session and the directory
cannot be recreated without root, so no database can be started. Those tests were
green earlier in the same session while that directory existed
(`tests/agentboard` 432 pass, 0 fail, 1 skipped). The closing pass measured
`tests/agentboard` at 424 pass, 0 fail, 8 cancelled, 1 skipped — the 8 cancelled
are exactly that suite, and no test failed. A-MVP-06 and A-MVP-07 need the same
database, which is one reason they are `NOT_RUN` here.

## What is genuinely finished

Two genuinely installed executors behind `veritas.adapter/1.0.0`; eight governed
runs with minted corroborations, 65 contract-valid events each and raw process
logs; one project digest and one campaign grant across the whole run set; four
measurements with real denominators; a skills authority expansion refused on a
real run; five negative probes green with all seven hard-gate counters at 0; the
`HOST_UNISOLATED` tier, which makes a bounded unisolated pilot possible and a false
isolation claim structurally impossible; and a gate that publishes its own
disagreements instead of suppressing them.
