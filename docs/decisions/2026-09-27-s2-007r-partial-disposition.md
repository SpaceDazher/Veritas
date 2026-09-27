# S2-007R: the ticket ends PARTIAL, by owner decision (issue #45)

- Date: 2026-09-27
- Decided by: the repository owner, in the BB thread that runs #45
- Subject: the disposition of issue #45 after the S2-007R work landed
- What this document is: a record of a DECISION
- What this document is **not**: evidence, and it upgrades no status

## The decision

Issue #45 ends as **PARTIAL**. The engineering work stays as it is measured; the
rest of the acceptance criteria are handed to issue #12 (S2-012) with the list
below. The issue is **not** closed as satisfied: its own acceptance criteria are
not met, and this document says so rather than reinterpreting them.

## Nothing here upgrades a status

The statuses are unchanged and remain evidence-bound:

| field | value | set by |
| --- | --- | --- |
| `engineeringStatus` | `REVISE` | the gate: two of four mandatory gates are red |
| `realAdapterStatus` | `NOT_RUN_REAL_ADAPTER` | the gate: it cannot corroborate a real-adapter run |
| `assuranceStatus` | `NOT_MEASURED` | fixed: no independent human review, no empirical semantic accuracy |
| `aMvpStatus` | `NOT_CLAIMED` | fixed: no named operator accepted a bounded pilot |
| A-MVP-01..07 | 1 PASS claimed, 5 `NOT_RUN`, 1 `PARTIAL` | the run set; the gate refuses to corroborate the one PASS |

`PARTIAL` is a disposition — what the owner decided to do with the ticket — and
it is deliberately not written into any status field. A disposition that
overwrote a status would be a number that stopped being a measurement.

## The acceptance criteria, one by one

From the issue's own «Приёмка и эвалы»:

1. **`A-MVP-01..07 = PASS` on a real run** — **not met**.
   A-MVP-01 is PASS in the run set; the gate does not corroborate it, because it
   reads the per-case record only when it is bound to this commit **and** to a
   corroborated real-adapter run, and its real-adapter gate is red. A-MVP-04 is
   PARTIAL, the rest `NOT_RUN`.
2. **`realAdapterStatus` lifted from `NOT_RUN_REAL_ADAPTER` on evidence** —
   **not met**. The run set has eight governed runs with minted corroborations;
   the gate still reads the status as not corroborated, for the two reasons below.
3. **Seven measurements published with a method** — **partially met**. Four are
   MEASURED (`accepted_task_quality` 0/8, `pass_at_1` 0/8, `latency` 8.5 s median,
   `regression_rate` 0/32). `cost` is REFUSED because pi reports USD and codex
   reports no billing, and a sum across two bases is not a number; `intervention_time`
   is `NOT_RUN` because the event stream carries no terminal event;
   `skills_authority_expansion` is `NOT_RUN` because no real process log carries
   the argv↔request digest pair.
4. **`assuranceStatus` reported separately and honestly** — **met**. It is
   `NOT_MEASURED`, and no evidence in this repository can move it: a real run is
   not a review, and the permit that admitted the floor tier is neither a review
   nor an acceptance.
5. **No `A-MVP PASS` without a named operator** — **met**. No such claim is made
   anywhere, and this decision does not make one.

## What #12 inherits, and what would close each item

| # | item | what unblocks it |
| --- | --- | --- |
| 1 | `real-adapter-run` gate reads FAIL | the gate treats the driver's `PARTIAL` exit as a failure **before** it classifies anything. It needs a way to say "classified, and the answer is mixed" — a codex run that ends in a terminal non-reviewable state is an honest verdict and an honest exit code. |
| 2 | `comparison` gate freshness | the record's byte digest **and** its `recordDigest` both match the envelope the same invocation printed (verified directly), and the gate still reports a mismatch. The artifact is sound; the binding is not. |
| 3 | `dependencies` gate `BLOCKED_DEPENDENCY` | inherited from S2-002: `verify:s2-007-dependencies` fails on this host because `verify:s2-002` does. Reported by this ticket and deliberately not fixed by it. |
| 4 | `cost` measurement | either a model with reported billing on both executors, or an explicit product decision that the token proxy **is** the answer. That is a decision, not a bug. |
| 5 | `intervention_time` measurement | a terminal event type in the event stream of a governed run. |
| 6 | `skills_authority_expansion` argv half | the request's `allowed_tools` digest carried into each real process log. |
| 7 | A-MVP-02 | its clause (c) — the tracked diff must touch no frozen target — is false at this HEAD, because the owner's own `HOST_UNISOLATED` decision edited `contracts/`, `src/lib/agentboard/` and `src/lib/identity/`. This is the owner's decision, reported rather than edited around. |
| 8 | A-MVP-03 | the *derived* dispatch decision must select the adapter. It does not: the plan excludes the candidate and the claim binds an adapter explicitly. |
| 9 | A-MVP-05 | an authenticated human reviewer who is not the producer. Structurally unreachable in an agent run; this has always been #12's work. |
| 10 | A-MVP-06, A-MVP-07 | the two-process lease race and the crash/restart replay, both against a real PostgreSQL and a real crossing. Neither was executed. |
| 11 | the `HOST_UNISOLATED` floor itself | a digest-pinned image with a node runtime, a network allowlist replacing `--network=none`, and a secret-handle mechanism. Until all three exist, an isolated model-calling run is a design item, not a configuration knob, and A-MVP-04's isolation clause stays `NOT_RUN`. |

## Why not just close it

The issue's own rule is that `A-MVP PASS`, production readiness and the final
SolutionPack acceptance are not established by engineering evidence. A closed
issue with five unmet acceptance criteria is the exact shape this repository
exists to prevent. So the ticket's *work* is done and its *criteria* are not
met, and both statements are on the record.

## What is genuinely finished

The engineering contour, and it is worth keeping:

- two genuinely installed executors behind `veritas.adapter/1.0.0`, with the
  status reachable only through a record re-derived from bytes on disk and
  minted by the process that observed the process;
- a real governed run per adapter, 65 contract-valid events each, raw process
  logs, and a comparison on one project digest and one campaign grant;
- four measurements with real denominators, computed from the records rather
  than asserted in prose;
- five negative probes green with all seven hard-gate counters at 0, and 432
  board tests plus 40 contract tests passing;
- the `HOST_UNISOLATED` tier, which makes a bounded unisolated pilot possible
  and a false isolation claim structurally impossible.
