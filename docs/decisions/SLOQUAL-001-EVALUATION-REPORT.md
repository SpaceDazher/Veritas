# SLOQUAL-001 — Evaluation Report

Ticket: `tasks/SLOQUAL-001_SLO_QUALIFICATION.md` · Research issue
[#40](https://github.com/SpaceDazher/Veritas/issues/40) · Verdict:
**PASS_WITH_LIMITS** (local, single-host, in-process control plane).

What this package is: a pre-registered, reproducible SLO qualification of the
Veritas control-plane decision path. What it is not: a production SLO. The
measured system is `src/lib/identity/policy-engine.mjs` called in-process on
one developer host. The AgentOS research ticket that gave this method its
shape is a *method donor only*: its numbers measured AgentOS, and they are
neither transferred nor inherited here.

## 1. Frozen pre-registration

| Artifact | Version | Binding |
| --- | --- | --- |
| `contracts/sloqual-001-slo-contract.json` | `1.0.1` | self-hash `b400e41efc0e4012685056883033524ebd7e9ecb132e8d5baf4e8864aa83697d` |
| `contracts/sloqual-001-scenario-manifest.json` | `1.0.0` | SHA-256 `7b5715bb1063e38d35f16ee60e881e6efd65242001f8d6206964e3fb5e6bca6b` |

Contract v1.0.0 was committed (`1e2d56c`) before any measurement existed. The
first executed run returned `FAIL` and exposed a contract-modelling defect:
`hardGates.decision_divergence_between_runs` was declared as a per-run counter
although cross-run divergence is a property of the run *set*, so the
comparator correctly refused to accept it as "not reported". Contract v1.0.1
fixes that modelling error (`06a1fcc`), changes no threshold, statistic,
scenario, seed, workload or proof requirement, and records the change in its
`changeNote`. A failed run is not a result, so no measurement was inherited
from v1.0.0.

The gate enforces pre-registration instead of asserting it: it resolves
`git log -1 -- contracts/sloqual-001-slo-contract.json` and requires that
commit to be an ancestor of HEAD, otherwise the verdict is `NOT_RUN` and no
evidence is written. In a clean archive without `.git` the check reports
`NOT_RUN`, never a pass.

## 2. What was measured

17 scenarios × 5 seeds = **85 scenario-seed results per run**, plus **105
revocation trials** per run (21 per seed), executed twice in separate
processes with distinct run id, executor id, pid, nonce and output root.

- Arrival model: open loop. Every arrival instant is planned before the run,
  and latency is measured from the *planned* instant, so a slow response
  inflates measured latency instead of quietly reducing the offered load
  (no coordinated omission). `tests/sloqual/open-loop.test.mjs` pins that
  behaviour with a 60 ms injected stall.
- Warmup: the first 10 requests of every non-security scenario-seed are
  declared, dispatched, judged and recorded, but excluded from latency
  statistics only. The revocation family has no warmup.
- Statistics: nearest-rank percentiles, 95% percentile bootstrap
  (B = 2000, seed = 20260925), Wilson interval. Empty or non-finite input
  throws; an unmeasured SLI is a structural failure, not a satisfied
  threshold.
- Realization: 13 305 dispatched requests per run, 12 505 measured
  (800 warmup requests), ratio 1.000 in every family.
- Unit of analysis: one real `engine.authorize()` call. No stub, no fixture
  replay, no recorded decision.

## 3. Results

Hard counters are **zero in both runs** for every gate:
`cross_tenant_allow`, `unexpected_decision`, `allow_after_principal_freeze`,
`single_use_grant_replay_allow`, `decision_divergence_within_run`,
`missing_or_censored_samples`, `degenerate_scenario_decision_distribution`,
`allow_after_revocation_commit`, `revocation_trial_precondition_failures`.

| SLI (threshold) | Run A | Run B |
| --- | --- | --- |
| Warm p95, steady family (≤ 20 ms, CI upper must also be within) | **0.600 ms**, CI [0.572, 0.627] | **0.677 ms**, CI [0.620, 0.745] |
| Warm p99, steady family (≤ 50 ms) | 3.867 ms | 3.297 ms |
| Burst p95, burst family (≤ 200 ms, CI upper must also be within) | **1.554 ms**, CI [1.223, 2.072] | **0.440 ms**, CI [0.413, 0.468] |
| Revocation max, S1-008 (≤ 5000 ms) | **143.009 ms** over 105 trials, 0 post-revoke allows | **0.219 ms** over 105 trials, 0 post-revoke allows |
| Scheduling lateness p95 (≤ 100 ms) | 0.661 ms | 0.301 ms |

Both runs produced the identical ordered decision-sequence digest
(`6ea5a581dd33b4d1…`) and identical per-scenario decision digests, so the
exact comparison rule is satisfied: the same frozen inputs produce the same
decisions in a second process.

Evidence: `evidence/sloqual-001-run-a.json`,
`evidence/sloqual-001-run-b.json`, `evidence/sloqual-001-comparison.json`,
`evidence/sloqual-001-integrity.json`. Raw per-request observations stay
outside the repository under `results/sloqual-001/<run-id>/` and are bound
into the evidence by SHA-256.

## 4. Verdict: PASS_WITH_LIMITS

Zero failures, five itemized limits. These limits are properties of the
*evidence base*, not defects of the measured code:

1. **`production_profile_mapping` — NOT_MEASURED.** No representative
   production workload profile (rate, mix, workspace/principal scale,
   database scale) exists for Veritas. The warm p95 of ~0.6 ms describes an
   in-process decision function on a shared laptop, not a deployed service.
2. **`full_scale_fault_and_soak_families` — NOT_MEASURED.** Fault and soak
   families run at pilot scale (seconds, one process, in-memory enforcement
   state). The full-scale requirements — sustained ≥ 6 h, soak ≥ 24 h,
   process loss, mass invalidation at production scale — are declared
   `NOT_RUN` in every manifest scenario.
3. **`external_independent_execution` — NOT_MEASURED.** Both runs execute on
   one host. Process separation is not host separation: shared CPU, memory
   and kernel noise stay uncontrolled. The recorded host load average during
   run A was 23.1 on 16 logical cores, which is exactly why run A shows a
   143 ms revocation outlier and a 13.3 ms soak p95 that run B does not.
4. **`human_slo_countersignature` — NEEDS_INPUT.** A Veritas SLO has no
   accountable owner. The frozen contract states
   `countersignature.status = NEEDS_INPUT`; JSON is not authorization.
5. **`end_to_end_request_path` — NOT_MEASURED.** HTTP/API, PostgreSQL,
   sandbox execution and the provider edge are outside the frozen scope. No
   end-to-end latency or availability SLO is measured or claimed.

## 5. Authority boundary

`PASS_WITH_LIMITS` is not `PASS`. It does not mean production readiness,
production SLO authorization, independent external audit, a legal opinion,
a capacity plan or spending approval. A `PASS` from this contract would mean
only that the frozen local contract was satisfied by the two recorded runs,
and even that verdict keeps `productionSloAuthorized: false`
(`authority` in the comparison evidence). Reaching an actual production SLO
requires a different artifact: a countersigned contract over a mapped
production profile, measured on independent hosts, and reviewed by a human
owner.

## 6. Reproduce and re-verify

```bash
npm ci
npm run test:sloqual        # 70 unit tests: statistics, open loop, comparator, freeze, scenarios
npm run verify:sloqual-001  # two independent runs + fail-closed comparison + evidence (about 2 minutes)
npm run verify:clean-checkout
```

`verify:sloqual-001` exits non-zero only on `FAIL`. `PASS_WITH_LIMITS` is
recorded as the honest outcome of this ticket; turning a limit into a pass
requires new evidence, not a changed expectation. `sloqual-tests` and
`sloqual-001` are registered gates of the clean-checkout verification.
