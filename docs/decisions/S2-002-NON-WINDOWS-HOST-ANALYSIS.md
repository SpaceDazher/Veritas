# S2-002 on a non-Windows host: three accounting defects, and one of them fails in the permissive direction

**Status:** analysis for an owner decision. **Nothing in S2-002 was changed.**
**Ticket:** [SpaceDazher/Veritas#7](https://github.com/SpaceDazher/Veritas/issues/7) (S2-007 is
`BLOCKED_DEPENDENCY` on this) and S2-002 itself.
**Host measured:** Linux/x64, Node v22.23.2, podman 4.9.3. **Date:** 2026-09-25.

## 1. What blocks S2-007

`npm run verify:s2-007-dependencies` re-runs `npm run verify:s2-002` as a mandatory
gate. It exits 1, so S2-007 reports `BLOCKED_DEPENDENCY` even though every S2-007
engineering gate is green. The S2-002 failure reproduces on the untouched base commit
`f590d37`, which contains zero S2-007 files, so it is not caused by S2-007.

An adversarial verification pass was run against the first version of this analysis and
**partly refuted it**. The corrected finding is below; the refutation is what changed the
recommendation, and it is recorded here rather than quietly dropped.

## 2. The corrected finding

The six `npm test` failures and the `verify:s2-002` exit 1 come from **two**
platform-scoping defects in `scripts/s2-002-run.mjs` plus **two** further Windows-only
gates — not from one trial, and **not** from a single benign bookkeeping nit.

### Defect 1 — an unhandled `PLATFORM_UNSUPPORTED`

`sandbox/cancellation-survivors` is Windows-only by construction:

```js
// scripts/s2-002-run.mjs:185-186
trials.push({ id: 'sandbox/cancellation-survivors', live: true, run: async () => {
  if (!IS_WINDOWS) return 'PLATFORM_UNSUPPORTED';
```

`PLATFORM_UNSUPPORTED` is produced in exactly one place and handled in **zero**
(`grep -rn PLATFORM_UNSUPPORTED scripts/ src/ tests/` returns only the producer). A Linux
corpus run produced **283 observations of which exactly one has `match: false`** — that
declined trial, recorded as:

```json
{"trialId":"sandbox/cancellation-survivors","kind":"sandbox","expected":"SURVIVORS_ZERO",
 "observed":"PLATFORM_UNSUPPORTED","decision":"DENY",
 "reasonCodes":["SANDBOX_CONTROL_VIOLATED"],"survivors":-1,"match":false}
```

So a trial that was deliberately **not exercised** is written up as a **violated** control.
`-1` is a parse sentinel, not a survivor count, and it is summed into
`survivors_after_cancellation` (`s2-002-run.mjs:297-300`).

### Defect 2 — the oracle and the trial set are scoped inconsistently

```js
// scripts/s2-002-run.mjs:95 — dropped from the ORACLE off Windows
...(IS_WINDOWS ? [['sandbox/fs-junction-escape', 'LINK_ESCAPE']] : []),
```

but the trial itself is still pushed on any platform where `junctionReady`
(`s2-002-run.mjs:182-184`). On Linux it therefore **executes and passes**
(`match: true`, `observed: LINK_ESCAPE`) while the oracle never expected it — producing
`trialCount=283/oracle=282` and two `UNKNOWN_TRIAL` diagnostics. This is a second,
independent defect and is not caused by the declined trial.

### Defect 3 — cancellation accounting is wrong in the PERMISSIVE direction (the serious one)

This is what the first version of this analysis got wrong, and it matters most.

On a non-Windows host `listDescendants` returns an empty list
(`src/lib/identity/sandbox.mjs:213`) and the child is spawned with `detached: false`
(`sandbox.mjs:389`), so `process.kill(-pid)` cannot reach the process group and
`terminateTree` kills only the direct child. Reproduced directly against the production
adapter on this host:

```
parent pid        : 399463
grandchild pids   : 399465, 399466
alive BEFORE cancel: 2 / 2
cancel() returned : {"terminated":true,"survivors":0,"remainingProcessIds":[],"pid":399463} in 102 ms
parent alive after : false
alive AFTER cancel : 2 / 2   <-- LEAKED: 399465, 399466

VERDICT: FALSE PASS — cancel() reported survivors:0 while 2 descendant(s) are still running
```

**Consequence: if the declined Windows-only trial were simply enabled on this host, it
would report `SURVIVORS_ZERO` and pass — a false pass.** The platform decline is
currently the only thing preventing the record from claiming a safety property that this
host does not have. That is the opposite of the "harmless bookkeeping" reading, and it
is why the gate must not be relaxed here.

(A second, smaller effect: `await done` never resolves when a grandchild inherits the
child's stdio, so a caller that awaits it can hang past the process's own timeout.)

### Defect 4 — the negative sentinel fails OPEN in the primary gate

`verify-s2-002.mjs` compares a counter with `value > limit`. Any negative value passes:

| counter value | limit 0 |
| --- | --- |
| `0` | passes |
| `1`, `5` | blocked |
| `-1`, `-9999`, `-1000000000` | **passes** |

So the `-1` sentinel is caught only by `tests/identity/replay-runs.test.mjs`, never by
`verify:s2-002` itself. A future sentinel of any negative magnitude would pass silently.

## 3. Complete symptom map on this host

| Failing assertion | File | Cause |
| --- | --- | --- |
| `hard counter fs_network_secret_escapes is zero in both runs` | `tests/identity/replay-runs.test.mjs` | Defect 1 — a declined trial counted as a secret escape |
| `hard counter survivors_after_cancellation is zero in both runs` | `tests/identity/replay-runs.test.mjs` | Defect 1 + 3 — the `-1` sentinel, and a genuinely unmeasured property |
| `survivors after cancellation are zero (observed on this platform)` | `tests/identity/replay-runs.test.mjs` | Defect 1 — the trial cannot run here |
| `Run A vs Run B decision mismatch is zero` | `tests/identity/replay-runs.test.mjs` | Defects 1 **and** 2 — fails on `counterViolations` and on the `283/282` count |
| `probe G … is detected, never escaped` | `tests/identity/security-probes.test.mjs` | probe G is Windows-only and skips by design (`security-probes.mjs:236-238`) |
| `no probe is silently skipped on this platform` | `tests/identity/security-probes.test.mjs` | contradicts probe G's own honest, reasoned skip |

Two further Windows-only gates silently skip rather than fail: `tests/identity/sandbox.test.mjs:117`
and `:213`.

## 4. What is established, and what is not

**Established.**

* **Zero** filesystem/network secret escapes were observed on this host. The `1` is a
  declined trial; no other observation contributes.
* The committed Windows evidence is **not** contradicted. It records
  `"platform": "win32/x64 node v22.23.2"` with both counters `0`, and the digest of its
  committed observations matches. Notably, the **Linux run's executed observations hash to
  the same digest as the Windows run's** — the executed corpus agrees; it is the Linux
  *oracle* that diverges.
* Process-tree cancellation on this host is **not safe and not measured**:
  `cancel()` under-reports survivors. The `LOCAL_RESTRICTED` tier must stay blocked here.

**Not established.** That S2-002 needs its safety controls weakened on Linux. It does
not: it needs its **accounting** fixed and its sandbox **re-measured on the platform
whose measurement it is entitled to claim**.

## 5. Why nothing in S2-002 was changed here

The counter arithmetic, the runner, `tests/identity/**`, the sandbox implementation, the
S2-002 evidence and the frozen manifest are another ticket's deliverables, and the S2-007
issue forbids relaxing or renaming a gate to obtain a green status. Editing them from
inside S2-007 to clear S2-007's own dependency gate is exactly that.

**Operationally important:** running `npm run verify:s2-002` or `npm run test:security-probes`
on a non-Windows host **overwrites the frozen Windows evidence** with non-Windows
measurements, including the false-pass cancellation result. Do not do that. During this
investigation the S2-002 runner was executed only with
`--output-root .bb/chats/…`, and `git status --short results evidence` was verified clean
afterwards.

## 6. The decision, and the exact change it implies

**Recommendation: re-measure S2-002 on Windows and keep the Linux gate red.** Relaxing
the Linux counters would delete the only signal that this host cannot support the tier,
and Defect 3 shows the relaxed result would be a **false pass**.

Two things are worth fixing regardless, and neither turns the gate green on Linux:

1. **Give platform-scoped trials a real `NOT_RUN` semantic** instead of scoring them as
   violations: a distinct not-run state, `decision: 'BLOCKED_SANDBOX'`, reason code
   `SANDBOX_CONTROL_NOT_EXERCISED_ON_PLATFORM` (never `..._VIOLATED`), exclusion from
   `fs_network_secret_escapes` and from the survivors sum, and a visible `not_run_trials`
   count so a skipped hard counter is *reported* rather than fabricated — while leaving
   `LOCAL_RESTRICTED` blocked. Replace "no probe is silently skipped" with "no probe is
   skipped **without a recorded reason and a blocked tier**".
2. **Scope the oracle and the trial set consistently** (Defect 2) and **close the negative
   sentinel hole** in the gate (Defect 4) — e.g. reject any counter that is not a finite
   non-negative number, rather than comparing it with `>`.

`src/lib/identity/sandbox.mjs`'s non-Windows cancellation behaviour (Defect 3) is a
real defect in the sandbox itself, not in S2-002's harness, and should be tracked on its
own: on a non-Windows host either enumerate descendants via the process group (which
requires spawning the child `detached`) or refuse cancellation and report the tier as
blocked, rather than reporting `survivors: 0` while descendants live.

## 7. How to reproduce

```bash
# Defects 1 and 2 — the declined trial and the oracle/trial mismatch
node scripts/s2-002-run.mjs --run-id diag --executor-id diag --nonce-base nb-diag \
  --output-root .bb/chats/thr_8sxageuj7j/tmp/s2-002-diag
node -e "const o=require('./.bb/chats/thr_8sxageuj7j/tmp/s2-002-diag/observations.json');
         console.log(o.filter(x=>x.kind==='sandbox'&&x.match===false));
         console.log('trials:', o.length)"

# Defect 3 — cancel() under-reports survivors on a non-Windows host
# (the probe used here spawns two grandchildren, calls cancel(), then checks liveness
#  independently with process.kill(pid, 0); the reproduction is quoted in §2)

# Defect 4 — any negative counter passes a `value > limit` check
node -e "const l=0; for (const v of [0,1,-1,-9999]) console.log(v, !(v>l)?'PASSES':'blocked')"

# The failures are pre-existing, not caused by S2-007
git worktree add --detach /tmp/veritas-base f590d37   # base has zero S2-007 files
(cd /tmp/veritas-base && node --test --test-concurrency=1 tests/identity/replay-runs.test.mjs)
```

No secret, credential or private locator appears in this document.
