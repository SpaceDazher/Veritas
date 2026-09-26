# S2-002 — Process Cancellation Must Not Report Unverified Success

Issue: [SpaceDazher/Veritas#41](https://github.com/SpaceDazher/Veritas/issues/41)
Status: fixed, with new versioned evidence on **both** platforms.
Scope: `src/lib/identity/sandbox.mjs`, `src/lib/identity/process-observer.mjs`
(new), `src/lib/identity/process-tree-fixture.mjs` (new), the frozen S2-002
corpus runner, the S2-002 comparator, adversarial probe G, and the cancellation
regression suite.

## 1. The defect

On a non-Windows host, `cancel()` resolved `{ terminated: true, survivors: 0 }`
while a descendant of the spawned process was still running. Three separate
failures combined:

1. **Descendant enumeration was a stub off Windows.**
   `listDescendants()` returned `Promise.resolve([])` on every non-Windows
   platform. A tree with no observed descendants is indistinguishable from a
   tree that was never enumerated, and the survivor check was fed the first.
2. **The POSIX "tree kill" signalled one process and reported success anyway.**
   `treeKill()` called `process.kill(-pid, 'SIGKILL')`, but the probe child was
   spawned with `detached: false`, so it was *not* a process-group leader and
   the negative pid addressed a group that did not exist. The `catch` fell back
   to `process.kill(pid, 'SIGKILL')` — the direct child only — and the function
   then `resolve(true)` unconditionally. A signal request was reported as a
   termination.
3. **The hard counter laundered the unknown.** The corpus recorded
   `survivors: -1` when the live cancellation trial was skipped, and the
   comparator accepted any counter `<= 0`. `-1` passed
   `survivors_after_cancellation: 0`, so "we did not look" satisfied a hard
   gate whose limit is zero.

Observed on `linux/x64` before the fix (`/bin/sh` spawning a `setsid`
descendant that keeps a heartbeat):

```
[+  508ms] BEFORE  root=559213(S) descendant=559214(S) beats=1
[+  650ms] AFTER   cancel() -> {"terminated":true,"survivors":0,"remainingProcessIds":[],"pid":559213}
[+  650ms] AFTER   ground truth: descendant=S  sandbox.isAlive=true
[+ 2652ms] +2s     ground truth: descendant=S  beats 1 -> 3   <- still working
```

`cancel()` claimed success 100 ms after spawn while the descendant kept
running. The run's own outcome did not arrive until the 60 s timeout fired,
because the surviving descendant held the child's stdout/stderr pipes open.

A fourth, separate defect made the property unobservable off Windows in the
first place: adversarial probe G and the corpus's live cancellation trial both
returned `SKIPPED` / `PLATFORM_UNSUPPORTED` on non-Windows, and the frozen
corpus carried a Windows-shaped trial set (`sandbox/fs-junction-escape` was
excluded from the oracle on POSIX even though `symlinkSync(..., 'junction')`
succeeds there as a directory symlink, so the run produced a trial the oracle
did not know). `verify:s2-002` therefore could not pass on Linux at all.

## 2. The fix

### 2.1 Termination is proven, not assumed

Cancellation, timeout, and ordinary exit now return a terminal proof:

| proof | meaning | `terminated` | `survivors` |
|---|---|---|---|
| `TERMINATED` | the tree was re-observed and nothing is left alive | `true` | `0` |
| `SURVIVORS_REMAINING` | observed, at least one tracked pid is alive | `false` | `>= 1` |
| `UNVERIFIED` | the process table could not be read | `false` | `null` |

`terminated: true` is emitted only for `TERMINATED`. An unavailable observer,
an unavailable descendant query, or a surviving pid all fail closed. This
covers the Windows path too: a failed CIM query previously resolved as an
empty descendant list, which is the same lie in a different place.

### 2.2 A real process observer

`src/lib/identity/process-observer.mjs` is the only source of truth about what
is running. Every query returns `{ ..., observable, rootPresent, reason }`:

- **Windows** — `Win32_Process` (CIM), as before, but a query failure is now
  `observable: false` instead of `[]`. The root's existence is answered from the
  same CIM snapshot as the descendant walk, so a vanished root is no longer
  indistinguishable from a live one.
- **Linux** — a `/proc` snapshot: a parent walk from the root, plus process
  group and **session** membership, plus `/proc` `starttime` as a pid identity
  token.
- **Other POSIX** — `ps -A -o pid=,ppid=,pgid=,sid=`, same three facts.
- **None available** — `observable: false`, fail closed.

`rootPresent: false` on a readable table means the tree's shape is unknown, not
that the tree was empty: descendants are re-parented to init and stop being
reachable from a pid that is gone.

### 2.3 A tree the OS can actually be asked about

- A readable process table with the root already gone is not an empty tree:
  descendants are re-parented to init and stop being reachable from it. A run
  that ends on its own (`completed` / `failed`) is therefore reported
  `UNVERIFIED` with `survivors: null` and `SBX_TREE_SHAPE_NOT_OBSERVED`, not as
  an empty tree. Cancellation and timeout capture the tree while the root is
  alive, which is exactly what makes their proof valid.
- POSIX probe children are spawned as process-group leaders
  (`detached: true` → `setsid`), so a group-directed `SIGKILL` is meaningful.
  Windows keeps `detached: false` because `taskkill /T` walks the parent chain.
- The tree is captured **before** the root dies, and the tracked pid set
  carries its session/process group. That is what finds a descendant which
  left the group with `setsid(2)` — the POSIX counterpart of Windows
  `start /b` — and, on re-discovery, the grandchild that is re-parented to init
  once its parent is gone.
- Session/pgroup expansion is only used when the root is genuinely isolated
  from the adapter's own session and process group
  (`SBX_PROCESS_GROUP_NOT_ISOLATED` when it is not), so it can never sweep in
  unrelated host processes.
- A recycled pid is reported as `SBX_PID_REUSED`, is never signalled, and is
  never counted as a survivor. The identity token exists where the platform
  exposes one (Linux `/proc` starttime); Windows CIM has none, so the case
  records that residual rather than asserting a control the platform cannot
  support.
- One tree definition, in `src/lib/identity/process-tree-fixture.mjs`, is shared
  by the corpus runner, the adversarial probes, the verification stage and the
  regression suite, so the four cannot drift into observing different trees.
  POSIX uses `setsid(2)`; Windows uses `Start-Process`, which starts an
  independent process that does **not** inherit the parent's stdio handles, so a
  run can finish while the descendant is still alive. Both publish the
  descendant's own pid, which is what gives every live case independent ground
  truth instead of the adapter's own verdict.

### 2.4 Counters that cannot be laundered

`survivors_after_cancellation` in the corpus runner is now fail-closed by
construction:

- a mismatching trial contributes at least 1, whatever it reported;
- a claimed `SURVIVORS_ZERO` contributes 0 only with `survivors === 0` **and**
  `TERMINATED` from both `cancel()` and the run outcome;
- a claimed `BLOCKED_UNVERIFIED` contributes 0 only with `survivors === null`
  **and** `UNVERIFIED` from both;
- every other observed value contributes `max(1, survivors)`.

The comparator additionally rejects any counter that is not a non-negative
integer (`-1` used to pass a `value > limit` test), and flags a zero-survivor
claim with no `TERMINATED` proof, or an `UNVERIFIED` claim that carries a
survivor count.

### 2.5 Platform-independent corpus

The frozen corpus now has the same trial set and the same digest on every host:
the link-escape trial is unconditional (`'junction'` on Windows, `'dir'` on
POSIX; a host that refuses to create the link fails the corpus closed instead
of censoring the trial), and the cancellation trial spawns a real descendant on
every platform instead of returning `PLATFORM_UNSUPPORTED`. Adversarial probe G
is cross-platform and no longer reports `SKIPPED` off Windows.

## 3. Coverage

`tests/identity/cancellation-process-tree.test.mjs` (new) and
`scripts/verify-s2-002-cancellation-v2.mjs` (new, `npm run
verify:s2-002-cancellation`):

| case | kind | asserts |
|---|---|---|
| `cancellation/descendant-session-escape` | live | 3-level tree that leaves the process group is reaped; `TERMINATED`; independently observed descendant pids are dead |
| `cancellation/timeout-descendant-escape` | live | the same property through the timeout path, without an explicit `cancel()` |
| `cancellation/negative-control-no-process-table` | negative control | an observer that cannot read the process table yields `UNVERIFIED`, `terminated: false`, `survivors: null` |
| `cancellation/negative-control-descendant-query-fails` | negative control | descendant enumeration failing alone also fails the proof closed, even when liveness still works |
| `cancellation/recycled-pid-not-signalled` | negative control | a stale identity token reports `pidReused`; the unrelated live pid is neither signalled nor counted |
| `cancellation/self-completed-run-makes-no-claim` | negative control | a run that exits on its own reports `UNVERIFIED` with no survivor count, because its tree was never observed while the root lived |
| `cancellation/s2-002-frozen-corpus-hard-counters` | replay | the frozen corpus replays clean on this host: all six hard counters at zero, no counter violations, no oracle violations |
| `cancellation/historical-evidence-untouched` | integrity | the eight pre-fix evidence records still match their committed digests |

In the frozen corpus: `sandbox/cancellation-survivors` (real descendant, plus
independent ground truth on the pids the descendant published) and
`sandbox/cancellation-observation-unavailable` (the first negative control,
wired into the hard counter).

## 4. Evidence

New, versioned, and additive. No historical record is rewritten. Each host
writes its own file, so the two observations stay separate records and are never
merged — a Windows-only replay still does not establish the non-Windows
property.

| file | content |
|---|---|
| `evidence/s2-002-cancellation-v2.json` | `evidenceRevision: 2`, `linux/x64`, observer `platform:linux`, preserved hard gates, counters, 8 cases with raw detail, verdict `PASS` |
| `evidence/s2-002-cancellation-v2-win32.json` | the same 8 cases observed on `win32/x64`, observer `platform:win32`, verdict `PASS` |
| `*-integrity.json` | SHA-256 of the record, `historicalEvidenceRewritten: false` |

Untouched, and verified byte-identical to their committed digests by the
`cancellation/historical-evidence-untouched` case:
`evidence/s2-002-run-a.json`, `run-b.json`, `comparison.json`,
`comparison-integrity.json`, `security-probes.json`, `podman-sandbox.json`,
`gvisor-sandbox.json`, `dependency-binding.json`.

That is enforced, not just intended. Note that `npm run test:security-probes`
and `npm run verify:s2-002` regenerate their own reports by design, so
re-running them is an explicit separate act, not part of publishing this fix.

The new evidence file is deliberately **not** in the frozen integrity manifest
(`scripts/validate-contracts.mjs`): it records raw pids from a live process
tree, so it is a per-run observation record rather than a reproducible digest.
The verification code is frozen; the observation it produces is evidence.

Ordering matters when running the gates: `npm run test:security-probes` and
`npm run verify:s2-002` regenerate their own reports by design, and the A–K
report is inside the frozen manifest, so run `node scripts/validate-contracts.mjs`
on a pristine checkout, and re-freeze (`--freeze`) only after a deliberate
evidence regeneration on the target platform. A probe-G detail line produced on
POSIX is not the Windows record.

The S2-002 hard gates are unchanged and still enforced at zero:
`cross_tenant_success`, `authority_expansion`, `fs_network_secret_escapes`,
`survivors_after_cancellation`, `allow_after_revocation_commit`,
`missing_or_censored_trials`. The new stage references them; it does not
redefine or relax them.

The corpus digest changes, because the corpus gained a trial and lost a
platform-conditional one. That is a corpus revision, recorded as
`corpusRevision: 2` in every summary, and it is exactly why a Windows-only
replay could not establish the non-Windows property: the old corpus had no
non-Windows cancellation evidence in it to begin with.

`npm run verify:s2-002` — the process-separated authority — was re-run on
**both** hosts after the fix and exits `0` on each: 284 compared trials, zero
mismatched decisions, zero counter violations, all six hard counters at zero.
Before the fix the same command could not pass off Windows at all. Those runs
are not committed, because `verify:s2-002` writes
`evidence/s2-002-run-a.json`, `run-b`, `comparison` and
`comparison-integrity` by design and those are the pre-fix records; the
in-process replay inside `cancellation/s2-002-frozen-corpus-hard-counters`
publishes the same result as new versioned evidence instead. Both hosts report
the same corpus digest, which is the point of making the corpus
platform-independent.

## 5. What this does not establish

1. This is the termination control of an in-process probe adapter, not a
   kernel containment boundary. `LOCAL_RESTRICTED` and `UNTRUSTED_CODE` stay
   blocked or bound to the Podman/gVisor evidence.
2. Descendant discovery on POSIX depends on `/proc` (or `ps`). A host with
   neither reports `UNVERIFIED` — correct, and still not a pass.
3. Session and process-group identity assume the OS models them as `/proc` and
   `ps` report them. A descendant that escapes both (a nested container with its
   own PID namespace) is outside the observation boundary and is reported as
   unobserved rather than as terminated.
4. The Windows observer has no per-pid identity token, so a recycled pid
   cannot be told apart from one of ours there. The case records that residual
   rather than asserting a control the platform cannot support.
5. A self-completed run never gets a termination proof, because its tree shape
   is unknowable once the root is gone. That is the honest outcome, but it also
   means `proof: TERMINATED` on this adapter means exactly one thing: "a tree
   observed while the root was alive was re-observed as empty", nothing more.
6. Both platforms have now been observed independently and both records are in
   `evidence/`, neither derived from the other. A future change to the
   termination control still has to be re-observed on both.
7. Live execution in #7 must not rely on this property until that
   two-platform evidence is re-accepted in review.
