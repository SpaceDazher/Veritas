# S2-002 — Evaluation Report

Ticket: `tasks/S2-002_IDENTITY_SANDBOX.md` — identity, agent rights and the
local sandbox gate. Branch: `codex/s2-002-identity-sandbox`.
Verdict: **PASS_WITH_LIMITS** (after the gVisor/PostgreSQL corrective round).
Bounded `LOCAL_RESTRICTED` and `UNTRUSTED_CODE` execution are enabled only
through their separate evidence-bound backends. The remaining limits are
production authentication and durable multi-process authority state.

## 0A. Podman corrective round

WSL2 was enabled and rootless Podman installed after the original report.
The registered `sbx-podman-local-restricted-v1` profile is content-addressed
to `evidence/s2-002-podman-sandbox.json`. A real authorization-to-container
smoke proves policy `ALLOW`, pinned-image execution and terminal cleanup.
The observed boundary is: rootless Podman, cgroup v2, UID 65534, read-only
rootfs, all capabilities dropped, `no-new-privileges`, seccomp mode 2,
network namespace with loopback only, no host mounts/injected environment,
32 PIDs, 128 MiB and 0.5 CPU. The corpus, frozen manifest and clean-checkout
gate include this profile.

## 0B. gVisor, database and tooling closure round

`sbx-gvisor-untrusted-v1` closes the previously blocked bounded
`UNTRUSTED_CODE` path. The exact policy/evidence binding routes canonical
argv to the pinned Alpine image through runsc `release-20260907.0` in
systrap mode. The evidence observes `4.19.0-gvisor`, its boot marker,
auto-userns, zero capabilities, read-only rootfs, loopback-only networking,
no host mounts or environment injection and cgroup limits. Probe K rejects
evidence substitution and separate-command confusion.

The database limitation is closed by a disposable PostgreSQL 17.11 smoke:
ordered SQL migrations are SHA-256-bound, one task+event transaction commits,
a duplicate operation id is rejected, and the loopback-only tmpfs container
is removed. Random runtime credentials are neither logged nor persisted.
The unused `drizzle-kit` development dependency and its deprecated esbuild
loader chain were removed; full and runtime `npm audit` now report zero
vulnerabilities.

## 0. Corrective round — response to the independent REVISE review

An independent review (best-of-3 verifier) returned REVISE with five P0 and
two P1 findings. All seven were reproduced and fixed:

| Finding | Fix |
|---|---|
| P0 comparator fail-open (`NaN > 0`, empty runs, no oracle check) | `compareRuns` rewritten fail-closed: empty/missing/NaN counters are violations; every observation must satisfy its frozen expected verdict; trialCount consistency enforced; new tests pin it |
| P0 canonical arguments / resource type unvalidated | engine enforces `CANONICAL_ARGUMENTS_MISSING`, `ARGUMENT_NOT_CANONICAL`, `RESOURCE_TYPE_MISMATCH`; corpus, probes and tests carry canonical args |
| P0 lease usable across capabilities | exact lease binding: capability, grant identity, principal, workspace, validity; `LEASE_NOT_REQUIRED` when a lease is presented without need; registry gained correctly bound claim.write/cache.write grants + leases; the corpus cell that had recorded the flaw as `ALLOW` was corrected |
| P0 cross-tenant message.send allowed | recipient must hold workspace access (ACL or live grant): `RECIPIENT_OUT_OF_SCOPE`, `UNKNOWN_RECIPIENT`; corpus gained cross-tenant recipient cells |
| P0 flaky red suite (survivor counting races) | sandbox liveness now consults the child's observed exit (`exitSeen`) before `OpenProcess`, descendant enumeration retries, bounded tree-settle before counting; sandbox suite green across repeated runs |
| P1 clean-checkout claimed PASS without evidence | honest correction: the previous run had actually failed (`tar` drive-letter bug, npm spawn bug). Both fixed (`--relative-path tar extraction`, `npm.cmd` via cmd.exe, git-inventory fallbacks, synthetic placeholder for the build-time DB variable) and a real PASS is now recorded in `evidence/clean-checkout.json` |
| P1 dependencies S1-007/S1-008/S1-010 unbound | RESOLVED: the Stage-1 tickets live in `AgentOS/research/tickets/stage-1` (head `259d9afe…`). All three are completed gates (`pass_with_limits`) and are now digest-bound in `evidence/s2-002-dependency-binding.json`: S1-007 retrieval/index isolation (chain `4c344ab2…`), S1-008 revocation latency ≤5s (chain `5c43c03d…` — the requirement S2-002 enforces), S1-010 tool-poisoning detection (chain `8442d0de…`, gate verdict PASS) |

Policy version is `s2-002-policy-v5`; v3 added the exact Podman profile and
OS-evidence binding, v4 closed the command confused-deputy path, and v5 adds
the separate gVisor profile/capability. Both backends derive argv and timeout
only from policy-digested `canonical_args` and ignore any separately supplied
command.
Frozen-manifest scope now covers the whole S2-002 implementation, oracle
suites, corpus runner, comparator and security docs.

The second independent review found seven additional fail-open or
reproducibility gaps. This corrective round closes them as follows:

| Finding | Resolution |
|---|---|
| Comparator accepted a singleton self-consistent corpus | comparator now imports a host-owned exact oracle (all trial IDs, expected outcomes, count and digest); missing, duplicate, unknown or altered cells fail |
| Canonical arguments were checked by name, not target value | every resource-bearing argument and `workspace_id` must equal the authorized target; required values reject null/undefined and invalid structured/scalar types |
| Lease omitted exact fencing/task binding | presented token must equal the stored lease token; task requests must match `lease.task_ref`; grant/capability/workspace/resource bindings remain exact |
| Windows cancellation could leave a process | descendants are captured before kill; direct and tree termination are combined; the OS process table, not `process.kill(pid,0)`, is the terminal survivor oracle; Probe G passes with zero survivors |
| Clean-checkout omitted S2-002 acceptance commands | archive verifier now runs dependency verification, identity, sandbox, security probes, two-run replay, typecheck, lint, build and runtime audit as required gates |
| Dependency binding was host-local | all `D:/...` paths were removed; pinned repository/commit/tree, repo-relative paths and pinned raw URLs are verified by `verify:s2-002-dependencies` |
| Early DENY could return `document: null` | every outcome, including malformed/unknown adapter/principal/workspace/action inputs, carries a contract-valid AuthorizationDecision |


## 1. Verdict summary

| Requirement (Definition of Done) | Status |
|---|---|
| 1. S2-001 dependency binding reproducible from clean checkout | PASS (`evidence/s2-001-pilot-binding.json`, `PASS_WITH_LIMITS`, `productionDeploymentAuthorized=false`, upstream `6845858`) |
| 2. All schemas and server-side policy paths implemented and versioned | PASS — 8 contracts at `1.0.0`, single engine for Web/API/CLI |
| 3. ACL matrix covers 20 principals and all listed paths | PASS — 140-cell board.read matrix + capability/derived/nonce cells per run |
| 4. Hard counters zero in both independent runs | PASS — see §4 |
| 5. Revocation latency and trial minimum per run | PASS — 100 trials/run, final max 0.0644 ms / 0.0678 ms (limit 5000 ms) |
| 6. All adversarial probes detected by production path | PASS — 11/11 DETECTED, 0 ESCAPED |
| 7. Process-tree cancellation and required OS controls observable | PASS — rootless Podman for local-restricted; gVisor userspace kernel + auto-userns for untrusted; legacy Windows probe records survivors = 0 |
| 8. Frozen hashes, commit/tree, environment and outputs converge | PASS — manifests re-frozen per commit; `manifest:check` green |
| 9. Full test/typecheck/lint/build/security set in clean checkout | PASS — see §5; `build` used a synthetic placeholder `DATABASE_URL` (see §5 note) |
| 10. Documentation honestly separates local proofs from production guarantees | PASS — THREAT-MODEL §5, SANDBOX-PROFILE §3 |

Gate outcome per ticket: identity policy and two bounded container paths are
proven locally. The verdict stays `PASS_WITH_LIMITS`; alternate images,
host workspace access, networked workloads and injected secrets are not
authorized, and the fixture registry is not production authentication.

## 2. What was built

1. **Contracts (versioned `1.0.0`, fail-closed):** `contracts/{workspace,
   principal,role,capability,grant,lease,sandbox-profile,
   authorization-decision}.schema.json` — unknown fields, unknown versions
   and malformed documents are rejected; semantic cross-field rules (no
   self-issued grants, no self-delegation, expiry ordering, real UTC
   timestamps) enforced in `src/lib/identity/contract-registry.mjs`.
2. **Subjects model:** `src/lib/identity/principals.mjs` — 20 principals
   (5 humans, 5 personal agents, 4 external Codex/pi/OpenCode/Hermes
   principals, 6 platform agents) across 7 workspaces (5 private, 1
   project, 1 shared), 10 roles, 22 capabilities, 17 grants, 8 leases,
   sandbox profiles. Personal agents act only via explicit human-issued
   grants; platform agents carry no delegation and cannot self-grant.
3. **Policy engine:** `src/lib/identity/policy-engine.mjs` — one
   server-side decision point for Web/API/CLI; default deny; grants pinned
   to principal+capability+workspace+resource ids; leases with monotonic
   fencing tokens; one-time nonces; immediate revocation; human-only,
   producer-blocked approvals; `BLOCKED_SANDBOX` for unproven execution
   tiers; every decision returns a contract-valid AuthorizationDecision
   with input digest and audit reference.
4. **Sandbox adapters:** `src/lib/identity/sandbox.mjs` — filesystem
   canonicalization (traversal/UNC/device/junction/symlink), deny-by-default
   network with exact allowlists, environment allowlist, opaque secret
   handles with redaction, artifact outputs with SHA-256 + provenance,
   process-tree cancellation with survivor accounting (§ limits in
   `docs/security/S2-002-SANDBOX-PROFILE.md`). The executable bridge
   `src/lib/identity/podman-sandbox.mjs` accepts only bounded argv and routes
   an evidence-bound policy `ALLOW` into the fixed rootless Podman profile.
5. **Adversarial corpus A–K:** `scripts/security-probes.mjs` — every probe
   attacks the production modules directly; any ESCAPED is a hard fail.
6. **Independent replay:** `scripts/s2-002-run.mjs` (frozen corpus runner,
   283 trials) + `scripts/verify-s2-002.mjs` (two process-separated runs,
   per-trial decision comparison, hard counters, evidence writing).
7. **TDD:** all suites written RED-first; post-observation test mutations
   are recorded in `docs/decisions/S2-002-TEST-REVIEW-LOG.md`.

## 3. Adversarial corpus results (`evidence/s2-002-security-probes.json`)

A cross-tenant retrieval, B private-claim laundering, C payload/env forging,
D junction/symlink/traversal escape, E prompt injection (authority/secrets),
F foreign-scope messaging, G process-tree survival, H stale
grant/lease/fencing after revocation, I nonce/idempotency replay,
J corrupted/missing evidence fail-open, K gVisor evidence substitution and
separate-command confusion.

**11/11 DETECTED, 0 ESCAPED, 0 SKIPPED (Windows).**

## 4. Independent replay (`evidence/s2-002-comparison.json`)

| Metric | Requirement | Run A | Run B |
|---|---|---|---|
| Trials per run | full frozen corpus | 283 | 283 |
| Cross-tenant successful reads/writes/messages | 0 | 0 | 0 |
| Authority expansions | 0 | 0 | 0 |
| Filesystem/network/secret escapes | 0 | 0 | 0 |
| Survivors after cancellation | 0 | 0 | 0 |
| Allow-after-revocation-commit | 0 | 0 | 0 |
| Missing/censored trials | 0 | 0 | 0 |
| Revocation decision latency (100 trials) | max ≤ 5000 ms | 0.0644 ms | 0.0678 ms |
| Decision mismatch A vs B | 0 | 0 (283 compared) | — |
| Frozen-oracle violations (either run) | 0 | 0 | 0 |

Runs differ in executor id, nonce base and output root; the corpus digest
is identical. Raw observations: `results/s2-002/run-a/observations.json`,
`results/s2-002/run-b/observations.json` (tracked in Git). Integrity digests
of the evidence files: `evidence/s2-002-comparison-integrity.json`.

Coverage: all 20 principals × all 7 workspaces (board.read matrix) plus
explicit cells for every capability family (planning, source/search,
claims/summaries, cache, artifacts/export, messaging, tool
discovery/execution, approvals/cancellation), derived-artifact inheritance,
nonce sequencing, sandbox boundary controls and 100 revocation trials —
per run. Errors/timeouts are not excluded from denominators; every trial
carries a terminal observation.

## 5. Verification commands (executed)

```
npm ci
npm run verify:s2-002-dependencies # portable 4/4 dependency binding
npm run test:identity          # includes exact-oracle and dependency regressions
npm run test:sandbox           # 18 tests
npm run test:security-probes   # 11/11 DETECTED, exit 0
npm run verify:podman-sandbox  # real WSL2/rootless Podman controls + authorized smoke
npm run verify:gvisor-sandbox  # real runsc/systrap userspace-kernel controls + authorized smoke
npm run verify:postgres-smoke  # PostgreSQL 17, migrations, transaction and replay rejection
npm run verify:s2-002          # process-separated runs, ok=true, exit 0
npm run typecheck              # exit 0
npm run lint                   # exit 0
npm run build                  # exit 0 — with synthetic placeholder
                               # DATABASE_URL (no credentials, no DB
                               # connection at build time; the app requires
                               # the variable to be present even for
                               # compilation). Real credentials were not
                               # supplied, per ticket stop conditions.
npm audit --omit=dev           # see evidence/dependency-audit-*.json policy
npm run manifest:check         # exit 0
node scripts/validate-contracts.mjs  # exit 0 (incl. S2-001 probes)
node scripts/verify-pilot-binding.mjs # PASS_WITH_LIMITS
node scripts/verify-clean-checkout.mjs # real PASS recorded (see §5 note)
git diff --check && git status --short
```

`npm run verify-clean-checkout` now records a genuine clean-archive PASS in
`evidence/clean-checkout.json` (all required commands PASS, including both
sandbox profiles, the PostgreSQL smoke and full/runtime dependency audits at
zero vulnerabilities). The archive check uses the repo's `VERITAS_GIT_INVENTORY` /
`VERITAS_SOURCE_COMMIT` / `VERITAS_SOURCE_TREE` fallbacks, fresh
`node_modules`, and the synthetic passwordless placeholder for the
compile-time database variable.

Note on measurement evidence semantics: `verify:s2-002` regenerates
`evidence/s2-002-run-{a,b}.json` on every execution by design — revocation
latencies, run durations and temporary output-root paths necessarily vary.
The committed evidence corresponds to the final acceptance run. A re-run in
a clean archive leaves all decisions, counters and the comparison verdict
identical (`ok=true`, mismatch 0); only the timing fields and the observation
digests derived from them differ, which is why `manifest:check` is evaluated
on the committed state and re-frozen after each accepted run.

`npm audit --omit=dev` outcome is recorded in the runtime dependency audit;
no new runtime dependencies were introduced by S2-002 (ajv and Node built-ins
only).

## 6. Limits and out-of-scope guarantees (explicit)

1. **No production authentication / multi-tenancy.** The registry is
   synthetic fixture data proving policy mechanics; it is not a deployed
   IdP, and 20 principals are ACL coverage, not concurrent users.
2. **Bounded sandbox only.** `LOCAL_RESTRICTED` uses the measured
   WSL2/rootless Podman profile; `UNTRUSTED_CODE` uses the measured
   gVisor/systrap userspace-kernel profile plus Podman auto-userns. Host
   mounts, networked jobs, environment/secret injection and alternate images
   remain blocked (`docs/security/S2-002-SANDBOX-PROFILE.md` §3).
3. **In-memory enforcement state.** Nonces, fencing ceilings and
   revocations are per engine instance; a durable multi-process deployment
   needs an atomic shared authority store.
4. **Confinement limits.** Podman cgroup v2 enforces memory/CPU/PID ceilings.
   AppArmor/SELinux is unavailable in this WSL2 distribution; gVisor's
   userspace kernel is the compensating boundary for the exact untrusted
   profile. The legacy Windows process probe is evidence only.
5. **Secrets.** No real credentials, tokens or private source content were
   used or committed; build and archive checks use a synthetic passwordless
   placeholder variable as noted.
6. **Stage-1 dependency gates** (S1-007, S1-008, S1-010) are bound as
   `pass_with_limits` records of the AgentOS repository at head `259d9afe…`;
   their own limits carry over as upstream context, not as S2-002 failures.

## 7. Artifact index

- Contracts: `contracts/*.schema.json` (8 files, `1.0.0`, frozen manifest)
- Implementation: `src/lib/identity/*` (registry, principals, engine,
  sandbox, Podman/gVisor execution bridges, profiles, TS types)
- Database: `migrations/*.sql`, `scripts/apply-migrations.mjs`,
  `scripts/verify-postgres-smoke.mjs`
- Tests: `tests/identity/*.test.mjs`, `tests/database/*.test.mjs` (contracts, policy, sandbox, probes,
  replay)
- Probes/corpus: `scripts/security-probes.mjs`, `scripts/s2-002-run.mjs`,
  `scripts/verify-s2-002.mjs`
- Evidence: `evidence/s2-001-pilot-binding.json`,
  `evidence/s2-002-security-probes.json`, `evidence/s2-002-run-{a,b}.json`,
  `evidence/s2-002-comparison.json`, `evidence/s2-002-comparison-integrity.json`,
  `evidence/s2-002-podman-sandbox.json`, `evidence/frozen-manifest.json`,
  `evidence/s2-002-gvisor-sandbox.json`, `evidence/postgres-smoke.json`,
  `evidence/root-manifest.json`
- Raw runs: `results/s2-002/run-{a,b}/observations.json`, `summary.json`
- Reviews: `docs/decisions/S2-002-TEST-REVIEW-LOG.md`
- Hash binding: all artifacts are hash-bound by `evidence/root-manifest.json`
  at the recorded implementation commit/tree.
