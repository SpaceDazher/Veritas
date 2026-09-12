# S2-002 — Sandbox Profile (frozen)

Status: FROZEN for S2-002 evaluation. This document states exactly which
sandbox controls are implemented, which are observed by tests, and which
remain blocked because the platform cannot prove them. It deliberately
refuses to call the current state a full sandbox.

## 1. Tiers

| Tier | Purpose | Execution status |
|------|---------|------------------|
| `NO_EXEC` | contract/evidence operations only | execution forbidden (`SBX_TIER_FORBIDS_EXEC`) |
| `LOCAL_RESTRICTED` | gated live processes behind proven OS controls | **BLOCKED** (`SBX_NO_KERNEL_NETWORK_BOUNDARY`) |
| `UNTRUSTED_CODE` | hostile code, kernel/container boundary required | **BLOCKED** (same reason) |

`NO_EXEC` is a contract-valid profile (`contracts/sandbox-profile.schema.json`,
`sbx-no-exec-default`). `LOCAL_RESTRICTED`/`UNTRUSTED_CODE` target
specifications exist in `src/lib/identity/sandbox-profiles.mjs` and carry no
`os_controls_evidence` by design: the profile contract requires that
evidence, and we do not possess it.

## 2. Controls implemented and observed

All controls below live in `src/lib/identity/sandbox.mjs` and are asserted
by `tests/identity/sandbox.test.mjs`, by the adversarial probes (D, E, G)
and by both frozen replay runs.

### 2.1 Filesystem (enforced)

- Workspace roots are allowlisted; `resolvePath` canonicalizes through the
  deepest existing ancestor and `fs.realpath`, then enforces containment.
- Rejected before any filesystem access: `..` traversal (`PATH_ESCAPE`),
  absolute paths outside roots (`ROOT_VIOLATION`), UNC paths (`UNC_PATH`),
  DOS device names including per-segment (`DEVICE_PATH`), junction/symlink
  escapes (`LINK_ESCAPE`). Windows junction and symlink escapes are covered
  by integration tests using real links.
- Case-insensitive Windows comparison; back- and forward-slash
  normalization.

### 2.2 Network (deny by default; allowlist exact-match)

- `deny_all` forbids every destination (checked host+port pairs).
- Allowlist profiles match exact host and port; empty allowlist under
  `allowlist` policy is rejected by the profile contract itself.
- Kernel-level enforcement of child-process network access is NOT available
  on this stack — see §3.

### 2.3 Environment and secrets (enforced)

- Child environments contain only profile-allowlisted variables plus
  `VERITAS_SANDBOX_TIER` / `VERITAS_SANDBOX_PROFILE`; non-allowlisted keys
  (e.g. credential variables) are dropped.
- Secrets exist only behind opaque handles (`sec-*`); values never enter
  environments. `redact()` removes secret values from any text and probes
  assert redaction, including under injected prompt content.

### 2.4 Process tree and cancellation (enforced, observed live)

- Public execution paths of non-executable tiers never spawn (`BLOCKED_SANDBOX`
  before any process is created).
- `startForControlProbe` is the research instrument that observes OS
  controls: `cwd` inside the workspace, filtered environment, non-detached
  spawn, hidden window, per-profile `max_processes` (violations rejected
  with `LIMIT_PROCESSES`), `timeout_ms`.
- Cancellation and timeouts capture descendants before termination, use
  direct `SIGKILL` plus `taskkill /T /F` on Windows (process-group kill on
  POSIX), and retry addressable survivors. Terminal survivor proof queries
  the Windows process table rather than relying on `process.kill(pid, 0)`.
  Query/termination failures remain non-zero (fail-closed). A
  grandchild spawned via `start /b` is reaped; timeout and cancellation
  produce terminal outcomes (`timeout` / `cancelled`), never `success`.

### 2.5 Outputs (enforced)

- Outputs may be written only into the profile-bound artifact root, by bare
  file name; path syntax cannot escape.
- Every output records SHA-256, byte count and provenance (profile id, tier,
  workspace roots, fixed creation time).

### 2.6 Lifecycle semantics (enforced)

- Every run ends in exactly one terminal state: `completed`, `failed`,
  `timeout`, `cancelled` or `BLOCKED_SANDBOX`. There is no `success` state
  and no unknown-outcome path; unknown outcomes would fail closed.

## 3. What this sandbox is NOT (honest boundary statement)

1. No kernel-level network boundary: Node.js on Windows cannot create or
   verify an AppContainer (or equivalent container/restricted-token
   isolation) for child processes. A child that ignored our filtered
   environment could still open sockets. Therefore `LOCAL_RESTRICTED` and
   `UNTRUSTED_CODE` remain blocked for all agent-triggered execution, and
   live execution of untrusted code stays forbidden.
2. `cwd` + filtered env + tree kill is explicitly NOT claimed to be a full
   sandbox (ticket requirement).
3. Memory/CPU ceilings are recorded in outcomes and plans but are not
   kernel-enforced on this stack.
4. Follow-up required to unblock `LOCAL_RESTRICTED`: AppContainer or
   container-based isolation with a provable network deny-by-default
   boundary, its observed evidence digest, and a contract-valid
   `LOCAL_RESTRICTED` profile — then and only then may execution tier gates
   open.

## 4. Engine integration

The policy engine maps capability `exec_tier` to a sandbox tier and returns
`BLOCKED_SANDBOX` (`SBX_NO_OS_EVIDENCE`) unless a profile of that tier with
`os_controls_evidence` exists and the adapter re-verifies the kernel
boundary at runtime. Capability discovery may describe tools; discovery is
never a substitute for execution-time authorization.
