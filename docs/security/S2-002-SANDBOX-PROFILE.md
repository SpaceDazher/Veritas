# S2-002 — Sandbox Profile (frozen)

Status: FROZEN for S2-002 evaluation. This document states exactly which
sandbox controls are implemented, which are observed by tests, and which
remain blocked because the platform cannot prove them. It deliberately
refuses to generalize the bounded local profile into an untrusted-code claim.

## 1. Tiers

| Tier | Purpose | Execution status |
|------|---------|------------------|
| `NO_EXEC` | contract/evidence operations only | execution forbidden (`SBX_TIER_FORBIDS_EXEC`) |
| `LOCAL_RESTRICTED` | fixed, low-risk commands in a pinned container | **ENABLED** only as `sbx-podman-local-restricted-v1` |
| `UNTRUSTED_CODE` | hostile code in the bounded local profile | **ENABLED** only as `sbx-gvisor-untrusted-v1` |

`NO_EXEC`, `sbx-podman-local-restricted-v1` and
`sbx-gvisor-untrusted-v1` are contract-valid profiles. Each executable
profile is registered only while its exact evidence content address is
present in the authorization decision. Missing or substituted evidence
therefore fails closed before spawn.

The Podman backend is `src/lib/identity/podman-sandbox.mjs`. Callers may
provide only a bounded argv vector, job id and timeout. The WSL distribution,
image digest and isolation flags are host-owned constants. Alternate images,
host mounts, network access, environment/secret injection and shell command
strings are not request fields.

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

### 2.2 Network (deny by default)

- `deny_all` forbids every destination (checked host+port pairs).
- Allowlist profiles match exact host and port; empty allowlist under
  `allowlist` policy is rejected by the profile contract itself.
- The enabled Podman profile uses a separate container network namespace with
  `--network=none`; observation exposes only loopback (`lo`).

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

The Podman backend additionally enforces rootless execution, UID 65534,
read-only rootfs, all capabilities dropped, `no-new-privileges`, seccomp,
private IPC, 32 PIDs, 128 MiB memory, 0.5 CPU and a 16 MiB noexec tmpfs. It
always attempts exact container cleanup, including after timeout. The real
authorization-to-execution smoke is recorded in
`evidence/s2-002-podman-sandbox.json`.

The gVisor backend is `src/lib/identity/gvisor-sandbox.mjs`. It launches a
host-owned pinned image through `/usr/bin/runsc` in systrap mode, with an
outer 65,536-ID Podman auto-userns mapping. Observed controls include the
`4.19.0-gvisor` runtime kernel and gVisor boot marker, UID 65534, zero
effective capabilities, `no_new_privs`, seccomp, read-only rootfs, no host
mounts, no environment injection, loopback-only networking, 32 PIDs,
128 MiB memory and 0.5 CPU. The full record is
`evidence/s2-002-gvisor-sandbox.json` and is SHA-256-bound to the profile.

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

1. This is a bounded local confinement proof, not proof that every hostile
   program or kernel attack is safe. The `UNTRUSTED_CODE` label applies only
   to the exact pinned gVisor profile and evidence digest.
2. AppArmor and SELinux are unavailable in this WSL2 distribution. gVisor's
   userspace kernel is the compensating isolation boundary; deployment on a
   production host should still receive an independent sandbox review.
3. The profile deliberately has no network allowlist, host workspace mount,
   environment injection or secret delivery. Workloads requiring those
   features are unsupported rather than silently weakened.
4. Only the pinned Alpine digest already present in the rootless image store
   is accepted; pulling or selecting images is outside the execution request.

## 4. Engine integration

The policy engine maps capability `exec_tier` to a registered profile and
binds the profile id and evidence digest into every `ALLOW` decision. The
execution bridge rejects an `ALLOW` that lacks either exact binding. Runtime
verification re-observes the controls and compares them to the committed
record before acceptance. Capability discovery may describe tools; discovery
is never a substitute for execution-time authorization.
