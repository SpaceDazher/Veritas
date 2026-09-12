# S2-002 — Threat Model (frozen)

Status: FROZEN for S2-002 evaluation. Changes require a new version and
human review. Scope: the local bounded identity and sandbox gate of the
Veritas Agent Board workspace (`codex/s2-002-identity-sandbox`).

## 1. Assets under protection

1. Workspace contents: tasks, sources, claims, summaries, caches, artifacts
   and their ACL boundaries (five private workspaces, one project workspace,
   one shared library).
2. Authority state: principals, roles, capabilities, grants, leases,
   fencing tokens, nonces and their revocation state.
3. The policy engine itself: its decisions must stay a function of the
   registry and the request, never of request-embedded claims.
4. Secret values reachable through opaque handles inside sandboxed
   operations.
5. Evidence integrity: frozen contracts, manifests, probe and run records.

## 2. Subjects (20 principals, deterministic fixtures)

- 5 human owners (`prn-owner-alice|bob|carol|dave|eve`), each owning one
  private workspace.
- 5 personal agents (`prn-agent-*`), each acting only through explicit
  human-issued grants.
- 4 external service principals (`prn-external-codex|pi|opencode|hermes`),
  isolated identities with grant-only access.
- 6 platform agents (collector, curator, analyst, experimenter, verifier,
  operator) with role-bound access inside assigned workspaces only.

The number of principals is ACL coverage, not a claim of 20 concurrent
human users. No principal inherits another's authority; platform agents
never carry personal delegation and never issue grants to themselves.

## 3. Trust boundaries

```
Web / API / CLI  ──►  policy engine (single server-side decision point)
                          │  reads
                          ▼
                   authority registry (principals, roles, capabilities,
                   grants, leases, sandbox profiles)
sandbox adapter  ──►  filesystem / network / environment / process tree
```

1. Any caller surface (Web, API, CLI) is untrusted; only the engine's
   decision grants authority. Parity is enforced: the adapter never changes
   a decision (input digests differ per surface for audit only).
2. Everything outside the engine's registry is data. JSON fields, prompts,
   environment variables, model output and content hashes are never proof
   of identity or authority.
3. The sandbox adapter is the only component permitted to create processes,
   and its executable tiers are blocked while no kernel-level network
   boundary is provable (see SANDBOX-PROFILE).

## 4. Threats and controls (mapped to adversarial probes A–J)

| ID | Threat | Control | Probe | Result |
|----|--------|---------|-------|--------|
| T1 | Cross-tenant source/search retrieval | default deny; grant resource scope pinned per workspace | A | DETECTED |
| T2 | Private claim laundered into shared summary/cache | derived artifacts inherit strictest input ACL; cross-tenant input ⇒ DENY `CROSS_TENANT_INPUT` | B | DETECTED |
| T3 | Payload/env forging role, principal, approval | request fields beyond the canonical shape are inert; approvals human-only, producer self-approval denied | C | DETECTED |
| T4 | Junction/symlink/`..`/UNC/device path escape | canonicalization via deepest existing ancestor + realpath containment; device segments rejected pre-fs | D | DETECTED |
| T5 | Source prompt injection expanding authority or leaking secrets | injected text treated as inert data; escalation attempts re-evaluated by engine; secret redaction in logs | E | DETECTED |
| T6 | Inter-agent message crossing scope/tenant | messaging capabilities absent from unauthorised roles; workspace-scoped | F | DETECTED |
| T7 | Child process surviving cancellation/timeout | tree kill (`taskkill /T /F`, POSIX group kill); survivor count asserted zero | G | DETECTED |
| T8 | Stale grant/lease/fencing token after revocation | revocation forbids use immediately; fencing token monotonic per task; stale ⇒ `STALE_FENCING_TOKEN` | H | DETECTED |
| T9 | Nonce/idempotency replay changing effect | one-time grants atomically consume nonce; replay ⇒ `GRANT_NONCE_CONSUMED` | I | DETECTED |
| T10 | Corrupted/missing policy evidence failing open | registry compiles at import; corrupt clock/profile aborts; tampered decision documents fail contract validation | J | DETECTED |

Every probe drives the production modules (`policy-engine.mjs`,
`sandbox.mjs`) — no guard is re-implemented inside tests. Probe outcomes are
recorded in `evidence/s2-002-security-probes.json`; hard-fail on any ESCAPED.

## 5. Residual threats (explicitly accepted for this gate)

1. No kernel-level sandbox: `LOCAL_RESTRICTED`/`UNTRUSTED_CODE` execution
   stays `BLOCKED_SANDBOX`; live code execution is forbidden until
   AppContainer/container evidence exists.
2. No production authentication: registry records are synthetic fixtures;
   the engine models server-side authorization, not a deployed identity
   provider (IdP).
3. In-memory enforcement state: nonces, fencing ceilings and revocations
   live per engine instance; a durable multi-process deployment needs an
   atomic shared authority store (follow-up, out of scope here).
4. Memory/CPU limits of child processes are recorded but not kernel
   enforced on this stack.

## 6. Failure policy

Any probe ESCAPED, any hard counter above zero in either replay run, or any
decision mismatch between Run A and Run B fails the gate. The engine fails
closed: unknown inputs, unknown versions and unknown principals produce
DENY/BLOCKED, never best-effort ALLOW.
