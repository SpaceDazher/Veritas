# S2-007R: the HOST_UNISOLATED floor tier and the named authorisation (issue #45)

- Status: accepted by the repository owner in the thread that runs issue #45
- Ticket: S2-007R (SpaceDazher/Veritas#45), carried over from #7
- Touches: `contracts/sandbox-profile.schema.json`,
  `src/lib/identity/sandbox-profiles.mjs`, `src/lib/agentboard/constants.mjs`,
  `src/lib/agentboard/policy.mjs`, `src/lib/agentboard/scheduler.mjs`,
  `src/lib/agentboard/commands.mjs`, `src/lib/agentboard/clock.mjs` (new)

## The problem, measured

S2-007R has to run two genuinely installed executors (`codex` 0.157.1, `pi`
0.87.1) through the `veritas.adapter/1.0.0` boundary. Both are model-calling
agents, and the board refuses to start a run whose isolation profile is not one
with measured OS controls — deliberately, so that a degraded unisolated run
cannot pass as an isolated one.

On this host that leaves no lawful way to start a run at all:

| measured fact | how it was measured |
| --- | --- |
| `createSandbox(...).executionAllowed === false` for every executable tier, reason `SBX_NO_KERNEL_NETWORK_BOUNDARY` | `scripts/verify-s2-007r-host-unisolated.mjs`, field `measurements.shippedRuntimeVerdict` |
| the pinned isolation image contains no `node`, `npm`, `codex` or `pi` | same script, `measurements.pinnedIsolationImage` |
| inside that image `/proc/net/route` has no route line and DNS does not resolve; a plain `wget` to `1.1.1.1` returns `Network unreachable` | same script, `routeLines`/`dns` |
| a credential could not reach a containerised child even with egress: `injectedEnvironment: 0`, `mounts: 0`, and `secret_handles: []` in the profile | same script, `measurements.credentialPath` |
| the host itself has egress (`HTTP 200` from the provider's models endpoint) | same script, `measurements.hostEgress` |

So the proven profiles are proven for deterministic, non-model command
execution, and a model-calling executor can only run in the host process space.
`evidence/s2-007r-host-unisolated.json` is that measurement, digest-bound into
the profile as its `os_controls_evidence`.

## The three options, and why this one

1. **Name a proven profile for a process that never entered its container.**
   Rejected. The `sandbox_profile_id` in the registration, in the journal, in
   the run record and in every downstream summary would then name controls that
   were not in force. A disclosure block beside it does not repair a field that
   is itself false, and `assertSandboxExecutable` would be satisfied by a claim
   rather than by a fact. This is the one option that makes the record lie in the
   field a reader looks at first.
2. **Leave the proven set untouched and let the run be refused.** Rejected by the
   owner, correctly: it delivers a boundary and a refusal, no measurements, and
   leaves the missing capability undocumented and unowned.
3. **Add a strictly lower tier that describes exactly what is in force, and
   require a named human authorisation to use it.** Chosen.

## What the tier is, and is not

`SANDBOX_HOST_UNISOLATED` (`sbx-host-unisolated-v1`, tier `HOST_UNISOLATED`) is
an ordinary host process with nothing OS-enforced around it. It is not in
`PROVEN_SANDBOX_PROFILE_IDS` and never will be: `isExecutableSandboxProfile` keeps
meaning "this tier has measured OS controls", so no existing control is relaxed.

The contract makes the tier unable to impersonate an isolated one. `HOST_UNISOLATED`
**must** declare `network.policy: "unrestricted"` and `environment.allowlist:
["*"]` with no secret handles — the schema forbids `deny_all`, forbids an
allowlist, and forbids secret handles for this tier — and it must carry the
digest of the measured absence of controls. The mirror rule forbids an isolated
tier from declaring `unrestricted` or a wildcard environment. Both directions are
enumerated as negatives in `tests/identity/contracts.schemas.test.mjs`.

## The authorisation

`policy.assertLiveExecutionAuthorized(profileId, { authorization, now })` is the
single gate a live execution passes through:

- an isolated profile with measured controls needs nothing, and a permit supplied
  for one is **refused**, not ignored — a permit nobody needs is either a
  mistake or an attempt to buy something;
- `HOST_UNISOLATED` is admitted only with a complete permit: id, authorising
  principal, label, authority (`HUMAN_OWNER`), scope (`SINGLE_PILOT_RUN`), the
  profile it names, an issued/expires window, and a digest over its own body;
- everything else, including the `*_blocked` and `NO_EXEC` profiles, is refused
  exactly as before.

The permit is a **server-resolved execute() option**, never a payload argument.
An adapter, a task, an execution event, a skill or a replayed record can neither
supply nor widen it — the confused-deputy rule is unchanged. The window is judged
against the injected board clock, never the process clock. The permit travels
with the run in `execution.start`'s `sandboxDecision`, so a later reader can
re-judge the same document the run started under.

The permit itself is emitted by `scripts/s2-007r-authorization.mjs` rather than
checked in as JSON, so its `body_digest` is computed by the same function that
verifies it and a hand-edited file cannot keep a valid digest.

## Consequence for the acceptance record

- A-MVP-04's **isolation clause** is `NOT_RUN` on this host, always, whatever
  the run shows. Termination, fencing and reconciliation clauses are measurable.
- `assuranceStatus` stays `NOT_MEASURED`; `aMvpStatus` stays `NOT_CLAIMED`. The
  permit is neither a review nor an acceptance.
- The permit does not approve spend. The board's budget grant does that,
  separately, and the pilot brief's `execution_authorized: false` is unchanged.
- `evidence/s2-007r-host-unisolated.json` must be quoted by digest in the run
  record; a record without that block is refused.

## What would remove the need for this tier

1. a digest-pinned image containing the node runtime and the executor binaries;
2. a network allowlist replacing `--network=none` with the provider endpoint only;
3. a secret-handle mechanism in the profile, so a credential reaches the child
   without exporting the operator environment.

Until all three exist, an isolated model-calling run is not a configuration
knob. It is a separate S2-002 capability, and it belongs to #12's dependency
list, not to a workaround in this ticket.

## Note on a stale premise

`docs/stages/S2-007.md` states that S2-002 process-tree cancellation is unsound
off Windows because `listDescendants` returns `[]` and the child is not detached.
At this HEAD that is no longer true: `sandbox.mjs` sets
`useProcessGroup = process.platform !== 'win32'` and passes `detached:
useProcessGroup`, and `process-observer.mjs` implements a real POSIX tree walk.
The claim belongs to the stage record's owner and is reported here rather than
edited in place.
