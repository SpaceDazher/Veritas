# S2-002 — Test Review Log

Separate review record for any change to tests/oracles after candidate
results were observed, as required by `tasks/S2-002_IDENTITY_SANDBOX.md`
(TDD section). Entries are appended chronologically and are never removed.

## Entry 1 — 2026-09-12, phase 2 (policy engine), RED→GREEN cycle

Scope: `tests/identity/policy-engine.test.mjs` only. No contract, schema,
registry or engine test was weakened; both mutations happened while the
engine under test still failed its suite (pre-GREEN reconciliation of test
fixtures with the frozen seeded registry).

1. Mutation: "write capability without ACL or grant is denied" — request
   moved from `prn-owner-alice`/`ws-alice-private`/`task.create` to
   `prn-external-pi`/`ws-veritas-project`/`task.create`.
   Reason: the original request accidentally targeted the workspace owner,
   whose `rol-workspace-owner` ACL legitimately grants `task.create`, so the
   test contradicted the frozen registry rather than testing default deny.
   The replacement tests the same rule (default deny without ACL and grant)
   against a principal with neither.

2. Mutation: "identical requests through web, api and cli produce identical
   decisions" — deep-equal on full result replaced by comparison of
   decision + reason codes + document without `input_digest`/`audit_ref`,
   plus an assertion that the digests differ across adapters.
   Reason: `adapter` is deliberately part of the hashed request so audit
   records identify the issuing surface; authority fields are identical.
   The mutated test asserts exactly this contract and adds a negative check
   that the audit digest does distinguish surfaces.

Reviewer note: both mutations tighten or neutral-rescope the oracle; no
failure was masked. The failing behavior that motivated each mutation is
covered by other tests in the same suite (ownership matrix, default deny,
audit document checks).

## Entry 2 — phase 5 (independent replay), RED→GREEN cycle

Scope: `tests/identity/replay-runs.test.mjs` only, written before the runner
existed and reconciled while it still failed:

1. `runCorpus` is asynchronous (the corpus contains the live cancellation
   probe), so the two corpus executions moved to module top-level `await`
   instead of synchronous calls inside `describe`. No expectation changed.
2. Import path corrected from `../../../scripts/...` to `../../scripts/...`
   (test file lives at `tests/identity/`, not `tests/identity/<subdir>`).
   Import-resolution fix only.

Both mutations are mechanical harness corrections made while the suite was
still RED; no oracle was weakened and no failing behaviour was masked.

## Entry 3 — corrective round after independent REVISE review

Scope: an external review returned verdict REVISE with P0 findings. The
corrective round reproduced every finding, then fixed the production code.
Test-suite mutations in this round:

1. `tests/identity/policy-engine.test.mjs`: the `req()` fixture helper now
   fills canonical arguments per action (the engine gained canonical
   argument/resource-type enforcement, so bare `args: {}` fixtures stopped
   reflecting legitimate requests). Twelve new tests pin the fixes:
   canonical arguments present/absent/non-canonical, resource-type
   mismatch, exact lease binding (capability, grant, principal,
   not-required), message recipient scoping. One ownership test now uses
   per-action resource types (resource-type enforcement made the shared
   `task`-typed resource wrong for `board.read`).
2. `tests/identity/replay-runs.test.mjs`: five new comparator tests pin the
   fail-closed behaviour (empty runs, NaN/missing counters, frozen-oracle
   mismatch identical in both runs, sandbox match flag, trialCount
   consistency). One test id fixed from `acl/...|...` to `acl/.../...` to
   match the runner's actual trial-id format.
3. No oracle was weakened. The corpus runner's `cap/curator/claim.write`
   expectation was CORRECTED: the review found the old cell recorded a
   lease/capability mismatch as `ALLOW`; the registry now carries a
   dedicated claim.write grant + lease, and a second negative trial pins
   `LEASE_CAPABILITY_MISMATCH`. New positive/negative message-recipient
   cells and a wrong-grant-lease cell were added.

## Entry 4 — pending

No further entries yet.
