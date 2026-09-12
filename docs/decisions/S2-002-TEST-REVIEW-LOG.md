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

## Entry 2 — pending

No further entries yet.
