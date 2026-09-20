# S2-006 round-three closure — TDD evidence

Date: 2026-09-19  
Branch: `codex/s2-006-independent-semantic-verifier`

## RED

Commit `9ad5a621cc311aa07b5739fdc2a403ee2686347d` added executable
reproducers before the implementation changes. The focused run had 39 tests:
31 passed and 8 failed on the reviewed defects (ACL intersection and immutable
metadata, adjudicator custody, owner authority/sample/split handling, verdict
propagation, PostgreSQL serialization and task-budget scope).

## GREEN

The implementation now provides these guarantees:

- private input allowlists are intersected; incompatible workspace/ACL
  republication is an atomic `IdempotencyConflict`;
- every annotation and adjudication signature uses the custody-aware registry;
  the retired shared-key argument fails closed;
- owner evidence cannot mint its own keys, principals or grants; trust is a
  separate operator input, fixture-grade trust is refused, the original
  manifest is schema-validated, split families/templates are disjoint, and at
  least 20 deduplicated external locked-test cases are required;
- an eligible owner run participates in the aggregate verdict instead of being
  reduced to fixture-only `NEEDS_INPUT`;
- PostgreSQL locks the external-call row before transition decisions, predicates
  updates on the observed state, and tracks task spend by `(grant, operation)`.

Focused offline verifier run: 299 tests, 293 pass, 0 fail, 6 explicit
`NOT_RUN_DB` skips. A separate loopback-only ephemeral PostgreSQL run executed
`tests/verifier/store.test.mjs` with no skips: 30/30 pass, including the
finalize/reconciliation race and independent per-operation task budgets.
`npm run verify:s2-006-db-replay` also passed with two processes, identical
digests, crash/restart fencing and zero duplicate ledger/outbox writes.

## Remaining product limitation

The default verdict remains `NEEDS_INPUT`: no real external corpus, independent
annotators/adjudicator, method-owner threshold decision or production custody
keys were supplied. The code path can now advance only when those inputs arrive
through a separately trusted owner bundle; this report does not claim semantic
calibration or production readiness.
