# S2-001 pilot reconciliation

## Result

S2-001 is `PASS_WITH_LIMITS`. The earlier local contract workspace remained
fail-closed because it intentionally had zero real pilot executions. Scenario A was
subsequently executed in the separate public repository
`SpaceDazher/Veritas-AI-Production-Pilot` and merged to its `main` branch as commit
`6845858bccf3aec27c656649ac40ad01148e7505` with tree
`b5341a37be08b318f28015cf83afeb106fe4138b`.

The authoritative cross-repository binding is
`evidence/s2-001-pilot-binding.json`. Four upstream JSON artifacts are frozen under
`evidence/external/s2-001/`. `scripts/verify-pilot-binding.mjs` checks their canonical
SHA-256 values, internal evidence digests, task/submission linkage, human actor and
the explicit production boundary.

## What was demonstrated

- Codex and pi ran as distinct processes against one frozen task contract.
- PostgreSQL held canonical task state and an append-only hash-linked event chain.
- The task reached `IN_REVIEW`, then a named repository owner approved the exact
  Solution Blueprint digest.
- The upstream branch and final merge were reproduced from a clean Git archive.
- The approved incremental paid API budget was USD 0; no production deployment was
  authorized or performed.

## Binding limitations

- The approved object is a Solution Blueprint, not a deployed application.
- Subscription CLIs did not expose exact per-call billing telemetry.
- Ambiguous external side-effect reconciliation was specified but not exercised.
- Both real agent processes ran on the same host.
- The human decision used an operator-mediated local session, not production identity
  infrastructure.
- Scenario B is contract-only and moves through S2-003–S2-006 rather than being
  backfilled with synthetic evidence here.

These limits are inherited by downstream tickets. They do not block S2-002 identity,
grant and sandbox work, but S2-002 must not claim production authentication or
multi-host isolation from this evidence.
