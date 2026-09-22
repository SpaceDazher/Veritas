# S2-006 owner corpus loader hardening — TDD evidence

Date: 2026-09-22
Branch: `codex/s2-006-independent-semantic-verifier`

## Scope

The owner-input boundary must reject malformed or non-canonical external
corpora without throwing, and it must validate each submitted case against the
frozen `corpus-case` contract before using case fields or scenario digests.
This change does not convert a staging package into calibrated owner evidence.

## RED

Commits `10e5ccc` and `23013d2` added four regression scenarios before the
implementation change:

- a manifest whose `splitAssignments` has the staging object shape;
- the same malformed package exercised through the CLI;
- a case that is missing required frozen-schema fields;
- a canonical manifest whose `cases` directory is missing.

The focused run failed on the expected unsafe behavior: two paths threw
`TypeError`, the invalid case bypassed schema validation, and the absent
directory leaked `ENOENT`.

## GREEN

Commit `f136c4b` makes the boundary fail closed:

- manifest issues stop loading before any manifest fields are dereferenced;
- a missing or unreadable cases directory returns a typed quarantine issue;
- every submitted case is validated by the frozen Ajv corpus-case validator;
- `scenario` must be an object before canonical digest computation;
- the already-read directory listing is reused for the unmanifested-file
  check.

The focused owner-input suite passes 15/15. The complete verifier suite passes
303/303 (297 pass and 6 explicit environment/owner-input skips), and the full
project suite passes 766/766 (760 pass and the same 6 honest skips). Typecheck,
lint, production build, the S2-006 dependency gate, the main verifier gate and
the real PostgreSQL replay all exit zero. The database replay used two OS
processes, produced identical digests, recovered an abruptly terminated call
through fencing with exactly one settlement, and reported zero duplicate
outbox IDs.

## Security review

Untrusted owner files are now rejected before field use. The change does not
relax authority, signature, custody, split, minimum-sample or independence
requirements, and it introduces no network access, secret material or new
capability. Invalid input remains data, not executable instruction.

## v0.5 staging-package result

`veritas_owner_inputs_v05.zip` is internally self-consistent as staging data,
but the official loader now returns `QUARANTINED` cleanly instead of crashing.
Its manifest is not the frozen external-manifest contract, its split assignment
shape is non-canonical, and its cases are draft records rather than compiled
corpus cases. It also contains no independently signed labels, adjudication,
method-owner threshold decision or external trust bundle.

The honest status therefore remains
`STAGING_VALIDATED / MODEL_ASSISTED_NOT_INDEPENDENT / NEEDS_INPUT`. This report
does not claim semantic calibration, independent evaluation or production
readiness.
