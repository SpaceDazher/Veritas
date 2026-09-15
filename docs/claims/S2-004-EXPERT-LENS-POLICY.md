# S2-004 — Expert Lens Policy

Ticket: `tasks/S2-004` · Verdict: `PASS_WITH_LIMITS`.

## What a lens is

An expert lens (`contracts/expert-lens.schema.json`) is a per-user,
per-workspace trust preference for one expert in one domain and task class,
with a ranking weight in [0, 1], a validity period, a rationale, an issuer
and explicit revocation. It has **no authority and no truth field** — the
schema rejects any extra property, so a lens physically cannot carry an
authority or truth value.

## What a lens may do

- change presentation order of candidate claims for exactly one owner
  (workspace + principal): `adjusted_rank = base_rank + weight` with a
  stable tie-break;
- suggest additional sources for reading priority.

## What a lens may never do (enforced, probe F)

- change evidence counts, family collapse results, epistemic types,
  lifecycle, calibration records or gate verdicts —
  `lensesPreservedCandidates` proves every original candidate field survives
  byte-for-byte and only `adjusted_rank`/`lens_influence` are added;
- leak across owners: `listExpertLenses` returns lenses only to their owner
  workspace+principal pair; a lens issued for user A is invisible to user B
  and to other workspaces;
- outlive its validity window, task class or expert binding: expired,
  wrong-task-class and expert-mismatched lenses contribute zero influence;
- survive revocation: `revokeExpertLens` (issuer, owner or admin only)
  stamps `revoked_at` + reason; the lens immediately disappears from new
  decisions, while previously produced results keep their provenance through
  the recorded `lens_id`.

## Separation from evidence, calibration and gates

A trusted expert's unsupported claim gets review priority — nothing else.
Evidence family counts stay at zero for unsupported claims, calibration
records stay `NOT_MEASURED` without an independent evaluator, and an
`ACCEPTED_BOUNDED` verdict still requires an authorized reviewer decision
from someone who is not the producer. Lens weight is a ranking input only
and is never an input to any gate, threshold or verdict.
