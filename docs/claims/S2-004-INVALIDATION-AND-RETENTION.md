# S2-004 — Invalidation and Retention

Ticket: `tasks/S2-004` · Verdict: `PASS_WITH_LIMITS`.

## Invalidation triggers

`contracts/graph-invalidation-event.schema.json` enumerates the triggers:
source snapshot tombstone/correction/retraction, content segment
tombstone/correction, claim tombstone/correction/revocation, access
restriction and retention expiry. Every event records the exact trigger
(id + revision), a reason code + description, traversal evidence (method,
visited count, traversed edge ids), the affected descendants and a
completion state; `FAILED`/`PARTIAL` require `failed_descendants`.

## Transitive semantics

- A tombstone/correction/retraction of a parent snapshot or segment marks
  every claim evidenced by that segment `STALE`.
- A claim correction (`reviseClaim`) supersedes the old revision
  (`SUPERSEDES` edge, old revision projected `SUPERSEDED`) and any claim
  that `DEPENDS_ON` the superseded revision is marked `STALE` until
  re-review; `TRANSLATES` edges propagate staleness to translations.
- Re-review after invalidation is possible: an authorized reviewer decision
  moves a `STALE` claim back to a verified state and clears the stale
  reasons; the invalidation events remain in the ledger.

Invalidation is authority-gated: only the system principal (the ingestion
layer) or an admin can trigger it — content can never invalidate anything.

## Audit trail and retention

Invalidation never deletes anything. Claim history stays queryable, evidence
maps stay resolvable, and the audit outbox grows: the reason a payload is
unavailable stays visible while the payload itself can be hidden per
retention/ACL. Access restriction and retention expiry are modeled as
invalidation triggers that mark affected claims stale/restricted with the
reason preserved (`upstream_tombstoned`, `retention_expired`,
`access_revoked`, …).

## PostgreSQL shape

`claims`, `evidence_edges` and `claim_edges` rows are append-only content;
projected lifecycle lives in `claim_state` (migration 0004) and is updated
transactionally together with the `graph_invalidation_events` row and the
audit outbox entry. Derived ACL equals the most restrictive ACL of all
inputs; deletion/restriction hides payload, never lineage.
