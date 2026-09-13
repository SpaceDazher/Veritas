# S2-003 — Provenance, ACL and Retention

Status: contract-first, read-only ingestion subsystem for Veritas.
Ticket: `tasks/S2-003_SOURCE_INGESTION.md` · Verdict: `PASS_WITH_LIMITS`.

## 1. Complete fetch provenance

Every committed `source-snapshot` carries a mandatory `fetch_provenance`
block: `operation_id` (idempotency key), `connector_id`, `connector_version`,
a sanitized credential-free `fetched_from` locator, `fetched_at`, optional
`grant_id` and `content_type_validated`. The ingestion-run contract requires
frozen input digests (`connector_contracts_sha256`, `corpus_sha256`,
`policy_sha256`) plus environment provenance (commit, tree). Provenance
completeness is enforced twice: by schema (`required`) and by the run
integrity counters (`provenance_complete_pct` must equal 100; both replay
runs report 100).

ACL, license and retention are **inherited from the source descriptor**, never
from content (probe K). The snapshot's `acl` block records
`visibility: public | project | private`, `workspace_id`, `tenant_id` and —
for private sources — mandatory `allowed_workspace_ids` /
`allowed_principal_ids` (a private descriptor without a scope is rejected by
the contract registry's semantic checks).

## 2. Append-only storage and lifecycle

`migrations/0002_source_ingestion.sql` creates append-only tables:
`source_descriptor`, `source_snapshot`, `content_segment`, `source_lineage`,
`ingestion_run`, `ingestion_event`, `source_proposal` and the idempotency
ledger `ingestion_operation` (primary key `(workspace_id, operation_id)`).
`UPDATE`/`DELETE` on payload tables raise `APPEND_ONLY_VIOLATION` via trigger —
proven against a live PostgreSQL 17 instance in
`evidence/postgres-smoke.json` (`ingestionAppendOnlyRejected: true`,
`ingestionTableCount: 8`, applied on an empty database with a digest ledger
and drift detection on replay).

- **Corrections** append a new version bound with `supersedes_snapshot_id`
  (unique `(canonical_locator, version)`; self-supersede rejected).
- **Deletion/retraction** appends a `tombstone` snapshot (mandatory reason),
  moves the current pointer atomically and tombstones the descriptor, while
  the prior snapshot and all audit events remain (probe A).
- **Current pointer** is the last entry of the version chain, updated in the
  same critical section as the appended row and event.

## 3. Idempotency, crash and reconciliation

`ingestion_operation` is the ledger: an `INTENT` row is written before any
side effect; the terminal is recorded exactly once. Replays with the same
`(workspace_id, operation_id)` return the recorded terminal without
re-executing. A crash leaves `INTENT`; the restart path reconciles via
`connector.reconcile(operationId)` and terminates with
`RECONCILIATION_REQUIRED` — never a blind retry, never a duplicate snapshot
or duplicate event (probe J; corpus cases `crash-*`,
`reconciliation-is-terminal-not-retry`). The database mirror enforces the
same property via the composite primary key
(`ingestionDuplicateOperationRejected: true` in the smoke evidence).

Hard counters from both replay runs: `operations_stuck_intent = 0`,
`duplicate_committed_snapshots = 0`, `committed_without_snapshot = 0`.

## 4. Deduplication and lineage

Staged, deterministic, wall-clock-free (`src/lib/ingestion/dedup.mjs`):

1. exact raw-byte SHA-256 → `exact_duplicate`, automated + confirmed;
2. exact normalized-content SHA-256 (NFC, unified newlines) → same;
3. exact canonical provider identity + version → mirror / new-version chain;
4. near-duplicate classifier (5-word shingle Jaccard) → **candidate** lineage
   with evidence and confidence, `automated: false`, `NOT_CALIBRATED`,
   advisory only.

Only stages 1–3 may create automated, confirmed lineage; they never delete or
physically merge snapshots (probe C: copies link upstream and do not count as
independent confirmations; near-miss identities never auto-merge — corpus
`nearmiss-*` cases prove `lineage_automated == 0`).
`source count` metrics may collapse verified upstream lineage, but physical
documents and citations remain.

## 5. Extraction quality

Every `content-segment` stores the observable quality model: extraction
`method` (`native_text | parser | ocr | asr | manual_export`), extractor name
and version, optional `config_sha256`, `confidence` in [0, 1],
`uncertainty_flags` (`LOW_CONFIDENCE`, `MISSING_RANGES`, `UNDECODABLE_BYTES`,
`OCR_NOISY`, `ASR_NOISY`, `LANGUAGE_UNCERTAIN`, `TRUNCATED`), `missing_ranges`,
coverage and `status: COMPLETE | PARTIAL | FAILED | QUARANTINED`. Low OCR/ASR
confidence (< 0.5) without uncertainty flags is rejected by semantic checks;
low confidence is never converted into confident text. Malformed inputs are
stored with visible uncertainty (probe E) except the empty payload, which is a
`FAILED` terminal — silent empty successes are forbidden.

## 6. ACL enforcement on every read/export

`src/lib/ingestion/export-policy.mjs` enforces scope server-side on every
export: `private` requires the viewer principal or workspace to be in the
descriptor-inherited allow-list; `project` requires workspace/tenant match;
out-of-scope viewers get `EXPORT_DENIED`. The public-evidence view of a
non-public snapshot contains **existence metadata only** (digests are not
content): `content_included: false`, zero segments, no private bytes in any
serialized output (probe G). Private source bytes are never committed; all
fixtures are synthetic canaries.

## 7. Retention and licensing gates

Descriptors with `LICENSE_UNKNOWN` cannot be retained forever and block
ingestion downstream (`LICENSE_UNKNOWN` → `FAILED`, no snapshot). Retention
`retain_then_delete` with an expired `retain_until` (evaluated on the injected
decision clock, not the wall clock) blocks ingestion
(`RETENTION_BLOCKED`). `keep_forever` with unknown license is rejected at
descriptor registration time.
