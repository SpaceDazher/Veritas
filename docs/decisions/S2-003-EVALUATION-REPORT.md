# S2-003 — Source Ingestion Evaluation Report

Ticket: `tasks/S2-003_SOURCE_INGESTION.md`
Branch: `codex/s2-003-source-ingestion` (base: `origin/main` at the S2-002
merge `4b4456a3acbe78371e2afcc75d81da59d2765b53`)

## Verdict: PASS_WITH_LIMITS

All fifteen Definition-of-Done conditions of §15 are evidenced below. `PASS`
without limits is forbidden by the ticket and is not claimed: live private
connectors, production OCR/ASR quality, near-duplicate calibration and an
external independent audit are out of local S2-003 scope.

## 1. Dependency proof (§18.1)

Gate: `scripts/verify-s2-003-dependencies.mjs` →
`evidence/s2-003-dependency-binding.json`. Status: **PASS** (28 byte-level
checks), fail-closed (`BLOCKED_DEPENDENCY` otherwise; mutation coverage in
`tests/ingestion/dependency-binding.test.mjs`, 11 tests).

- `origin/main` = S2-002 merge `4b4456a3acbe78371e2afcc75d81da59d2765b53`;
  S2-002 closure commit `f28e45b1ef044f9ab6b6c616c0380ac4f368ff5b` reachable.
- S2-002 evidence read from **Git bytes** at `f28e45b1` (blob digests pinned in
  the binding record): closure-record, root/frozen manifests (every frozen
  entry re-hashed from Git blob bytes), green clean-checkout, A/B comparison
  (0 mismatches), Podman + gVisor sandbox records, PostgreSQL smoke,
  34/34 policy probes, 11/11 security probes.
- S1-001 pinned to AgentOS commit `259d9afe16495aa780f834d0b1b903d5451e158a`
  (never a branch or temp path); tracked copy
  `evidence/external/s1-001/evaluation-record.json` verified by SHA-256
  `eaaeab0124408253e49bde44282b4fde9dda975deabdf04c43119ad7e1a963b5`
  (1727 bytes), `result: pass_with_limits`,
  `reval_1DG5Q6WEAY6A40A901M0TDDN6N`; cross-bound against the AgentOS commit
  recorded in the S2-002 binding at `f28e45b1`.

## 2. Contracts, corpus and evaluators (§18.3)

Nine contracts at `1.0.0` — digests in
`docs/ingestion/S2-003-CONNECTOR-CONTRACT.md` §1; registry
`src/lib/ingestion/contract-registry.mjs` (schema + semantic checks, fail-closed
on unknown fields/versions). TS types generated from the same schemas
(`src/lib/ingestion/contracts.d.ts`, drift test).

- Corpus: 74 cases (minimum 72), SHA-256 per case in
  `corpus/s2-003/manifest.json`
  (`corpus_manifest_sha256 7eb80b1c21b4c945127ff10a6bf53f50eae26bc2701051b343d058bb453a005d`),
  evaluator (`scripts/s2-003-run.mjs`) pinned at
  `1fe59b8eb48709712a5beddb4b9718dfad6b67089f1522c34ce9478791e898d6`.
  Categories: gold_import 8, edit_delete 8, exact_duplicate 6, mirror_lineage 6,
  near_miss_identity 6, malformed_partial 8, unavailable_connector 6,
  acl_private 8, embedded_instructions 6, crash_reconciliation 6,
  timestamps_clock 6.

## 3. Connector executability (§18.2)

Executable in a bounded profile: `markdown_obsidian` (read-only vault,
byte-identity test), `manual_export`, `web_url` (injected fetch, no
credentials). `github` / `telegram` / `youtube` / `arxiv_huggingface`:
canonical identity and fixture normalization implemented and tested; live
fetch is an honest `BLOCKED_CONNECTOR` without a verified credential grant —
empty successful imports are structurally impossible.

## 4. Case matrix (§18.4)

Per-category coverage: gold imports across all 8 source kinds; edits,
corrections and deletions (tombstone semantics); raw/normalized exact
duplicates and mirror lineage; near-miss identities (never auto-merged);
malformed/partial inputs (stored with visible uncertainty; empty payload
fails); unavailable/rate-limited connectors; private/ACL/license/retention
blocks; embedded instructions (data-only classification); crash/unknown
outcome/reconciliation; timestamps and wall-clock perturbation.

## 5. Run A / Run B and hard counters (§18.5, §13)

Two process-separated runs over the same frozen corpus, distinct executor ids,
nonces (`n-8f4dffb1bd7086a4` / `n-af66410de38ce103`), output roots and
injected clocks (`2026-01-15T08:00:00.000Z` / `2026-03-21T23:59:59.999Z`).
Raw observations: `evidence/s2-003-run-a.json`, `evidence/s2-003-run-b.json`;
comparison: `evidence/s2-003-comparison.json`.

Terminal distribution per run (74/74 cases each):
COMMITTED 55, FAILED 6, RECONCILIATION_REQUIRED 4, TOMBSTONED 4,
BLOCKED_CONNECTOR 2, ACCESS_DENIED 2, CANCELLED 1.

| Hard counter | Limit | Run A | Run B |
| --- | --- | --- | --- |
| provenance completeness | 100% | 100% | 100% |
| operations stuck in INTENT | 0 | 0 | 0 |
| duplicate committed snapshots | 0 | 0 | 0 |
| committed outcomes without snapshot | 0 | 0 | 0 |
| unauthorized/private exports | 0 | 0 | 0 |
| instruction-driven authority expansions | 0 | 0 | 0 |
| silent empty successes | 0 | 0 | 0 |
| unreconciled unknown outcomes | 0 | 0 | 0 |
| missing/censored cases | 0 | 0 | 0 |
| Run A/B decision mismatches | 0 | 0 (74 compared) |
| content identity mismatches | 0 | 0 |
| instruction-flagged segments (non-vacuous check) | ≥1 | 5 | 5 |

Near-duplicate results are `NOT_CALIBRATED`: the classifier is advisory-only
and no precision/recall is claimed without an independent gold set.

## 6. Probes A–L (§18.6)

`scripts/s2-003-security-probes.mjs` → `evidence/s2-003-security-probes.json`:
**12/12 DETECTED, 0 skipped, 0 escaped** through the production path —
A deleted source (tombstone current, prior preserved), B same-locator edit
(immutable v2 supersedes v1), C cross-channel duplicate (linked upstream,
confirmed exact_duplicate, both snapshots remain), D unavailable media
(FAILED/NOT_FOUND, zero snapshots), E malformed/uncertain extraction visible
downstream, F embedded instructions (classified data-only, policy untouched),
G private export (out-of-scope denied; public view content-free), H alias
collisions (aliases converge, distinct objects never merge), I clock
perturbation (identity/verdict stable, telemetry differs), J crash replay
(RECONCILIATION_REQUIRED, zero duplicates), K forged provenance (host-observed
metadata wins), L manifest substitution (digest drift → QUARANTINED).

## 7. PostgreSQL migration/replay evidence (§18.7)

`evidence/postgres-smoke.json`: ephemeral loopback-only PostgreSQL 17.11
(rootless Podman, pinned image digest, tmpfs data, random credentials, no host
ports beyond loopback, cleanup verified). Both migrations applied on an empty
database inside one transaction with a digest ledger; re-apply path is
drift-checked. Ingestion section: 8 tables present, `UPDATE source_snapshot`
rejected by `APPEND_ONLY_VIOLATION` trigger, duplicate
`(workspace_id, operation_id)` insert rejected (23505).

## 8. Clean checkout and exit codes (§18.8)

`npm run verify:clean-checkout` archives HEAD into an empty directory and runs
npm ci plus the full gate set (S2-002 suite, S2-003 dependencies, ingestion
tests, S2-003 security probes, S2-003 replay, manifests, contracts, typecheck,
lint, build with a placeholder `DATABASE_URL`, both audits). Green = exit 0;
the tracked record is `evidence/clean-checkout.json`. Individual acceptance
commands from §16 are wired as npm scripts and were executed green:
`npm ci`, `verify:s2-003-dependencies`, `test:ingestion` (85 tests),
`test:s2-003-security-probes`, `verify:s2-003`, `verify:postgres-smoke`,
`typecheck`, `lint`, `build`, `npm audit --omit=dev` (0 vulnerabilities),
`npm audit` (0), `verify:clean-checkout`, `manifest:check`, `git diff --check`
(clean), `git status --short` (clean at closure).

## 9. Honest limitations and inputs for S2-004 (§18.10)

- No live private connectors: github/telegram/youtube/arxiv_huggingface
  require verified grants; normalization is fixture-proven only.
- OCR/ASR are fixture-level; no production extraction quality is claimed.
- Near-duplicate detection is advisory and `NOT_CALIBRATED`; a calibrated
  gate and an independent gold set are prerequisites for any merging policy.
- Authorization state is per-engine in-memory (S2-002 limitation inherited);
  the SQL mirror exists but the pipeline store is not yet a live PostgreSQL
  client (the migration and its append-only/idempotency semantics are proven
  directly against the database).
- No production authentication; no external independent audit.
- S2-004 inputs: `SourceSnapshot`/`ContentSegment`/`source_lineage` contracts
  as the claim-graph substrate; `embedded_instruction_classification` as
  data-only input; candidate lineage requires explicit human confirmation
  before it may influence any downstream verdict.
