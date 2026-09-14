# S2-003 — Source Ingestion Evaluation Report

Ticket: `tasks/S2-003_SOURCE_INGESTION.md`
Branch: `codex/s2-003-source-ingestion` (base: `origin/main` at the S2-002
merge `4b4456a3acbe78371e2afcc75d81da59d2765b53`)

## REVISE round 2 (post-review, 2026-09)

Second review confirmed the round-1 fixes and raised 5×P1 + 1×P2. All fixed
and re-evidenced:

| # | Finding | Fix | Evidence |
| --- | --- | --- | --- |
| P1-1 | Run A/B and clean-checkout evidence pinned to intermediate commits; `verify:s2-003` dirtied the tree on every run | raw run observations default to `results/s2-003/` (untracked); tracked `evidence/` copies are bound by an explicit `--write` acceptance run at the final HEAD; clean-checkout evidence treated as self-referential metadata (excluded from the payload manifest to break the update cycle) | `evidence/s2-003-run-{a,b}.json` environment.commit equals final HEAD; `evidence/clean-checkout.json` sourceCommit = final HEAD; `git status` clean after acceptance runs |
| P1-2 | SQL store wrote snapshot/segments/lineage/ledger in separate autocommit statements; `ingestion_event` received no inserts | new `commitIngest` on both stores: BEGIN; guarded INTENT→terminal ledger update; snapshot; segments; lineage; descriptor tombstone; `ingestion_event` rows (SNAPSHOT_COMMITTED/LINEAGE_APPENDED/DESCRIPTOR_TOMBSTONED/OPERATION_COMPLETED); COMMIT — any failure rolls back leaving INTENT for reconciliation. Pipeline commits only through this method | `src/lib/ingestion/postgres-store.mjs#commitIngest`; DB replay passes with per-operation events in the DB |
| P1-3 | Streaming branch keyed on nonexistent `body.getAsyncIterator`; real fetch fell into unbounded `arrayBuffer()` | bounded reading uses `body.getReader()` (Web streams) with per-chunk budget enforcement and controller abort; the production node transport additionally counts bytes at the socket and destroys the request over budget | hardening test «Web-stream body … aborted over budget» proves the streaming path aborts mid-stream |
| P1-4 | DNS resolver optional (`null` default) → un-resolved hostnames reached the connector; validated address not bound to the connection (TOCTOU) | resolver is mandatory by default (`node:dns` lookup, all addresses); the production transport is `node:http(s)` with a validating `lookup` hook on the Agent — the connection itself can only use a DNS answer that passed the SSRF check, closing the rebinding window; offline fixture transport (no network) still passes the same URL/resolver checks | hardening tests: default resolver installed and real; forbidden targets rejected; redirect-into-private refused |
| P1-5 | DB-backed Run A/B executed sequentially in one process (same PID); comparison did not record PIDs | `s2-003-db-replay.mjs` is now a coordinator/child split: each run executes in its own OS process via `--child`; the comparison report records `pids` and `executors` for both runs | `evidence/s2-003-db-comparison.json` `pids: {run_a: <pid-a>, run_b: <pid-b>}` (distinct) |
| P2-6 | `budget.max_segments` declared but unenforced | pipeline quarantines an operation whose extraction produced more segments than the budget allows | hardening test «extraction amplification … quarantined» |

## REVISE round 1 (post-review, 2026-09)

The first implementation returned PASS_WITH_LIMITS and was sent back for
revision with 7×P1 + 1×P2 findings. All of them are fixed and re-evidenced:

| # | Finding | Fix | Evidence |
| --- | --- | --- | --- |
| P1-1 | 9/12 probes recorded DETECTED without awaiting the async probe bodies (`detail: {}` in evidence) | probes are registered then executed with `await fn()`; the verdict is decided only by the awaited outcome | `evidence/s2-003-security-probes.json` (12/12 DETECTED with real detail strings; the earlier TDZ defect in probe harness was also hidden by this bug and is fixed) |
| P1-2 | Pipeline trusted the caller-supplied descriptor and any non-empty `grant_id` | `ingest()` validates the request against the fetch-request contract, resolves the descriptor **only** from the canonical store by `request.source_id`, and enforces workspace/actor/connector binding; grant_required connectors verify the grant against an injected ledger (principal, workspace, scope, expiry) and fail closed without one | `tests/ingestion/security-hardening.test.mjs` (substitute connector_id, foreign workspace, unregistered source, malformed request owns no ledger entry, grant matrix) |
| P1-3 | Idempotency digest excluded actor/connector/grant/lease/budget/claimed | `requestDigest` binds the full request; reuse with a different payload is a `DuplicateOperationError` conflict → FAILED, no second snapshot | hardening tests «same operation id with a different actor/budget» |
| P1-4 | Dedup scanned all snapshots globally | `decideDedup` requires a viewer (tenant_id mandatory) and filters candidates by tenant + server-side ACL before every stage; cross-tenant duplicates are invisible | hardening test «raw-byte duplicate from another tenant is invisible»; scope-less call is a programming error |
| P1-5 | HTTP connector: SSRF, auto-redirect, unbounded body, no real timeout | scheme allow-list, loopback/private/link-local/CGNAT/ULA literal-IP and localhost-like hostname rejection, injectable resolver re-checking resolved addresses, manual redirects (≤5 hops, each hop re-validated), chunked body reads aborted at `max_bytes`, AbortController timeout | hardening tests (12 forbidden targets, resolver re-check, redirect-into-private refused, budget quarantine, TIMEOUT) |
| P1-6 | Vault root escapable via symlink/junction | connector pins `realpathSync(vaultRoot)`; every fetch resolves the realpath and rejects anything outside it (`VAULT_PATH_SYMLINK_ESCAPE`) | hardening test with a real junction pointing outside the vault |
| P1-7 | SQL ledger could not perform INTENT → terminal (full append-only on the table); replays were memory-only | `ingestion_operation` now enforces exactly one server-side transition (identity columns immutable, terminal final); `source_descriptor` allows the single `lifecycle → tombstoned` transition; new `PostgresIngestionStore` (async interface) and `scripts/s2-003-db-replay.mjs` run Run A and Run B against two separate PostgreSQL schemas | `evidence/s2-003-db-comparison.json` (74/74 cases, 0 mismatches, hard counters zero), `evidence/postgres-smoke.json` (`ingestionTransitionEnforced: true`) |
| P2-8 | PR-level `git diff --check 4b4456a3..HEAD` exit 2 (blank line at EOF of generated declarations) | generator trims trailing whitespace to a single newline; working tree clean | `git diff --check 4b4456a3..HEAD` → exit 0 |

Review-order note: probes were fixed first; re-running them honestly exposed
three further probe-side defects (TDZ shadowing, shadowed factory in probe C,
static telemetry clocks in probe I) which are also fixed — 12/12 DETECTED
stands on real assertions now.

New/updated artifacts: `src/lib/ingestion/postgres-store.mjs`,
`scripts/s2-003-db-replay.mjs` (`npm run verify:s2-003-db-replay`),
`evidence/s2-003-db-comparison.json`, `evidence/s2-003-security-probes.json`,
`tests/ingestion/security-hardening.test.mjs` (16 tests), updated
`migrations/0002_source_ingestion.sql`, `evidence/postgres-smoke.json`,
`evidence/clean-checkout.json` (25/25 commands PASS).

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
