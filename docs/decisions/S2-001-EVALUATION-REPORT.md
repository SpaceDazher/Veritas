# S2-001 · Evaluation report

## Honest verdict: BLOCKED for complete pilot acceptance

**PASS_WITH_LIMITS for the delivered draft-contract and local synthetic-workspace
checks. S2-001 is not declared fully accepted, no issue closure, no production
readiness.** Scenario A project is approved; concrete execution access, budgets,
model availability and source selection are not. Scenario B has an approved topic
but no exact question/documents. Drafts are saved, not silently promoted to frozen
approved experiments. No paid/provider experiments or real agent runs occurred.

Branch: `codex/s2-001-product-contract`. Upstream baseline:
`57ce8a4a6a607c4a421ee12dc49c6dd854d404b5` (README only). First schema/acceptance
commit: `2e3cf72`. Final implementation and closure SHAs are reported by local Git;
see evidence/commit-record.json and the final response. No push or merge to main.

## Delivered

All 23 requested files, plus shared machine-readable PilotProfile, pending output
and human-decision examples, acceptance/needs-input schemas, deterministic
validators, separate adversarial review, dependency inventory, hashed draft
manifest and test evidence. Full inventory: evidence/FILE_INVENTORY.md.

Additional local Web/API/CLI contract workspace uses Next.js + PostgreSQL/Drizzle.
Create planning tasks, search/filter Kanban/list, inspect criteria, update safe
planning states, read history, export data and read versioned policies. Atomic
writes, expected revision, payload-bound idempotency and snapshot replay are
implemented and tested. UI, API and CLI share one database. No real adapter or
agent process is represented by a synthetic RUNNING fixture or suggested label.

## Answered and unresolved

Answered: A project = Veritas Agent Board; one simultaneous local job is the user’s
MVP requirement; SolutionPack completeness maps to A-OUT-01..14 and A-MVP-01..07;
research dossier maps to B-OUT-01..12. AgentOS execution/adapter boundaries, all nine
states, ten adapter methods, eleven typed errors, data scopes, source provenance,
safety/human gates and lexicographic metrics are documented. Human owns final
solution approval; an uncalibrated semantic evaluator is advisory only.

Every unresolved input has status NEEDS_INPUT, owner user and operation-local
blocks in OPEN_DECISIONS and pilot-profile.json: target checkout/repo/tool rights;
installed adapters/models/non-secret authorization methods/hardware; numeric
per-task/campaign/day budgets and currency; timeout; budget/decision owner identity;
exact B source allowlist, lawful access and research question; freshness windows;
baseline/quality/coverage/non-inferiority thresholds; independent reviewer. One-job
parallelism is known, but grants no execution authority. Missing is not zero/free.

## Executed checks

| Check | Result | Exit code / evidence |
|---|---|---|
| JSON Schema examples | 11/11 valid | 0 · evidence/contract-tests.json |
| Invalid schema mutations | 25/25 rejected | 0 · same report |
| Mandatory negative policy probes | 27/27 expected outcomes | 0 · per-case results in same report |
| Positive local controls + prerequisite checks | 2 positive, 8 additional checks | 0 · same report |
| Output-to-acceptance mapping / frozen draft hashes | Verified by validator | 0 |
| PostgreSQL schema push | Applied two dedicated demo tables / additive journal fields | 0 |
| Web/API/CLI integration + desktop/mobile smoke | 19/19 checks | 0 · evidence/workspace-smoke.json |
| Runtime dependency audit | 0 advisories | 0 · dependency-audit-runtime.json |
| Full dev/tooling dependency audit | 9 advisories: 3 high, 5 moderate, 1 low; 0 critical | **1** · dependency-audit-full.json |
| Next type generation | PASS | 0 · evidence/logs/next-typegen.log |
| TypeScript noEmit | PASS | 0 · evidence/logs/tsc.log |
| Production build | PASS, tracing warning fixed | 0 · evidence/logs/build.log |
| Managed build/start + /api/health | PASS | tool success; see evidence/validation-summary.json |

Public artifact scan, clean-checkout validation and final Git cleanliness are
recorded separately in evidence/public-artifact-check.json,
evidence/clean-checkout.json and evidence/validation-summary.json. Heuristic
scanning is not a comprehensive DLP proof. This run consumed no personal source
content and source manifests contain only safe redacted identifiers.

## Negative outcomes, exactly scoped

NEEDS_INPUT: NEG-03 missing budget; NEG-04 unknown model/access; NEG-11 missing
source. HUMAN_REVIEW: NEG-09 opinion-as-fact; NEG-10 unsupported causal knowledge.
BLOCKED: NEG-01/02 hidden goal/threshold changes; NEG-05/06 absolute-best and
self-approval; NEG-07/08 private export/source instruction authority; NEG-12
research verdict as rollout; all NEG-13..27 board hazards (double claim, forged
capability, lease expiry, crash, empty response, DONE without artifacts, failed
tests, criteria mutation, self-grant, repeated effects, open dependency, zombie
worker, unknown-outcome retry, cross-user leak, divergent interface revision).

These 27 are **synthetic explicit-predicate policy probes**, not inference of
malicious semantics, real lease races, process termination, provider behavior or
privacy isolation. Actual HTTP tests separately cover concurrent idempotent task
creation, payload mismatch, stale revisions, forbidden states, permission-field
injection, required block reason, event snapshot replay and CLI/UI parity.

## Failed attempts retained, not concealed

- Initial contract generator: SyntaxError, exit 1; fixed closing brace before first
  generated/committed schemas. No pilot artifacts were fabricated by the failure.
- Browser attempt 1: exit 1, missing Chromium libnspr4.so. 11 server/CLI checks had
  passed. Browser dependencies installed; initial installation tool timed out while
  apt continued, then completed. evidence/workspace-smoke-attempt-1.json retained.
- Browser attempt 2: exit 1, incorrect test oracle expected three Codex cards instead
  of the actual two. Corrected oracle to canonical API count, not application data.
  evidence/workspace-smoke-attempt-2.json retained.
- Final smoke: exit 0, all 19 checks. Only recorded synthetic test IDs are cleaned
  up; test reports and screenshots are retained.

## Adversarial review and inherited evidence

See ADVERSARIAL_REVIEW.md: measured-empty templates, false freeze/READY, changed
idempotency payload, missing replay data, empty policy context, tracing scope,
unsafe source paths and misleading fixture/runtime claims were addressed. This
was a separate pass by the same executor, **not an independent audit**. Independent
pilot evaluation is still NEEDS_INPUT.

AgentOS pinned checkout `a7940e113492c83a29533d1e93f2724c36a9bbc1`: read S1-019/020
closures and decision/evaluation records, resolved referenced evidence files and
recorded SHA-256 inventory. Their reported verdict is PASS_WITH_LIMITS,
research-only, no Goal acceptance or production authority. Stage 1 chains/runners
were not independently rerun; the file inventory is not a new research verdict.

## Limits and re-entry

Zero real pilot runs → empirical result metrics NOT_MEASURED, denominator 0. No
candidate winner, verifier accuracy, two-real-adapter success, generic executable
adapter, process crash/timeout/cancel evidence, lawful source imports or substantive
research conclusions are claimed. No authenticated multi-tenancy or final approval
exists in the public demo. Do not submit private data. Tooling advisories remain.

To unblock only the dependent operation, obtain explicit user-owned inputs and
scoped authenticated approvals; validate and freeze a new experiment revision,
then execute under numeric budget/time caps with independent verification. Final
SolutionPack acceptance and production authorization remain separate human actions.
