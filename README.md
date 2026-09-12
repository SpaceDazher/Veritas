# Veritas

Ad Veritatem · От источников — к знаниям. От гипотез — к проверенным решениям.

## S2-001 — Product contract and control scenarios

**Ticket result: PASS_WITH_LIMITS.** The product contract is published and scenario A
was executed in the public
[Veritas-AI-Production-Pilot](https://github.com/SpaceDazher/Veritas-AI-Production-Pilot)
repository with real Codex and pi processes, PostgreSQL canonical state, a
digest-bound human solution approval and a clean-archive replay. The upstream result
is bound here by `evidence/s2-001-pilot-binding.json` to merge commit
`6845858bccf3aec27c656649ac40ad01148e7505`.

This is not production approval. Scenario B remains a frozen contract and is not
executed; it depends on the Stage 2 ingestion, provenance, synthesis and verifier
tickets. The original synthetic workspace evidence remains historical and must not
be reinterpreted as a real local adapter run.

Start with [Product Contract](docs/product/PRODUCT_CONTRACT.md),
[Open Decisions](docs/decisions/OPEN_DECISIONS.md),
[Scenario A](docs/scenarios/SCENARIO_A_CODEX_PI_HARNESS.md),
[Scenario B](docs/scenarios/SCENARIO_B_CROSS_DOMAIN_RESEARCH.md) and
[Evaluation Report](docs/decisions/S2-001-EVALUATION-REPORT.md).

## Additional local contract workspace

Next.js App Router + PostgreSQL via Drizzle. Web Kanban, HTTP API and a generic
**board client CLI** share one canonical synthetic planning state. The CLI is **not**
a runnable agent adapter. No real adapters, scheduler, authenticated human approval,
private data, production rollout or multi-user authorization are implemented.
Displayed RUNNING and agent labels are explicitly synthetic fixtures, not live work.
Do not expose this demo as a private multi-user service or submit private data.

### Clean checkout

1. Use Node.js 22+ and npm; run `npm ci` with the committed lockfile.
2. Provision PostgreSQL separately and set `DATABASE_URL` in an untracked `.env`
   (see `.env.example`). No credentials are bundled or inferred.
3. Run `npx drizzle-kit push` against that dedicated local demo database.
4. Run `node scripts/validate-contracts.mjs` (offline, reads committed fixtures).
5. Run `npx next typegen`, `npm exec tsc -- --noEmit --pretty false`, and `npm run build`.
6. For operator use, run `npm run dev` for the local Web demo. The managed sandbox
   uses its own production lifecycle and `/api/health` healthcheck.
7. Open the local URL; fixture tasks seed idempotently on the first board read.

### Web / API / CLI

- `/`: search/filter Kanban, list view, create a public planning task, view criteria,
  update planning state, inspect journal and export task/document artifacts.
- `GET /api/board`: consistent task/event snapshot with canonical revision.
- `GET /api/capabilities`: machine-readable discovery; explicitly disabled execution.
- `POST /api/board`: create/update planning only; expected revision, persistent
  idempotency key bound to payload, atomic event snapshot. DONE/RUNNING/CLAIMED
  transitions are rejected. This is a public synthetic demo, not authentication.
- `node scripts/veritas-cli.mjs discovery`
- `node scripts/veritas-cli.mjs tasks`
- `node scripts/veritas-cli.mjs events`
- `node scripts/veritas-cli.mjs create "Synthetic planning task"`

Use `VERITAS_URL` for a different local endpoint. Real pilot runner commands remain
NEEDS_INPUT; no speculative Codex/pi credentials or provider calls are supplied.

### Verification and evidence

- `node scripts/validate-contracts.mjs`: schemas, output-to-case traceability,
  draft integrity and 34 synthetic policy probes (including the seven S2-001
  adversarial probes). No semantic calibration claim.
- `npm run verify:draft`: deterministic contract, policy, inventory, public-artifact,
  typecheck, build and audit checks; returns `PASS_WITH_LIMITS` while pilots are blocked.
- `npm run verify:pilot-binding`: verifies the frozen external pilot snapshots,
  upstream commit/tree binding, canonical evidence digests and production boundary.
- `npm run verify:acceptance`: still returns nonzero `BLOCKED` for this repository's
  synthetic local workspace. The completed external scenario A pilot is evaluated
  by `verify:pilot-binding`; it does not turn the demo into a production runner.
- `node scripts/synthetic-smoke.mjs`: offline synthetic smoke only. Database/browser
  smoke remains `NOT_RUN` unless a dedicated PostgreSQL URL and local server are
  explicitly available; no screenshots or real pilot results are claimed.
- `npx tsx scripts/cleanup-smoke.ts`: deletes only task IDs explicitly recorded by
  the smoke run from the dedicated synthetic database. Not a production operation.
- `scripts/generate-contracts.py` and `scripts/generate-docs.py` reproduce public
  draft files. `node scripts/validate-contracts.mjs --freeze` is an explicit draft
  integrity update, **not** experiment freeze or approval. Review changes first.
- `python3 scripts/collect-baseline.py <existing-approved-AgentOS-checkout>` records
  safe dependency hashes. It does not run Stage 1 or fetch private sources.

### Rollback

Stop the local demo, preserve/export its dedicated database if needed, and use
`git switch --detach 57ce8a4a6a607c4a421ee12dc49c6dd854d404b5` for the original
README-only repository. That baseline has no app. Do not drop shared databases.
Returning to this branch restores the source; schema push is additive for the two
`veritas_demo_*` tables. Actual agent-run rollback remains a future SolutionPack
acceptance case, NOT_RUN.

This branch must not be merged to main without separate owner permission.
