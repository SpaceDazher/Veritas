# S2-004 — Claim Graph Contract

Ticket: `tasks/S2-004` · Verdict: `PASS_WITH_LIMITS`.
Status: bounded local implementation; semantic quality is `NOT_CALIBRATED`.

## Scope and ownership

Veritas owns the claim graph and its API. S2-003 owns source snapshots and
content segments; S2-005 reads the graph for retrieval/synthesis; S2-006
independently evaluates claims; S2-010 projects the graph into Web/API/CLI/
Obsidian. This contract fixes what those stages may assume.

## Canonical contracts (versioned 1.0.0)

Ten JSON Schemas under `contracts/` are the single source of truth
(`claim`, `evidence-edge`, `claim-edge`, `expert-profile`, `expert-lens`,
`calibration-record`, `claim-extraction-request`, `claim-extraction-result`,
`claim-review-decision`, `graph-invalidation-event`). TypeScript types are
generated (`npm run claims:types`) and a drift test fails the suite if the
committed declarations diverge. Unknown contract versions, missing digests,
invalid enum values, unbounded scopes and unknown extra properties are
rejected fail-closed by `src/lib/claims/validation.mjs`.

## Trust model

- Evidence support (`evidence_support`), authorship, user expert trust
  (`user_expert_trust`), measured calibration (`measured_calibration`),
  review status and epistemic type are separate fields. Nothing in the
  implementation folds them into a single truth score, and the schema
  forbids extra fields that could carry one.
- A model or agent may propose claims and relations; only an authorized
  reviewer decision can promote a claim, and a producer can never review or
  accept their own claim — even while holding the reviewer role.

## Immutability and revisions

Every claim/edge record is immutable. A correction creates a new revision
(`reviseClaim`) with a `SUPERSEDES` claim-edge; lifecycle is a *projected*
state (`claim_state` in PostgreSQL, an in-memory map in the memory store)
derived from review decisions and invalidation events, never a rewrite of
content. Review decisions bind the canonical digest of the exact claim
revision; `ACCEPT_BOUNDED`/`REJECT` are terminal and single-use; replaying
the exact same decision is idempotent, reusing its id with different content
is an `IDEMPOTENCY_CONFLICT`.

## Canonical digests and deterministic ids

Canonical JSON is stable-sorted, whitespace-free JSON with undefined-valued
keys stripped. `canonical_digest` covers every semantic field of a revision
including its id; `claim_content_digest` (id-free) derives the deterministic
claim id `clm-<sha256-24>` so identical content in the same workspace maps to
the same node across processes (Run A/B and the PostgreSQL replay compare
graph digests on this basis).

## Extraction conventions v1.0.0 (used by the corpus oracle)

The rule-based extractor (`src/lib/claims/extraction.mjs`) is deterministic;
the frozen corpus oracle (`corpus/s2-004`, authored by
`prn-corpus-annotator`) follows exactly these conventions, so field accuracy
is measurable:

- one sentence = at most one atomic proposition; sentences with unresolved
  anaphora (`This/It/They…`), `depending on`, more than two exclusion
  clauses or no verb cue produce an `ambiguous` abstention — never a guess;
- epistemic type by first-cue order: forecast cues, hypothesis cues, analogy
  cues, mechanism cues, opinion cues, observation cues, else `FACT_CLAIM`;
- `polarity` is machine-checkable negation (`not/no/never/without/fails
  to/neither/nor` cue present → `negated`);
- `modality` ∈ indicative/possibility/necessity/conditional from modal cues;
- units come from a fixed table (%, percentage/basis points, USD, EUR, kg,
  kWh, GW, TWh, tonnes, km, miles, meters, °C, hours/days/months/years,
  people/patients/respondents/students/households/companies/jobs/cases/
  deaths); the denominator region (`per N x`, `out of N x`, `of N x`,
  `of <base>` for shares) is masked before unit/value/population extraction
  so denominator words never leak into other fields;
- years (`19xx/20xx`) are masked for value extraction — they are period
  markers, never claim values;
- a `FORECAST` without an explicit horizon (`by/in <year>`) is recorded with
  `lifecycle=QUARANTINED` and the `missing_forecast_horizon` qualifier; the
  import clock never becomes an event or forecast time — `published_at`,
  `event_time`, `observed_at`, `fetched_at` always come from the snapshot;
- embedded instructions (`embedded_instruction_classification.present` with
  classification ≠ `none`) cause a `policy_blocked` abstention for the whole
  segment: the data stays inert and can never assign itself a type or
  authority.

## Evidence binding and derived ACL

An evidence edge binds a claim revision to the exact span of an immutable
segment; `quote_digest` must equal the SHA-256 of the span bytes — this is
the machine-checkable span binding metric. Derived ACL equals the most
restrictive ACL of all inputs (private > project > public, allow-sets
intersect). Binding further evidence to an already reviewed claim revision
requires a new revision and a new decision.

## Atomicity and idempotency

`commitExtraction` writes claims + evidence edges + audit event in one
transaction (PostgreSQL: a real transaction; memory: an undo log) or
nothing. Every operation is recorded in an operation ledger keyed by
operation id and input digest: replay returns the recorded outcome, a
different actor/input digest under the same id or idempotency key is an
`IDEMPOTENCY_CONFLICT` with zero mutations, and unknown outcomes lead to
reconciliation, never blind retry.
