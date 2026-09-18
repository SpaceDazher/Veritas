# S2-005 Evaluation Report — Cross-domain retrieval and synthesis

## Verdict: PASS_WITH_LIMITS

All local gates are green (dependency gate, frozen corpus runs A/B, PostgreSQL
replay, probes A–L, thresholds, clean-checkout). The limits below are inherited
and declared, not measured away: no unconditional PASS is claimed or possible
on this evidence base.

## 1. Dependency gate

`npm run verify:s2-005-dependencies` → **PASS (57 checks, FULL_GIT_BYTES)**.
Binds S2-004 (canonical base `7662face…`, verified head `f412272…`,
implementation `24c4792…`) by blob digest at the closure commit: schemas,
graph revisions, exact evidence spans, server-side ACL, stale propagation,
Run A/B evidence, DB replay, PASS_WITH_LIMITS verdict bytes and carried
limits. Stage-1 S1-007 (retrieval and index isolation) and S1-009
(provider-neutral delegation semantics) are pinned to AgentOS commit
`a7940e1…` with digest-verified tracked copies. Consumer inputs (frozen
corpora, ACL contract, time model, S2-003/S2-004 limitations) are pinned by
blob digest; executable and origin/main contract versions are byte-identical
to the pinned ones (§1.4 — no origin/main/record/executable mismatch).

## 2. Contracts and implementation

Six versioned JSON Schemas (`1.0.0`) in `contracts/`, TypeScript types
generated into `src/lib/synthesis/contracts.d.ts`
(`npm run synthesis:types`; drift test fails closed):

- `retrieval-request` — actor/workspace, query, `as_of`, domains, languages,
  geography, time window, source policy, budget, allowed modes, frozen
  corpus/index versions;
- `retrieval-hit` — immutable claim revision + span digests, family id, ACL
  snapshot, score components, rank, explicit inclusion/exclusion reason;
- `retrieval-run` — query/index/model/seed/config hashes, candidates, hits,
  failures, abstentions, cost, executor provenance;
- `evidence-map` — statement → claims → spans with supports/contradicts/
  qualifies, entailment status, unavailable-evidence gaps, family collapse,
  stale status;
- `hypothesis-card` — ANALOGY|HYPOTHESIS|OBSERVATION|MECHANISM_CLAIM, domains,
  nodes, relation (strength separate from causal assertion), temporal
  ordering, mediators, confounders, alternatives, scope limits, falsifiers,
  test design, counterevidence, corpus-scoped novelty, separated uncertainty;
- `synthesis-result` — input versions, maps, cards, competing explanations,
  unresolved contradictions, coverage/abstention, explicit
  READY_FOR_REVIEW|INCOMPLETE|BLOCKED with human-readable reasons.

Runtime serialization crosses the same ajv boundary as consumer fixtures
(`src/lib/synthesis/validation.mjs`): requests, hits, runs, maps, cards and
results are validated fail-closed at build time.

## 3. Frozen corpus and retrieval comparison

55 cases in 8 categories (`corpus/s2-005/manifest.json`, oracle locked,
authored by `prn-corpus-annotator`): local exact (12), global cross-domain
(10), contradiction (6), private/forbidden nodes (6), retroforecast (6),
unknown answers (6), hypothesis labels (8), family collapse (1).

All four retrieval modes ran on every case (paired, same questions, frozen
inputs): lexical BM25, hashed tf-idf vector (`hashed-tfidf-256/1.0.0`),
fusion (RRF + deterministic reranker), graph (lexical seeds + claim-edge
expansion under budget).

**Result: no mode separated from the others on this corpus.** Local stratum
(27 gold questions, ≥ frozen minimum 20): exact McNemar b=c=0 and paired
bootstrap (10 000 permutations, 95% CI [0,0]) — every pair is a tie at
ceiling (recall@10 = 1.0, nDCG@10 = 1.0 per mode). Global stratum: NOT_MEASURED
for paired statistics (10 questions < frozen minimum 20; mean fusion
recall@10 = 1.0, nDCG@10 = 0.9693 reported without a significance claim).
Per the frozen decision rule (positive median difference with CI excluding
zero), **the graph candidate is NOT declared an architectural winner; it
stays optional** — on this corpus the committed claim edges do not link
domains beyond what lexical matching already finds.

Ceiling effect honesty: the frozen corpus differentiates correctness
disciplines (abstention, ACL, as_of, entailment, causal rules) far better
than ranking quality. Ranking separation needs a larger, harder gold set —
handed to S2-006 (§8).

## 4. Run A/B and PostgreSQL replay

- Run A (`exec-s2-005-a`, PID/nonce/output root A, clock 2026-01-15) and
  Run B (`exec-s2-005-b`, distinct PID/nonce/output root, clock 2026-03-21):
  identical decisions and graph digest across all 55 cases
  (`evidence/s2-005-comparison.json`, comparison ok, integrity counters equal
  and zero).
- PostgreSQL replay (`npm run verify:s2-005-db-replay`): two schemas, two
  child processes against `PostgresClaimGraphStore`, identical decisions,
  digest `ef9caba2…`, 55/55, hard counters zero
  (`evidence/s2-005-db-comparison.json`).
- Results depend only on (index, request, mode, seed); wall-clock latency is
  telemetry and never enters decisions.

## 5. Metrics (numerators/denominators/missing)

| Metric | Value | Threshold | Status |
|---|---|---|---|
| private/unauthorized hit rate | 0 | 0 (hard) | PASS |
| future leakage rate | 0 | 0 (hard) | PASS |
| stale-hit rate | 0 | 0 (hard) | PASS |
| provenance substitution | 0 | 0 (hard) | PASS |
| causal overclaim rate | 0/8 labeled | 0 (hard) | PASS |
| fact-from-analogy | 0 | 0 (hard) | PASS |
| hidden contradiction | 0 | 0 (hard) | PASS |
| silent exclusion | 0 | 0 (hard) | PASS |
| duplicate side effects | 0 | 0 (hard) | PASS |
| authority expansions | 0 | 0 (hard) | PASS |
| probes A–L failures | 0/12 | 0 (hard) | PASS |
| citation entailment (delivered statements) | 45/45 = 1.0 | ≥ 0.9 | PASS |
| contradiction recall | 6/6 = 1.0 | ≥ 0.7 | PASS |
| local recall@10 (fusion) | 1.0 | ≥ 0.6 | PASS |
| global recall@10 (fusion) | 1.0 | ≥ 0.4 | PASS |
| hypothesis classification | 8/8, falsifiable 8/8 | reported | MEASURED |
| abstention rate | 8/55 = 0.1455 | reported | MEASURED |
| incomplete EvidenceMaps | 12/57 = 0.2105 | reported | MEASURED |
| family-collapsed evidence (10 reprints) | 1 family | reported | PASS |
| budget accounting | 36 876 ops / 2 650 001 budget, 1 deliberate exhaustion (unk-046) | reported | MEASURED |

All 55 cases PASS (12 local, 10 global, 6 contradiction, 6 private,
6 retroforecast, 6 unknown, 8 hypothesis labels, 1 family collapse).

## 6. Adversarial probes A–L

12/12 green (`evidence/s2-005-security-probes.json`): span-less synthesis →
INCOMPLETE; confounded correlation → HYPOTHESIS, causal assertion rejected;
restatement → similar_prior_found; post-as_of document → never indexed;
private node → zero leak; ten reprints → one family; contradicting lenses →
both shown, ranking-only; missing source → explicit gap, no fabricated
citation; invalidated parent → STALE; prompt injection → quarantined inert;
poisoned graph candidate → rejected before quality ranking; number/negation/
unit drift → NOT_ENTAILING.

## 7. Honest limitations (carried and declared)

- Semantic quality is `NOT_CALIBRATED`: the oracle was authored alongside
  the implementation by the same project (documented conventions), not by an
  independent external body; no external replay exists.
- No causality from correlation, analogy or expert authority; a lens is
  ranking-only.
- Live private connectors remain unproven and OCR/ASR remain fixture-level
  (S2-003 limits carried forward).
- Human approval is not claimed anywhere: every reviewer decision in the
  evidence base was produced by the described principals in fixtures.
- The vector baseline is a deterministic hashed tf-idf embedder, not a
  production semantic model; a production embedding model is `NOT_RUN` and
  must not be inferred from these numbers.
- Retrieval ranking separation is ceiling-limited on this corpus (all four
  modes tie); graph retrieval stays optional per the frozen decision rule.
- Global-stratum paired statistics are `NOT_MEASURED` below the frozen
  minimum of 20 gold questions.
- Novelty is scoped to `corpus/s2-005@1.0.0` + lock horizon:
  `novel_to_selected_corpus` never means "never discovered by anyone".
- S2-006 (independent semantic verifier) and S2-008 (R&D) are not started.

## 8. Handoff for S2-006 / S2-008

For S2-006 (verifier):
- Read API: `src/lib/synthesis/retrieval.mjs` (`buildRetrievalIndex`,
  `executeRetrievalRequest`, `auditRunForLeaks`) and
  `src/lib/synthesis/synthesis.mjs` (`entailmentOf`, `buildEvidenceMap`,
  `buildHypothesisCard`, `synthesize`, `classifyRelation`) with contract
  types in `src/lib/synthesis/contracts.d.ts`.
- Independent re-evaluation inputs: frozen corpus
  `corpus/s2-005/manifest.json` (locked digests), thresholds
  `contracts/s2-005-thresholds.json`, Run A/B + DB replay evidence under
  `evidence/s2-005-*`.
- Open items: independent gold corpus and blind re-annotation; a larger
  cross-domain stratum (≥ 20 gold questions) so paired mode statistics
  become MEASURED; calibrated novelty assessment against an external corpus.

For S2-008 (R&D):
- HypothesisCard typing and causal discipline are machine-enforced
  (`classifyRelation` matrix, probe B/K/L); any R&D exploration must reuse
  the promotion rule: producers never promote their own cards; promotion
  requires a recorded review artifact (S1-011 rule, carried binding).
- Competing-explanation and uncertainty surfaces keep author confidence,
  expert trust, measured calibration and evidence support separate (S1-012).

## 9. Command log

`npm run verify:s2-005-dependencies` → PASS (57 checks).
`npm run synthesis:types` → in sync.
`npm run test:retrieval` / `npm run test:synthesis` / `npm run
test:s2-005-security-probes` → green.
`npm run verify:s2-005` → PASS_WITH_LIMITS.
`npm run verify:s2-005-db-replay` → ok, digest `ef9caba2…`.
`npm test`, `npm run typecheck`, `npm run lint`, `npm run build`,
`npm audit --omit=dev`, `npm run verify:clean-checkout`,
`npm run manifest:check`, `git diff --check <base>..HEAD` — see the
acceptance log; any command that could not run is recorded as `NOT_RUN_*`,
never as PASS.
