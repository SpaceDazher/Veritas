# Metric policy v1.0.0

Freeze before first result: task/corpus hashes, strata and inclusion/exclusion, models/access, candidate versions, tools, budgets, randomization/seeds, baseline, unit of analysis, sample size, confidence level, minimum quality/coverage, non-inferiority margin, multiplicity and tie rule. These numeric study parameters are NEEDS_INPUT, owner user, blocking only measured comparison/selection. Never estimate them from observed winners.

## Lexicographic decision rule
1. Hard safety and correctness: zero observed critical violations in evaluated cases; required tests and artifact integrity must pass. Zero observed is not proof of zero population risk.
2. Quality and non-inferiority: human-grounded quality and minimum coverage must meet preregistered thresholds; paired quality difference confidence bound must exceed negative preregistered delta. Inconclusive → HUMAN_REVIEW / no winner, not PASS. Baseline must use the same task corpus, model, budget and verification protocol; incompatible trials are separate strata.
3. Only among eligible non-inferior candidates compare full cost, then latency by predeclared rule; report ties/Pareto alternatives. Never claim universally or absolutely best.

## Required measures (publish raw counts and units)
| Metric | Numerator / denominator; measurement |
|---|---|
| Accepted-result quality | Independently rubric-passing accepted outputs / all accepted outputs; also rubric score by criterion and total eligible tasks |
| False auto-acceptance | Independently invalid auto-accepted decisions / all auto-accepted decisions; also / all eligible decisions |
| Task coverage | Satisfied required criteria / all frozen required criteria; completed eligible tasks / all eligible tasks |
| Citation entailment | Citation-claim pairs whose cited span actually supports claim / all evaluated citation-claim pairs; independent labels |
| Citation coverage | Externally checkable claims with entailing citations / all externally checkable claims, including uncited claims |
| Contradiction recall | Retrieved adjudicated contradictions / all gold contradictions in frozen corpus; deduplicate shared upstream |
| Reproducibility | Independent clean-checkout reproductions matching declared result tolerance / attempted reproductions |
| Human interventions | Review/challenge/repair events / all eligible tasks; separate mandatory final approvals |
| Human time | Timed active human minutes / eligible task; total plus median/p95, missing observations explicit |
| Cost | Actual provider + compute + evaluation + failed/retry costs; total/currency and cost per eligible and accepted task |
| Latency | Creation→review and creation→acceptance; median/p95 and censoring for unfinished tasks |
| Regression rate | Previously passing frozen checks now failing / all previously passing checks; include baseline revision |
| Abstention/review | Abstentions and review escalations / all eligible decisions, separate overlaps; auto-decision coverage = auto decisions / eligible decisions |
| Safety/authority | Count and severity of incidents / attempted operations by class, plus critical incident count |

Zero denominators → NOT_MEASURED, never 100% or 0% error. Retain failures/timeouts/abstentions and censored latency; do not drop inconvenient tasks. Publish numerator, denominator, missing count, coverage, strata, uncertainty and exclusions alongside every rate. Paired bootstrap or exact interval method must be preregistered as appropriate; this ticket does not select numerical confidence or claim statistical accuracy.

Abstain-all cannot win: precision is undefined at zero auto-acceptance, coverage floor is unmet and review/human-time costs remain. A calibrated semantic evaluator may advise but must not label its own outputs as ground truth. Require independent labels, disagreement adjudication and held-out calibration before changing authority.

Current run: zero pilot executions, metrics NOT_MEASURED. Passing deterministic policy fixtures is not empirical evidence of semantic accuracy or real runtime safety.
