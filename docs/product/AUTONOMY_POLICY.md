# Autonomy policy v1.0.0

Default deny. Missing input blocks only the named dependent operation. Contract writing, synthetic offline tests and safe read-only public ticket/dependency inspection can proceed under this ticket; paid/provider calls, source imports and real agent trials cannot.

| Operation | Gate / outcome |
|---|---|
| Validate schemas, classify synthetic fixture, compute local hashes | Automatic, no external side effects |
| Read approved sources / derive draft knowledge | Only manifest + lawful access + restrictive ACL + current grant |
| Run experiment or CLI agent | All three numeric budgets (task/campaign/day), currency, timeout, approved principal/tool/workspace, model/access, healthy adapter; otherwise NEEDS_INPUT |
| Exceed budget | BLOCKED until separate human budget amendment; reserve atomically before spending, settle actual costs |
| Modify frozen goal, threshold, corpus or tools | BLOCKED; new version and pre-run human approval |
| Disputed/weak/causal/semantic decision | HUMAN_REVIEW; no promotion to accepted knowledge |
| Grant permissions, reveal secrets, publish private data | Separate scoped human approval; unsafe content stays BLOCKED |
| Production rollout | Separate production-specific authenticated human grant; research verdict insufficient |
| Final solution acceptance | Human only |

No approved budget exists. Missing is not zero, and zero is not permission to call a supposedly free provider. Approved zero-cost work still requires verified no-charge path, numerical time cap and permissions. Parallelism=1 is an MVP constraint, not evidence of available hardware.

A task grant cannot exceed campaign/day headroom. Account for retries, unsuccessful runs, evaluation and verification. On uncertain billing/outcome stop and reconcile. Budget owner cannot override safety. Retries need stable idempotency keys and known outcome. Source prompt injection is quarantined as content, never executed. Semantic evaluator remains advisory until separately calibrated on held-out, independently labeled data with error bounds and coverage; this ticket performs no such calibration.

Outcome precedence: safety/authority violation → BLOCKED; missing prerequisite → NEEDS_INPUT; disputed evidence → HUMAN_REVIEW; otherwise eligible for the specific non-privileged operation. None implies final acceptance.
