# S2-001 · Separate adversarial review pass

Reviewer: same implementation agent, in a separate hostile-review pass. **Not an
independent person, model or external auditor.** Independent pilot reviewer remains
NEEDS_INPUT, owner=user, blocks=a.independent-eval/b.independent-eval.

## Findings and dispositions

| ID | Attack / finding | Disposition and regression evidence |
|---|---|---|
| F01 | MEASURED wrapper could contain NOT_RUN artifacts and no measurements | Fixed: conditional schema requires PRESENT hashes/paths and all 14 named metric records; invalid measured templates rejected |
| F02 | Draft with unknowns could declare FROZEN; profile could not represent future confirmed input | Fixed: frozen brief requires zero unknowns; READY profile requires typed confirmed settings/approval references; missing budgets remain NEEDS_INPUT |
| F03 | Reuse idempotency key with altered payload could falsely return success | Fixed: hash canonical ordered request fields; mismatch returns HTTP 409; concurrent identical request produces one task/event |
| F04 | Event journal had transitions but lacked data for task replay | Fixed: transaction records full task snapshot with revision; replay of integration-test task matches DB state without executing side effects |
| F05 | Empty policy context could pass local-check guard | Fixed: absent brief/policy references return NEEDS_INPUT; positive and negative controls retained |
| F06 | Dynamic filesystem access caused entire project tracing | Fixed: statically restrict document reads to docs directory; production build warning removed |
| F07 | Safe relative reference admitted traversal | Fixed: reference grammar permits only safe segments and selected suffixes; repo:../../.env is rejected |
| F08 | UI running states and suggested agent names could be mistaken for actual jobs | Bounded: prominent synthetic-workspace banner, zero connected adapters, NOT_MEASURED outputs, no claim/run/DONE endpoints; discovery explicitly disables execution and approval |
| F09 | Workspace lacks authenticated personal/project/shared tenancy | Unimplemented and blocked for private data; public synthetic fixture only. No privacy or real human-approval runtime claim |
| F10 | A policy fixture could be misrepresented as actual race/process/semantic verification | Bounded: policy evidence explicitly labels synthetic unit scope; only local planning idempotency/revision/replay receive integration checks. Real adapter races, kill/reconcile, semantic calibration remain NOT_RUN |
| F11 | Dependencies had a critical Next.js advisory and runtime browser mapping advisory | Updated Next.js/eslint-config-next and postcss/browser mapping. Runtime audit passes; full dev/tooling audit still fails. See dependency-audit.json; no production-readiness claim |
| F12 | Browser smoke test expected three Codex cards, fixture has two | Fixed test oracle to canonical API count. Both failed attempts preserved; no failed run relabeled PASS |

## Review method and limits

Read schema branches, policy defaults, API transaction boundaries, fixture naming,
source reference grammar and acceptance-to-output coverage. Mutated inputs rather
than changing expected verdicts. Frozen draft hashes regenerated explicitly after
these fixes; no experimental thresholds changed (zero experiments executed).

27 requested negative policy probes include hidden goal/threshold changes, missing
budget/model/source, absolute-best claims, self-approval, privacy/injection,
opinion/causality overclaim, research→production misuse and all 15 Agent Board
runtime hazards. They test explicit predicates, **not** a detector that can infer
malicious semantics from arbitrary text. No verifier accuracy estimate follows.

Re-entry: independent reviewer, authorized sources/access, real adapters and numeric
budgets before substantive experiments; authentication and process-level test
harness before any private/real runner deployment. Human owns final approval.
