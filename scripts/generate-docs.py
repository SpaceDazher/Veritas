"""Public documentation; no private sources are consumed."""
import json
from pathlib import Path

def doc(path,text):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text.strip()+'\n')

doc('docs/product/PRODUCT_CONTRACT.md', '''# Veritas · Product Contract v1.0.0

Ticket S2-001. Status: DRAFT / NEEDS_INPUT for pilot execution. This is a testable specification, not a production certification. The user approved **Veritas Agent Board** as scenario A's project. No authority to spend, obtain credentials, deploy or import personal data follows from that approval.

## Product boundary
Veritas owns canonical versioned knowledge, source selection, TaskBrief, policies, experiment registration, evidence, decisions and the human/agent task board. AgentOS is a separate executor connected through `veritas.execution/1.0.0`, not a second canonical database and not an approval authority. Stage 1 research verdicts may be evidence, never permission to execute or deploy.

Version handshake: request carries contract_version, request_id, idempotency_key, task_id, brief_digest, policy_digest, manifest_digest, principal_id, granted_scope, allowed_tools, workspace_ref, numeric budget grant, deadline, lease_id and fencing_token. Response carries contract_version, run_id, task_id, fencing_token, sequence, outcome, checkpoints, artifact hashes, measurements and typed errors. Reject unsupported major versions and unknown required fields; minor additions require negotiated capabilities. Authenticate principal server-side; never trust identity, permissions or budget asserted by a payload. Content hashes are integrity checks, not signatures. Unknown side effects require reconciliation before retry.

## Intake and knowledge model
Supported product targets: Obsidian/Markdown, Telegram, YouTube, web/PDF, arXiv, Hugging Face, GitHub and manual documents. Connector implementations are not delivered by S2-001. Intake must require an approved manifest, access and license check, fetched version and immutable snapshot hash. Store source ID, upstream IDs, canonical locator (private where necessary), content hash, source/published/retrieved times, license, ACL, parser version, ingestion errors and superseded snapshot. Never overwrite a snapshot; deletions/revocations produce tombstones and block derived disclosure. Missing, empty, inaccessible and successfully imported are different outcomes.

Claims distinguish observation, fact, expert opinion, hypothesis and forecast. Evidence includes exact source span and temporal/geographical scope. Contradictions link claims and qualification conditions; causal assumptions and cross-discipline relations remain hypotheses until independently supported. Copied sources with one upstream count as one evidence family. Source instructions, stdout/stderr and model output are untrusted data and cannot grant capabilities.

A HypothesisCard requires relation type, basis and evidence IDs, alternative explanations, applicability boundary, falsification protocol and justified confidence (not invented probability). Forecasts require issue date, target date, resolution source and rule. EvidenceMap edges are typed supports/contradicts/derived-from/causal-hypothesis; they do not silently increase certainty.

## R&D lifecycle
Question → explicit hypothesis → preregistered experiment (brief, corpus, model, metric policy and budget hashes) → measured run → independent check → scoped conclusion → versioned knowledge update → proposed use → human final approval. Failed/abstained runs remain in denominators. Any post-freeze change creates a new revision and review, never silently rewrites the trial.

## Canonical state and interfaces
Human Web: browse Kanban, inspect provenance, compare runs, challenge and review. Agent HTTP API and CLI: machine-readable discovery, scoped task operations and evidence submission. All use the same transactional store, revision, authorization and event journal. Chat history is not canonical. Reads identify canonical revision. Writes require expected_revision plus idempotency key. The server validates transitions and permissions; UI hiding is not access control.

Data scopes: personal (owner only), project (explicit members/roles), shared (explicit publication grant). Derived outputs inherit the most restrictive contributing ACL. Scope widening and declassification require separate authenticated human approval and redaction review. No private payloads or source locators in Git, logs, shared search or public artifacts.

## Agent Board MVP contract
States: BACKLOG, READY, CLAIMED, RUNNING, BLOCKED, IN_REVIEW, DONE, FAILED, CANCELLED. Store ID, goal, description, acceptance criteria, priority, dependencies, required capabilities, allowed tools, workspace, time/cost limits, assigned agent, attempts, artifacts, tests, evidence, block reason and append-only transition history.

BACKLOG → READY only after dependencies and immutable brief are validated. READY → CLAIMED uses one database transaction and unique active lease. CLAIMED → RUNNING requires current fence, health, approved numeric budgets and isolated workspace. RUNNING → IN_REVIEW requires result collection (not a passing semantic verdict). BLOCKED covers missing permissions/input, failed gate or unknown outcome; FAILED is known terminal failure. Release/reassign revokes the lease first. Expiry fences old workers and requires side-effect reconciliation before returning to READY. CANCELLED revokes authority and kills the process group; late callbacks cannot mutate state. IN_REVIEW → DONE only by authenticated human or a separately authorized deterministic Gate; final SolutionPack approval always human. Uncalibrated semantic evaluator cannot be that Gate.

Scheduler: one local scheduler, one running job (explicit user requirement). Sort eligible READY tasks by priority then stable ID; require closed dependencies, administrator-registered capabilities, healthy available agent and available approved budget reservations. Pick stable adapter ID on ties and log reasons plus excluded candidates. Never substitute a more privileged agent. Atomic claim/renew uses DB time, compare-and-swap and fencing. Persistent idempotency records suppress duplicate mutations; replay reconstructs state without reissuing side effects.

Runner: approved CLI binary and argument allowlist, isolated worktree, minimal environment, no inherited secrets, timeout/cancel with process-group termination, checkpoint/resume bound to brief+workspace hashes, untrusted redacted logs, artifacts and tests returned to review. Unknown outcomes return RECONCILIATION_REQUIRED; no blind retry.

Adapter interface `veritas.adapter/1.0.0`: identify(), capabilities(), health(), claim(task), start(run), status(run), checkpoint(run), cancel(run), collect_result(run), release(task). Capability discovery is a claim to validate against operator registration, not permission. Typed errors: AGENT_UNAVAILABLE, AUTH_REQUIRED, CAPABILITY_MISMATCH, BUDGET_EXCEEDED, PROVIDER_FAILURE, EMPTY_RESPONSE, TIMEOUT, CANCELLED, MALFORMED_RESULT, UNKNOWN_OUTCOME, RECONCILIATION_REQUIRED.

Targets: Codex local/cloud, Claude Code, OpenCode, Hermes, pi and future versioned adapters. MVP needs two genuinely different real adapters plus generic CLI adapter; wrappers around one mocked agent do not qualify. Actual availability is NEEDS_INPUT. S2-001 does not implement or claim this runner.

## What is delivered here
Machine-validated draft contracts, acceptance cases and policy fixture tests, safe source manifests, policy documentation and an additional local **contract workspace** (Next.js/PostgreSQL Web, API, CLI). Workspace cards are clearly labeled synthetic planning fixtures; no adapters are connected, no execution or final approval endpoints exist. It is not the Agent Board MVP, not authenticated multi-tenancy, and must not receive private data. See OUT_OF_SCOPE and evaluation report.

## Completion and critical failures
A SolutionPack is ready for review only when all A-OUT and A-MVP cases have artifact/run evidence, pinned installation/rollback, metrics and independent review. Human approval is a separate hashed decision. Dossier requires every B-OUT case and unresolved claims labeled. Critical: leaks, authority escalation, duplicate execution, fabricated evidence, hidden brief/threshold changes, false final approval, unsafe retries and unsupported causal certainty. Any critical violation prevents acceptance regardless of cost or speed.
''')
doc('docs/product/PILOT_PROFILE.md','''# PilotProfile v1.0.0

Canonical structured profile: `pilots/pilot-profile.json` (validated by pilot-profile.schema.json). Both TaskBriefs reference it. Contract fixtures are pinned in evidence/frozen-manifest.json; execution briefs remain NEEDS_INPUT, not approved/frozen experiments.

## Answered
- A project: **Veritas Agent Board**, approved in the user's ticket addition.
- Goal: one canonical Kanban for humans and AI agents, extensible versioned adapters.
- Concurrent jobs: **1**, explicitly required for the first local runner. This is not a spending grant.
- Codex/pi are scenario A target roles, not proof of installed binaries/models.
- Owner of missing input: user. Final decision and budget owner identities remain unassigned.
- Final solution approval belongs to an authenticated human, not an agent.

## Unknowns
See OPEN_DECISIONS and JSON settings: target repository commit, legal tool/repo permissions, installed agents/models/auth methods, hardware, task/campaign/day numeric budget and currency, numeric timeout, owner identities, exact source allowlist, exact research question, freshness windows, metric thresholds/baseline/non-inferiority and reviewer.

The public Veritas repository was readable to prepare this ticket. That does not prove permission to run a pilot against a selected repository revision, write to remote or access personal sources. No shell discovery of user credentials is performed. Credential values never belong in PilotProfile; later use only opaque server-side credential references.

## Freshness
Each category must have owner-approved max_age, time basis and exception approver: GitHub/config/skills use pinned revision plus current compatibility date; official statistics use reference period and revision date; web/Telegram/expert opinions use publication and observation date; scientific papers/arXiv use version/retraction status; YouTube uses publication/transcript version; vault/manual sources use selected immutable local revision. Numeric windows are all NEEDS_INPUT and block only claims of currentness. Historical analysis can use an explicitly bounded as-of date, not silently treat old material as current.

## Freeze
After unknowns are answered: validate schemas and authorization, bind canonical serialized brief/profile/manifest/policy/corpus digests, obtain authenticated human approval, then register experiment before any paid or external run. Current frozen-manifest records draft integrity only, not human authorization.
''')
doc('docs/product/AUTONOMY_POLICY.md','''# Autonomy policy v1.0.0

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
''')
doc('docs/product/METRIC_POLICY.md','''# Metric policy v1.0.0

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
''')
doc('docs/product/HUMAN_APPROVAL_POLICY.md','''# Human approval policy v1.0.0

Human remains final SolutionPack owner. Input owner=user; authenticated decision/budget identities NEEDS_INPUT. AgentOS verdict, JSON actor_type, UI click without identity, or a model's self-reported approval is not authorization.

Review package contains frozen brief/policy/source digests, producer and independent verifier identities, test results, evidence, actual costs, coverage/uncertainty, alternatives, unresolved contradictions, rollback and requested decision scope.

Actions: approve, reject, challenge, retry, reassign, cancel. Server checks authenticated subject, role, current revision, resource ACL, conflicts (producer cannot self-approve), requested scope and hard gates. Store immutable HumanDecision: subject identity, scope, exact artifact digest, reason, timestamp and audit reference. A pending example is not a signed grant. A new artifact digest invalidates prior approval. Rejected/challenged output cannot silently return to approved; retries create linked attempts and preserve history.

Critical actions (budget increase, permission change, secrets access, declassification, production rollout) require separate explicit confirmation showing exact scope and consequence; final research/solution approval grants none of these automatically. Budget authority and final result authority are separate roles even if one human later holds both. Human cannot waive data safety or falsify test evidence.

The included local workspace has no authenticated approval or execution endpoint. Moving a planning card to review or archiving it is not final solution approval. Human approval must be implemented and identity provisioned before the actual pilot.
''')
doc('docs/scenarios/SCENARIO_A_CODEX_PI_HARNESS.md','''# Scenario A · Codex/pi harness for Veritas Agent Board

Status NEEDS_INPUT; project selected, execution not authorized. Machine inputs: pilots/scenario-a/task-brief.json, source-selection-manifest.json, acceptance-cases.json and shared pilot-profile.json. Output template is not a completed SolutionPack.

## Concrete target and vertical task
Target product: user-approved Veritas Agent Board. Target repository commit/access remain NEEDS_INPUT. Proposed first small repository task (draft, not owner-frozen): add a read-only machine-readable capabilities/discovery response with contract version and supported task states, a matching CLI command and parity tests. Acceptance: Web/API/CLI expose the same canonical revision, all nine states, no secret material and no implicit grant. Owner must confirm exact task, checkout and commands before execution. This bounded suggestion is not a guessed permission.

## Input gates
Discover installed Codex/pi binaries and actual model identifiers only after permission; record versions and non-secret authorization method/reference. Require repo/tool ACL, isolated workspace, CPU/storage availability, numeric per-task/campaign/day budget, timeout, one-job concurrency, source/version manifest and baseline/eval corpus. Missing field blocks its operation, not offline contract work.

## Procedure
1. Analyze pinned project architecture and task; freeze TaskBrief and criteria before creating results.
2. Search only approved versioned knowledge for relevant methods, roles, skills and workflow configurations; record provenance and rejected options.
3. Register candidate C1 (Codex implements, pi independently reviews) and C2 (pi implements, Codex independently reviews) as unexecuted candidate designs, not available integrations. Add a simple baseline under the same conditions. Independent evaluation cannot be replaced by the producer model.
4. Freeze corpus, tasks, models, seeds, budgets and metric policy; counterbalance order and preserve failures. If equivalent models/access unavailable, stop matched comparison or preregister separate strata.
5. Execute approved runs in separate clean workspaces through versioned adapters; atomically lease, log deterministic dispatch reasons, collect code/tests/redacted logs/checkpoints/costs. Timeout/cancel fences callbacks and reconciles unknown effects.
6. Run acceptance/security checks and independent evaluation; semantic evaluator is advisory. Compare by safety/correctness, quality + non-inferiority, then cost/latency. No absolute-best claim.
7. Prepare every A-OUT artifact (roles, configs, skills, development process, common Kanban, project memory, handoffs, evals, measured metrics, clean install, rollback, evidence, limitations, approval request). Record two different real adapters and generic CLI evidence for A-MVP, or explicitly NOT_RUN.
8. Human reviews immutable pack: approve/reject/challenge/retry/reassign/cancel. Only authorized Gate/human can mark execution DONE; final pack acceptance always human. Journal replay reconstructs events without re-executing commands.

## Expected checks and failure paths
Every output has A-OUT-01..14; runner/adapter criteria A-MVP-01..07; NEG-01..27 are explicit contract probes. Atomic race requires two real concurrent DB transactions; a policy unit test is not equivalent. Process crash/timeout/cancel need process-level evidence. No artifacts/failed tests → BLOCKED; unavailable credentials/model/budget → NEEDS_INPUT; weak independent evidence → HUMAN_REVIEW; unknown side effects → BLOCKED/RECONCILIATION_REQUIRED.

## Reproduction and exit
This ticket's fixture reproduction: README commands. Future real pack must add exact pinned adapter install, permitted model configuration, test command, rollback command and independent rerun with hashes. No real execution commands are invented here. Exit is a review-ready measured SolutionPack plus human request, not automatic rollout. Current expected result remains not produced; there is no measured winner.
''')
doc('docs/scenarios/SCENARIO_B_CROSS_DOMAIN_RESEARCH.md','''# Scenario B · Cross-domain research

Status NEEDS_INPUT. Approved topic: links between AI development, energy, economics, state policy, compute infrastructure and scientific technologies. Precise research question, geography, temporal horizon and chosen documents are absent; substantive import/analysis is blocked rather than fabricated.

## Inputs
pilots/scenario-b/task-brief.json and source-selection-manifest.json contain safe category placeholders for selected Obsidian documents, permitted Telegram sources, official documents/statistics, scientific articles, expert opinions and web sources. They are **not an allowlist** and import_authorized=false. No vault content, private messages, tokens/cookies or sensitive locators are copied to Git. Human selects lawful sources using a private registry; the public manifest receives opaque safe IDs only.

## Procedure and verifiable intermediate outputs
1. Resolve exact question and population/time boundary with user; approve concrete source list and access. Freeze manifest, as-of date and category freshness windows. Missing source → NEEDS_INPUT, not empty success.
2. Retrieve only within authorization; private store saves immutable snapshot/digest, license, ACL, author/publisher, upstream family, source/publication/retrieval times, parser/transcript version and exact spans. Reject unsafe source; log sanitized reason.
3. Create claim register with explicit observation/fact/opinion/hypothesis/forecast type. Expert prestige does not change type. Add temporal/geographic scope and confidence rationale.
4. Deduplicate identical claims and common upstream. Build supports/contradicts map with independent corroboration counts. Represent disagreement conditions and unknowns, not majority-vote truth.
5. Analyze through AI engineering, power systems, macroeconomics, state policy, infrastructure and scientific-method lenses. Record disagreements and methodological limits. Timeline distinguishes events from publication and forecasts.
6. Propose higher-order links as HypothesisCards: type, basis, alternative explanations (common driver, reverse causality, confounding), applicability bounds, operational falsifier, confidence rationale. Correlation is not causation and novelty is not verification.
7. Build EvidenceMap from conclusions→claims→exact spans and snapshot IDs; missing access and restricted citations remain explicit. External verification requires separate source authorization.
8. Forecasts require real issue/target dates, resolving criteria and source before inclusion; no invented pilot dates. Register next studies with measurable outcome, stop rules, independent verification and approved budgets before any experiments.
9. Package every B-OUT artifact (map, register, support/contradiction map, lenses, timeline, EvidenceMap, cards, alternatives, forecasts, unknowns, next studies, human review). Include provenance and metrics with denominators; no fabricated findings to fill templates.
10. Escalate disputed/unsupported conclusions to human. Only reviewed, scoped conclusions update canonical knowledge with revision and provenance. Propose use separately; research approval is not production permission.

## Acceptance
B-OUT-01..12 check each output; NEG-01..12 cover policy abuse including privacy, prompt injection, causal overclaim, missing sources and misuse of AgentOS verdict. Citation entailment/coverage and contradiction recall require independently adjudicated corpus, which is not available. Current examples prove schema shape only. Public fixture tests need no personal data. Completion requires real authorized inputs, measured evidence and human package, currently blocked.
''')
profile=json.loads(Path('pilots/pilot-profile.json').read_text())
lines=['# Open decisions · S2-001','', 'Project A is selected. The following are unresolved; no absence grants permission.','']
for name,value in profile['settings'].items():
 lines += [f'## {name}','```yaml','status: NEEDS_INPUT','owner: user','blocks: ['+', '.join(value['blocks'])+']','reason: '+value['reason'],'```','']
doc('docs/decisions/OPEN_DECISIONS.md','\n'.join(lines))
doc('docs/decisions/ASSUMPTIONS.md','''# Assumptions and evidence boundaries

- Confirmed user statement: project A is Veritas Agent Board; first runner has one simultaneous job. Not inferred: model, budget, hardware or access.
- Observed baseline: upstream Veritas HEAD `57ce8a4a6a607c4a421ee12dc49c6dd854d404b5`, only README.md. Sandbox additionally supplied a Next.js/PostgreSQL starter, initially without .git. Upstream history restored and work done on codex/s2-001-product-contract; no merge/push authorized.
- Issue #1 read successfully over public GitHub API (HTTP 200); status READY is specification readiness, not execution authority. Dependencies S1-019 and S1-020.
- AgentOS inspected at immutable checkout `a7940e113492c83a29533d1e93f2724c36a9bbc1`. Read closures, S1-019 technical decision/operator decision, S1-020 summary/evaluation record and referenced canonical evidence packs. Upstream reports PASS_WITH_LIMITS, research-only. This ticket does not independently rerun Stage 1 or calibrate its evaluator.
- Inherited limitations: same-host process separation, frozen local research corpus, one operator; absent production-like/legal/hardware/population-human/external-audit evidence. Goal acceptance and production authority remain false.
- C1/C2 candidate roles and first discovery task are explicitly proposed protocol designs, not approved experimental settings or available adapters.
- Local Web board is a synthetic contract-planning workspace. No private data or real agent execution is represented. Persistent database is canonical for this fixture workspace only; the complete leased runner and authorization boundary are future work.
''')
doc('docs/decisions/OUT_OF_SCOPE.md','''# Out of scope / stop rules

S2-001 specifies and validates a contract; it does not certify the Agent Board MVP or run the two substantive pilots. No paid/external experiments, provider/model calls, personal imports, credential collection, installation of external agent shells, real scheduler jobs, remote repository writes, production rollout or merge to main.

Additional sandbox UI/API/CLI demonstrate a single canonical **public synthetic** planning workspace, not authenticated personal/project/shared tenancy. Do not place private documents or secrets there. No final approval/claim/process execution API is exposed. Two real adapters, generic executable adapter, lease race/kill/reconciliation tests and production authentication remain NOT_RUN / unimplemented, not passed by mocks.

Stop dependent operation if target unselected, budget not numerical/approved, credentials required, legal/technical access absent, source unsafe, expected result unverifiable or authority widened. Preserve draft with NEEDS_INPUT/BLOCKED and owner=user. Other safe offline work can finish. Do not treat pending user response as permission.

Schemas and deterministic rule probes validate structural safety policy, not semantic truth, empirical accuracy, external access, proper process isolation or legal compliance. No claim of near-100% verifier accuracy, absolute-best solution or production readiness.
''')
print('Generated product policies, both E2E scenario protocols and decision registers.')
