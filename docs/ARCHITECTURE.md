# Архитектура Veritas

Документ описывает текущий код на `main`, а не целевой продукт. Где модуль реализован и проверен, но ещё не подключён к Web/API, это указано явно.

## Системный контур

```text
                          +---------------------------+
                          | AgentOS (external engine) |
                          | executor / scheduler      |
                          +-------------+-------------+
                                        |
                                  veritas.execution/1.0.0
                                        |
                                        v
+-------------+       +--------------------------------------------+
| Browser     | ----> | Next.js App Router                         |
| Web client  |       | src/app, src/components                   |
+-------------+       +--------------------+-----------------------+
                             |                  |
                /api/board   |                  | /api/capabilities
                             v                  v
                      +------+------------------+------+
                      | HTTP and contract boundary    |
                      | src/app/api, scripts CLI      |
                      +---------------+---------------+
                                      |
                                      v
                      +---------------+-------------------------------+
                      | Typed domain modules                           |
                      |                                               |
                      | board / contract-policy                        |
                      | identity / sandbox                             |
                      | ingestion / claims / synthesis / verifier      |
                      +----------------------+------------------------+
                                             |
                              +--------------+--------------+
                              |                             |
                              v                             v
                    +---------+--------+          +---------+---------+
                    | PostgreSQL       |          | Contracts/evidence|
                    | Drizzle + SQL    |          | tests, gates,     |
                    | ordered migrations|          | replay artifacts  |
                    +-------------------+          +-------------------+
```

AgentOS не является вторым canonical store Veritas. Veritas владеет task/knowledge/evidence/decisions; будущий AgentOS adapter исполняет только явно разрешённую operation и возвращает typed result.

## Слои

### 1. Presentation

- `src/app/page.tsx` загружает board snapshot и локальные product documents.
- `src/components/workspace.tsx` реализует synthetic planning UI, фильтры, task details и docs projection.
- `src/app/globals.css` и `src/app/layout.tsx` содержат presentation metadata и styles.

Web workspace не является источником authority. Он показывает только то, что вернул серверный board boundary.

### 2. HTTP и CLI boundary

| Endpoint | Назначение | Authority |
| --- | --- | --- |
| `GET /api/board` | Read snapshot задач и event journal. | Только synthetic fixture board. |
| `POST /api/board` | Create task или planning-state update. | Execution, claims, leases, approval и DONE запрещены. |
| `GET /api/capabilities` | Machine-readable capability discovery. | Явно возвращает `executionEnabled=false`. |
| `GET /api/health` | PostgreSQL connectivity probe. | Только availability, не product acceptance. |
| `scripts/veritas-cli.mjs` | Board client для discovery/tasks/events/create. | Не executable agent adapter. |

Board writes используют operation id, payload hash, expected revision, atomic event snapshot и repeatable-read read path. Replay с тем же operation id возвращает прежний outcome; reuse с другим payload даёт conflict.

### 3. Domain modules

#### Policy и board

- `src/lib/contract-policy.mjs` - deterministic fail- classifier для S2-001 contract fixtures. Это не production authentication.
- `src/lib/board.ts` - synthetic planning state и capability descriptor.

#### Identity и sandbox

- `src/lib/identity/policy-engine.mjs` - default-deny authorization для exact capability/resource/workspace, grants, leases, fencing, revocation, approval ownership и cross-scope derived inputs.
- `src/lib/identity/sandbox.mjs` - path, environment, redaction, process-tree и artifact boundary для research probes.
- `src/lib/identity/podman-sandbox.mjs` - evidence-bound rootless Podman execution adapter.
- `src/lib/identity/gvisor-sandbox.mjs` - evidence-bound gVisor execution adapter.
- `src/lib/identity/contracts.ts` и `contracts/*.schema.json` - compile-time и runtime contract surfaces.

Эти модули имеют собственные unit, security и replay tests. Текущий public board route не выполняет user authentication и не подключает `policyEngine` к каждой board operation, поэтому demo нельзя считать multi-user authorization surface.

#### Ingestion и provenance

- `src/lib/ingestion/pipeline.mjs` реализует lifecycle `QUEUED -> ... -> COMMITTED` и typed terminal failures.
- Server-side descriptor, а не payload, определяет connector, workspace, ACL, license, retention и grant requirements.
- Snapshots неизменяемы; correction/delete/tombstone создают новые records.
- Idempotency digest связывает actor, workspace, grant, budget, selector и claimed metadata.
- Embedded instructions, fetched content и model output остаются untrusted data.

Connector types включают Markdown/Obsidian, web/PDF, GitHub, Telegram, YouTube, arXiv/Hugging Face и manual export. Наличие contract type не означает, что live credentials или connector разрешены.

#### Claims и synthesis

- `src/lib/claims/store.mjs` хранит immutable claim revisions, evidence edges, supersession, review и invalidation events.
- `src/lib/synthesis/retrieval.mjs` и `synthesis.mjs` строят evidence maps, contradictions, cross-domain candidates и hypothesis cards.
- Citation без entailment, number/negation drift, future/removed evidence и stale parents дают явный partial/stale/abstain outcome.
- Correlation, analogy, hypothesis, mechanism и causal proof остаются разными типами.
- `PROMOTED` не возникает автоматически из текста или внешнего источника.

#### Verifier

- `src/lib/verifier/api.mjs` - provider-neutral pure compute/query surface над exact artifact revisions.
- `src/lib/verifier/rubric.mjs`, `calibration.mjs`, `policy.mjs` и `comparator.mjs` реализуют fail-closed evaluation, calibration и missingness.
- `src/lib/verifier/store.mjs` предоставляет memory и PostgreSQL stores с immutable payload, idempotency ledger, outbox, fencing и reconciliation.
- Producer не может self-review; locked labels, private evidence и external calibration имеют отдельные trust boundaries.

Verifier является library/harness surface. В текущем Web workspace нет пользовательского endpoint для calibration approval.

### 4. Persistence

- `src/db/index.ts` создаёт PostgreSQL pool и Drizzle client.
- `src/db/schema.ts` описывает synthetic board tables через Drizzle.
- `migrations/0001...0007` добавляют board, ingestion, claim graph, verifier и ACL/state hardening surfaces.
- Ingestion, claims и verifier имеют собственные `postgres-store` implementations для transaction-specific invariants.

Миграции ordered и checksum-bound. Не редактируйте уже применённую migration; добавляйте следующую additive migration и отдельный rollback/replay evidence.

### 5. Contracts и evidence

- `contracts/*.schema.json` - machine-readable source of truth для public artifacts.
- `src/**/*.d.ts` - generated compile-time projections, которые не заменяют JSON Schema.
- `evidence/` - tracked claims о прогонах, dependency bindings, calibration, clean checkout и closure.
- `results/` - generated или replayed result records.
- `scripts/verify-*.mjs` - fail-closed gates, проверяющие конкретный deliverable.

## Data flows

### Board read и planning write

```text
UI/CLI -> /api/board -> Drizzle transaction -> PostgreSQL
                              |                  |
                              +-> task rows <----+
                              +-> event journal-+
```

Read возвращает task rows и append-only events в одном repeatable-read snapshot. Planning write меняет только разрешённое состояние и создаёт event в той же transaction.

### Source ingestion

```text
FetchRequest
  -> schema validation
  -> canonical server-side SourceDescriptor
  -> ACL/license/retention/grant checks
  -> connector fetch
  -> immutable snapshot + extracted segments
  -> atomic commit / typed terminal outcome
```

Unknown outcome входит в reconciliation. Пустой fetch, denied source и malformed content не могут стать успешным `COMMITTED`.

### Claim, synthesis и verification

```text
Versioned SourceSnapshot
  -> atomic Claim + evidence edges
  -> retrieval / EvidenceMap / HypothesisCard
  -> provider-neutral semantic verification
  -> calibration + independent adjudication
  -> human decision on exact artifact digest
```

Каждый переход связывает request digest, idempotency key, actor authority, audit record и artifact revision. Неясный outcome не превращается в blind retry.

## Что подключено, а что нет

| Capability | Реализация и tests | User surface | Статус |
| --- | --- | --- | --- |
| Synthetic planning board | Web, API, CLI, PostgreSQL | Да | Работает в demo scope. |
| Identity policy и sandbox | Модули, contracts, unit/security/replay gates | Нет authenticated board integration | Engineering evidence есть, public demo не авторизован. |
| Ingestion | Pipeline, connectors, stores, corpus | Нет общего Web/API | Провере harnesses/DB gates. |
| Claim graph | Memory/PostgreSQL stores, migrations, tests | Нет user UI/API | Contract/store deliverable. |
| Synthesis | Retrieval, evidence maps, hypotheses, tests | Нет user UI/API | Frozen research/engine deliverable. |
| Semantic verifier | API, stores, calibration, probes | Нет approval UI | Official S2-006 ждёт independent external inputs. |
| Agent execution | Не реализован | Нет | Future S2-007...S2-012 scope. |

## Инварианты безопасности

1. Unknown authority, stale revision, reused idempotency key с другим payload и untrusted content дают fail-closed outcome.
2. Payload, prompt, source text, digest и environment variables не являются authentication evidence.
3. Producer не может сам approve или независимо verify свой результат.
4. Derived artifact получает наиболее строгий ACL contributing inputs.
5. Revoked grant, stale fence и cancelled worker не могут завершить успешную операцию.
6. Exact-once side effect требует idempotency, unique receipt и reconciliation после неизвестного outcome.
7. Uncalibrated semantic evaluator не может быть final approval gate.
8. Research PASS не создаёт production rollout, budget, credential или data access authority.

## Известные ограничения

- Public board не аутентифицирован и не предназначен для private multi-user data.
- `next.config.ts` разрешает build при TypeScript errors, поэтому `npm run typecheck` остаётся обязательным отдельным gate.
- S2-002 полный suite чувствителен к OS и live process-tree поведению.
- S2-006 official verdict остаётся `BLOCKED_DEPENDENCY` без numeric HumanDecision, independent annotators/adjudicator и external locked corpus.
- AgentOS adapter, real scheduler, leases, budget reservation, remote execution и off-host operations отсутствуют.
- Evidence подтверждает конкретную среду и frozen input; перенос на production profile требует нового измерения.

## Куда добавлять изменения

- Product semantics: `docs/product/` и при необходимости ADR-like record в `docs/decisions/`.
- Machine contract: `contracts/` плюс generated TypeScript projection и schema tests.
- Domain behavior: соответствующий модуль в `src/lib/`.
- Persistent state: новая ordered migration в `migrations/` и store tests.
- Evidence: `evidence/` или task-scoped `results/`, с provenance и exact command.
- Stage/ticket status: [docs/stages/](stages/) и GitHub Issues.
