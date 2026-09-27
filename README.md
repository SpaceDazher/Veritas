# Veritas

*Ad Veritatem*: от источников к знаниям, от гипотез к проверяемым решениям.

Veritas - исследовательская и инженерная платформа для версионированных источников, атомарных утверждений, междисциплинарного синтеза и независимой проверки результатов. Проект разделяет знания, доказательства, решения и право действовать: research verdict сам по себе не является production-разрешением.

## Текущее состояние

| Контур | Состояние | Что означает |
| --- | --- | --- |
| AgentOS Stage 1 | Research closed, `PASS_WITH_LIMITS` | 20 активных тикетов `S1-001...S1-020` закрыты на уровне research; полный индекс перенесён в issues Veritas. |
| SLOQUAL-001 | `PASS_WITH_LIMITS` | Frozen SLO contract, 17 scenarios × 5 seeds и 105 revocation trials в двух независимых запусках; hard counters равны нулю, но production SLO не авторизован. |
| Veritas S2-001...S2-006 | Engineering issues closed | Есть контракты, code paths, migrations, тесты и evidence. Это не означает независимую semantic calibration. |
| Veritas S2-007 | Engineering boundary accepted on Windows, `COMPLETE_WITH_LIMITS` | Windows-приёмка на коммите `c922c09`: `verify:s2-007` → `COMPLETE_WITH_LIMITS` (4/4 обязательных gate), `npm test` 1194/1194. **Коммитированный `verify:clean-checkout` НЕ зелёный**: 36 PASS / 8 FAIL (WSL/Podman таймауты, зависшие контейнеры S2-003…S2-005, архивная деградация S2-006) — см. [Windows acceptance follow-up](docs/decisions/2026-09-26-s2-007-windows-acceptance.md). **Linux-гейт `verify:s2-002` стал зелёным**: смержить [#41](https://github.com/SpaceDazher/Veritas/pull/42) сделало контроль отмены исполнимым на любой платформе, поэтому на Linux он теперь ДОКАЗАН (`terminationProof`/`outcomeProof` = `TERMINATED`), а не пропущен — см. [S2-002 non-Windows analysis](docs/decisions/S2-002-NON-WINDOWS-HOST-ANALYSIS.md). 8 контрактов, store `agentboard_*`, детерминированный scheduler, атомарные leases с fencing, handoff `veritas.execution/1.0.0`, 41/41 негативных проб, все 7 hard-gate счётчиков = 0, двухпроцессный DB replay на реальном PostgreSQL 17.11 с crash-восстановлением. **Issue #7 закрыт решением владельца** после того, как невыполненная часть его исходного scope вынесена в [#45](https://github.com/SpaceDazher/Veritas/issues/45) (два реальных адаптера, сравнение конфигураций, семь измерений, A-MVP-01..07); выпуск «готовый harness Codex/pi» и human approval остаётся за [#12](https://github.com/SpaceDazher/Veritas/issues/12). Сами факты не изменились: реальных адаптеров нет, `A-MVP-01..07` = `NOT_RUN`, `assuranceStatus=NOT_MEASURED` — закрытие тикета не меняет ни одного из них. Открыто: коммит `c922c09` ещё не в origin; S2-003…S2-006 replay оставляет 4 временных контейнера; артефакты S2-007 в дереве привязаны к merge-коммиту, а не к merge-коммиту `main` — приёмку надо перегнать. Отчёт: [S2-007 Evaluation Report](docs/decisions/S2-007-EVALUATION-REPORT.md). |
| Veritas S2-008...S2-012 | Open | SolutionPack harness, web/API, R&D, self-improvement, persistence и pilot acceptance ещё не завершены. |
| Public board | Synthetic demo | Web, HTTP API и CLI работают с публичной planning fixture; real adapters, auth и private data отключены. Отдельный закрытый контур `agentboard_*` (живая доска) живёт в своём namespace, не выполняет агентов и требует серверной аутентификации. |

Подробности Stage 1 и ссылка на перенесённые issues: [docs/stages/stage-1.md](docs/stages/stage-1.md).

## Архитектура

```text
Browser
   |
   v
Next.js App Router (src/app)
   |-- Web workspace (src/components)
   |-- HTTP API (src/app/api)
   |
   v
Domain contracts and policy
   |-- board / contract-policy
   |-- identity / sandbox
   |-- ingestion / claims / synthesis / verifier
   |
   v
PostgreSQL + ordered SQL migrations
   |
   +---- bounded evidence, contracts and test harnesses

AgentOS is a separate executor. It is not wired into this repository yet and
cannot create its own grants, approvals, budgets or knowledge authority.
```

Подробная карта компонентов и текущие точки интеграции: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Быстрый старт

Требования: Node.js 22+, npm и PostgreSQL. Для sandbox verification также нужны Podman и, для `UNTRUSTED_CODE`, gVisor.

```bash
git clone https://github.com/SpaceDazher/Veritas.git
cd Veritas
cp .env.example .env
npm ci
```

Укажите локальный `DATABASE_URL` в `.env`, затем примените migrations:

```bash
npm run db:migrate
npm run dev
```

Откройте URL, который напечатает Next.js. Fixture tasks создаются идемпотентно при первом чтении board.

### Board CLI

CLI является клиентом synthetic board, а не agent adapter:

```bash
node scripts/veritas-cli.mjs discovery
node scripts/veritas-cli.mjs tasks
node scripts/veritas-cli.mjs events
node scripts/veritas-cli.mjs create "Synthetic planning task"
```

Для другого endpoint задайте `VERITAS_URL`.

## Основные команды

| Команда | Назначение |
| --- | --- |
| `npm run dev` | Локальный Web workspace. |
| `npm run build` | Production build Next.js. TypeScript проверяется отдельно. |
| `npm run typecheck` | Строгая проверка TypeScript без emit. |
| `npm run lint` | ESLint. |
| `npm test` | Полный Node test suite; S2-002 process-tree tests наблюдаются на любой поддерживаемой OS. |
| `npm run test:identity` | Identity, authorization и sandbox tests. |
| `npm run test:ingestion` | Source ingestion, provenance, dedup и ACL tests. |
| `npm run test:claims` | Claim graph и invalidation tests. |
| `npm run test:synthesis` | Retrieval, evidence maps, hypotheses и policy probes. |
| `npm run test:verifier` | Независимый semantic verifier, calibration, ACL и crash replay. |
| `npm run verify:s2-006` | Полный S2-006 gate. Сейчас ожидаемо `BLOCKED_DEPENDENCY` до внешней calibration. |
| `npm run verify:pilot-binding` | Проверка frozen external Scenario A pilot binding. |
| `npm run verify:s2-002-cancellation` | Process-tree cancellation: доказанное termination или fail-closed blocked/unknown, с negative control. |
| `npm run verify:sloqual-001` | SLOQUAL-001: два независимых прогона frozen SLO contract и fail-closed comparator. |
| `npm run test:sloqual` | Unit-тесты SLO harness: статистика, open-loop, comparator, freeze, сценарии. |
| `npm run verify:postgres-smoke` | Disposable PostgreSQL smoke test. |
| `npm run verify:podman-sandbox` | Наблюдаемая проверка `LOCAL_RESTRICTED` boundary. |
| `npm run verify:gvisor-sandbox` | Наблюдаемая проверка `UNTRUSTED_CODE` boundary. |

Подробный workflow разработчика: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Границы текущей реализации

- `/`, `/api/board` и board CLI используют одну PostgreSQL fixture state, но это публичный synthetic planning workspace.
- Эти интерфейсы не реализуют production authentication, private tenancy, leases, scheduler, process runner или final human approval.
- Identity, ingestion, claim graph, synthesis и verifier реализованы как typed domain modules, contract stores и verification harnesses. Не каждый из них уже exposed через пользовательский Web/API.
- `src/lib/identity/policy-engine.mjs` и sandbox bridges имеют собственные tests/evidence. Public synthetic board не следует выдавать за authenticated multi-user deployment.
- `PASS_WITH_LIMITS`, schema validation, fixture corpus или process-separated replay не равны external human audit, nearly 100% accuracy или production SLO.
- SLOQUAL-001 измеряет только in-process решение policy на одном хосте. Без production-профиля нагрузки, full-scale fault/soak, внешнего хоста и human countersignature его verdict остаётся `PASS_WITH_LIMITS`; см. [SLOQUAL-001-EVALUATION-REPORT.md](docs/decisions/SLOQUAL-001-EVALUATION-REPORT.md).
- Не публикуйте secrets, private source content, private locators или credentials в Git, issues, logs или public artifacts.

## Документация

| Документ | Назначение |
| --- | --- |
| [Product Contract](docs/product/PRODUCT_CONTRACT.md) | Продуктовая граница, версии, state machine и authority policy. |
| [Architecture](docs/ARCHITECTURE.md) | Реализованные компоненты, data flows и интеграционные ограничения. |
| [Development](docs/DEVELOPMENT.md) | Setup, migrations, tests, verification и troubleshooting. |
| [Stage 1](docs/stages/stage-1.md) | Импортированные AgentOS research tickets, решения и limits. |
| [SLOQUAL-001 Evaluation](docs/decisions/SLOQUAL-001-EVALUATION-REPORT.md) | Локальная SLO qualification: измерения, hard counters, limits и граница полномочий. |
| [Open Decisions](docs/decisions/OPEN_DECISIONS.md) | Входы, которые блокируют новые executions. |
| [Out of Scope](docs/decisions/OUT_OF_SCOPE.md) | Запрещённые и неподтверждённые claims. |
| [Evaluation Reports](docs/decisions/) | Исторические S2 evaluation records и evidence boundaries. |
| [AGENTS.md](AGENTS.md) | Правила работы с проектом. |

## Источник истины

- Frozen machine contracts: [`contracts/`](contracts/).
- Tracked evidence и replay records: [`evidence/`](evidence/) и [`results/`](results/).
- Исследовательские решения и их границы: [`docs/`](docs/).
- Активная работа: [GitHub Issues](https://github.com/SpaceDazher/Veritas/issues).
- Stage 1 canonical source: [AgentOS research tickets](https://github.com/SpaceDazher/AgentOS/tree/a7940e113492c83a29533d1e93f2724c36a9bbc1/research/tickets/stage-1).

## Лицензирование и данные

Перед добавлением внешнего материала проверьте license, attribution и retention requirements. Публичные fixtures безопасны для CI; private inputs должны оставаться в утверждённом private registry и не попадать в этот repository.
