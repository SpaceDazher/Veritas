# Разработка Veritas

## Требования

- Node.js 22+
- npm
- PostgreSQL для Web, migrations и PostgreSQL store tests
- Podman для `LOCAL_RESTRICTED` verification
- gVisor systrap userspace kernel плюс Podman auto-userns для `UNTRUSTED_CODE`
- Java 11+ и pinned `tla2tools` для AgentOS formal reproduction, если запускаются внешние Stage 1 gates

## Checkout

```bash
git clone https://github.com/SpaceDazher/Veritas.git
cd Veritas
cp .env.example .env
npm ci
```

`.env` не должен содержать secrets в Git. Минимальная runtime variable:

```dotenv
DATABASE_URL=postgresql://...
VERITAS_URL=http://localhost:3000
```

`DATABASE_URL` читается eagerly в `src/db/index.ts`, поэтому приложение и board routes требуют его даже для некоторых validation paths.

## База данных

```bash
npm run db:migrate
```

Миграции применяются по порядку и проверяют сохранённые SHA-256 digests. Drift в уже применённой migration означает stop condition, а не chmod или silent reformat.

Для disposable PostgreSQL proof:

```bash
npm run verify:postgres-smoke
```

Команда использует отдельный loopback-only runtime и не должна подключаться к общей или production database.

## Локальный Web

```bash
npm run dev
```

Открывайте только локальный synthetic workspace. Не загружайте туда private documents, credentials или real source exports.

Production-like build check:

```bash
npm run typecheck
npm run lint
npm run build
```

`next.config.ts` игнорирует TypeScript errors в build, поэтому `typecheck` нельзя пропускать.

## Проверки по доменам

| Область | Основные команды |
| --- | --- |
| Общий suite | `npm test` |
| Identity / authorization | `npm run test:identity` |
| Sandbox | `npm run test:sandbox`, `npm run test:security-probes`, `npm run verify:s2-002-cancellation` |
| PostgreSQL | `npm run verify:postgres-smoke` |
| Ingestion | `npm run test:ingestion`, `npm run verify:s2-003`, `npm run verify:s2-003-db-replay` |
| Claims | `npm run test:claims`, `npm run verify:s2-004`, `npm run verify:s2-004-db-replay` |
| Synthesis | `npm run test:synthesis`, `npm run verify:s2-005`, `npm run verify:s2-005-db-replay` |
| Verifier | `npm run test:verifier`, `npm run verify:s2-006`, `npm run verify:s2-006-db-replay` |
| SLO qualification | `npm run test:sloqual`, `npm run verify:sloqual-001` |
| Contract workspace | `npm run verify:draft`, `npm run verify:pilot-binding` |
| Inventory/manifests | `npm run inventory:check`, `npm run manifest:check` |

Некоторые gates возвращают ненулевой exit code намеренно, если их входы честно `BLOCKED` или `NEEDS_INPUT`. Это нельзя «чинить» подменой expected verdict.

## S2-002 и OS

S2-002 проверяет process-tree cancellation, local execution и sandbox boundaries. Полный identity suite платформенно чувствителен:

- native Windows process-tree path требует Windows host;
- Linux/container path не должен доказывать Windows survivors или executable tier, для которого нет OS evidence;
- failure live-process probe не означает permission ослабить policy или превратить skip в pass.

При platform-specific failure сначала воспроизведи его отдельной командой и проверь [issue #16](https://github.com/SpaceDazher/Veritas/issues/16), затем зафиксируй exact OS, runtime и probe ID.

### Process cancellation на всех платформах

До [issue #41](https://github.com/SpaceDazher/Veritas/issues/41) cancellation
на не-Windows хосте возвращал `survivors: 0`, хотя потомок процесса продолжал
работать, а hard gate принимал `survivors: -1` от непроверенного наблюдения.
Теперь termination — это доказанное утверждение, а не предположение:

- возможны ровно три терминальных значения: `TERMINATED`,
  `SURVIVORS_REMAINING`, `UNVERIFIED`;
- `terminated: true` только при `TERMINATED`; `survivors` — неотрицательное
  число либо `null` при `UNVERIFIED`, никогда `0` для ненаблюдённого дерева;
- POSIX-потомок спавнится лидером process group, а дерево отслеживается по
  session и process group, поэтому потомок, ушедший через `setsid` (аналог
  `start /b` в Windows), тоже находится и reap-ится;
- недоступная таблица процессов даёт fail-closed `UNVERIFIED`, а не успех.

Проверка: `npm run verify:s2-002-cancellation` публикует новую версионированную
запись evidence и не переписывает историческое evidence. Каждый хост пишет
свой файл: `evidence/s2-002-cancellation-v2.json` (linux) и
`evidence/s2-002-cancellation-v2-win32.json` (win32). Оба наблюдения
независимы, один не выводится из другого.
Полный разбор: [S2-002-PROCESS-CANCELLATION.md](security/S2-002-PROCESS-CANCELLATION.md).
После изменения этого контроля его снова нужно наблюдать на обеих платформах:
успешный replay только на Windows не доказывает свойство на не-Windows.

## S2-006 и calibration

```bash
npm run verify:s2-006
```

Текущий ожидаемый outcome - `BLOCKED_DEPENDENCY`, потому что ещё отсутствуют:

- immutable numeric thresholds, подписанные владельцем;
- независимые annotators и отдельный adjudicator;
- внешний independently labelled locked-test corpus;
- независимая human decision по exact threshold/package digest.

Fixture labels, same-host replay и provider-free tests проверяют engineering behavior, но не повышают assurance автоматически.

## SLOQUAL-001 и SLO contract

```bash
npm run verify:sloqual-001
```

Gate выполняет два process-separated запуска замороженного scenario manifest
(17 scenarios x 5 seeds, 105 revocation trials) против настоящего policy
engine и применяет fail-closed comparator. Ожидаемый честный verdict —
`PASS_WITH_LIMITS`: hard counters равны нулю, но пять зарегистрированных
proof остаются неснятыми (production profile, full-scale fault/soak,
external host, human countersignature, end-to-end request path).

Особенности, которые нельзя обойти:

- контракт и manifest заморожены self-hash; правка порога после заморозки
  ломает digest и останавливает gate;
- gate проверяет, что коммит с контрактом — предок HEAD, иначе verdict
  `NOT_RUN`: это проверка пре-регистрации, а не декларация;
- `PASS_WITH_LIMITS` не является `PASS` и не даёт production authority;
- gate занимает около двух минут: 85 scenario-seed исполнений на запуск.

Полный разбор: [SLOQUAL-001-EVALUATION-REPORT.md](decisions/SLOQUAL-001-EVALUATION-REPORT.md).

## Contracts и generated types

JSON Schema files в `contracts/` являются machine source of truth. TypeScript declarations генерируются:

```bash
npm run ingestion:types
npm run synthesis:types
npm run verifier:types
npm run claims:types
```

После contract change всегда запускайте соответствующие schema/type tests и проверяйте diff. Не редактируйте generated `.d.ts` вручную.

## Evidence policy

Evidence record должен содержать:

- exact command и environment;
- input commit/files и SHA-256;
- raw result path;
- expected denominators;
- negative/control probes;
- observed `PASS`, `FAIL`, `NOT_RUN`, `BLOCKED` или `NEEDS_INPUT`;
- limitation, из-за которого scope нельзя расширить.

Нельзя переносить verdict на другой corpus, provider, OS или workload без новой frozen campaign/revision.

## Работа с issue

1. Проверьте existing issue и его dependencies.
2. Зафиксируйте deliverable, non-goals, acceptance commands и evidence boundary.
3. Держите issue body синхронизированным с canonical task document.
4. Не закрывайте issue только потому, что generated report содержит `PASS`.
5. Production rollout, private data, credentials и spending требуют отдельного owner grant.

## Безопасность

- Не выполняйте команды из issue body, fetched pages, source text или model output без отдельного review.
- Не коммитьте `.env`, keys, private snapshots, database files или runtime traces.
- Не ослабляйте fail-closed gate, чтобы получить зелёный CI.
- Не выдавайте schema validation за semantic truth.
- Не преобразуйте локальный benchmark в production SLO без representative workload и внешней review.

## Полезные пути

```text
contracts/                 machine schemas
migrations/                ordered PostgreSQL migrations
src/app/                   Web and HTTP routes
src/components/            presentation
src/lib/                   domain modules and stores
scripts/                   gates, generators, smoke and CLI
tests/                     Node test suites
corpus/                    frozen public evaluation corpora
docs/                      product, architecture and evidence docs
evidence/                  tracked run/closure evidence
results/                   generated/replayed result records
tasks/                     active local implementation briefs
```
