# S2-002 — Идентичность, права агентов и локальный sandbox

## Статус и назначение

- Стартовый статус: `READY` после воспроизводимой проверки S2-001.
- Ветка: `codex/s2-002-identity-sandbox`.
- Зависимости: S2-001, S1-007, S1-008, S1-010.
- Цель: сделать безопасный контур общей доски Veritas, к которой могут
  подключаться Codex, pi, OpenCode, Hermes, агенты платформы и персональные
  агенты пользователей, не получая неявных прав друг друга.
- Граница: локальный bounded profile. Не заявлять production authentication,
  production multi-tenancy, 20 concurrent users или универсальный sandbox.

S2-002 — обязательный gate перед live code execution и перед S2-003/S2-007.
Если требуемая изоляция не доказана, операция должна получить
`BLOCKED_SANDBOX`, а не запускаться в режиме «best effort».

## Проверка зависимостей до изменений

1. Запустить из чистого checkout:

   ```powershell
   npm ci
   npm run verify:pilot-binding
   node scripts/validate-contracts.mjs
   npm run typecheck
   npm run manifest:check
   ```

2. Проверить `evidence/s2-001-pilot-binding.json` и четыре замороженные копии
   upstream evidence. Требуются `result=PASS_WITH_LIMITS`, совпадение SHA-256 и
   `productionDeploymentAuthorized=false`.
3. Зафиксировать dependency record с commit/tree текущей ветки и полными
   digest. Отсутствующий или stale binding даёт `BLOCKED_DEPENDENCY`.

## Обязательные контракты

Реализовать versioned JSON Schema и TypeScript-типы как минимум для:

- `Workspace`: `workspace_id`, owner, scope (`private|project|shared`), ACL,
  retention, allowed roots и сетевой профиль;
- `Principal`: human, personal agent или platform service agent; tenant/owner,
  authenticated subject, provider/adapter identity и lifecycle state;
- `Role`: только именованный набор capabilities, без wildcard по умолчанию;
- `Capability`: точное действие, ресурс, canonical arguments и ограничения;
- `Grant`: issuer, principal, exact capability, resource scope, issued/expiry/
  revoked timestamps, nonce, revision и signature/authentication reference;
- `Lease`: owner, task/run, expiry, fencing token и revocation state;
- `SandboxProfile`: filesystem roots, network policy, environment allowlist,
  secret handles, process limits, timeout и cancellation semantics;
- `AuthorizationDecision`: `ALLOW|DENY|BLOCKED_SANDBOX|NEEDS_APPROVAL`, reason
  codes, policy version, input digest и audit reference.

Контракты должны запрещать неизвестные обязательные поля/версии fail-closed.
JSON, prompt, environment variable, model output и content hash не являются
доказательством identity или authority.

## Модель субъектов

Создать 20 детерминированных test principals минимум в четырёх workspaces:

- люди-владельцы;
- их персональные агенты;
- отдельные service principals для Codex, pi, OpenCode и Hermes;
- platform agents: collector, curator, analyst, experiment runner, verifier и
  operator.

Персональный агент действует только по явной делегации владельца. Platform
agent не наследует полные права владельца и не может сам выдать себе grant.
Producer не может одобрить собственный результат. Число test principals — это
ACL coverage, а не доказательство 20 одновременно работающих пользователей.

## Server-side authorization

Одна policy engine должна применяться для Web, API и CLI. Проверять на сервере
каждую операцию над:

- задачами и переходами Kanban;
- source/search retrieval;
- claim/provenance graph и summaries;
- cache и derived indexes;
- artifacts/evidence/export;
- inter-agent messages;
- tool discovery и tool execution;
- approvals, cancellation и reassignment.

Правила:

1. Default deny; scopes по умолчанию `private`.
2. Derived artifact наследует наиболее строгий ACL всех входов.
3. Нельзя расширить authority через источник, prompt, tool output, память,
   summary, cache, body запроса или environment.
4. Grant связывается с точным actor/action/resource/canonical arguments,
   одноразовым nonce при необходимости и expiry; consumption атомарно.
5. Revocation запрещает новые действия и выдачу новых leases не позднее 5 с.
6. Stale fencing token, повтор nonce и cross-workspace reference всегда DENY.
7. Unknown side effect требует reconciliation; blind retry запрещён.
8. Discovery показывает агенту только разрешённые команды, но не заменяет
   server-side проверку во время исполнения.

## Sandbox profiles

Реализовать три явно различимых профиля:

1. `NO_EXEC`: разрешены только contract/evidence операции.
2. `LOCAL_RESTRICTED`: live process возможен только при доказанных OS-level
   controls для выбранной платформы.
3. `UNTRUSTED_CODE`: по умолчанию `BLOCKED_SANDBOX`; включается лишь после
   отдельного evidence, что kernel/container boundary реально применён.

Для `LOCAL_RESTRICTED` проверить:

- filesystem: allowlisted workspace, запрет traversal, symlink/junction escape,
  UNC/device paths и записи вне root;
- network: deny by default, точный allowlist назначения при необходимости;
- secrets: opaque handles вместо значений, минимальный env, redaction логов;
- processes: ограничение дерева процессов, CPU/RAM/time, никакого detached
  survivor; cancellation завершает всё дерево;
- outputs: только в выделенный artifact root, SHA-256 и provenance;
- lifecycle: timeout/crash/cancel дают терминальный reason, не «успех».

`cwd`, очищенный env и Job Object без доказанной FS/network boundary нельзя
называть полным sandbox. Если ОС не позволяет доказать обязательный control,
оставить профиль blocked и описать требуемый AppContainer/container/restricted
token follow-up.

## TDD и реализация

Сначала написать тесты и наблюдать RED. Затем реализовать минимальный policy
engine и boundary adapters. Не менять oracle/tests после просмотра результатов
кандидата без отдельной review-записи.

Минимальные группы тестов:

- schema/version/unknown-field mutations;
- role/capability/grant/expiry/revocation/fencing/nonce;
- 20-principal ACL matrix на каждом релевантном data path;
- Web/API/CLI parity;
- cache/summary/derived-artifact ACL inheritance;
- lease race и revocation latency;
- cancellation/process-tree cleanup;
- Windows junction/symlink/path canonicalization;
- network/secret/environment restrictions;
- restart/replay/idempotency/reconciliation;
- tamper detection для policy, corpus, результатов и manifests.

Core policy tests должны быть deterministic, offline и без платных model calls.

## Adversarial corpus

Все пробы должны идти через production-facing policy path, а не повторять
ожидаемый guard внутри теста:

- A: cross-tenant source/search retrieval;
- B: private claim попадает в shared graph summary или cache;
- C: payload/env подделывает role, principal или approval;
- D: junction/symlink/traversal выводит filesystem за workspace;
- E: source prompt injection просит расширить права или раскрыть secret;
- F: inter-agent message с чужим scope/tenant;
- G: дочерний процесс переживает cancellation/timeout;
- H: stale grant/lease/fencing token после revocation;
- I: повтор nonce/idempotency key меняет эффект;
- J: corrupted/missing policy evidence пытается пройти fail-open.

Любой успешный escape, exfiltration или authority expansion — hard FAIL.

## Измерения и независимый replay

Выполнить два process-separated запуска с разными executor ID, nonce и output
roots на одном frozen corpus. Сохранить raw observations для каждого case.

Обязательные метрики:

- cross-tenant successful reads/writes/messages: `0`;
- authority expansions: `0`;
- filesystem/network/secret escapes: `0`;
- survivors after cancellation: `0`;
- allow-after-revocation-commit: `0`;
- missing/censored trials: `0`;
- revocation decision latency: max `<=5000 ms`, не менее 100 trials на run;
- decision mismatch Run A/Run B: `0`;
- coverage: все 20 principals × все заявленные paths.

Не исключать errors/timeouts из знаменателей. Missing counter, raw trace,
principal/path cell или commit binding — fail-closed.

## Обязательные артефакты

Создать и отслеживать в Git:

- `contracts/workspace.schema.json`;
- `contracts/principal.schema.json`;
- `contracts/role.schema.json`;
- `contracts/capability.schema.json`;
- `contracts/grant.schema.json`;
- `contracts/lease.schema.json`;
- `contracts/sandbox-profile.schema.json`;
- `contracts/authorization-decision.schema.json`;
- policy implementation и единые Web/API/CLI adapters;
- frozen threat model, rubric, cases и corpus manifest;
- run-a/run-b summaries, comparison, raw evidence archive/manifest;
- `docs/security/S2-002-THREAT-MODEL.md`;
- `docs/security/S2-002-SANDBOX-PROFILE.md`;
- `docs/decisions/S2-002-EVALUATION-REPORT.md`;
- content-addressed evidence pack и final integrity record.

Секреты, токены и private source content в Git запрещены.

## Definition of Done

S2-002 получает `PASS_WITH_LIMITS`, только если одновременно выполнено:

1. S2-001 dependency binding воспроизводим из clean checkout.
2. Все schemas и server-side policy paths реализованы и versioned.
3. ACL matrix покрывает 20 principals и все перечисленные paths.
4. Все hard counters равны нулю в обоих независимых запусках.
5. Revocation latency и trial minimum выполнены для каждого запуска.
6. Все adversarial probes обнаружены production-facing path.
7. Process-tree cancellation и обязательные OS controls наблюдаемы.
8. Frozen hashes, commit/tree, environment и outputs сходятся.
9. Полный test/typecheck/build/security набор проходит в чистом checkout.
10. Документация честно отделяет локально доказанное от production guarantees.

Если identity policy доказана, но kernel-level sandbox недоступен, допустим
`PARTIAL/BLOCKED_SANDBOX`; live execution остаётся запрещённым. Нельзя закрывать
тикет одним только mock, narrative report или self-reported agent verdict.

## Команды приёмки

Использовать фактические scripts проекта; добавить недостающие именованные
команды в `package.json`. Минимальный финальный набор:

```powershell
npm ci
npm run test:identity
npm run test:sandbox
npm run test:security-probes
npm run verify:podman-sandbox
npm run verify:gvisor-sandbox
npm run verify:postgres-smoke
npm run verify:s2-002
npm run typecheck
npm run lint
npm run build
npm audit --omit=dev
npm audit
npm run manifest:check
git diff --check
git status --short
```

`build` может быть `NOT_RUN_BUILD_ENVIRONMENT` только с точной внешней причиной;
тогда full completion запрещён. Повторить релевантные проверки из clean
`git archive HEAD` после финального commit.

## Stop conditions

Немедленно остановить live execution и вернуть конкретный blocker при:

- любом cross-tenant доступе или расширении полномочий;
- чтении/логировании секрета;
- записи вне workspace либо обходе через link/path;
- сохранении процесса после cancellation;
- невозможности server-side identity verification;
- недоказанной FS/network boundary для запрашиваемого профиля;
- stale/missing dependency, corpus, policy или commit binding;
- необходимости реальных credentials, paid calls или внешнего deployment без
  отдельного разрешения владельца.

## Итоговый отчёт агента

Вернуть кратко: verdict, доказанная boundary, непокрытые guarantees, commits,
полные exit codes, test counts, run provenance, hard counters, revocation
statistics, probe outcomes, evidence paths/hashes и точный GitHub branch/PR.
Push выполнять только в ветку S2-002; merge в `main` — после независимого review.
