# S2-006E — инженерная приёмка verifier

## Статус: `COMPLETE_WITH_LIMITS` при зелёном финальном checkout

Этот отчёт применяется вместе с
`tasks/S2-006E_ENGINEERING_CLOSURE.md`. Статус инженерного deliverable
считается закрытым **только если** финальный
`evidence/clean-checkout.json` для текущего HEAD имеет `passed: true`,
все обязательные command records имеют `status: PASS` и
`npm run manifest:check` на том же HEAD завершился с кодом 0. До этих
наблюдений строка статуса является условием приёмки, не свидетельством
уже состоявшегося PASS. `assuranceStatus=NOT_MEASURED`; официальный
S2-006 остаётся `NEEDS_INPUT` по §16.

## Дефект, найденный во время закрытия

До исправления самостоятельный `verify:s2-006-db-replay` записывал свежий
результат в `results/s2-006/`, но агрегатор `verify:s2-006` доверял старому
`evidence/s2-006-db-comparison.json`. Поэтому два запуска могли выглядеть
зелёными, не связывая verdict с одним и тем же DB replay.

TDD: тест `tests/verifier/db-replay-freshness.test.mjs` сначала завершился
RED на отсутствующей fail-closed границе (checkpoint `f2bc667`), затем
GREEN после исправления (`1805084`). Новый модуль
`scripts/s2-006-db-gate.mjs` сверяет непосредственный JSON-отчёт текущего
процесса с записанным evidence, различает `PASS`, `NOT_RUN_DB` и `FAIL`,
требует `comparison.ok`, `hardGates.ok` и `crashPhase.ok`. Агрегатор сам
запускает replay; старый файл больше не является полномочием. Отрицательный
интеграционный контроль без доступа к WSL дал `exit 1`, `NOT_RUN_DB` и
неразрешённый probe S, хотя до него на диске был PASS. Повтор вне
песочницы на эфемерном PostgreSQL дал `exit 0` и все gate `PASS`.

Покрытие нового fail-closed модуля: `node --experimental-test-coverage
--test tests/verifier/db-replay-freshness.test.mjs` → 6/6 PASS; 100% lines,
96% branches, 100% functions. Эти показатели относятся к новому модулю,
не ко всему проекту.

## Наблюдаемые проверки после исправления

| Проверка | Итог |
| --- | --- |
| `npm ci` | exit 0; lockfile установил 390 пакетов. |
| `npm run verify:s2-006-dependencies` | exit 0; 75 Git-byte проверок, 0 issues. |
| `npm run verifier:types` | exit 0; 15 контрактов, generated types совпадают. |
| `npm run test:verifier` | exit 0; 317 tests: 311 pass, 0 fail, 6 `NOT_RUN_DB` skip. |
| `npm run test:s2-006-calibration` | exit 0; 93/93 pass. |
| `npm run test:s2-006-security-probes` | exit 0; 74/74 pass. |
| `npm run verify:s2-006` | exit 0 вне песочницы; текущий DB replay, dependency, types, suite, evidence run и probes — PASS; verdict `NEEDS_INPUT`. |
| `npm run verify:s2-006-db-replay` | exit 0; **внутренний** status PASS, Run A/B digests идентичны, `comparison.ok=true`, `hardGates.ok=true`, `crashPhase.ok=true`, duplicate outbox IDs = 0. |
| `npm test` | exit 0 вне песочницы; 780 tests: 774 pass, 0 fail, 6 DB-skip; отдельный replay покрывает DB-path. |
| `npm run typecheck` / `npm run lint` | exit 0 / 0. |
| `npm run build` | exit 0 с тем же compile-time placeholder `DATABASE_URL`, который использует clean-checkout; реального соединения при сборке нет. Без переменной сборка честно отказала. |
| `npm audit --omit=dev` / `npm audit` | exit 0 / 0; на момент прогона 0 vulnerabilities. |
| `npm run verify:clean-checkout` | Итог хранится в `evidence/clean-checkout.json`; PASS обязателен для действия строки статуса выше. |
| `npm run inventory:check` / `npm run manifest:check` / `git diff --check` | Финальные результаты обязательны после reseal. |

Первый sandboxed `npm test` дал 7 fail и 1 cancelled из-за запрещённого
доступа к WSL; повтор того же suite с локальным WSL/Podman, без изменения
тестов, дал 0 fail. Первый `npm audit` в песочнице не смог обратиться к
registry; повтор с разрешённым сетевым доступом завершился без уязвимостей.
Для DB replay код выхода 0 **сам по себе недостаточен**: `NOT_RUN_DB`
может иметь exit 0, поэтому проверен внутренний `status` и hard gates.

Первый clean-checkout также отказал: системный temp на C: имел около
460 МБ свободного места, изолированный `npm ci` получил `ENOSPC` и оставил
неполный `node_modules`. Независимо от нехватки места `contracts` обнаружил
устаревший `evidence/frozen-manifest.json` после фикса. Новая регрессия
сначала дала RED на отсутствующем DB-gate в freeze; затем был выполнен
явный `validate-contracts --freeze` и просмотрен diff: обновлены только
новый DB-gate, его тест, изменённый verifier, собственный hash freeze-скрипта
и S2-006 security-probes evidence. Финальный clean-checkout запускается с
временным каталогом и npm-cache на D:, а не с неполной копией на C:.

## Граница результата и downstream

- Данные калибровки относятся к 45 fixture-кейсам; независимость labels,
  внешняя semantic precision/recall и generalization — `NOT_MEASURED`.
- Нет method-owner HumanDecision и утверждённых numeric thresholds до
  unseal, независимых annotators/adjudicator или внешнего held-out корпуса.
  `evidence/s2-006-summary.json` перечисляет недостающие входы; его
  официальный verdict — `NEEDS_INPUT`.
- Provider stratum необязателен в начальном calibration scope и имеет
  `NOT_RUN_PROVIDER`; диагностический OpenRouter-пилот S2-006M не повышает
  assurance S2-006.
- Использовать можно лишь проверенные инженерные контракты verifier.
  Автоматическое принятие знаний, SolutionPack и production rollout не
  разрешены. Push, PR и merge этим отчётом также не разрешаются.
