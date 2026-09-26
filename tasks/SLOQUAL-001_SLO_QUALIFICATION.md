# SLOQUAL-001 — Production-like SLO qualification (extends S1-002)

## Статус и назначение

- Канонический ID: `SLOQUAL-001` (research ticket AgentOS, issue
  [#40](https://github.com/SpaceDazher/Veritas/issues/40)).
- Фаза: `Stage 1`, wave `quality extension`, priority `quality gate`.
- Owner role: `capacity`, co-owner `security` для gate S1-008.
- Исследовательский verdict источника: `PASS_WITH_LIMITS`.
- Verdict этого пакета: см. [SLOQUAL-001-EVALUATION-REPORT.md](../docs/decisions/SLOQUAL-001-EVALUATION-REPORT.md).
- Граница: локальная квалификация control-plane решений Veritas. Это не
  production SLO, не capacity plan и не разрешение rollout.

S1-002 дал короткий local benchmark и запретил читать его числа как
production SLO. S1-008 задал security gate «revoke-to-deny ≤ 5 s».
SLOQUAL-001 добавляет к ним воспроизводимый qualification-пакет для
Veritas: заранее замороженный SLO contract, версионированный scenario
manifest, open-loop нагрузка без coordinated omission, fail-closed
comparator и обязательный независимый повтор в отдельном процессе.

## Границы полномочий

- `PASS_WITH_LIMITS` не является `PASS`, production readiness, независимой
  внешней проверкой, юридическим заключением или разрешением расходов.
- Порог, записанный в JSON, не является авторизацией: SLO не имеет
  подписанного владельца (`countersignature.status = NEEDS_INPUT`).
- Измерения этой qualification — single-host, in-process, pilot scale.
  Перенос чисел на production без отдельного профиля нагрузки запрещён.

## Обязательные артефакты

| Артефакт | Назначение |
| --- | --- |
| `contracts/sloqual-001-slo-contract.json` | Замороженный SLO contract v1.0.0: SLI, hard gates, thresholds, registered proofs, правило verdict, self-hash. |
| `contracts/sloqual-001-scenario-manifest.json` | Версионированный manifest: 17 scenarios × 5 seeds, 19 workloads, open-loop arrival model, warmup policy, 105 revocation trials. |
| `src/lib/sloqual/` | Harness: freeze-проверка, статистика, open-loop clock, измерение, fail-closed comparator. |
| `scripts/sloqual-freeze.mjs` | Author-time инструмент заморозки (self-hash + binding manifest). |
| `scripts/sloqual-run.mjs` | Один независимый запуск манифеста. |
| `scripts/verify-sloqual-001.mjs` | Два process-separated запуска, comparator, evidence. |
| `evidence/sloqual-001-*.json` | Run A, run B, comparison, integrity digests. |

## Правила, которые нельзя нарушать

1. **Пре-регистрация.** Контракт фиксируется коммитом раньше того, как
   измеряется. Gate проверяет, что коммит с контрактом — предок HEAD;
   иначе вердикт `NOT_RUN`, а не результат.
2. **Fail closed.** Отсутствующая метрика, неполное покрытие, коллизия
   provenance двух запусков, несовпадение digest — это `FAIL`, а не `PASS`.
3. **Измерение настоящее.** Единица анализа — один вызов
   `policy-engine.authorize()`. Заглушки, фикстуры и повтор «из памяти»
   не считаются измерением.
4. **Сравнение точное.** Решения сравниваются побайтово (canonical
   digest); тайминги по определению различаются и сравниваются только
   порогами.
5. **Warmup объявлен.** Первые 10 запросов каждого scenario-seed
   исключены из статистики латентности, но учтены во всех hard counters
   и в raw observations.
6. **Отсутствие доказательства — limit, а не pass.** Неизмеренная
   необходимость всегда понижает verdict и появляется в отчёте с точной
   формулировкой недостающего доказательства.

## Воспроизведение

```bash
npm ci
npm run verify:sloqual-001   # два независимых запуска + comparator + evidence
npm run test:sloqual         # unit-тесты статистики, comparator, freeze и harness
```

Ожидаемый честный результат: `PASS_WITH_LIMITS` с нулём hard failures и
явным списком limits. `FAIL` означает нарушение инварианта или
структурную ошибку и требует разбора, а не подгонки порогов.

## Связи

- Зависимости: S1-002 (benchmark/SLO assumptions), S1-008 (revocation gate).
- Исходный research ticket и его bundle остаются каноническим evidence в
  [SpaceDazher/AgentOS](https://github.com/SpaceDazher/AgentOS/tree/a7940e113492c83a29533d1e93f2724c36a9bbc1/research/tickets/stage-1/SLOQUAL-001).
- Индекс Stage 1: [docs/stages/stage-1.md](../docs/stages/stage-1.md).
