# S2-006E — приёмка инженерной части verifier

## Контракт до контрольного прогона

Это дополнение применяет `tasks/S2_AUTONOMOUS_DELIVERY_PLAN.md` к уже
реализованному S2-006. Объект приёмки — исходный код, frozen-контракты,
интеграция и воспроизводимость verifier. База сравнения — `origin/main`
`d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f`; защищённые upstream
bindings проверяет штатный dependency gate. Это **не** изменение §16
оригинального S2-006 и не отдельная реализация verifier.

`engineeringStatus=COMPLETE_WITH_LIMITS` допустим только если одновременно:

1. `verify:s2-006-dependencies`, `verifier:types`, `test:verifier`,
   `test:s2-006-calibration`, `test:s2-006-security-probes` и
   `verify:s2-006` завершаются с кодом 0; summary выводит verdict из
   evidence, а не фиксированной строкой.
2. `verify:s2-006-db-replay` выполняется на реальном PostgreSQL: Run A/B
   совпадают, `comparison.ok` и `hardGates.ok` истинны, crash/restart
   `crashPhase.ok` истинен, hard violations и дубликатов нет. Агрегатор
   выполняет свежий replay сам и сверяет его прямой отчёт с записанным
   evidence; прежний зелёный файл не может заменить новый запуск.
3. `npm test`, `typecheck`, `lint`, `build`, `npm audit --omit=dev`,
   `npm audit`, `verify:clean-checkout`, `inventory:check` и
   `manifest:check` завершаются с кодом 0. Допустимые skipped tests
   перечисляются по причине; никакой обязательный gate не прячется в skip.
4. `git diff --check` зелёный; рабочее дерево после reseal чистое.
   Отчёт либо связанное машинное evidence называет фактические exit codes,
   commit и оставшиеся ограничения.

Если один из обязательных пунктов не выполнен, статус `REVISE` или
`BLOCKED_DEPENDENCY`, не `COMPLETE_WITH_LIMITS`. Запуск из неизменённого
чистого checkout имеет приоритет над устаревшей записью о прошлом прогоне.

## Явно исключённые утверждения

- Официальный S2-006 остаётся `NEEDS_INPUT`, пока его §16 не подтверждён
  независимыми annotators/adjudicator, внешним held-out корпусом,
  pre-unseal thresholds и настоящим HumanDecision.
- 45 fixture-кейсов измеряют только поведение тестовой системы; модельные
  ответы, дополнительные prompts и разные API-вызовы не делают labels
  независимыми. Precision/recall на внешней population — `NOT_MEASURED`.
- Инженерное закрытие не выдаёт grant, не меняет ACL, не публикует
  приватные материалы и не разрешает production rollout или финальное
  принятие исследовательского результата.
- Downstream может полагаться только на проверенные технические свойства
  verifier; для зависимости от семантической точности нужен отдельный
  независимый calibration gate.

Итоговый наблюдаемый протокол и статус записываются отдельно в
`docs/decisions/S2-006E-ENGINEERING-CLOSURE.md` после контрольного прогона.
