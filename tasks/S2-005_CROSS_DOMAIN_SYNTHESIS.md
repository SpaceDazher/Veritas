# S2-005 — Поиск и междисциплинарный синтез

## Статус и цель

- Статус: `READY`. S2-004 завершён с `PASS_WITH_LIMITS` и слит через PR #17;
  реализация всё равно начинается с воспроизводимого dependency gate.
- Ветка задания: `codex/s2-005-cross-domain-synthesis`, от `origin/main`
  `7662face2091c1f591af2b586502beb4ea698e5e`.
- Зависимости: S2-004, S1-007, S1-009; S2-003 и S2-002 наследуются через
  S2-004. Любые ограничения upstream остаются обязательными.
- Результат: воспроизводимый поиск по разрешённым источникам и claim graph,
  сравнение retrieval-подходов, `EvidenceMap` и `HypothesisCard` для локальных
  и междисциплинарных вопросов.

Веритас должен помогать находить новые полезные связи между доменами, но не
называть красивую аналогию доказанным механизмом, корреляцию — причиной, а
новизну относительно локальной базы — мировой научной новизной.

## 1. Dependency gate до реализации

Состояние планирования на 2026-09-16: S2-004 канонизирован в `origin/main`
merge-коммитом `7662face2091c1f591af2b586502beb4ea698e5e`; проверенный head
S2-004 `f4122726c2926819066fa96255a9ab8aebea25fa` является его предком.
Это снимает известный внешний блокер, но не заменяет проверку evidence.

Реализовать `verify:s2-005-dependencies` и tracked record. Из байтов Git и
канонических evidence pack проверить:

1. `origin/main` содержит завершённый S2-004 с воспроизводимым
   `PASS_WITH_LIMITS` или более строгим допустимым verdict; его схемы, graph
   revisions, exact evidence spans, ACL и stale propagation совпадают с
   зафиксированными SHA-256.
2. S1-007 даёт проверенные isolation bindings, а S1-009 — границы
   provider-neutral adapter/unsupported semantics. Ссылки на плавающую ветку
   или narrative без digest недостаточны.
3. Frozen корпус, разрешённые права доступа, версия часов/временной модели и
   limitations S2-003/S2-004 доступны потребителю.
4. Нет несовпадения `origin/main`, dependency record и исполняемой версии
   контрактов.

При неуспехе — `BLOCKED_DEPENDENCY`. До зелёного gate разрешены только
контракт, тестовые фикстуры и проектная документация; никаких ложных
результатов retrieval или synthesis.

## 2. Потребители и канонические контракты

Provider: Veritas search/synthesis service. Потребители: человек через
Web/API/CLI, персональные и платформенные агенты, S2-006 verifier, S2-008 R&D
и финальный S2-012 pilot. Единственный источник истины для payload-границы —
версионные JSON Schema в `contracts/`; TypeScript-типы выводить из них.

Создать `1.0.0` схемы минимум для:

- `retrieval-request`: actor/workspace, exact query/task, as-of cutoff,
  domains, languages, geography, time window, source policy, budget,
  allowed retrieval modes и frozen corpus/index versions;
- `retrieval-hit`: immutable source/segment/claim revision and span digests,
  family ID, scope/ACL, score components, rank, inclusion/exclusion reasons;
- `retrieval-run`: query/input/index/model/seed/config hashes, candidates,
  selected hits, failures, abstentions, latency/cost, execution provenance;
- `evidence-map`: каждое проверяемое высказывание вывода → точные claims →
  evidence edges → spans/snapshots; supports, contradicts, qualifiers,
  unavailable evidence, upstream collapse и stale status;
- `hypothesis-card`: `ANALOGY|HYPOTHESIS|OBSERVATION|MECHANISM_CLAIM`,
  originating domains, proposed relation, temporal order, mediators,
  confounders, alternatives, scope/assumptions, falsifiers, test design,
  counterevidence, novelty scope and uncertainty;
- `synthesis-result`: версии входов, EvidenceMap и HypothesisCards,
  competing explanations, unresolved contradictions, coverage/abstention,
  explicit `READY_FOR_REVIEW|INCOMPLETE|BLOCKED` and human-readable reasons.

Определить required/optional/null, enum, errors и compatibility rules.
Runtime serialization и consumer fixtures должны проходить один и тот же
контракт. Не копировать графовые поля вручную в параллельных форматах.

## 3. Корпус и retrieval baseline

Сформировать легально доступный и зафиксированный корпус с provenance,
периодами, source families, версиями индексов и gold relevance labels.
Включить локальные точные вопросы, глобальные междоменные вопросы,
противоречия, частные/запрещённые узлы, ретропрогноз и неизвестные ответы.
Пустой или неразмеченный gold set не позволяет заявлять retrieval quality.

Сравнить на одинаковом корпусе и одинаковых запросах:

1. лексический baseline (например, BM25/FTS);
2. vector baseline с версионными embedding model и индексом;
3. lexical+vector fusion с reranker;
4. graph/community retrieval как экспериментальный кандидат.

Graph method должен доказать добавочную ценность на заранее определённых
local/global strata. Если он хуже или дороже без полезного эффекта, оставить
его опциональным, а не объявлять архитектурным победителем. При недоступности
модели/API записать `NOT_RUN`, не заменять живой benchmark фиктивными числами.

Заранее зафиксировать top-k, query construction, index refresh rule, seeds,
tie-breaking, score normalization, budget and timeout. Индекс не вправе
содержать новые данные по сравнению с выбранным `as_of`.

## 4. Политика доступа и доверия

- Retrieval выполняет server-side ACL S2-002 до scoring, cache, rerank,
  logging и передачи модели. Недоступный private node не появляется даже в
  count, snippet, embedding result или explanation.
- Derived artifacts наследуют наиболее строгий ACL всех входов.
- Source text, graph labels, tool output и model output — данные, не policy.
- Expert lens S2-004 может ранжировать оптики для конкретного пользователя,
  но не меняет truth status, evidence count или verifier verdict.
- Unknown lineage не считается независимым подтверждением; десять копий
  одного upstream — одна evidence family.
- Stale/revoked/tombstoned nodes не входят в новые доказательные выводы.
  Исторический replay явно показывает, что было известно в тот момент.

## 5. Синтез и причинные утверждения

Строить результат из typed claims S2-004; в каждом переходе хранить input
revisions/digests и правила преобразования. Для каждой междоменной связи:

1. Назвать тип: аналогия, проверяемая гипотеза, наблюдение или
   evidence-backed mechanism claim.
2. Указать два или более домена и конкретные узлы/спаны, которые связываются.
3. Разделить наблюдаемую корреляцию, аналогическую структуру, возможный
   механизм и причинное утверждение.
4. Для причинной гипотезы записать temporal ordering, mediator,
   confounders, альтернативные объяснения и способ опровержения.
5. Указать population, geography, period, units, domain limits и
   условия, при которых связь перестанет действовать.
6. Показать противоречащие evidence и недостающие ключевые источники.
7. Отделить уверенность автора, доверие к эксперту, measured calibration
   и evidence support.
8. Не повышать тип epistemic claim без отдельного независимого основания
   и полномочного review.

`EvidenceMap` обязателен для всех externally checkable выводов. Наличие
цитаты без entailment не является доказательством. Недоступные и
неразрешённые источники отображать как пробел, а не молча опускать.

## 6. Временная корректность и новизна

- Отдельно учитывать event, publication, observation, ingestion and index
  times. Wall-clock выполнения — telemetry, не вход в decision/seed/oracle.
- Для ретропрогноза заморозить `as_of`; никакие более поздние snapshot,
  graph correction, label, model training signal или source revision не
  попадают в поиск/синтез.
- Новизну измерять только относительно явно названного frozen corpus и
  поискового горизонта. Вывод: `novel_to_selected_corpus`,
  `similar_prior_found` или `NOT_ASSESSED`; не «никем прежде не открыто».
- Исправление/удаление upstream claim делает производные карты/гипотезы
  `STALE` и запускает пересчёт либо явное abstention.

## 7. Эвалы и acceptance gates

До реализации заморозить rubric, корпус, stratification и thresholds.
Producer не может менять locked-test labels или пороги после результата.
Публиковать numerator/denominator, missing count, coverage, uncertainty и
разрезы по домену, времени, типу вопроса и правам доступа.

Измерять минимум:

- Recall@k и nDCG@k по local/global questions;
- citation entailment и citation coverage;
- contradiction recall;
- domain и time coverage;
- family-collapsed independent evidence count;
- leakage/unauthorized hit rate и stale-hit rate;
- latency/cost с полным budget accounting;
- hypothesis classification, falsifiability и causal overclaim rate
  по независимо размеченному набору;
- abstention rate и долю неполных EvidenceMaps.

Сравнение baseline и graph-кандидата должно быть paired, на одинаковых
вопросах и frozen inputs. Отсутствие независимых labels → `NOT_MEASURED`,
не 100%. Синтетические фикстуры проверяют корректность pipeline, но не
показывают реальную исследовательскую точность.

Hard fail при любом private leak, future leakage, подмене provenance,
ложном causal proof, создании факта из аналогии, сокрытии critical
contradiction, silent exclusion из знаменателя или неконтролируемом
повторном side effect.

## 8. Обязательные adversarial probes

A. Убедительный синтез без поддерживающих spans → `INCOMPLETE`/abstain.

B. Корреляция во времени с известным confounder → не causal mechanism.

C. Пересказ существующего источника → не `novel_to_selected_corpus`.

D. Ретропрогноз с документом, опубликованным после `as_of` → запрет.

E. Private graph node/embedding/snippet/count в shared query → нулевой leak.

F. Десять перепечаток одного upstream → одна evidence family.

G. Две экспертные оптики противоречат: показать обе, условия расхождения и
неопределённость; не выбирать истину по популярности или trust weight.

H. Запрос требует источник, которого нет или доступ запрещён: явный coverage
gap и abstention вместо выдуманной цитаты.

I. Удалённый/исправленный parent claim → EvidenceMap/HypothesisCard `STALE`.

J. Prompt injection в документе пытается поменять rubric/ACL/tools →
содержимое инертно, authority counters равны нулю.

K. Graph retrieval получает лучшие offline цифры ценой leakage или
неограниченного бюджета → кандидат отклоняется до quality ranking.

L. Число или отрицание меняется при summary/translation → ссылка не
entailing, вывод не принят.

## 9. Исполнение и воспроизводимость

TDD: сначала regression/security tests и наблюдаемый RED, затем минимальная
реализация и GREEN. Frozen Run A и process-separated Run B — разные executor,
PID, nonce, output root на одном implementation commit. Comparator fail-closed
проверяет полный состав cases, decision digests, EvidenceMap/HypothesisCard
digests, метрики, failures и hard counters. Результаты не должны зависеть
от текущего wall-clock, порядка обхода файлов или случайного tie-break.

Сохранить raw observations, environment manifest, index/model versions,
query traces, labels, code commit, frozen hashes и объяснение выбора между
baseline и graph candidate. Отличать tested implementation commit от
последующего evidence-container commit без самоссылочного хеша.

Команды приёмки (добавить соответствующие scripts в `package.json`):

```powershell
npm ci
npm run verify:s2-005-dependencies
npm run synthesis:types
npm run test:retrieval
npm run test:synthesis
npm run test:s2-005-security-probes
npm run verify:s2-005
npm run verify:s2-005-db-replay
npm test
npm run typecheck
npm run lint
npm run build
npm audit --omit=dev
npm audit
npm run verify:clean-checkout
npm run manifest:check
git diff --check <canonical-base>..HEAD
git status --short
```

Любая неисполненная команда указывается как `NOT_RUN_*`, а не PASS.

## 10. Deliverables

- versioned JSON Schemas, derived types, storage/API implementation;
- frozen retrieval/synthesis corpus, independent labels and rubric;
- lexical/vector/fusion/reranker baselines и graph candidate с общей
  матрицей вопросов и честным comparator;
- `EvidenceMap`, `HypothesisCard`, competing-explanations output;
- dependency binding, Run A/B, comparison, probes A–L, DB replay,
  clean-checkout, environment/index/model manifests;
- `docs/decisions/S2-005-EVALUATION-REPORT.md` с полной матрицей
  measured/unknown/deferred;
- handoff для S2-006 verifier и S2-008 R&D.

Допустимый итог: `BLOCKED_DEPENDENCY` до merge S2-004; `REVISE` при hard
violation; `PASS_WITH_LIMITS` после зелёных локальных gate, если остаются
неизмеренные production/external-validity границы. Безусловный `PASS` не
выводится из красивого demo или synthetic corpus.

Push, PR и merge — только по отдельной команде пользователя.
