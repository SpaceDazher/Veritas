# S2-006 — Независимый semantic verifier и калибровка

> План автономного закрытия **инженерных** deliverables Stage 2:
> `tasks/S2_AUTONOMOUS_DELIVERY_PLAN.md`. Он не меняет официальный verdict
> этого тикета и не подменяет независимую калибровку модельной оценкой.

> Дополнение от 2026-09-22: при отсутствии независимых людей владелец разрешил
> отдельный автономный маршрут `S2-006M` — модельную подготовку и проверку
> корпуса. Его план и проверяемые результаты находятся в
> `tasks/S2-006M_MODEL_ASSISTED_PILOT.md`. Этот маршрут не меняет контракты,
> verdict или требования к независимой калибровке S2-006 ниже. Модельный
> оператор не выдаёт HumanDecision, не подписывает чужую роль и не объявляет
> свои оценки независимыми.

## Статус и цель

- Статус: `READY`. S2-005 слит через PR #18 в `origin/main`.
- Ветка задания: `codex/s2-006-independent-semantic-verifier`, от
  `origin/main` `d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f`.
- Канонический head S2-005:
  `36fd8f854459f3ee419a997293c966e6840a2373`; dependency gate обязан
  программно доказать, что он достижим из указанного `origin/main`.
- Зависимости: S2-005, S2-004, S2-003 и S2-002; S1-011/S1-012 и продуктовые
  политики наследуются как обязательные ограничения.
- Результат: отдельный, воспроизводимый и fail-closed verifier, который на
  независимо размеченном held-out корпусе измеряет семантическую корректность
  claims, EvidenceMap, HypothesisCard и synthesis results, публикует
  калибровку, uncertainty и coverage и передаёт спорные решения человеку.

S2-006 не создаёт «универсальный балл истины». Он проверяет ограниченные,
явно названные свойства относительно конкретных источников, corpus/version,
rubric и population. Даже успешно откалиброванный verifier остаётся
советующим компонентом: он не может принимать собственный вывод, повышать
эпистемический тип, выдавать разрешения, менять ACL или заменять критическое
решение человека.

## 1. Dependency gate до реализации

Создать `verify:s2-006-dependencies` и tracked record
`evidence/s2-006-dependency-binding.json`. Проверка из байтов Git и
канонических evidence pack должна fail-closed подтвердить:

1. Merge object `d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f` имеет ровно ожидаемых
   родителей, в порядке Git:
   `7662face2091c1f591af2b586502beb4ea698e5e` и
   `36fd8f854459f3ee419a997293c966e6840a2373`; второй parent — точный head
   S2-005. На старте `origin/main` обязан указывать на этот merge object;
   проверка выполняется по fetched remote-tracking refs (preflight в
   разделе 14): устаревшая локальная рабочая копия — повод для preflight
   `git fetch origin`, а не для `BLOCKED_DEPENDENCY`.
   Если `origin/main` позднее продвинут, gate разрешает его только после
   отдельного reviewed rebase binding, который доказывает неизменность
   защищённой S2-005/policy поверхности; простого ancestor check недостаточно.
2. S2-005 воспроизводит `PASS_WITH_LIMITS`, полный suite, clean checkout,
   dependency gate, Run A/B, DB replay и probes с совпадающими SHA-256.
3. Доступны и совпадают frozen inputs S2-005: `corpus/s2-005/manifest.json`,
   `contracts/s2-005-thresholds.json`, schemas/types, Run A/B, DB evidence и
   evaluation report; verifier не принимает narrative вместо digest.
4. S2-004 предоставляет неизменяемые claim revisions, exact spans,
   provenance/lineage, ACL, calibration record и invalidation semantics;
   S2-003/S2-002 обеспечивают source snapshots, grants и isolation bindings.
5. Expected blobs читаются через `git show d7ce192:<path>`, а не из current
   worktree или самосгенерированного dependency record. Record сохраняет
   resolved refs/object IDs, exit codes и SHA-256 `METRIC_POLICY`,
   `HUMAN_APPROVAL_POLICY`, `AUTONOMY_POLICY`, S1-011/S1-012 bindings и всех
   защищённых S2-005 manifests/contracts/evidence indexes.
6. Все ограничения upstream перенесены: synthetic-only corpus, hashed TF-IDF
   вместо production embeddings, global paired statistics `NOT_MEASURED`,
   novelty только `novel_to_selected_corpus`, отсутствие production claim.
7. Нет расхождения между `origin/main`, dependency record, manifest и
   реально исполняемыми contract versions.

При неуспехе итог — `BLOCKED_DEPENDENCY`. До зелёного gate разрешены только
контракты, тестовые фикстуры и проектная документация; измеренные semantic
результаты публиковать запрещено.

## 2. Граница S2-006 и не-цели

Verifier обязан независимо оценивать:

- entailment точного cited span относительно проверяемого statement;
- полноту и корректность citation/qualifier/scope binding;
- обнаружение противоречий и различение contradiction от scope difference;
- сохранность чисел, единиц, отрицаний, модальности и временных ограничений;
- epistemic type и запрет повышения analogy/correlation до mechanism claim;
- causal overclaim, temporal ordering, mediators, confounders, alternatives;
- near-duplicate/source-family collapse и независимость evidence;
- stale/revoked/tombstoned/future evidence и `as_of` leakage;
- completeness/abstention EvidenceMap и synthesis result;
- novelty только относительно названного внешнего frozen corpus и горизонта.

Не входят в S2-006:

- доказательство абсолютной истинности утверждений или мировой новизны;
- автоматическое `ACCEPT_BOUNDED`, финальное принятие SolutionPack или
  production rollout;
- получение credentials, платные provider calls, импорт private corpus или
  найм экспертов без отдельного решения владельца;
- изменение producer outputs S2-003/S2-005 на месте;
- R&D exploration S2-008 и продуктовые интерфейсы S2-010, кроме стабильных
  read API/contract fixtures, нужных будущим потребителям.

## 3. Trust model и независимость

Независимость — многомерное свойство, а не boolean. Каждый run и report
должен отдельно фиксировать:

- `artifact_producer`: кто/что создало оцениваемый output;
- `verifier_implementation_owner` и immutable implementation digest;
- `annotators`, `adjudicator` и их роли/доменные компетенции;
- blindness: скрыты ли producer identity, producer verdict, predictions,
  thresholds и split assignment;
- data independence: использовались ли cases при разработке producer или
  verifier;
- model/provider/prompt independence и общую lineage, если она есть;
- process/workspace independence и конфликт интересов;
- кто имел доступ к locked-test labels до unseal.

Минимум для утверждения `INDEPENDENTLY_CALIBRATED`: разметка не создана
producer/verifier, predictions скрыты от annotators, calibration и locked
test разделены, thresholds зафиксированы до unseal, а разногласия разрешены
отдельным adjudicator. Синтетические principals проверяют policy, но не
считаются реальными независимыми людьми. Один агент, модель или процесс,
разыгравший несколько ролей, не создаёт независимости.

Обязательна server-enforced role/access matrix с разными S2-002-authenticated
subjects и workspaces: `candidate`, `label_custodian`, минимум два
`annotator`, `adjudicator`, `evaluation_harness` и `reviewer`. Каждый locked
case получает минимум два независимых blind raw labels до adjudication;
annotator не может adjudicate тот же case, а producer/candidate/verifier
operator не может быть annotator или adjudicator. Каждый label set и
adjudication подписываются/аттестуются authenticated subject над exact digest
corpus+split+case+rubric+label bytes. Подписи проверяемы: offline HMAC-SHA256
или Ed25519, ключи в custody у назначенных субъектов (не у candidate или
verifier operator); policy engine криптографически верифицирует подпись над
exact digest и не доверяет полю `auth_ref`. Self-attestation, role reuse,
forged signature, отсутствующая или не прошедшая верификацию подпись и
конфликт интересов отклоняются до semantic comparison.

Реализация verifier изолирована module whitelist'ом: разрешены identity/ACL,
persistence primitives, контракты и их валидация, canonical JSON, hashing.
Запрещено импортировать producer-семантику (entailment/relation/classification
функции `src/lib/synthesis/*` и `src/lib/claims/*`) в путь проверки candidate;
producer-функции разрешены только deterministic baseline (раздел 9). Каждое
исключение фиксируется в independence profile.

Candidate никогда не получает locked labels, split secrets или adjudication
ни до, ни после unseal. Его predictions и полный run manifest запечатываются
до unseal. Run A и process-separated Run B независимо исполняют один frozen
candidate на одних inputs до unseal и запечатывают два prediction-set digest
и два run-manifest digest. У детерминированного candidate prediction-set
digests могут совпадать — различными обязаны быть run-manifest digests
(executor ID, PID, nonce, output root). Только после этого labels открываются
отдельному comparator process, который сравнивает оба sets по заранее заданному
exact/tolerance rule и не перезапускает candidate. Все успешные и отклонённые access attempts входят
в audit.

Если независимые annotators/adjudicator, их полномочия или conflict records
не предоставлены, инфраструктура может быть реализована и протестирована,
но эмпирическая калибровка получает `NOT_MEASURED` с причиной
`evaluator_not_independent` и итог не выше `NEEDS_INPUT` для этой части.

## 4. Канонические контракты

JSON Schema draft 2020-12 в `contracts/` остаются единственным источником
истины; TypeScript-типы генерируются, а drift падает. Не создавать второй
несвязанный формат calibration/truth score. Ввести `calibration-record` v2
как новую contractVersion с чтением v1: исторические v1-records остаются
валидными, consumers обязаны понимать обе версии. v2 содержит richer
evaluator independence profile по разделу 3, расширенный статус-enum
(`NEEDS_INPUT`, `NOT_APPLICABLE`) и разрешает `denominator: 0` только в
паре со status `NOT_MEASURED` и reason code. `calibration-record`
(immutable per-run запись) явно связывается с новым `calibration-report`
(агрегат по запуску калибровки) без дублирования формата. Добавить минимум:

- `semantic-verification-request`: actor/workspace, exact artifact kind/id/
  revision/digest, requested checks, as-of, ACL/grant, rubric/corpus/model/
  threshold versions, budget и idempotency key;
- `semantic-verification-item`: атомарный statement/span/card criterion,
  gold/predicted label, bounded verdict, reason codes, exact evidence links,
  missingness, uncertainty и provenance;
- `semantic-verification-result`: immutable input/output digests, item
  results, disagreements, critical findings, abstentions, coverage,
  independence profile и `READY_FOR_HUMAN_REVIEW|INCOMPLETE|BLOCKED`;
- `annotation-set`: frozen case IDs, split, blind assignment, annotator role,
  labels, timestamps, source/rubric digests и signature/attestation status;
- `adjudication-record`: conflicting labels, retained raw labels, decision,
  rationale, adjudicator identity, exact versions и audit reference;
- `verifier-run`: implementation/model/prompt/tool/config hashes, seed,
  environment, input/output roots, failures, cost/latency and execution
  provenance;
- `calibration-report`: metric records, confusion matrices, numerator/
  denominator/missing, slices, intervals, selective-risk/coverage results,
  threshold decision, independence tier, limitations and expiry/drift scope;
- `verifier-invalidation-event`: model/prompt/rubric/corpus/contract drift,
  revoked labels, changed source revision и перечень затронутых records;
- `semantic-provider-grant`: authenticated principal, tool, workspace,
  model/access, currency, timeout, бюджет task/campaign/day и
  no-training/no-retention status;
- `corpus-case` / `annotation-manifest` / `rubric`: source_family,
  semantic_template, strata-теги, license/locator, provenance и SHA-256
  case/label/rubric bytes.

Для каждого поля определить required/optional/null, closed enum, limits,
compatibility и canonical serialization. Каноническая сериализация
фиксируется как версионный алгоритм `canonical-json-v1` (sorted-key JSON,
in-repo реализация на Node stdlib, без новых зависимостей); idempotency keys
и все digests считаются только по canonical form, а
`semantic-verification-request` содержит обязательное поле
`canonical_args_digest`.

Grant/capability поверхность расширяется новыми resource types
(`annotation_set`, `adjudication_record`, `locked_label`,
`verification_result`, `calibration_report`, `verifier_run`) и ролями
(`candidate`, `label_custodian`, `annotator`, `adjudicator`,
`evaluation_harness`, `reviewer`) с явной capability-матрицей по разделу 3.
Frozen upstream схемы S2-002, включая `grant.schema.json`, не мутируются. Unknown version, extra authority
field, missing digest или неполная lineage должны отклоняться.

Verifier verdict не должен записываться в `claim-review-decision` как будто
это человеческий `ACCEPT_BOUNDED`. Связь с claim/synthesis выполняется через
отдельный immutable evaluation artifact; authorised reviewer принимает
самостоятельное решение по точному digest.

## 5. Compute/query API, command API и поведение verifier

Разделить provider-neutral pure compute/query API:

- `verifyClaim` / `verifyEvidenceMap`;
- `verifyHypothesisCard` / `verifySynthesisResult`;
- `getVerificationResult` / `listCalibrationReports`;
- `auditVerifierRunForLeaks`;

и explicit state-changing command API:

- `publishVerificationResult` / `publishCalibrationReport`;
- `publishAdjudication` / `invalidateCalibration`.

`compareWithIndependentLabels` и `calibrateVerifier` выполняются только
isolated evaluation harness после sealed-prediction handoff. Их temporary
outputs не каноничны, пока отдельная publish command не прошла capability,
exact-args, idempotency, transaction/audit/outbox и reconciliation gates.
Pure/read-only mode гарантирует нулевую mutation tracked files и DB.

Все операции читают exact revisions/digests и не изменяют upstream artifact.
Коррекция создаёт новую версию evaluation artifact и `SUPERSEDES` link.
Ошибки и abstention типизированы; исключение, timeout или unavailable source
не превращаются в semantic fail/pass. Для каждого check возвращаются scope,
reason codes и границы применимости.

Статусы проверки ограничены локальным смыслом, например `SUPPORTED`,
`CONTRADICTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`,
`OUT_OF_SCOPE`, `STALE_INPUT`, `BLOCKED_POLICY`. Они не являются глобальной
истиной и не меняют lifecycle claim без отдельного полномочного review.

## 6. Независимый корпус и разметка

До первого measured run заморозить task definition, rubric, corpus,
sampling frame, split, inclusion/exclusion, labels, models/tools, thresholds,
seed и statistical plan.

Корпус должен:

1. Содержать externally authored, законно используемые материалы с exact
   snapshot/span provenance; generated fixtures хранятся отдельной stratum.
2. Покрывать claim/evidence, retrieval/synthesis и cross-domain cases,
   включая минимум 20 eligible externally authored, independently labelled
   global cross-domain questions после source-family и semantic-template
   dedup, причём минимум 20 относится именно к `locked_test` global stratum;
   размеры остальных splits и strata задаются preregistered power analysis
   от целевых denominators. Это структурный минимум для измеренной
   paired-статистики, а не обещание достаточной statistical power;
   power/sample-size обосновываются заранее. Re-annotation S2-004/S2-005 и generated fixtures идут в отдельные
   strata и не входят в external-validity/global paired denominator.
3. Иметь непересекающиеся `dev`, `calibration`, `locked_test` splits по
   source family и semantic template, чтобы paraphrase/duplicate не протёк
   между splits.
4. Включать positive, negative, ambiguous, contradictory, missing-source,
   private, stale, future, multilingual/translation, numeric/unit/negation,
   causal и abstention cases.
5. Сохранять raw независимые labels, disagreements и adjudication; consensus
   не стирает исходные голоса.
6. Не помещать private/licensed raw content в Git/evidence. Если текст нельзя
   распространять, хранить разрешённый locator+digest и отмечать
   невоспроизводимость для читателя без доступа.
7. Иметь manifest с SHA-256 каждого case/label/rubric и проверку, что после
   первого результата frozen bytes не менялись.

Blind re-annotation S2-004/S2-005 обязана быть отдельной от новых внешних
cases и явно помечаться как re-evaluation, чтобы не выдать повторную разметку
synthetic corpus за external validity.

## 7. Rubric и semantic decision rules

Rubric должен быть проверяемым и versioned. Для каждого класса определить
примеры, контрпримеры, допустимую неоднозначность и правило abstention.

- Entailment требует поддержки именно statement с его polarity, quantities,
  units, population, geography, period и modality. Topic overlap не равен
  entailment.
- `PARTIALLY_SUPPORTED` не проходит критерий полного entailment и не может
  быть автоматически пересчитан в support.
- Contradiction требует совместимых scope/units/time; различие scope,
  отсутствие данных и независимые claims не являются contradiction.
- Evidence family считается по upstream lineage; unknown lineage не создаёт
  дополнительной независимости.
- Аналогия, temporal co-occurrence и correlation не доказывают mechanism.
  Causal status требует заранее определённых признаков, но даже их наличие
  не отменяет human review.
- Missing/forbidden evidence показывается как coverage gap. Verifier не
  штрафует producer за недоступный секрет содержимым, которого verifier сам
  не вправе видеть.
- Novelty проверяется только против frozen external search corpus и search
  horizon. Допустимы `novel_to_selected_corpus`, `similar_prior_found`,
  `NOT_ASSESSED`; утверждение мировой новизны запрещено.
- Stale/future/revoked evidence делает зависимый verdict invalid/incomplete,
  даже если текст семантически похож.

## 8. Calibration protocol и метрики

До unseal locked test создать reviewed `contracts/s2-006-thresholds.json`.
Числовые thresholds, confidence level, non-inferiority margin, multiplicity,
tie rule, coverage floor и sample-size rationale принадлежат владельцу/
назначенному method owner. Их нельзя выводить из увиденного победителя.
Method owner назначается только отдельным immutable HumanDecision от
authenticated owner=user, связанным с exact study+threshold digest, scope и
audit reference; self-appointment агентом/verifier запрещён. Отсутствующие
решение или значения дают `NEEDS_INPUT`, а не implicit defaults.

Публиковать raw confusion counts, numerator, denominator, missing count,
coverage, exclusions, interval method и результаты по заранее объявленным
slices. Минимальный набор:

- citation entailment precision/recall/F1 и citation coverage;
- exact-span и qualifier/number/unit/negation preservation;
- contradiction precision/recall, включая scope-difference confusion;
- epistemic-type macro metrics и causal-overclaim rate;
- near-duplicate/source-family collapse precision/recall;
- stale/future invalidation recall и unauthorized leakage rate;
- EvidenceMap completeness, critical-contradiction miss rate;
- hypothesis falsifiability/completeness и bounded novelty assessment;
- false advisory-acceptance и false advisory-rejection rates;
- abstention/review rate, selective risk versus coverage;
- inter-annotator agreement и adjudication rate с raw disagreements;
- calibration curve, Brier score/ECE только если verifier выдаёт
  вероятности; иначе явно `NOT_APPLICABLE`;
- human interventions и active human time с missing/censoring;
- regression rate против frozen upstream/baseline;
- safety/authority incidents на attempted operations по классам;
- latency, actual cost, failures/timeouts и reproducibility.

Нулевой denominator, invalid labels, недостаточный sample или несоблюдённая
independence → `NOT_MEASURED`, не 0%/100%. Abstain-all не может выиграть:
precision без coverage недостаточна. Общий score не должен скрывать hard
failure или провал отдельной safety-critical stratum.

Threshold выбирается только на calibration split. Locked test unseal —
одноразовое событие с audit record, разрешаемое только immutable
HumanDecision от authenticated owner=user над exact digest
study+thresholds+audit reference (по аналогии с method owner); custody split
secrets закреплена за ролью `label_custodian`, и probe H проверяет
отсутствие доступа до этого решения. После него запрещены изменение модели,
prompt, rubric, corpus, labels, thresholds или preprocessing в рамках того
же run. Любая адаптация создаёт новую preregistration/version и новый
неиспользованный locked test.

Заранее фиксируются unit of analysis, family/template clusters, estimator,
resampling/exact method, confidence level, multiplicity family, missing-data
handling и power для critical strata. Decision rule лексикографический:
сначала нулевые hard violations; затем quality+coverage и нижняя граница
paired confidence interval выше `-delta`; при inconclusive —
`HUMAN_REVIEW/no winner`; только среди eligible non-inferior candidates
сравниваются полный cost, затем latency по frozen rule. Trials с разными
model, budget или protocol являются отдельными strata и не образуют paired
winner comparison.

## 9. Baselines и независимый comparator

На одинаковых cases/splits сравнить минимум:

1. deterministic rule/schema baseline;
2. текущий S2-004/S2-005 heuristic verifier behavior; этот baseline —
   единственное место, где разрешено переиспользование producer-функций
   (`entailmentOf`, `buildEvidenceMap`, `compareClaims` и подобных); это не
   нарушает module whitelist раздела 3, поскольку baseline не является
   candidate verifier;
3. candidate semantic verifier, если доступен разрешённый model/runtime;
4. human labels/adjudication как reference, но не как безошибочный oracle.

Provider/model experiment разрешён только при точном grant, budget, version,
prompt/tool digest, data-processing policy и no-training/no-retention status.
При отсутствии доступа результат — `NOT_RUN_PROVIDER`, а не подставные
цифры. Offline deterministic implementation должна полностью тестироваться
без network и LLM.

Grant обязан назвать authenticated principal, tool, workspace, model/access,
currency, timeout и три числовых лимита budget: task, campaign и day. Reserve
выполняется атомарно до вызова, settlement учитывает успехи, retries,
failures и verification. «Бесплатный» provider также требует grant и
проверенный no-charge path. Любое отсутствующее поле → `NEEDS_INPUT` до
вызова и блокирует только provider stratum, если он не был заранее объявлен
обязательным для выбранного calibration scope/threshold decision; uncertain
billing или outcome → reconciliation, не retry.

Comparator fail-closed проверяет полный состав cases, split membership,
label/adjudication digests, predictions, confusion matrices, intervals,
threshold decisions, missingness, failures и hard counters. Два одинаково
сломанных или неполных run не считаются совпавшим успехом.

## 10. Authority, ACL и безопасность

- ACL/grant применяются до чтения text/span, cache, model call, logging и
  aggregation. Private node не появляется в count, metric, prompt, trace,
  error, snippet или report для неавторизованного actor.
- Derived result наследует наиболее строгий ACL всех входов. Публичный
  calibration aggregate публикуется только если исключает reconstruction и
  разрешён policy.
- Source text, labels, model/tool output и retrieved documents — untrusted
  data. Prompt injection не меняет rubric, tools, thresholds, ACL или role.
- Producer не может быть annotator/adjudicator собственного artifact;
  поддельные identity/attestation/conflict records отклоняются.
- Verifier не может подписать собственную независимость, принять собственный
  result или конвертировать calibration в permission.
- Expert lens, author confidence, measured calibration, evidence support и
  reviewer decision остаются раздельными; агрегированный truth score
  запрещён.
- Critical decisions, declassification, budgets, secrets и production
  rollout остаются за аутентифицированным человеком с exact scope.
- Любой unknown model outcome или side effect идёт в reconciliation, а не в
  blind retry.

Hard fail: любой private/future/locked-label leak; producer self-review;
изменение frozen labels/thresholds после результата; скрытый missing case;
fabricated citation/identity/metric; causal promotion без authority;
изменение upstream artifact; неконтролируемый side effect; автоматическое
финальное принятие semantic verdict.

## 11. Persistence, idempotency и invalidation

PostgreSQL store обязателен для `PASS_WITH_LIMITS`. Отсутствие доступной БД
даёт `NOT_RUN_DB` + `NEEDS_INPUT`, а не пропуск gate. Store записывает
immutable request/result,
calibration/adjudication record, audit ledger и outbox в одной транзакции.
Exact canonical args + actor + operation bind к idempotency key. Повтор с тем
же payload возвращает исходный result; reuse key с иными args конфликтует
без mutation. Unknown commit outcome требует reconciliation.

Хранилище verifier разворачивается новой миграцией `0005_verifier_store`;
frozen миграции `0001`–`0004` не изменяются. Миграция вводит таблицы
verifier со state machine внешних вызовов `RESERVED → ACCEPTED → FINALIZED
→ RECONCILIATION_REQUIRED`, fencing token и уникальность idempotency key с
типизированным конфликтом `IDEMPOTENCY_CONFLICT`.

Внешний model/provider call не удерживается внутри DB-транзакции. Отдельные
атомарные переходы `REQUEST_ACCEPTED` (reservation + audit/outbox) и
`RUN_FINALIZED` (exact response digest + settlement + audit/outbox) связаны
fencing/idempotency; crash/timeout/unknown outcome между ними переходит в
reconciliation и тестируется process kill/restart.

Model/prompt/tool/rubric/corpus/threshold/contract/source revision входят в
identity calibration. Любое изменение создаёт новую version; старый report
остаётся историческим и становится `STALE`/`OUT_OF_SCOPE` для нового input.
Source correction, revoked label или upstream invalidation порождают
`verifier-invalidation-event` и вычислимый impact set. Никакой in-place
перезаписи history.

PostgreSQL replay обязан использовать минимум два отдельных процесса и
доказывать equality ожидаемых immutable records, отсутствие duplicate
ledger/outbox writes, cross-tenant leaks и partial commits.

## 12. Обязательные adversarial probes

A. Topic-overlap citation не entail-ит statement → не `SUPPORTED`.

B. Число, единица, отрицание или modality изменены summary/translation →
semantic mismatch с точным reason code.

C. Два claims различаются population/time/scope → не ложное contradiction.

D. Корреляция и temporal order без causal basis → не mechanism claim.

E. Убедительный output без cited spans → `INSUFFICIENT_EVIDENCE`/abstain.

F. Десять перепечаток одного upstream → одна evidence family.

G. Private span/count просачивается в shared verification/report → hard fail.

H. Post-`as_of` source или locked-test label доступен раньше unseal → hard
fail и invalid run.

I. Producer пытается разметить/принять собственный artifact или подделать
independent identity → reject без записи acceptance.

J. Prompt injection в source/label просит сменить rubric, ACL, threshold или
tool → inert content, authority counters zero.

K. Verifier abstains на всех cases и показывает высокую precision → coverage
gate не пройден, candidate не выбран.

L. Два одинаково неполных/сломанных Run A/B → comparator fail-closed.

M. Threshold или label изменён после просмотра locked result → новая version,
старый run invalid; нельзя «починить» тот же experiment.

N. Stale/revoked parent claim сохраняет прежний semantic score → calibration
не применима, dependent result stale.

O. Similar prior вне S2-005 corpus найден во frozen external corpus → не
`novel_to_selected_corpus` для нового горизонта; мировой novelty claim всё
равно запрещён.

P. Model/provider timeout или content-policy refusal → typed missing/abstain,
не semantic pass/fail и не исключение из denominator молча.

Q. После unseal candidate пытается прочитать labels/adjudication либо
comparator повторно вызывает candidate вместо двух заранее sealed Run A/B
prediction sets → hard fail.

R. Один actor повторно используется как annotator+adjudicator, self-attests
independence или подделывает signature/digest binding → reject.

S. Crash после `REQUEST_ACCEPTED` или неизвестный provider outcome → fenced
reconciliation без duplicate charge/result/outbox.

## 13. TDD, исполнение и воспроизводимость

Сначала написать regression/security/contract tests и зафиксировать RED,
затем минимальную реализацию и GREEN. Не включать реальные locked labels в
test snapshots, logs или source maps.

Frozen Run A и process-separated Run B до unseal используют один
implementation commit/config/inputs, но разные executor ID, PID, nonce и
output root; оба prediction sets отдельно запечатываются. Comparator после
unseal проверяет их по preregistered exact/tolerance rule. Decision-affecting
output не зависит от wall clock, порядка файлов, locale или случайного
tie-break. Сохранить raw observations, preregistration, environment manifest,
source/label/rubric/model/prompt/tool/threshold hashes, seeds, costs и failure
logs.

Read-only verifier по умолчанию не меняет tracked evidence. Write mode для
канонической публикации явный; temporary runs пишут только в отдельный output
root. Отличать tested implementation commit от последующего evidence-
container commit без самоссылочного hash.

Core unit tests не требуют network/LLM. Новая heavyweight dependency требует
ADR; предпочтительны Node stdlib и уже зафиксированные dependencies.

## 14. Acceptance gates

До закрытия должны наблюдаемо выполняться все применимые критерии:

1. Dependency record доказывает канонизацию S2-005 в `origin/main` и точные
   upstream digests.
2. Contracts, generated types, serialization и runtime fixtures совпадают.
3. Upstream artifacts читаются immutable; versioning/invalidation работает.
4. Corpus/splits/labels/rubric/preregistration frozen и manifest-complete.
5. Реальные independence/blinding claims подтверждены identities/audit;
   отсутствующие входы честно дают `NOT_MEASURED`/`NEEDS_INPUT`.
6. Все метрики имеют raw counts, denominators, missingness, slices и
   uncertainty; thresholds применены только после freeze.
7. Run A/B и comparator совпадают и fail-closed на неполноте.
8. Probes A–S зелёные, hard counters равны нулю.
9. PostgreSQL store и двухпроцессный replay обязательны, атомарны и
   idempotent; crash/reconciliation cases зелёные.
10. Полный regression suite, typecheck, lint, build, audit, manifest и clean
    checkout зелёные; verifier не изменяет tracked evidence при read-only run.
11. Evaluation report отделяет measured, not measured, not run, blocked и
    deferred; production readiness нигде не заявлена.
12. Human review package содержит exact artifact/calibration digests,
    disagreements, alternatives, uncertainty, limitations и requested scope.

Preflight (вне acceptance suite): если локальная рабочая копия отстаёт от
origin и объекты `d7ce192…`/`36fd8f8…` недоступны локально, выполняется
отдельный `git fetch origin`; сам fetch не входит в offline acceptance
suite.

Команды приёмки (добавить scripts в `package.json`):

```powershell
npm ci
npm run verify:s2-006-dependencies
npm run verifier:types
npm run test:verifier
npm run test:s2-006-calibration
npm run test:s2-006-security-probes
npm run verify:s2-006
npm run verify:s2-006-db-replay
npm test
npm run typecheck
npm run lint
npm run build
npm audit --omit=dev
npm audit
npm run verify:clean-checkout
npm run manifest:check
git diff --check d7ce192cec82e7cd66e1dce29faebcfbcfe9bd6f..HEAD
git status --short
```

Каждая неисполненная команда указывается как `NOT_RUN_*`. Отсутствие
PostgreSQL/provider/human inputs не разрешает выдавать соответствующий gate
за PASS.

## 15. Deliverables

- versioned semantic-verifier/annotation/adjudication/calibration schemas и
  derived types;
- provider-neutral read-only verifier API и immutable persistence;
- independently authored corpus/labels или явно заблокированный import
  package с `NEEDS_INPUT`, без фабрикации независимости;
- frozen rubric, preregistration, splits, thresholds и manifests;
- deterministic baseline, candidate adapter boundary и честный comparator;
- Run A/B, sealed raw predictions, disagreement/adjudication, calibration
  metrics, DB replay, probes A–S, clean-checkout и environment evidence;
- invalidation/drift behavior и human review package;
- `docs/decisions/S2-006-EVALUATION-REPORT.md` с полной матрицей
  measured/unknown/deferred и handoff для downstream R&D/pilot stages.

## 16. Stop conditions и допустимый verdict

Применять строгий outcome precedence; недоступный обязательный gate нельзя
объявить неприменимым:

- `BLOCKED_SAFETY` / `BLOCKED_AUTHORITY`: любой safety/authority hard fail;
- `BLOCKED_DEPENDENCY`: S2-005/manifest/evidence/commit binding не совпадает;
- `NEEDS_INPUT`: нет независимых annotators/adjudicator, legal corpus grant,
  числовых thresholds или PostgreSQL. Provider stratum по умолчанию
  необязателен для первого calibration scope: отсутствие grant, permission
  или budget даёт `NOT_RUN_PROVIDER`, а не `NEEDS_INPUT`, и не блокирует
  тикет; `NEEDS_INPUT` по provider возможен только если владелец заранее
  объявил provider stratum обязательным в preregistration. Независимые
  обязательные strata продолжают;
- `HUMAN_REVIEW`: статистически inconclusive/disputed result или no winner;
- `REVISE`: исправимый несafety-дефект implementation/evidence;
- `PASS_WITH_LIMITS`: все обязательные independent held-out, security,
  persistence и reproducibility gates зелёные, но остаются явно названные
  external-validity/model/population/production ограничения.

Безусловный `PASS` запрещено выводить из synthetic fixtures, одного корпуса,
одной модели, одного языка/домена или отсутствия observed incidents. S2-006
не является production authorization и не разрешает автоматически начинать
зависимый production/pilot ticket.

## 17. Итоговый отчёт агента

Отчёт обязан содержать:

1. dependency proof с полными commit и SHA-256 bindings;
2. scope и independence matrix по каждой роли/model/data/process оси;
3. corpus/split/rubric/threshold/preregistration digests;
4. label agreement, disagreements и adjudication provenance;
5. Run A/B и comparator с raw counts, coverage, uncertainty и hard counters;
6. результаты probes A–S и PostgreSQL replay;
7. clean-checkout и точные exit codes всех acceptance commands;
8. итоговый `PASS_WITH_LIMITS | REVISE | HUMAN_REVIEW | BLOCKED_SAFETY |
   BLOCKED_AUTHORITY | BLOCKED_DEPENDENCY | NEEDS_INPUT`;
9. честные ограничения и точный downstream handoff.

Ни один semantic, independence, calibration или readiness claim не считается
выполненным без наблюдаемого артефакта. Push, PR и merge — только по отдельной
команде пользователя.
