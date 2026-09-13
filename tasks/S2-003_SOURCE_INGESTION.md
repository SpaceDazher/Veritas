# S2-003 — Сбор источников и версионные снимки

## Статус и назначение

- Статус на старте: `READY`.
- Ветка: `codex/s2-003-source-ingestion`.
- База: `origin/main` на merge-коммите S2-002
  `4b4456a3acbe78371e2afcc75d81da59d2765b53`.
- Зависимости: S2-002 и S1-001.
- Результат: contract-first, read-only ingestion subsystem для Veritas,
  превращающий разрешённый внешний материал в неизменяемые, версионные и
  проверяемые `SourceSnapshot`/`ContentSegment` без потери происхождения.
- Это не claim graph, не синтез знания и не финальный verifier. Эти слои
  принадлежат S2-004, S2-005 и S2-006.

Система должна принимать выбранные источники из Obsidian/Markdown,
URL/HTML/PDF, GitHub, Telegram, YouTube, arXiv и Hugging Face через единый
connector contract. В первой реализации разрешены локальные файлы, публичные
источники и заранее подготовленные ручные экспорты. Live-доступ к приватному
источнику запрещён без отдельного проверяемого grant.

## 1. Проверка зависимостей до изменений

До реализации создать `scripts/verify-s2-003-dependencies.mjs` и tracked record
`evidence/s2-003-dependency-binding.json`.

Проверка обязана fail-closed подтвердить:

1. `origin/main` содержит merge S2-002 и commit
   `f28e45b1ef044f9ab6b6c616c0380ac4f368ff5b` достижим из `main`.
2. S2-002 имеет `PASS_WITH_LIMITS`, зелёный clean-checkout и точные SHA-256
   root/frozen manifests.
3. Профиль прав, sandbox и PostgreSQL evidence S2-002 проверяются из байтов
   Git, а не из narrative-полей.
4. S1-001 привязан к фиксированному commit AgentOS и его tracked evidence
   проверен по SHA-256. Временный путь или ветка `main` вместо commit SHA
   недопустимы.
5. Отсутствующая зависимость, неполный digest, недостижимый commit или
   несовпадение payload должны дать `BLOCKED_DEPENDENCY`, а не warning.

Если dependency gate не проходит, остановиться до изменения контрактов.

## 2. Границы полномочий и владельцы контрактов

Provider ingestion boundary принадлежит Veritas. Его потребители:

- S2-004 claim/provenance graph;
- S2-005 cross-domain synthesis;
- S2-006 calibrated verifier;
- human reviewer через Web/API/CLI;
- персональные и платформенные агенты, действующие через права S2-002.

Единственный источник истины для каждой payload-границы — versioned JSON
Schema в `contracts/`. TypeScript-типы должны генерироваться или выводиться из
тех же схем; независимые ручные копии формата запрещены.

Connector не получает права от содержимого источника. Текст документа,
frontmatter, HTML, PDF annotations, transcript, README, issue, comment и model
output всегда являются untrusted data и не могут:

- менять policy, ACL, роль, grant или sandbox profile;
- инициировать tool call;
- запрашивать секрет;
- добавлять новый connector;
- разрешать публикацию или export;
- помечать собственный результат как проверенный.

## 3. Обязательные канонические контракты

Создать версии `1.0.0` минимум для следующих сущностей:

1. `source-descriptor.schema.json`
   - `source_id`, `connector_id`, `source_kind`;
   - canonical locator без секрета;
   - display locator отдельно;
   - owner/author/publisher;
   - workspace/tenant/ACL;
   - license, retention и deletion policy;
   - public/private/project classification;
   - enabled/blocked/tombstoned lifecycle.
2. `connector-contract.schema.json`
   - connector/version;
   - поддерживаемые source kinds;
   - auth mode и required grant scope;
   - read-only operations;
   - timeout, retry, rate-limit и reconciliation semantics;
   - capability и sandbox binding;
   - нормализованные terminal/error states.
3. `fetch-request.schema.json`
   - точный source/version selector;
   - actor, workspace, grant/lease и idempotency key;
   - budget/time limits;
   - никакого raw credential.
4. `source-snapshot.schema.json`
   - immutable snapshot/version id;
   - exact raw-byte SHA-256 и normalized-content SHA-256;
   - canonical URL/message/repository/object id;
   - author/publisher;
   - `published_at`, `event_time`, `observed_at`, `fetched_at` как разные поля;
   - parent/supersedes/tombstone bindings;
   - language, MIME, size, extraction status;
   - ACL/license/retention inherited from the descriptor;
   - complete fetch provenance.
5. `content-segment.schema.json`
   - stable segment id и snapshot id;
   - page/span/line/timecode coordinates;
   - exact segment digest;
   - original and normalized language;
   - extraction method/version;
   - OCR/ASR confidence и uncertainty flags;
   - embedded-instruction classification как data-only metadata.
6. `ingestion-run.schema.json`
   - run/executor/nonce/output root;
   - frozen connector, corpus и policy digests;
   - counts и все terminal outcomes;
   - raw observation references;
   - environment/commit/tree provenance.
7. `source-lineage.schema.json`
   - exact duplicate, mirror, translation, quotation, repost или derived
     relation;
   - upstream/downstream ids;
   - evidence и confidence;
   - automated relation никогда не уничтожает отдельный snapshot.
8. `source-proposal.schema.json`
   - отдельная очередь предлагаемых источников;
   - proposer, reason, expected domain, access/license uncertainty;
   - состояния `PROPOSED | REVIEW_REQUIRED | APPROVED | REJECTED`;
   - proposal не запускает import автоматически.
9. `connector-error.schema.json`
   - закрытый enum минимум:
     `BLOCKED_CONNECTOR`, `ACCESS_DENIED`, `NOT_FOUND`, `TOMBSTONED`,
     `RATE_LIMITED`, `TIMEOUT`, `MALFORMED_CONTENT`, `UNSUPPORTED_FORMAT`,
     `LICENSE_UNKNOWN`, `RETENTION_BLOCKED`, `QUARANTINED`,
     `UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED`;
   - retryability и reconciliation action;
   - безопасная redacted diagnostic detail.

Все схемы требуют `additionalProperties: false`, закрытые enums, канонические
строковые идентификаторы и явную nullability. Неизвестная версия контракта
должна отклоняться.

## 4. Connector interface

Создать единый интерфейс адаптера с операциями наподобие:

```text
discoverCapabilities()
resolveDescriptor(request)
fetchVersion(request)
extract(snapshot)
reconcile(operationId)
observeDeletion(sourceId)
```

Набор имён можно изменить, но observable semantics должны быть едины.

Обязательные классы connector contract:

- `markdown_obisidian` — выбранный read-only root, Markdown и разрешённый
  frontmatter; исходный vault никогда не изменяется;
- `web_url` — public URL/HTML и content-type validation;
- `pdf` — raw bytes плюс page-bound segments;
- `github` — repository/blob/issue/PR/comment identity с commit/object SHA;
- `telegram` — canonical chat/message id и edit/delete semantics;
- `youtube` — video id, transcript version и timecodes;
- `arxiv_huggingface` — canonical paper/model/dataset/revision identity.

Минимально исполняемые в S2-003 адаптеры:

1. локальный Markdown/Obsidian adapter;
2. prepared/manual-export adapter для offline fixtures;
3. публичный HTTP snapshot adapter без cookies и user credentials.

Остальные provider adapters могут завершаться `BLOCKED_CONNECTOR`, если их
live credential/access не выдан, но обязаны реализовать и проверить canonical
identity/fixture normalization. Пустой успешный импорт запрещён.

## 5. Canonical identity и временная модель

Не использовать wall-clock как вход решения о равенстве, версии или качестве.

- `published_at` — заявленное время публикации;
- `event_time` — время события, если источник его описывает;
- `observed_at` — когда система впервые наблюдала версию;
- `fetched_at` — операционная телеметрия получения.

`observed_at`/`fetched_at` разрешены в audit, но не могут менять content digest,
dedup verdict или результат evaluator. Deterministic replay с другим временем
обязан дать те же identity, lineage и решения.

Canonical locator строится provider-specific кодом. Redirect, tracking query,
URL alias или display title не могут молча создавать новую сущность либо
склеивать разные сущности. Canonicalization version хранится в snapshot.

## 6. Хранение и жизненный цикл

Добавить append-only PostgreSQL migrations минимум для:

- `source_descriptor`;
- `source_snapshot`;
- `content_segment`;
- `source_lineage`;
- `ingestion_run` и `ingestion_event`;
- `source_proposal`;
- migration ledger с digest drift protection.

Требования:

1. Raw snapshot и normalized segment immutable.
2. Исправление создаёт новую версию с `SUPERSEDES`.
3. Delete/retraction создаёт tombstone; предыдущий факт существования и audit
   сохраняются согласно retention policy.
4. Current pointer обновляется атомарно с ingestion event.
5. `operation_id`/idempotency key уникальны в нужном scope.
6. Unknown outcome требует reconciliation, а не blind retry.
7. После crash/restart повтор не создаёт второй snapshot или второй side
   effect.
8. ACL и tenant/workspace scope проверяются server-side на каждом чтении,
   записи, export и построении derived artifact.
9. Private bytes не попадают в public evidence, logs, URL или source proposal.

## 7. Дедупликация и lineage

Использовать ступенчатое решение:

1. exact raw-byte digest;
2. exact normalized-content digest;
3. exact canonical provider identity/version;
4. candidate near-duplicate или mirror relation.

Только первые три детерминированных совпадения могут автоматически связывать
объекты. Near-duplicate classifier создаёт candidate lineage с evidence и
confidence; он не удаляет и не объединяет snapshots без отдельного gate.

Source count для последующих аналитических метрик должен уметь схлопывать
проверенный upstream lineage, но физические документы и citations сохраняются.

## 8. Extraction quality

Для каждого сегмента хранить наблюдаемое качество:

- native text / parser / OCR / ASR / manual export;
- extractor name/version/config digest;
- confidence, missing ranges, undecodable bytes;
- page/line/span/timecode coverage;
- language detection и translation lineage;
- `COMPLETE | PARTIAL | FAILED | QUARANTINED`.

Низкая уверенность не преобразуется в уверенный текст. Malformed PDF,
недоступное видео или отсутствующий transcript завершаются явным состоянием,
а не пустой коллекцией с `PASS`.

## 9. Pipeline и terminal states

Минимальная машина состояний:

```text
QUEUED → AUTHORIZED → FETCHING → SNAPSHOT_STAGED → EXTRACTING
       → VALIDATING → COMMITTED
```

Допустимые терминалы:

```text
COMMITTED | BLOCKED_CONNECTOR | ACCESS_DENIED | TOMBSTONED |
QUARANTINED | FAILED | CANCELLED | RECONCILIATION_REQUIRED
```

Каждый run получает ровно один терминал. Transition и audit event фиксируются
атомарно. Cancellation обязана завершать весь связанный процесс/container tree.

## 10. TDD и реализация

Сначала создать тесты и получить наблюдаемый RED. Затем реализовать минимальный
код до GREEN.

Тесты должны покрыть:

- schema success и mutation rejection;
- unknown fields/version fail-closed;
- canonical identity всех connector classes;
- idempotent re-import;
- edit с тем же URL/message id создаёт новую версию;
- correction и tombstone propagation;
- exact duplicate и mirror lineage;
- near-duplicate не склеивается автоматически;
- source vault остаётся byte-identical;
- ACL/private/public export;
- license и retention blocking;
- OCR/ASR uncertainty;
- published/event/observed/fetch time separation;
- wall-clock perturbation не меняет decision output;
- crash/restart/reconciliation;
- connector timeout/rate limit/unavailable;
- Web/API/CLI decision parity;
- реальную PostgreSQL migration/transaction smoke;
- clean checkout без host-only paths или shared dependencies.

Unit tests не используют сеть и реальные секреты. Live/public integration
tests отделены, bounded и сохраняют raw evidence.

## 11. Frozen evaluation corpus

Создать versioned corpus минимум из 72 cases, равномерно включающий:

- gold imports;
- edits/corrections/deletes;
- exact duplicates;
- mirror/translation/repost lineage;
- near-miss identities;
- malformed/partial inputs;
- unavailable/rate-limited connectors;
- private/ACL/license/retention cases;
- embedded instructions;
- crash/unknown outcome/reconciliation;
- timestamps и wall-clock perturbations.

Манифест хранит SHA-256 каждого case и всех evaluator/connector contracts.
Кандидат не может менять corpus, rubric или expected outcomes. Изменение frozen
input даёт `QUARANTINED`.

## 12. Обязательные adversarial probes

Все пробы идут через production-facing ingestion path:

- **A — deleted source:** удалённый пост не остаётся active/current;
- **B — same locator edit:** новый content под тем же URL/message id создаёт
  новую immutable version;
- **C — cross-channel duplicate:** копии связываются с upstream и не считаются
  независимыми подтверждениями;
- **D — unavailable media:** video/PDF/connector failure не превращается в
  успешный пустой import;
- **E — malformed PDF/OCR:** повреждение и uncertainty видимы downstream;
- **F — embedded instructions:** источник не расширяет authority и не вызывает
  tool;
- **G — private export:** private snapshot/segment не попадает в public output;
- **H — URL alias collision:** разные provider objects не склеиваются;
- **I — clock perturbation:** другое время запуска не меняет identity/verdict;
- **J — crash replay:** повтор после unknown outcome не дублирует version/event;
- **K — forged provenance:** автор/дата/license/ACL из payload не заменяют
  host-observed metadata;
- **L — manifest substitution:** stale/corrupt connector или corpus hash
  останавливает run.

Ни одна проба не может быть `SKIPPED` в обязательном локальном профиле.

## 13. Измерения и independent replay

Выполнить Run A и Run B в отдельных процессах с разными:

- executor id;
- PID;
- nonce;
- output root;
- temporary PostgreSQL database/schema.

Оба запуска используют одинаковые frozen contracts/corpus и не могут менять
oracle. Сравнить все решения и content-derived identifiers.

Жёсткие критерии:

- все обязательные corpus cases выполнены в каждом run;
- provenance completeness = 100%;
- exact idempotency violations = 0;
- unauthorized/private exports = 0;
- instruction-driven authority expansions = 0;
- silent empty successes = 0;
- unreconciled unknown outcomes = 0;
- duplicate committed snapshots for one idempotency key = 0;
- missing/censored cases = 0;
- Run A/B decision mismatch = 0;
- content identity mismatch = 0;
- все A–L probes detected;
- comparator fail-closed на missing/NaN/unknown fields и неполный corpus.

Не заявлять precision/recall near-duplicate detection без независимого gold
set. Такие результаты маркировать `NOT_CALIBRATED` и использовать только как
advisory candidate lineage.

## 14. Обязательные артефакты

Минимальный набор:

- `tasks/S2-003_SOURCE_INGESTION.md`;
- `contracts/*` из §3;
- `src/lib/ingestion/`;
- `migrations/0002_*`;
- `tests/ingestion/`;
- `scripts/verify-s2-003-dependencies.mjs`;
- `scripts/s2-003-run.mjs`;
- `scripts/verify-s2-003.mjs`;
- `scripts/s2-003-security-probes.mjs`;
- frozen fixtures/corpus manifest;
- `docs/ingestion/S2-003-CONNECTOR-CONTRACT.md`;
- `docs/ingestion/S2-003-PROVENANCE-AND-RETENTION.md`;
- `docs/decisions/S2-003-EVALUATION-REPORT.md`;
- Run A/Run B raw observations и comparison;
- dependency, PostgreSQL, security, clean-checkout и environment evidence;
- обновлённые frozen/root/closure manifests.

Raw private source bytes не коммитить. Для private fixtures использовать только
явно синтетические canary-данные.

## 15. Definition of Done

S2-003 можно закрыть как `PASS_WITH_LIMITS`, только если одновременно:

1. dependency gate полностью PASS;
2. все канонические schemas и provider/consumer проверки GREEN;
3. минимум три адаптера из §4 исполняются в bounded профиле;
4. остальные connector classes имеют tested normalization и честный
   `BLOCKED_CONNECTOR` без credential grant;
5. PostgreSQL migrations проходят на пустой БД и повторно без drift;
6. re-import/edit/delete/tombstone/crash semantics доказаны;
7. источник Obsidian/Markdown остаётся неизменённым;
8. provenance/ACL/license/retention заполнены или ingestion блокируется;
9. все hard counters из §13 равны нулю в двух runs;
10. A–L probes обнаружены через основной путь;
11. Run A/Run B совпадают по решениям и content identity;
12. clean checkout, tests, typecheck, lint, build и оба npm audit проходят;
13. manifest/frozen hashes сверяются с Git bytes;
14. нет production, universal-dedup или calibrated-verifier claims;
15. Git tree чист, `git diff --check` проходит.

`PASS` без ограничений запрещён: live private connectors, OCR/ASR production
quality, near-duplicate calibration и external independent audit не входят в
локальный S2-003.

## 16. Команды приёмки

Агент должен создать и выполнить эквиваленты:

```powershell
npm ci
npm run verify:s2-003-dependencies
npm run test:ingestion
npm run test:s2-003-security-probes
npm run verify:s2-003
npm run verify:postgres-smoke
npm run typecheck
npm run lint
npm run build
npm audit --omit=dev --json
npm audit --json
npm run verify:clean-checkout
npm run manifest:check
git diff --check
git status --short
```

Green означает exit code `0`. Environmental failure необходимо исправить и
перезапустить; narrative «не относится к изменениям» не считается проверкой.

## 17. Stop conditions

Немедленно остановить соответствующую ветвь и вернуть `NEEDS_INPUT` или
`BLOCKED_*`, если:

- нет права читать, сохранять или экспортировать источник;
- private content должен попасть в Git/public evidence;
- license/retention/attribution невозможно определить;
- требуется cookie, token, paid API или persistent schedule без отдельного
  одобрения владельца;
- connector предлагает ослабить S2-002 policy/sandbox;
- невозможно сохранить raw content digest или точный source span;
- dependency/evidence hash расходится;
- unknown side effect нельзя reconcile;
- исходный Obsidian vault пришлось бы изменить;
- acceptance требует автоматически считать мнение или extracted text
  установленным фактом.

Не запрашивать и не создавать credentials. Не выполнять push, PR или merge без
явного указания владельца.

## 18. Итоговый отчёт агента

Отчёт должен содержать:

1. dependency proof с полными commit/digest bindings;
2. перечень реально исполняемых и заблокированных connectors;
3. версии и SHA-256 всех contracts/corpus/evaluators;
4. матрицу cases по типам источников и негативным классам;
5. результаты Run A/Run B и hard counters;
6. результаты probes A–L;
7. PostgreSQL migration/replay evidence;
8. clean-checkout и точные exit codes;
9. итоговый `PASS_WITH_LIMITS | REVISE | BLOCKED`;
10. честные ограничения и входы для S2-004.

Никакой критерий не объявляется выполненным без наблюдаемого артефакта.
