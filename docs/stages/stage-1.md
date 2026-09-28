# Stage 1: исследовательские тикеты AgentOS

## Назначение

Stage 1 - это завершённый исследовательский пакет AgentOS, а не набор production-модулей Veritas. Он устанавливает evidence-gated baseline для источников, capacity, formal safety, topology, backend, isolation, revocation, protocol boundaries, knowledge, HCI, privacy и синтеза решений.

Canonical source:

- repository: [SpaceDazher/AgentOS](https://github.com/SpaceDazher/AgentOS)
- inspected commit: [`a7940e113492c83a29533d1e93f2724c36a9bbc1`](https://github.com/SpaceDazher/AgentOS/tree/a7940e113492c83a29533d1e93f2724c36a9bbc1)
- ticket plan: [`docs/RESEARCH_STAGE_1_TICKETS.md`](https://github.com/SpaceDazher/AgentOS/blob/a7940e113492c83a29533d1e93f2724c36a9bbc1/docs/RESEARCH_STAGE_1_TICKETS.md)
- ticket root: [`research/tickets/stage-1`](https://github.com/SpaceDazher/AgentOS/tree/a7940e113492c83a29533d1e93f2724c36a9bbc1/research/tickets/stage-1)

Официальный portfolio verdict: `PASS_WITH_LIMITS`. Активный portfolio содержит 20 тикетов и 4 parked items. `SLOQUAL-001` оформлен как отдельное quality extension, расширяющее S1-002.

## Перенос в Veritas

Тикеты перенесены как migration-index issues `#20...#40`. В каждом body сохранены canonical ID, wave, priority, owner role, verdict, dependencies, краткий результат, limits и pinned AgentOS source.

2026-09-26: право на запись в issues подтверждено (PATCH по #20 вернул 200), и issues #20-#40 закрыты как research closure: в каждом добавлен комментарий с canonical record, verdict, pinned commit `a7940e1` и границей полномочий. Закрытие означает research evaluation, а не `PASS`, production readiness или разрешение rollout; `PASS_WITH_LIMITS` и parked items PARK-01..PARK-04 остаются частью решения. Issue #40 (SLOQUAL-001) закрыт по решению владельца вместе с остальными: его human threshold countersignature остаётся в статусе `NEEDS_INPUT` и отслеживается не состоянием issue, а parked item PARK-03 (production SLO claim).

Repository labels `stage:1`, `area:research`, `source:agentos`, `status:pass` и `status:pass-with-limits` созданы и прикреплены к issues #20-#40 (`status:pass` — у #22 / S1-003, у остальных `status:pass-with-limits`).

## Активные тикеты

| ID | Veritas issue | Wave | Owner | Verdict | Решение |
| --- | --- | --- | --- | --- | --- |
| S1-001 | [#20](https://github.com/SpaceDazher/Veritas/issues/20) | W0 | sources | `PASS_WITH_LIMITS` | Bounded promotion policy для 12 decision-critical записей. |
| S1-002 | [#21](https://github.com/SpaceDazher/Veritas/issues/21) | W0 | capacity | `PASS_WITH_LIMITS` | Local control-plane baseline; production SLO не заявлен. |
| S1-003 | [#22](https://github.com/SpaceDazher/Veritas/issues/22) | W0 | formal | `PASS` | SHACL lifecycle validation, 26/26 profile agreement. |
| S1-004 | [#23](https://github.com/SpaceDazher/Veritas/issues/23) | W1 | formal | `PASS_WITH_LIMITS` | Bounded Alloy/TLA/simulation baseline для INV1-INV6 и recovery. |
| S1-005 | [#24](https://github.com/SpaceDazher/Veritas/issues/24) | W1 | architecture | `PASS_WITH_LIMITS` | Modular monolith выбран для MVP envelope. |
| S1-006 | [#25](https://github.com/SpaceDazher/Veritas/issues/25) | W2 | architecture | `PASS_WITH_LIMITS` | In-process scheduler выбран; durable boundary остаётся migration target. |
| S1-007 | [#26](https://github.com/SpaceDazher/Veritas/issues/26) | W2 | security | `PASS_WITH_LIMITS` | Per-scope index projections выбраны вместо shared RLS index. |
| S1-008 | [#27](https://github.com/SpaceDazher/Veritas/issues/27) | W2 | security | `PASS_WITH_LIMITS` | Local revoke-to-deny измерен ниже 5 s; production SLO не заявлен. |
| S1-009 | [#28](https://github.com/SpaceDazher/Veritas/issues/28) | W2 | architecture | `PASS_WITH_LIMITS` | Provider-neutral MCP/A2A adapter boundary и capability gaps. |
| S1-010 | [#29](https://github.com/SpaceDazher/Veritas/issues/29) | W3 | security | `PASS_WITH_LIMITS` | Layered tool-poisoning evaluation, quarantine и human review. |
| S1-011 | [#30](https://github.com/SpaceDazher/Veritas/issues/30) | W1 | knowledge | `PASS_WITH_LIMITS` | Minimal promote/challenge gate выбран вместо полной argumentation/TMS. |
| S1-012 | [#31](https://github.com/SpaceDazher/Veritas/issues/31) | W2 | knowledge | `PASS_WITH_LIMITS` | Document granularity; reputation может ранжировать, но не authorize. |
| S1-013 | [#32](https://github.com/SpaceDazher/Veritas/issues/32) | W3 | hci | `PASS_WITH_LIMITS` | Solo conformance package; population pilot отменён. |
| S1-014 | [#33](https://github.com/SpaceDazher/Veritas/issues/33) | W4 | hci | `PASS_WITH_LIMITS` | Provisional `CARD_WITH_GRAPH_DRILLDOWN`; human study не проводилась. |
| S1-015 | [#34](https://github.com/SpaceDazher/Veritas/issues/34) | W4 | hci | `PASS_WITH_LIMITS` | `CANONICAL_ID_ONLY`; petname не используется как authority identity. |
| S1-016 | [#35](https://github.com/SpaceDazher/Veritas/issues/35) | W3 | formal | `PASS_WITH_LIMITS` | Lineage evidence complete; design decision остаётся `INCONCLUSIVE`. |
| S1-017 | [#36](https://github.com/SpaceDazher/Veritas/issues/36) | W4 | formal | `PASS_WITH_LIMITS` | STIT/ATL остаются offline, non-authoritative analytics. |
| S1-018 | [#37](https://github.com/SpaceDazher/Veritas/issues/37) | W4 | privacy | `PASS_WITH_LIMITS` | `CLIENT_SIDE_INDEX_ONLY`; attested indexer только research ceiling. |
| S1-019 | [#38](https://github.com/SpaceDazher/Veritas/issues/38) | W5 | synthesis | `PASS_WITH_LIMITS` | P0 architecture synthesis: шесть EP rows `ADOPT_WITH_LIMITS`. |
| S1-020 | [#39](https://github.com/SpaceDazher/Veritas/issues/39) | W6 | audit | `PASS_WITH_LIMITS` | Independent Stage 1 research closure. |

## Quality extension

| ID | Veritas issue | Verdict | Назначение |
| --- | --- | --- | --- |
| SLOQUAL-001 | [#40](https://github.com/SpaceDazher/Veritas/issues/40) (closed) | `PASS_WITH_LIMITS` | Production-like SLO qualification, расширяющая S1-002 и использующая revocation gate S1-008. |

SLOQUAL-001 выполнил два authoritative runs по 17 scenarios × 5 seeds и 105 revocation trials. Hard failures и mandatory security violations равны нулю, но warm p95 confidence interval пересекает 20 ms, сохраняются pilot-scale limits, pending human SLO ownership и same-host independent rerun. Полный `PASS` не заявлен.

В Veritas этот метод перенесён как локальный qualification-пакет control plane: frozen SLO contract ([contracts/sloqual-001-slo-contract.json](../contracts/sloqual-001-slo-contract.json)), версионированный scenario manifest, open-loop измерение настоящего `policy-engine.mjs`, fail-closed comparator и gate `npm run verify:sloqual-001`. Veritas-пакет повторяет структуру доказательства (17 scenarios × 5 seeds, 105 revocation trials, два независимых запуска), но измеряет другой код: числа AgentOS к Veritas не переносятся, а его verdict не наследуется. Локальный verdict — `PASS_WITH_LIMITS`: [SLOQUAL-001-EVALUATION-REPORT.md](../decisions/SLOQUAL-001-EVALUATION-REPORT.md).

## Dependency DAG

```text
W0  S1-001, S1-002, S1-003
W1  S1-004 (002,003), S1-005 (002), S1-011 (001,003)
W2  S1-006 (002,005), S1-007 (003,005), S1-008 (002,004),
    S1-009 (001,005), S1-012 (001,003,011)
W3  S1-010 (001,009), S1-013 (011,012), S1-016 (003,007)
W4  S1-014 (011,013), S1-015 (013), S1-017 (004,016),
    S1-018 (007,008,009)
W5  S1-019 (004...018)
W6  S1-020 (001...019)
```

S1-020 является единственным closure sink активного portfolio. SLOQUAL-001 расширяет S1-002 и использует S1-008 security gate, но не входит в исходный active count 20.

## Итоговые архитектурные решения

S1-019 зафиксировал research-scoped baseline:

- один modular monolith с явными внутренними policy/execution/governance boundaries;
- in-process scheduler как MVP backend при сохранении durable single-writer migration contract;
- per-scope index projections и deny-equivalent retrieval boundary;
- provider-neutral AgentOS adapter, который не может выдать grant из protocol payload;
- минимальный knowledge gate с challenge, retraction и append-only history;
- offline responsibility analytics, которые никогда не изменяют Gateway decision;
- client-side indexing как доказанный выбор для Profile C; MLS/TEE indexer остаётся bounded research direction;
- evidence, prototype и formal verdict не преобразуются в production authorization.

## Что не доказано

- Все внешние аудиторы, процессы и replay runners находятся на одном host.
- S1-001 не проверил все 176 исторических `u` sources.
- S1-002 является коротким local benchmark; SLOQUAL-001 сам остаётся `PASS_WITH_LIMITS`.
- Veritas-реализация SLOQUAL-001 измеряет только in-process decision path: HTTP, PostgreSQL, sandbox и provider path не измерены.
- S1-004 формальные модели имеют bounded state space и моделируют design contract.
- S1-013/014/015 не имеют population human study.
- S1-018 не имеет hardware TEE evidence.
- S1-020 не выдаёт product Goal acceptance, legal approval или rollout authority.
- Ни один Stage 1 verdict не разрешает private import, spending, credential acquisition или production deployment.

## Parked items

| ID | Тема | Re-entry condition |
| --- | --- | --- |
| PARK-01 | Deployment-specific legal/high-risk classification | Named deployment, jurisdiction, role и qualified review. |
| PARK-02 | Mass verification всех 176 `u` sources | Отдельное решение о budget, access, verifier method и acceptance corpus. |
| PARK-03 | Production SLO claim | Representative production-like profile, CI/ops ownership и explicit SLO review. |
| PARK-04 | Production rollout Profile C | Новый threat/privacy/attestation/operations review и отдельное rollout decision. |

## Связь с Veritas Stage 2

Stage 1 задаёт research dependencies для S2, но не выполнит их автоматически. В частности:

- S1-001/S1-003/S1-011/S1-012 ограничивают source и knowledge promotion semantics;
- S1-004/S1-005/S1-006/S1-007/S1-008 задают safety, topology, backend, isolation и revocation baseline;
- S1-009/S1-010 ограничивают protocol и untrusted-content boundary;
- S1-013...S1-018 сохраняют human, ontology, privacy и deployment limits;
- S1-019/S1-020 требуют сохранять явные `PASS_WITH_LIMITS`, parked items и отсутствие production authority.

Текущий S2 backlog и статусы: [Veritas Issues](https://github.com/SpaceDazher/Veritas/issues).
