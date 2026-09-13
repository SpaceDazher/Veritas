# S2-003 — Connector Contract

Status: contract-first, read-only ingestion subsystem for Veritas.
Ticket: `tasks/S2-003_SOURCE_INGESTION.md` · Verdict: `PASS_WITH_LIMITS`.

## 1. Boundary and ownership

The provider ingestion boundary belongs to Veritas. Its consumers are the
S2-004 claim/provenance graph, S2-005 cross-domain synthesis, the S2-006
calibrated verifier, human reviewers via Web/API/CLI, and personal/platform
agents acting strictly through S2-002 rights. The only source of truth for
every payload boundary is a versioned JSON Schema in `contracts/`
(draft 2020-12, `additionalProperties: false`, closed enums, explicit
nullability, `contractVersion: "1.0.0"`):

| Contract | SHA-256 (schema bytes) |
| --- | --- |
| `source-descriptor.schema.json` | `74bf15ee4c9ff2999779edf596272713456004251dc599ede1ca446b24d8fc2d` |
| `connector-contract.schema.json` | `8535b35b6e4c708f198551285a0acc94efccd6bb9702d6e26ff575523981fd17` |
| `fetch-request.schema.json` | `cf23ed91d18857e18fc33dbcb71aff799f1700b0073badc6a3b8db798903227d` |
| `source-snapshot.schema.json` | `9f66fc4811f75b44acd93c76ba6629dd189a12a7c875025f5dad970032032166` |
| `content-segment.schema.json` | `b6f8aac5e538315147c8ea1c0e265c75a0995d30accc4de46b7c714e85e2706e` |
| `ingestion-run.schema.json` | `37704c2f362361b9f053debb16a1fc46287377d106e0ebdd02d567f3f58e1bae` |
| `source-lineage.schema.json` | `f85e099dde96885bdaa97e07ae3adc835003ca7cf82326777eb8b8741b64e3f5` |
| `source-proposal.schema.json` | `01daf6a020a2bd6c28183c64a2df378f1199819f23f4286c6f5e28ccac34131c` |
| `connector-error.schema.json` | `d10cafb7f940b3b301484e3d2df9b844b875c386a4d92587f8f7180f96a19de2` |

TypeScript types are **generated** from these schemas
(`scripts/generate-ingestion-types.mjs` → `src/lib/ingestion/contracts.d.ts`);
`tests/ingestion/contracts.types.test.mjs` fails closed on drift. Hand-written
copies of contract formats are forbidden.

## 2. Untrusted content rule

Text documents, frontmatter, HTML, PDF annotations, transcripts, README text,
issues, comments and model output are **untrusted data**. They can never:
change policy, ACL, role, grant or sandbox profile; initiate a tool call;
request a secret; add a connector; authorize publication or export; or mark
their own result as verified. Enforced structurally: the pipeline anchors
canonical identity and ACL on the registered descriptor (`src/lib/ingestion/
pipeline.mjs`), never on content; embedded-instruction findings are stored as
**data-only metadata** on the segment (`embedded_instruction_classification`)
and are covered by probes F and K.

## 3. Uniform adapter interface

Every adapter implements the same observable operations
(`src/lib/ingestion/connectors/*`):

```text
discoverCapabilities()   auth mode, limits, terminal states
resolveDescriptor(request)  provider-canonical descriptor identity
fetchVersion(request)    bytes + mime type, or a normalized connector error
extract(snapshot, fetched)  segments with coordinates + extraction quality
reconcile(operationId)   post-crash outcome probe
observeDeletion(...)     deletion semantics for the provider
```

Normalized failure enum (closed, from `connector-error.schema.json`):
`BLOCKED_CONNECTOR | ACCESS_DENIED | NOT_FOUND | TOMBSTONED | RATE_LIMITED |
TIMEOUT | MALFORMED_CONTENT | UNSUPPORTED_FORMAT | LICENSE_UNKNOWN |
RETENTION_BLOCKED | QUARANTINED | UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED`.
Any outcome outside the enum is `UNKNOWN_OUTCOME_RECONCILIATION_REQUIRED`,
never a silent success. An empty successful import is structurally impossible
(`pipeline.mjs` rejects byte-less fetches).

## 4. Connector classes and S2-003 executability

| Class (`source_kind`) | Connector | S2-003 status |
| --- | --- | --- |
| `markdown_obsidian` | `conn-markdown-obsidian` | **Executable** (read-only vault; byte-identity proven by test) |
| `manual_export` | `conn-manual-export` | **Executable** (offline fixtures / prepared exports) |
| `web_url` | `conn-web-url` | **Executable** (public HTTP snapshots, content-type validated, no cookies/credentials) |
| `github` | `conn-github` | Canonical identity + fixture normalization implemented and tested; live fetch is honestly `BLOCKED_CONNECTOR` without a verified grant |
| `telegram` | `conn-telegram` | Same as github |
| `youtube` | `conn-youtube` | Same as github |
| `arxiv_huggingface` | `conn-arxiv-huggingface` | Same as github |

Naming note: the ticket's literal class string `markdown_obisidian` contains a
typo; contract v1.0.0 normalizes it to `markdown_obsidian`. The semantics are
unchanged (read-only vault root, Markdown plus frontmatter as untrusted data).

## 5. Canonical identity

Canonical locators are built only by `src/lib/ingestion/canonical.mjs`
(`CANONICALIZATION_VERSION = "1.0.0"`), per provider:

- `web_url`: lowercase host, default ports removed, fragment removed, tracking
  parameters (`utm_*`, `fbclid`, `gclid`, …) stripped, remaining query sorted,
  trailing slash removed.
- `github`: lowercased `owner/repo` + commit SHA + blob SHA / issue / pull /
  comment identity.
- `telegram`: canonical `chat/{id}/message/{id}`.
- `youtube`: canonical video id (11 chars) + transcript version.
- `arxiv_huggingface`: arXiv id **with revision** (a bare id is rejected as
  unresolved) or lowercased HF `models|datasets|spaces/{id}@{revision}`.
- `markdown_obsidian`: vault-relative path (the absolute host path never leaks
  into identity; traversal is rejected).
- `manual_export`: namespaced export id.
- `pdf`: URL-based identity when a URL exists, otherwise `sha256/{digest}`.

At ingestion time the pipeline anchors identity on the **registered
descriptor** (`request.identity?.canonical_locator ?? descriptor.canonical_locator`),
so content can never influence identity. Redirects, tracking queries, URL
aliases and display titles cannot silently create or merge entities
(probe H, `tests/ingestion/canonical-identity.test.mjs`).

## 6. Temporal model

Four separate timestamps (see `docs/ingestion/S2-003-PROVENANCE-AND-RETENTION.md`
for the decision rules): `published_at` (source claim), `event_time` (source
claim), `observed_at` (first host observation), `fetched_at` (fetch telemetry).
Only the two host timestamps are telemetry; they never enter digests,
identity, dedup verdicts or evaluator output. The decision clock is injected
(`createDecisionClock`); the wall clock is not a decision input (probe I).

## 7. Pipeline and terminals

```text
QUEUED → AUTHORIZED → FETCHING → SNAPSHOT_STAGED → EXTRACTING
       → VALIDATING → COMMITTED
```

Terminals (exactly one per operation):
`COMMITTED | BLOCKED_CONNECTOR | ACCESS_DENIED | TOMBSTONED | QUARANTINED |
FAILED | CANCELLED | RECONCILIATION_REQUIRED`. Authorization is server-side
from the descriptor only (lifecycle, license, retention, grant requirement,
budget). Every transition emits an audit event in the same critical section;
the PostgreSQL mirror lives in `migrations/0002_source_ingestion.sql`.
