-- S2-007 Agent Board canonical store (separate namespace, separate from the
-- synthetic public demo).
--
-- HARD BOUNDARY: migrations 0001-0007 created `veritas_demo_*`, ingestion,
-- claim-graph and verifier tables. NONE of them is a production board table and
-- none of them is a real task. This migration creates a disjoint
-- `agentboard_*` namespace. Migrating demo or planning fixtures into the live
-- board is forbidden by default: there is no data-copy step, no backfill and no
-- view over the demo tables.
--
-- Canonical guarantees implemented here:
--   * one task row is the single source of truth; its `revision` is monotonic
--     and every write is a compare-and-swap on the expected revision;
--   * `agentboard_operation` is a persistent idempotency ledger keyed by the
--     SHA-256 of the canonical-json-v1 command arguments — identical arguments
--     replay the prior result, different arguments are a conflict;
--   * `agentboard_transition`, `agentboard_audit` and `agentboard_outbox` are
--     append-only and are written in the SAME transaction as the task state
--     change, or nothing is written at all;
--   * exactly ONE active lease per task, enforced by a partial unique index,
--     with a globally monotonic fencing token from a sequence;
--   * budget scopes (task/campaign/day) are serialized by row locks on
--     `agentboard_budget_spend`, so parallel settles cannot both pass;
--   * outbox rows carry a dispatch state machine with a recovery-safe
--     semantic: PENDING -> SENT -> ACKED / FAILED / RECONCILIATION_REQUIRED,
--     where RECONCILIATION_REQUIRED is never a blind retry.
--
-- No payload column is ever UPDATEd in place. A correction publishes a new
-- record.

CREATE SEQUENCE IF NOT EXISTS agentboard_fencing_token_seq START 1;
CREATE SEQUENCE IF NOT EXISTS agentboard_sequence_seq START 1;

-- ============================================================================
-- CANONICAL TASK
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_task (
    task_id                VARCHAR(64) PRIMARY KEY,
    workspace_id           VARCHAR(64) NOT NULL,
    -- Canonical revision, monotonic per task. Reads report it; writes CAS on it.
    revision               INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    state                  VARCHAR(16) NOT NULL CHECK (state IN (
        'BACKLOG', 'READY', 'CLAIMED', 'RUNNING', 'BLOCKED',
        'IN_REVIEW', 'DONE', 'FAILED', 'CANCELLED'
    )),
    priority               VARCHAR(8) NOT NULL CHECK (priority IN ('HIGH', 'MEDIUM', 'LOW')),
    title                  VARCHAR(160) NOT NULL,
    goal                   VARCHAR(2000) NOT NULL,
    description            VARCHAR(4000) NOT NULL,
    dependencies           JSONB NOT NULL DEFAULT '[]'::jsonb,
    required_capabilities  JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_tools          JSONB NOT NULL DEFAULT '[]'::jsonb,
    workspace_ref          JSONB NOT NULL,
    time_limits            JSONB NOT NULL,
    cost_limits            JSONB NOT NULL,
    brief_digest           CHAR(64) NOT NULL CHECK (brief_digest ~ '^[0-9a-f]{64}$'),
    policy_digest          CHAR(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    manifest_digest        CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    -- True only after a validated immutable TaskBrief; a frozen brief with
    -- execution_authorized=false still does NOT authorize any run.
    brief_validated        BOOLEAN NOT NULL DEFAULT FALSE,
    assigned_adapter_id    VARCHAR(64),
    active_lease_id        VARCHAR(64),
    fencing_token          BIGINT,
    attempts               INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    artifacts              JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_refs          JSONB NOT NULL DEFAULT '[]'::jsonb,
    block_reason           VARCHAR(500),
    history_digest         CHAR(64) NOT NULL CHECK (history_digest ~ '^[0-9a-f]{64}$'),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A task may not name itself as a dependency.
    CONSTRAINT agentboard_task_no_self_dependency
        CHECK (NOT (dependencies @> to_jsonb(ARRAY[task_id])))
);

CREATE INDEX IF NOT EXISTS idx_agentboard_task_state
    ON agentboard_task (workspace_id, state, priority, task_id);
CREATE INDEX IF NOT EXISTS idx_agentboard_task_lease
    ON agentboard_task (active_lease_id) WHERE active_lease_id IS NOT NULL;

-- ============================================================================
-- ACL — enforced before any payload is returned, in the same transaction that
-- writes the row it protects.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_acl (
    task_id               VARCHAR(64) PRIMARY KEY REFERENCES agentboard_task(task_id) ON DELETE RESTRICT,
    workspace_id          VARCHAR(64) NOT NULL,
    visibility            VARCHAR(16) NOT NULL CHECK (visibility IN ('personal', 'project', 'shared')),
    allowed_principal_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agentboard_acl_workspace
    ON agentboard_acl (workspace_id, visibility);

-- ============================================================================
-- LEASES — one active lease per task, monotonic fence, DB time only.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_lease (
    lease_id         VARCHAR(64) PRIMARY KEY,
    task_id          VARCHAR(64) NOT NULL REFERENCES agentboard_task(task_id) ON DELETE RESTRICT,
    workspace_id     VARCHAR(64) NOT NULL,
    adapter_id       VARCHAR(64) NOT NULL,
    principal_id     VARCHAR(64) NOT NULL,
    fencing_token    BIGINT NOT NULL CHECK (fencing_token > 0),
    -- ACTIVE | RELEASED | EXPIRED | REVOKED. Only ACTIVE counts as the right
    -- to act; revoking precedes reassignment so a late callback can never win.
    lease_state      VARCHAR(16) NOT NULL CHECK (lease_state IN ('ACTIVE', 'RELEASED', 'EXPIRED', 'REVOKED')),
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    released_at      TIMESTAMPTZ,
    -- Reason the previous right was withdrawn, for audit.
    revoked_reason   VARCHAR(500),
    CONSTRAINT agentboard_lease_expiry_after_issue CHECK (expires_at > issued_at)
);

-- The database-level guarantee that two processes cannot both hold the lease.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agentboard_lease_single_active
    ON agentboard_lease (task_id) WHERE lease_state = 'ACTIVE';
CREATE UNIQUE INDEX IF NOT EXISTS idx_agentboard_lease_fence_unique
    ON agentboard_lease (fencing_token);
CREATE INDEX IF NOT EXISTS idx_agentboard_lease_adapter
    ON agentboard_lease (adapter_id, lease_state);

-- ============================================================================
-- ADAPTER REGISTRATION — operator-registered capabilities, not permissions.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_adapter (
    adapter_id             VARCHAR(64) PRIMARY KEY,
    workspace_id           VARCHAR(64) NOT NULL,
    provider               VARCHAR(32) NOT NULL CHECK (provider IN (
        'codex', 'pi', 'claude_code', 'opencode', 'hermes', 'generic_cli', 'test'
    )),
    display_name           VARCHAR(120) NOT NULL,
    adapter_kind           VARCHAR(16) NOT NULL CHECK (adapter_kind IN ('real', 'wrapper', 'test', 'unavailable')),
    health                 VARCHAR(16) NOT NULL CHECK (health IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
    principal_id           VARCHAR(64) NOT NULL,
    declared_capabilities  JSONB NOT NULL DEFAULT '[]'::jsonb,
    declared_tools         JSONB NOT NULL DEFAULT '[]'::jsonb,
    sandbox_profile_id     VARCHAR(64) NOT NULL,
    max_concurrency        INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrency = 1),
    provenance_status      VARCHAR(40) NOT NULL CHECK (provenance_status IN (
        'NOT_RUN_REAL_ADAPTER', 'REAL_ADAPTER_AVAILABLE',
        'REAL_ADAPTER_NOT_INSTALLED', 'REAL_ADAPTER_CREDENTIALS_MISSING'
    )),
    provenance_detail      VARCHAR(500) NOT NULL,
    registered_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agentboard_adapter_workspace
    ON agentboard_adapter (workspace_id, health, adapter_id);

-- ============================================================================
-- BUDGET — numeric grants and serialized spend accumulators.
-- An unassigned budget is not zero: a NULL/absent grant blocks the run.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_budget_grant (
    grant_id        VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    task_id         VARCHAR(64) REFERENCES agentboard_task(task_id) ON DELETE RESTRICT,
    currency        VARCHAR(8) NOT NULL CHECK (currency IN ('USD', 'EUR', 'GBP', 'RUB')),
    task_limit      DOUBLE PRECISION CHECK (task_limit IS NULL OR task_limit > 0),
    campaign_limit  DOUBLE PRECISION CHECK (campaign_limit IS NULL OR campaign_limit > 0),
    day_limit       DOUBLE PRECISION CHECK (day_limit IS NULL OR day_limit > 0),
    timeout_ms      INTEGER CHECK (timeout_ms IS NULL OR timeout_ms > 0),
    granted_by      VARCHAR(64) NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agentboard_budget_grant_task
    ON agentboard_budget_grant (task_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_agentboard_budget_grant_workspace
    ON agentboard_budget_grant (workspace_id);

-- The serialization point for spend. INSERT-if-missing plus SELECT ... FOR
-- UPDATE inside the settle transaction means two parallel settles on one grant
-- cannot both observe headroom. day_key buckets the day scope by the UTC
-- calendar day of the injected store clock.
CREATE TABLE IF NOT EXISTS agentboard_budget_spend (
    grant_id        VARCHAR(64) NOT NULL,
    operation_id    VARCHAR(64) NOT NULL,
    task_id         VARCHAR(64) NOT NULL,
    workspace_id    VARCHAR(64) NOT NULL,
    day_key         VARCHAR(10) NOT NULL,
    currency        VARCHAR(8) NOT NULL,
    spent_task      DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (spent_task >= 0),
    spent_campaign  DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (spent_campaign >= 0),
    spent_day       DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (spent_day >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (grant_id, day_key)
);

CREATE INDEX IF NOT EXISTS idx_agentboard_budget_spend_workspace
    ON agentboard_budget_spend (workspace_id, grant_id);

-- ============================================================================
-- EXECUTION RUN — one row per dispatched run, bound to a lease and a fence.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_run (
    run_id              VARCHAR(64) PRIMARY KEY,
    task_id             VARCHAR(64) NOT NULL REFERENCES agentboard_task(task_id) ON DELETE RESTRICT,
    workspace_id        VARCHAR(64) NOT NULL,
    adapter_id          VARCHAR(64) NOT NULL,
    lease_id            VARCHAR(64) NOT NULL,
    fencing_token       BIGINT NOT NULL CHECK (fencing_token > 0),
    request_id          VARCHAR(64) NOT NULL,
    idempotency_key     CHAR(64) NOT NULL,
    -- DISPATCH_PENDING | DISPATCHED | RUNNING | COLLECTED | CANCELLED |
    -- FAILED | RECONCILIATION_REQUIRED
    run_state           VARCHAR(32) NOT NULL CHECK (run_state IN (
        'DISPATCH_PENDING', 'DISPATCHED', 'RUNNING', 'COLLECTED',
        'CANCELLED', 'FAILED', 'RECONCILIATION_REQUIRED'
    )),
    -- Highest accepted event sequence for this run; the next event must be
    -- exactly this + 1 (monotonic, gap-checked).
    last_sequence       INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    brief_digest        CHAR(64) NOT NULL,
    policy_digest       CHAR(64) NOT NULL,
    manifest_digest     CHAR(64) NOT NULL,
    request_payload     JSONB NOT NULL,
    request_digest      CHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    result_payload      JSONB,
    result_digest       CHAR(64),
    error_payload       JSONB,
    spend               DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (spend >= 0),
    currency            VARCHAR(8) NOT NULL DEFAULT 'USD',
    dispatch_attempts   INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_attempts >= 0),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agentboard_run_idem
    ON agentboard_run (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_agentboard_run_task
    ON agentboard_run (task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agentboard_run_state
    ON agentboard_run (workspace_id, run_state, created_at);
-- At most one live run per task: a task may not be executed twice at once.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agentboard_run_single_live
    ON agentboard_run (task_id) WHERE run_state IN ('DISPATCH_PENDING', 'DISPATCHED', 'RUNNING');

-- ============================================================================
-- EXECUTION EVENTS — append-only, monotonic per run.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_execution_event (
    event_id       VARCHAR(64) PRIMARY KEY,
    run_id         VARCHAR(64) NOT NULL REFERENCES agentboard_run(run_id) ON DELETE RESTRICT,
    task_id        VARCHAR(64) NOT NULL,
    workspace_id   VARCHAR(64) NOT NULL,
    lease_id       VARCHAR(64) NOT NULL,
    fencing_token  BIGINT NOT NULL,
    sequence       INTEGER NOT NULL CHECK (sequence > 0),
    event_type     VARCHAR(24) NOT NULL CHECK (event_type IN (
        'ACCEPTED', 'STARTED', 'PROGRESS', 'CHECKPOINT', 'ARTIFACT',
        'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN'
    )),
    outcome        VARCHAR(32),
    payload        JSONB NOT NULL,
    payload_digest CHAR(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    emitted_at     TIMESTAMPTZ NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (run_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_agentboard_event_run
    ON agentboard_execution_event (run_id, sequence);
CREATE INDEX IF NOT EXISTS idx_agentboard_event_task
    ON agentboard_execution_event (task_id, received_at);

-- ============================================================================
-- APPEND-ONLY LEDGER: transitions, audit, outbox, idempotency.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agentboard_transition (
    transition_id   VARCHAR(64) PRIMARY KEY,
    task_id         VARCHAR(64) NOT NULL REFERENCES agentboard_task(task_id) ON DELETE RESTRICT,
    workspace_id    VARCHAR(64) NOT NULL,
    from_state      VARCHAR(16) NOT NULL,
    to_state        VARCHAR(16) NOT NULL,
    revision        INTEGER NOT NULL CHECK (revision > 1),
    actor           VARCHAR(64) NOT NULL,
    actor_kind      VARCHAR(32) NOT NULL,
    idempotency_key CHAR(64) NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    reason          VARCHAR(500) NOT NULL,
    lease_id        VARCHAR(64),
    fencing_token   BIGINT,
    brief_digest    CHAR(64) NOT NULL,
    policy_digest   CHAR(64) NOT NULL,
    manifest_digest CHAR(64) NOT NULL,
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    occurred_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agentboard_transition_task
    ON agentboard_transition (task_id, revision);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agentboard_transition_revision
    ON agentboard_transition (task_id, revision);

CREATE TABLE IF NOT EXISTS agentboard_audit (
    audit_id        VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    task_id         VARCHAR(64),
    actor           VARCHAR(64) NOT NULL,
    operation       VARCHAR(64) NOT NULL,
    idempotency_key CHAR(64) NOT NULL,
    outcome         VARCHAR(24) NOT NULL CHECK (outcome IN ('COMMITTED', 'REJECTED', 'REPLAYED')),
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agentboard_audit_workspace
    ON agentboard_audit (workspace_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_agentboard_audit_task
    ON agentboard_audit (task_id, occurred_at);

-- Outbox dispatch state machine. PENDING -> SENT -> ACKED is the happy path;
-- a crash before SENT is re-dispatchable, a crash after SENT with no ACK is
-- NOT re-dispatchable and escalates to RECONCILIATION_REQUIRED, because the
-- external side effect may already have happened.
CREATE TABLE IF NOT EXISTS agentboard_outbox (
    outbox_id       VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    task_id         VARCHAR(64),
    run_id          VARCHAR(64),
    event_type      VARCHAR(48) NOT NULL,
    idempotency_key CHAR(64) NOT NULL,
    dispatch_state  VARCHAR(32) NOT NULL CHECK (dispatch_state IN (
        'PENDING', 'SENT', 'ACKED', 'FAILED', 'RECONCILIATION_REQUIRED'
    )),
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error      VARCHAR(500),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at         TIMESTAMPTZ,
    acked_at        TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agentboard_outbox_idem
    ON agentboard_outbox (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_agentboard_outbox_pending
    ON agentboard_outbox (dispatch_state, created_at);

-- Persistent idempotency ledger. `args_digest` is the SHA-256 of the
-- canonical-json-v1 command arguments: same key + same digest replays
-- `result_payload`, same key + different digest is IDEMPOTENCY_CONFLICT.
CREATE TABLE IF NOT EXISTS agentboard_operation (
    idempotency_key CHAR(64) PRIMARY KEY CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    workspace_id    VARCHAR(64) NOT NULL,
    operation       VARCHAR(64) NOT NULL,
    args_digest     CHAR(64) NOT NULL CHECK (args_digest ~ '^[0-9a-f]{64}$'),
    result_payload  JSONB,
    actor           VARCHAR(64) NOT NULL,
    committed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agentboard_operation_workspace
    ON agentboard_operation (workspace_id, committed_at);

-- Reconciliation decisions for unknown external side effects. Recorded, never
-- guessed: only an authenticated human or an explicitly authorized
-- deterministic gate may close one, and a producer never may.
CREATE TABLE IF NOT EXISTS agentboard_reconciliation (
    reconciliation_id VARCHAR(64) PRIMARY KEY,
    workspace_id      VARCHAR(64) NOT NULL,
    task_id           VARCHAR(64),
    run_id            VARCHAR(64),
    -- OBSERVED_NO_EFFECT | OBSERVED_EFFECT_COMPLETED | OBSERVED_EFFECT_UNDONE
    -- | EFFECT_UNDETERMINED
    resolution        VARCHAR(40) NOT NULL CHECK (resolution IN (
        'OBSERVED_NO_EFFECT', 'OBSERVED_EFFECT_COMPLETED',
        'OBSERVED_EFFECT_UNDONE', 'EFFECT_UNDETERMINED'
    )),
    decided_by        VARCHAR(64) NOT NULL,
    decided_by_kind   VARCHAR(32) NOT NULL CHECK (decided_by_kind IN ('human_owner', 'human_reviewer', 'deterministic_gate')),
    evidence_ref      VARCHAR(64),
    detail            VARCHAR(1000) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agentboard_reconciliation_run
    ON agentboard_reconciliation (run_id, created_at);

-- Immutable guard: the live board must never be seeded from the synthetic
-- public demo. This row is written by the migration and can only be relaxed by
-- a future, separately reviewed migration.
INSERT INTO agentboard_audit (audit_id, workspace_id, task_id, actor, operation, idempotency_key, outcome, detail)
VALUES (
    'aud-s2-007-migration', 'ws-migration', NULL, 'prn-system-migration',
    'board.schema.initialize', repeat('0', 64), 'COMMITTED',
    '{"note":"live board created empty; veritas_demo_* fixtures are never migrated into it"}'::jsonb
)
ON CONFLICT (audit_id) DO NOTHING;
