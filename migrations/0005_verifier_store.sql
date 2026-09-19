-- S2-006 verifier store migration.
-- Immutable verifier records (requests, results, calibration reports,
-- adjudications, runs, invalidation events) are append-only: payload JSONB
-- columns are never UPDATEd — a correction publishes a new record plus a
-- verifier_invalidation_event with an explicit SUPERSEDES link. The only
-- mutable table is verifier_external_call_run, whose projected state follows
-- the RESERVED -> ACCEPTED -> FINALIZED -> RECONCILIATION_REQUIRED machine
-- (spec §11): reserve happens atomically before any provider call, the
-- provider call itself is never held inside a DB transaction, and a
-- crash/timeout/unknown outcome between REQUEST_ACCEPTED and RUN_FINALIZED
-- is escalated to reconciliation behind a unique fencing token — never a
-- blind retry. The operation ledger + audit outbox follow the migration
-- 0003/0004 pattern: one transaction writes record + audit + outbox or
-- nothing at all, and the idempotency key is unique with a typed
-- IDEMPOTENCY_CONFLICT on reuse with different arguments.

CREATE SEQUENCE IF NOT EXISTS verifier_fencing_token_seq START 1;

-- ============================================================================
-- IMMUTABLE VERIFIER RECORDS
-- ============================================================================

CREATE TABLE IF NOT EXISTS verifier_request (
    request_id            VARCHAR(64) PRIMARY KEY,
    workspace_id          VARCHAR(64) NOT NULL,
    actor                 VARCHAR(64) NOT NULL,
    contract_version      VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    idempotency_key       CHAR(64) NOT NULL,
    canonical_args_digest CHAR(64) NOT NULL,
    payload               JSONB NOT NULL,
    payload_digest        CHAR(64) NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_verifier_request_idem
    ON verifier_request (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_verifier_request_workspace
    ON verifier_request (workspace_id, created_at);

CREATE TABLE IF NOT EXISTS verifier_result (
    result_id       VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    request_ref     VARCHAR(64) NOT NULL,
    contract_version VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    output_digest   CHAR(64) NOT NULL,
    status          VARCHAR(32) NOT NULL CHECK (status IN (
        'READY_FOR_HUMAN_REVIEW', 'INCOMPLETE', 'BLOCKED'
    )),
    human_decision_required BOOLEAN NOT NULL DEFAULT TRUE,
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_verifier_result_output_digest
    ON verifier_result (output_digest);
CREATE INDEX IF NOT EXISTS idx_verifier_result_request
    ON verifier_result (request_ref);
CREATE INDEX IF NOT EXISTS idx_verifier_result_workspace
    ON verifier_result (workspace_id, created_at);

CREATE TABLE IF NOT EXISTS verifier_calibration_report (
    report_id       VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    corpus_version  VARCHAR(32) NOT NULL,
    thresholds_digest CHAR(64) NOT NULL,
    contract_version VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    independence_tier VARCHAR(32) NOT NULL CHECK (independence_tier IN (
        'INDEPENDENTLY_CALIBRATED', 'PARTIALLY_INDEPENDENT',
        'NOT_INDEPENDENT', 'UNVERIFIED'
    )),
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verifier_calibration_workspace
    ON verifier_calibration_report (workspace_id, corpus_version);

CREATE TABLE IF NOT EXISTS verifier_adjudication_record (
    adjudication_id VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    case_id         VARCHAR(64) NOT NULL,
    contract_version VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    adjudicator     VARCHAR(64) NOT NULL,
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verifier_adjudication_case
    ON verifier_adjudication_record (case_id);

CREATE TABLE IF NOT EXISTS verifier_run (
    run_id          VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    run_kind        VARCHAR(32) NOT NULL CHECK (run_kind IN (
        'candidate', 'deterministic_baseline', 'heuristic_baseline',
        'comparator', 'evaluation_harness'
    )),
    contract_version VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    run_manifest_digest CHAR(64) NOT NULL,
    prediction_set_digest CHAR(64) NOT NULL,
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_verifier_run_manifest_digest
    ON verifier_run (run_manifest_digest);
CREATE INDEX IF NOT EXISTS idx_verifier_run_workspace
    ON verifier_run (workspace_id, run_kind);

CREATE TABLE IF NOT EXISTS verifier_invalidation_event (
    event_id        VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    cause           VARCHAR(64) NOT NULL CHECK (cause IN (
        'model_drift', 'prompt_drift', 'rubric_drift', 'corpus_drift',
        'contract_drift', 'source_revision_changed', 'label_revoked',
        'threshold_changed'
    )),
    contract_version VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    payload         JSONB NOT NULL,
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verifier_invalidation_workspace
    ON verifier_invalidation_event (workspace_id, created_at);

-- ============================================================================
-- EXTERNAL CALL STATE MACHINE (provider calls stay outside DB transactions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS verifier_external_call_run (
    call_id         VARCHAR(64) PRIMARY KEY,
    workspace_id    VARCHAR(64) NOT NULL,
    actor           VARCHAR(64) NOT NULL,
    grant_ref       VARCHAR(64) NOT NULL,
    operation_id    VARCHAR(64) NOT NULL,
    state           VARCHAR(32) NOT NULL CHECK (state IN (
        'RESERVED', 'ACCEPTED', 'FINALIZED', 'RECONCILIATION_REQUIRED'
    )),
    fencing_token   BIGINT NOT NULL UNIQUE,
    reservation     JSONB NOT NULL DEFAULT '{}',
    response_digest CHAR(64),
    settlement      JSONB,
    reconcile_reason TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (state <> 'FINALIZED' OR (response_digest IS NOT NULL AND settlement IS NOT NULL)),
    CHECK (state <> 'RECONCILIATION_REQUIRED' OR reconcile_reason IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_verifier_external_call_workspace
    ON verifier_external_call_run (workspace_id, state);

-- ============================================================================
-- OPERATION LEDGER + AUDIT OUTBOX (migration 0003/0004 pattern)
-- ============================================================================
CREATE TABLE IF NOT EXISTS verifier_operation_ledger (
    workspace_id    VARCHAR(64) NOT NULL,
    operation_id    VARCHAR(64) NOT NULL,
    idempotency_key CHAR(64),
    actor           VARCHAR(64) NOT NULL,
    operation       VARCHAR(64) NOT NULL,
    input_digest    CHAR(64) NOT NULL,
    status          VARCHAR(32) NOT NULL CHECK (status IN ('COMMITTED', 'RECONCILIATION_REQUIRED')),
    outcome_digest  CHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, operation_id)
);

CREATE UNIQUE INDEX idx_verifier_operation_idem
    ON verifier_operation_ledger (workspace_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS verifier_audit_outbox (
    event_id        VARCHAR(64) PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    operation_id    VARCHAR(64) NOT NULL,
    actor           VARCHAR(64) NOT NULL,
    record_kind     VARCHAR(64),
    record_id       VARCHAR(128),
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verifier_outbox_operation
    ON verifier_audit_outbox (operation_id);
