-- S2-004 claim graph projected state and operation ledger.
-- Claim content rows (claims/evidence_edges/claim_edges) are immutable;
-- lifecycle is a *projected* state derived from review decisions and
-- invalidation events, so it lives in its own table and never rewrites
-- content. The operation ledger backs idempotent replay: a committed
-- operation returns its recorded outcome, an unknown one requires
-- reconciliation, never a blind retry (todo §5, §9).

-- Columns added after 0003 was drafted: machine-checkable negation, modality
-- and explicit denominator (todo §3, §4 — losing any of them is a hard fail).
ALTER TABLE claims ADD COLUMN IF NOT EXISTS polarity VARCHAR(16) NOT NULL DEFAULT 'affirmative'
    CHECK (polarity IN ('affirmative', 'negated'));
ALTER TABLE claims ADD COLUMN IF NOT EXISTS modality VARCHAR(16)
    CHECK (modality IN ('indicative', 'possibility', 'necessity', 'conditional'));
ALTER TABLE claims ADD COLUMN IF NOT EXISTS denominator VARCHAR(512);

CREATE TABLE IF NOT EXISTS claim_state (
    claim_id        VARCHAR(64) PRIMARY KEY,
    revision        INTEGER NOT NULL CHECK (revision >= 1),
    lifecycle       VARCHAR(32) NOT NULL CHECK (lifecycle IN (
        'PROPOSED', 'QUARANTINED', 'REVIEWED', 'ACCEPTED_BOUNDED',
        'REJECTED', 'STALE', 'REVOKED', 'SUPERSEDED'
    )),
    stale_reasons   JSONB NOT NULL DEFAULT '[]',
    reviewed        BOOLEAN NOT NULL DEFAULT FALSE,
    terminal_decision BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS claim_operation_ledger (
    workspace_id    VARCHAR(64) NOT NULL,
    operation_id    VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(64),
    actor           VARCHAR(64) NOT NULL,
    input_digest    CHAR(64) NOT NULL,
    status          VARCHAR(32) NOT NULL CHECK (status IN ('COMMITTED', 'RECONCILIATION_REQUIRED')),
    outcome_digest  CHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, operation_id)
);

CREATE UNIQUE INDEX idx_claim_operation_idem
    ON claim_operation_ledger (workspace_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS claim_audit_outbox (
    event_id        VARCHAR(64) PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    operation_id    VARCHAR(64) NOT NULL,
    actor           VARCHAR(64) NOT NULL,
    payload_digest  CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
