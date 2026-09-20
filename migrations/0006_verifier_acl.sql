-- S2-006 fix2-C migration (review findings 1 and 3).
-- Migration 0005 is FROZEN and stays untouched; this migration only ADDS:
--
-- 1. verifier_record_acl — store-level ACL metadata for immutable verifier
--    records (review finding 1): a derived verification result inherits the
--    STRICTEST of its inputs' ACLs (strictest_of_inputs), persisted OUTSIDE
--    the frozen contract payload, and enforced by the read API BEFORE any
--    record is returned to an actor. The ACL row is written in the SAME
--    transaction as the record itself (store.publish writes record + acl
--    atomically), so a published record is never readable before its ACL
--    exists.
--
-- 2. verifier_grant_budget_totals — the per-grant budget accumulator
--    (review finding 3): task/campaign/day scopes, serialized by a row lock
--    (INSERT-if-missing plus SELECT ... FOR UPDATE inside the finalize
--    transaction), so parallel finalizes on one grant can never pass the
--    budget check simultaneously. The day scope is bucketed by the UTC
--    calendar day of the injected store clock (day_key, 'YYYY-MM-DD');
--    crossing a day boundary resets the day scope deterministically.

CREATE TABLE IF NOT EXISTS verifier_record_acl (
    record_kind           VARCHAR(32) NOT NULL CHECK (record_kind IN (
        'request', 'result', 'calibration_report', 'adjudication', 'run', 'invalidation'
    )),
    record_id             VARCHAR(64) NOT NULL,
    workspace_id          VARCHAR(64) NOT NULL,
    visibility            VARCHAR(16) NOT NULL CHECK (visibility IN ('public', 'project', 'private')),
    inherited             VARCHAR(32) NOT NULL DEFAULT 'strictest_of_inputs',
    allowed_principal_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (record_kind, record_id)
);

CREATE INDEX IF NOT EXISTS idx_verifier_record_acl_workspace
    ON verifier_record_acl (workspace_id, record_kind);

CREATE TABLE IF NOT EXISTS verifier_grant_budget_totals (
    grant_ref        VARCHAR(64) PRIMARY KEY,
    workspace_id     VARCHAR(64) NOT NULL,
    day_key          VARCHAR(10) NOT NULL,
    settled_task     DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (settled_task >= 0),
    settled_campaign DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (settled_campaign >= 0),
    settled_day      DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (settled_day >= 0),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verifier_grant_budget_workspace
    ON verifier_grant_budget_totals (workspace_id);

-- Audit attribution for the day bucket: the UTC day a call was settled
-- under (the external-call state machine in 0005 is otherwise unchanged —
-- this only ADDS a nullable column).
ALTER TABLE verifier_external_call_run
    ADD COLUMN IF NOT EXISTS day_key VARCHAR(10);
