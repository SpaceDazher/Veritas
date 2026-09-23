-- S2-006 round-three hardening.
-- Task-scoped provider spend is keyed by both the grant and operation. The
-- existing per-grant accumulator remains the serialization point for
-- campaign/day totals; this table prevents unrelated operations from sharing
-- one task counter.

CREATE TABLE IF NOT EXISTS verifier_grant_task_budget_totals (
    grant_ref    VARCHAR(64) NOT NULL,
    operation_id VARCHAR(64) NOT NULL,
    workspace_id VARCHAR(64) NOT NULL,
    settled_task DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (settled_task >= 0),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (grant_ref, operation_id)
);

CREATE INDEX IF NOT EXISTS idx_verifier_grant_task_budget_workspace
    ON verifier_grant_task_budget_totals (workspace_id, grant_ref);

INSERT INTO verifier_grant_task_budget_totals
    (grant_ref, operation_id, workspace_id, settled_task)
SELECT grant_ref,
       operation_id,
       MIN(workspace_id),
       COALESCE(SUM(CASE
           WHEN settlement ? 'amount' AND jsonb_typeof(settlement->'amount') = 'number'
             THEN (settlement->>'amount')::float8
           ELSE 0
       END), 0)
FROM verifier_external_call_run
WHERE state = 'FINALIZED'
GROUP BY grant_ref, operation_id
ON CONFLICT (grant_ref, operation_id) DO NOTHING;
