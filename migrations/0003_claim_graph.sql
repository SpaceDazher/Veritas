-- S2-004 Claim Graph Migration
-- Immutable, versioned claim/provenance graph storage
-- All tables use append-only semantics with revision columns
-- Derived ACL = most restrictive ACL of all inputs
-- Transactional audit/outbox for event sourcing

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CLAIMS TABLE
-- ============================================================================
CREATE TABLE claims (
    claim_id          VARCHAR(64) NOT NULL,
    revision          INTEGER NOT NULL CHECK (revision >= 1),
    contract_version  VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    workspace_id      VARCHAR(64) NOT NULL,
    tenant_id         VARCHAR(64) NOT NULL,
    -- ACL (derived = most restrictive of all inputs)
    acl_visibility    VARCHAR(16) NOT NULL CHECK (acl_visibility IN ('public', 'project', 'private')),
    acl_workspace_id  VARCHAR(64) NOT NULL,
    acl_tenant_id     VARCHAR(64) NOT NULL,
    acl_allowed_workspaces TEXT[] DEFAULT '{}',
    acl_allowed_principals TEXT[] DEFAULT '{}',
    -- Epistemic classification (never auto-promoted)
    epistemic_type    VARCHAR(32) NOT NULL CHECK (epistemic_type IN (
        'OBSERVATION', 'FACT_CLAIM', 'EXPERT_OPINION',
        'HYPOTHESIS', 'FORECAST', 'ANALOGY', 'MECHANISM_CLAIM'
    )),
    -- Text content (original preserved, normalized separate)
    normalized_text   TEXT NOT NULL,
    original_text     TEXT NOT NULL,
    -- Proposition structure
    subject           VARCHAR(512) NOT NULL,
    predicate         VARCHAR(512) NOT NULL,
    object            VARCHAR(512) NOT NULL,
    qualifiers        TEXT[] DEFAULT '{}',
    uncertainty_type  VARCHAR(16) CHECK (uncertainty_type IN ('aleatory', 'epistemic', 'both')),
    uncertainty_desc  TEXT,
    method_name       VARCHAR(256),
    method_version    VARCHAR(32),
    method_config_digest CHAR(64),
    assumptions       TEXT[] DEFAULT '{}',
    exclusions        TEXT[] DEFAULT '{}',
    -- Quantitative attributes
    units             VARCHAR(128),
    value_min         NUMERIC,
    value_max         NUMERIC,
    population        VARCHAR(512),
    geography         VARCHAR(512),
    period_start      TIMESTAMPTZ,
    period_end        TIMESTAMPTZ,
    -- Temporal model (four distinct fields)
    event_time        TIMESTAMPTZ,
    published_at      TIMESTAMPTZ,
    observed_at       TIMESTAMPTZ NOT NULL,
    fetched_at        TIMESTAMPTZ NOT NULL,
    -- Language & translation
    language          VARCHAR(16) NOT NULL,
    translation_status VARCHAR(32) NOT NULL CHECK (translation_status IN ('original', 'translated', 'translation_pending')),
    canonical_digest  CHAR(64) NOT NULL,
    -- Lifecycle
    lifecycle         VARCHAR(32) NOT NULL CHECK (lifecycle IN (
        'PROPOSED', 'QUARANTINED', 'REVIEWED', 'ACCEPTED_BOUNDED',
        'REJECTED', 'STALE', 'REVOKED', 'SUPERSEDED'
    )),
    supersedes_claim_id VARCHAR(64),
    supersedes_revision INTEGER,
    -- Metadata
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by        VARCHAR(64) NOT NULL,
    -- Primary key is (claim_id, revision)
    PRIMARY KEY (claim_id, revision),
    -- Self-referential foreign key for supersedes
    FOREIGN KEY (supersedes_claim_id, supersedes_revision)
        REFERENCES claims (claim_id, revision) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_claims_workspace ON claims (workspace_id, tenant_id);
CREATE INDEX idx_claims_lifecycle ON claims (lifecycle);
CREATE INDEX idx_claims_canonical_digest ON claims (canonical_digest);
CREATE INDEX idx_claims_epistemic_type ON claims (epistemic_type);
CREATE INDEX idx_claims_subject_predicate ON claims (subject, predicate);

-- ============================================================================
-- EVIDENCE EDGES TABLE
-- ============================================================================
CREATE TABLE evidence_edges (
    edge_id               VARCHAR(64) NOT NULL,
    contract_version      VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    claim_id              VARCHAR(64) NOT NULL,
    claim_revision        INTEGER NOT NULL CHECK (claim_revision >= 1),
    segment_id            VARCHAR(64) NOT NULL,
    segment_revision      INTEGER NOT NULL CHECK (segment_revision >= 1),
    relation              VARCHAR(32) NOT NULL CHECK (relation IN (
        'SUPPORTS', 'CONTRADICTS', 'QUALIFIES', 'CONTEXTUALIZES', 'DERIVED_FROM'
    )),
    span_start            INTEGER NOT NULL CHECK (span_start >= 0),
    span_end              INTEGER NOT NULL CHECK (span_end >= span_start),
    quote_digest          CHAR(64) NOT NULL,
    entailment_status     VARCHAR(16) NOT NULL CHECK (entailment_status IN (
        'ENTAILED', 'CONTRADICTED', 'NEUTRAL', 'UNKNOWN'
    )),
    method_name           VARCHAR(128) NOT NULL,
    method_version        VARCHAR(32) NOT NULL,
    method_config_digest  CHAR(64),
    reviewer              VARCHAR(64),
    source_family_id      VARCHAR(64) NOT NULL,
    upstream_snapshot_ids TEXT[] NOT NULL,
    access_state          VARCHAR(16) NOT NULL CHECK (access_state IN (
        'available', 'restricted', 'tombstoned', 'unknown'
    )),
    retention_state       VARCHAR(16) NOT NULL CHECK (retention_state IN (
        'active', 'expired', 'deleted'
    )),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            VARCHAR(64) NOT NULL,
    PRIMARY KEY (edge_id),
    FOREIGN KEY (claim_id, claim_revision) REFERENCES claims (claim_id, revision) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_evidence_edges_claim ON evidence_edges (claim_id, claim_revision);
CREATE INDEX idx_evidence_edges_segment ON evidence_edges (segment_id, segment_revision);
CREATE INDEX idx_evidence_edges_family ON evidence_edges (source_family_id);
CREATE INDEX idx_evidence_edges_relation ON evidence_edges (relation);

-- ============================================================================
-- CLAIM EDGES TABLE
-- ============================================================================
CREATE TABLE claim_edges (
    edge_id                VARCHAR(64) NOT NULL,
    contract_version       VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    source_claim_id        VARCHAR(64) NOT NULL,
    source_revision        INTEGER NOT NULL CHECK (source_revision >= 1),
    target_claim_id        VARCHAR(64) NOT NULL,
    target_revision        INTEGER NOT NULL CHECK (target_revision >= 1),
    relation               VARCHAR(32) NOT NULL CHECK (relation IN (
        'SUPPORTS', 'CONTRADICTS', 'REFINES', 'GENERALIZES',
        'SPECIALIZES', 'DEPENDS_ON', 'SUPERSEDES', 'TRANSLATES', 'DUPLICATES_CANDIDATE'
    )),
    direction              VARCHAR(16) NOT NULL CHECK (direction IN ('forward', 'bidirectional')),
    scope_population_overlap  BOOLEAN NOT NULL DEFAULT FALSE,
    scope_geography_overlap   BOOLEAN NOT NULL DEFAULT FALSE,
    scope_period_overlap      BOOLEAN NOT NULL DEFAULT FALSE,
    scope_units_compatible    BOOLEAN NOT NULL DEFAULT FALSE,
    provenance_method         VARCHAR(128) NOT NULL,
    provenance_extractor      VARCHAR(128) NOT NULL,
    provenance_extractor_version VARCHAR(32) NOT NULL,
    provenance_config_digest  CHAR(64),
    provenance_confidence     NUMERIC CHECK (provenance_confidence >= 0 AND provenance_confidence <= 1),
    creation_authority        VARCHAR(64) NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by                VARCHAR(64) NOT NULL,
    PRIMARY KEY (edge_id),
    FOREIGN KEY (source_claim_id, source_revision) REFERENCES claims (claim_id, revision) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (target_claim_id, target_revision) REFERENCES claims (claim_id, revision) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_claim_edges_source ON claim_edges (source_claim_id, source_revision);
CREATE INDEX idx_claim_edges_target ON claim_edges (target_claim_id, target_revision);
CREATE INDEX idx_claim_edges_relation ON claim_edges (relation);

-- ============================================================================
-- EXPERT PROFILES TABLE
-- ============================================================================
CREATE TABLE expert_profiles (
    expert_id           VARCHAR(64) NOT NULL,
    contract_version    VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    aliases             TEXT[] DEFAULT '{}',
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          VARCHAR(64) NOT NULL,
    PRIMARY KEY (expert_id)
);

CREATE TABLE expert_domains (
    expert_id           VARCHAR(64) NOT NULL REFERENCES expert_profiles(expert_id) ON DELETE CASCADE,
    domain              VARCHAR(256) NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    provenance_claim_id VARCHAR(64),
    provenance_revision INTEGER,
    PRIMARY KEY (expert_id, domain, valid_from)
);

CREATE TABLE expert_affiliations (
    expert_id           VARCHAR(64) NOT NULL REFERENCES expert_profiles(expert_id) ON DELETE CASCADE,
    organization        VARCHAR(512) NOT NULL,
    role                VARCHAR(256) NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    provenance_claim_id VARCHAR(64),
    provenance_revision INTEGER,
    PRIMARY KEY (expert_id, organization, valid_from)
);

CREATE TABLE expert_conflicts (
    expert_id           VARCHAR(64) NOT NULL REFERENCES expert_profiles(expert_id) ON DELETE CASCADE,
    description         TEXT NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    provenance_claim_id VARCHAR(64),
    provenance_revision INTEGER,
    PRIMARY KEY (expert_id, description, valid_from)
);

CREATE TABLE expert_credentials (
    expert_id           VARCHAR(64) NOT NULL REFERENCES expert_profiles(expert_id) ON DELETE CASCADE,
    credential_type     VARCHAR(256) NOT NULL,
    issuer              VARCHAR(512) NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ,
    provenance_claim_id VARCHAR(64) NOT NULL,
    provenance_revision INTEGER NOT NULL,
    PRIMARY KEY (expert_id, credential_type, issuer, issued_at)
);

-- ============================================================================
-- EXPERT LENSES TABLE
-- ============================================================================
CREATE TABLE expert_lenses (
    lens_id              VARCHAR(64) NOT NULL,
    contract_version     VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    owner_workspace_id   VARCHAR(64) NOT NULL,
    owner_principal_id   VARCHAR(64) NOT NULL,
    expert_id            VARCHAR(64) NOT NULL REFERENCES expert_profiles(expert_id),
    domain               VARCHAR(256) NOT NULL,
    task_class           VARCHAR(32) NOT NULL CHECK (task_class IN (
        'fact_checking', 'forecasting', 'mechanism_analysis',
        'policy_review', 'risk_assessment', 'synthesis'
    )),
    weight               NUMERIC NOT NULL CHECK (weight >= 0 AND weight <= 1),
    valid_from           TIMESTAMPTZ NOT NULL,
    valid_until          TIMESTAMPTZ NOT NULL,
    rationale            TEXT NOT NULL,
    issuer               VARCHAR(64) NOT NULL,
    revoked_at           TIMESTAMPTZ,
    revocation_reason    TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (lens_id)
);

CREATE INDEX idx_expert_lenses_workspace ON expert_lenses (owner_workspace_id, revoked_at);
CREATE INDEX idx_expert_lenses_expert ON expert_lenses (expert_id);

-- ============================================================================
-- CALIBRATION RECORDS TABLE
-- ============================================================================
CREATE TABLE calibration_records (
    calibration_id           VARCHAR(64) NOT NULL,
    contract_version         VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    corpus_version           VARCHAR(32) NOT NULL,
    corpus_sha256            CHAR(64) NOT NULL,
    outcome_metric           VARCHAR(64) NOT NULL CHECK (outcome_metric IN (
        'extraction_accuracy', 'span_binding_accuracy', 'epistemic_type_accuracy',
        'qualifier_preservation', 'contradiction_precision', 'contradiction_recall',
        'upstream_collapse_accuracy', 'stale_invalidation_recall'
    )),
    outcome_threshold        NUMERIC NOT NULL CHECK (outcome_threshold >= 0 AND outcome_threshold <= 1),
    outcome_description      TEXT NOT NULL,
    numerator                INTEGER NOT NULL CHECK (numerator >= 0),
    denominator              INTEGER NOT NULL CHECK (denominator >= 1),
    missing_count            INTEGER NOT NULL CHECK (missing_count >= 0),
    uncertainty_method       VARCHAR(32) NOT NULL CHECK (uncertainty_method IN ('wilson', 'clopper_pearson', 'bootstrap')),
    uncertainty_lower        NUMERIC NOT NULL CHECK (uncertainty_lower >= 0 AND uncertainty_lower <= 1),
    uncertainty_upper        NUMERIC NOT NULL CHECK (uncertainty_upper >= 0 AND uncertainty_upper <= 1),
    uncertainty_confidence   NUMERIC NOT NULL CHECK (uncertainty_confidence >= 0 AND uncertainty_confidence <= 1),
    evaluator_independent    INTEGER NOT NULL CHECK (evaluator_independent >= 1),
    evaluator_blind          BOOLEAN NOT NULL,
    evaluator_separate_proc  BOOLEAN NOT NULL DEFAULT FALSE,
    status                   VARCHAR(16) NOT NULL CHECK (status IN ('MEASURED', 'NOT_MEASURED')),
    not_measured_reason      VARCHAR(64) CHECK (not_measured_reason IN (
        'no_valid_corpus', 'insufficient_samples', 'evaluator_not_independent', 'outcome_not_defined'
    )),
    measured_at              TIMESTAMPTZ NOT NULL,
    measured_by              VARCHAR(64) NOT NULL,
    PRIMARY KEY (calibration_id)
);

-- ============================================================================
-- CLAIM EXTRACTION REQUESTS & RESULTS
-- ============================================================================
CREATE TABLE claim_extraction_requests (
    request_id           VARCHAR(64) NOT NULL,
    contract_version     VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    segment_ids          TEXT[] NOT NULL,
    segment_hashes       CHAR(64)[] NOT NULL,
    extractor            VARCHAR(128) NOT NULL,
    extractor_version    VARCHAR(32) NOT NULL,
    prompt_version       VARCHAR(32) NOT NULL,
    parameters           JSONB NOT NULL DEFAULT '{}',
    seed                 CHAR(64),
    actor                VARCHAR(64) NOT NULL,
    workspace_id         VARCHAR(64) NOT NULL,
    idempotency_key      VARCHAR(64) NOT NULL UNIQUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (request_id)
);

CREATE TABLE claim_extraction_results (
    request_id           VARCHAR(64) NOT NULL REFERENCES claim_extraction_requests(request_id),
    contract_version     VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    proposed_claims      JSONB NOT NULL DEFAULT '[]',
    abstentions          JSONB NOT NULL DEFAULT '[]',
    malformed_output     JSONB NOT NULL DEFAULT '[]',
    audit_operation_id   VARCHAR(64) NOT NULL,
    audit_executor_id    VARCHAR(64) NOT NULL,
    audit_pid            INTEGER NOT NULL,
    audit_nonce          VARCHAR(64) NOT NULL,
    audit_output_root    CHAR(64) NOT NULL,
    status               VARCHAR(32) NOT NULL CHECK (status IN (
        'COMPLETED', 'QUARANTINED', 'FAILED', 'RECONCILIATION_REQUIRED'
    )),
    reconciliation_reason TEXT,
    completed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (request_id)
);

-- ============================================================================
-- CLAIM REVIEW DECISIONS
-- ============================================================================
CREATE TABLE claim_review_decisions (
    decision_id          VARCHAR(64) NOT NULL,
    contract_version     VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    claim_id             VARCHAR(64) NOT NULL,
    claim_revision       INTEGER NOT NULL CHECK (claim_revision >= 1),
    claim_digest         CHAR(64) NOT NULL,
    actor                VARCHAR(64) NOT NULL,
    decision             VARCHAR(32) NOT NULL CHECK (decision IN (
        'ACCEPT_BOUNDED', 'REJECT', 'QUARANTINE', 'REQUEST_REVISION'
    )),
    reason_codes         TEXT[] NOT NULL,
    expiry               TIMESTAMPTZ,
    supersedes_claim_id  VARCHAR(64),
    supersedes_revision  INTEGER,
    idempotency_key      VARCHAR(64) NOT NULL UNIQUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (decision_id),
    FOREIGN KEY (claim_id, claim_revision) REFERENCES claims (claim_id, revision) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (supersedes_claim_id, supersedes_revision) REFERENCES claims (claim_id, revision) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_review_decisions_claim ON claim_review_decisions (claim_id, claim_revision);
CREATE INDEX idx_review_decisions_actor ON claim_review_decisions (actor);

-- ============================================================================
-- GRAPH INVALIDATION EVENTS
-- ============================================================================
CREATE TABLE graph_invalidation_events (
    event_id             VARCHAR(64) NOT NULL,
    contract_version     VARCHAR(16) NOT NULL DEFAULT '1.0.0',
    trigger_type         VARCHAR(64) NOT NULL CHECK (trigger_type IN (
        'source_snapshot_tombstone', 'source_snapshot_correction', 'source_snapshot_retraction',
        'content_segment_tombstone', 'content_segment_correction',
        'claim_tombstone', 'claim_correction', 'claim_revocation',
        'access_restriction', 'retention_expiry'
    )),
    trigger_id           VARCHAR(128) NOT NULL,
    trigger_revision     INTEGER NOT NULL CHECK (trigger_revision >= 1),
    affected_descendants JSONB NOT NULL DEFAULT '[]',
    reason_code          VARCHAR(64) NOT NULL CHECK (reason_code IN (
        'upstream_tombstoned', 'upstream_corrected', 'upstream_retracted',
        'access_revoked', 'retention_expired', 'manual_invalidation'
    )),
    reason_description   TEXT NOT NULL,
    traversal_method     VARCHAR(16) NOT NULL CHECK (traversal_method IN ('bfs', 'dfs', 'topological')),
    traversal_visited    INTEGER NOT NULL CHECK (traversal_visited >= 0),
    traversal_edges      TEXT[] DEFAULT '{}',
    completion_state     VARCHAR(16) NOT NULL CHECK (completion_state IN (
        'PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'PARTIAL'
    )),
    failed_descendants   TEXT[] DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           VARCHAR(64) NOT NULL,
    PRIMARY KEY (event_id)
);

CREATE INDEX idx_invalidation_trigger ON graph_invalidation_events (trigger_id, trigger_revision);
CREATE INDEX idx_invalidation_state ON graph_invalidation_events (completion_state);

-- ============================================================================
-- TRANSACTIONAL AUDIT / OUTBOX
-- ============================================================================
CREATE TABLE audit_outbox (
    id                   BIGSERIAL PRIMARY KEY,
    event_type           VARCHAR(64) NOT NULL,
    payload              JSONB NOT NULL,
    claim_id             VARCHAR(64),
    claim_revision       INTEGER,
    correlation_id       VARCHAR(64),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at         TIMESTAMPTZ
);

CREATE INDEX idx_audit_outbox_unpublished ON audit_outbox (published_at) WHERE published_at IS NULL;
CREATE INDEX idx_audit_outbox_correlation ON audit_outbox (correlation_id);

-- ============================================================================
-- IDEMPOTENCY KEYS (for deduplication)
-- ============================================================================
CREATE TABLE idempotency_keys (
    key                  VARCHAR(64) NOT NULL PRIMARY KEY,
    claim_id             VARCHAR(64),
    claim_revision       INTEGER,
    operation_type       VARCHAR(32) NOT NULL,
    result               JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_idempotency_expires ON idempotency_keys (expires_at);

-- ============================================================================
-- FUNCTIONS FOR ATOMIC OPERATIONS
-- ============================================================================

-- Function to create a new claim revision atomically
CREATE OR REPLACE FUNCTION create_claim_revision(
    p_claim_id         VARCHAR(64),
    p_new_revision     INTEGER,
    p_normalized_text  TEXT,
    p_original_text    TEXT,
    p_subject          VARCHAR(512),
    p_predicate        VARCHAR(512),
    p_object           VARCHAR(512),
    p_epistemic_type   VARCHAR(32),
    p_lifecycle        VARCHAR(32),
    p_canonical_digest CHAR(64),
    p_created_by       VARCHAR(64),
    p_workspace_id     VARCHAR(64),
    p_tenant_id        VARCHAR(64)
) RETURNS VOID AS $$
BEGIN
    INSERT INTO claims (
        claim_id, revision, contract_version, workspace_id, tenant_id,
        acl_visibility, acl_workspace_id, acl_tenant_id,
        acl_allowed_workspaces, acl_allowed_principals,
        epistemic_type, normalized_text, original_text,
        subject, predicate, object, qualifiers,
        canonical_digest, lifecycle, created_by
    ) VALUES (
        p_claim_id, p_new_revision, '1.0.0', p_workspace_id, p_tenant_id,
        'project', p_workspace_id, p_tenant_id,
        '{}', '{}',
        p_epistemic_type, p_normalized_text, p_original_text,
        p_subject, p_predicate, p_object, '{}',
        p_canonical_digest, p_lifecycle, p_created_by
    );
END;
$$ LANGUAGE plpgsql;

-- Function to check cycles in claim edges (DEPENDS_ON, DERIVED_FROM)
CREATE OR REPLACE FUNCTION check_claim_edge_cycle(
    p_source_claim_id   VARCHAR(64),
    p_source_revision   INTEGER,
    p_target_claim_id   VARCHAR(64),
    p_target_revision   INTEGER,
    p_relation          VARCHAR(32)
) RETURNS BOOLEAN AS $$
DECLARE
    has_cycle BOOLEAN := FALSE;
BEGIN
    IF p_relation NOT IN ('DEPENDS_ON', 'DERIVED_FROM') THEN
        RETURN FALSE;
    END IF;

    -- Recursive CTE to detect cycles
    WITH RECURSIVE edge_path AS (
        SELECT source_claim_id, source_revision, target_claim_id, target_revision, 1 as depth
        FROM claim_edges
        WHERE relation IN ('DEPENDS_ON', 'DERIVED_FROM')
        AND source_claim_id = p_source_claim_id AND source_revision = p_source_revision

        UNION ALL

        SELECT ce.source_claim_id, ce.source_revision, ce.target_claim_id, ce.target_revision, ep.depth + 1
        FROM claim_edges ce
        JOIN edge_path ep ON ce.source_claim_id = ep.target_claim_id AND ce.source_revision = ep.target_revision
        WHERE ce.relation IN ('DEPENDS_ON', 'DERIVED_FROM')
        AND ep.depth < 100  -- Prevent infinite recursion
    )
    SELECT TRUE INTO has_cycle
    FROM edge_path
    WHERE target_claim_id = p_target_claim_id AND target_revision = p_target_revision
    LIMIT 1;

    RETURN has_cycle;
END;
$$ LANGUAGE plpgsql;

-- Trigger to prevent cycles on claim edge insert
CREATE OR REPLACE FUNCTION prevent_claim_edge_cycle()
RETURNS TRIGGER AS $$
BEGIN
    IF check_claim_edge_cycle(
        NEW.source_claim_id, NEW.source_revision,
        NEW.target_claim_id, NEW.target_revision,
        NEW.relation
    ) THEN
        RAISE EXCEPTION 'Cycle detected in claim edge: % % -> % %',
            NEW.source_claim_id, NEW.source_revision, NEW.target_claim_id, NEW.target_revision;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_claim_edge_cycle
    BEFORE INSERT ON claim_edges
    FOR EACH ROW EXECUTE FUNCTION prevent_claim_edge_cycle();

-- Function to propagate invalidation from parent
CREATE OR REPLACE FUNCTION propagate_invalidation(
    p_trigger_type    VARCHAR(64),
    p_trigger_id      VARCHAR(128),
    p_trigger_revision INTEGER,
    p_reason_code     VARCHAR(64),
    p_reason_desc     TEXT,
    p_created_by      VARCHAR(64)
) RETURNS VARCHAR(64) AS $$
DECLARE
    v_event_id VARCHAR(64);
    v_descendant RECORD;
BEGIN
    v_event_id := 'inv-' || substr(md5(random()::text || clock_timestamp()::text), 1, 16);

    INSERT INTO graph_invalidation_events (
        event_id, trigger_type, trigger_id, trigger_revision,
        affected_descendants, reason_code, reason_description,
        traversal_method, traversal_visited, traversal_edges,
        completion_state, created_by
    ) VALUES (
        v_event_id, p_trigger_type, p_trigger_id, p_trigger_revision,
        '[]', p_reason_code, p_reason_desc,
        'bfs', 0, '{}', 'IN_PROGRESS', p_created_by
    );

    -- Find and mark affected claims as STALE
    -- This is a simplified version; full implementation would traverse the graph
    FOR v_descendant IN
        SELECT c.claim_id, c.revision
        FROM claims c
        JOIN evidence_edges ee ON ee.claim_id = c.claim_id AND ee.claim_revision = c.revision
        WHERE ee.upstream_snapshot_ids @> ARRAY[p_trigger_id]::TEXT[]
           OR (p_trigger_type LIKE 'claim_%' AND c.claim_id = p_trigger_id)
    LOOP
        PERFORM create_claim_revision(
            v_descendant.claim_id, v_descendant.revision + 1,
            c.normalized_text, c.original_text, c.subject, c.predicate, c.object,
            c.epistemic_type, 'STALE',
            md5(c.normalized_text || c.original_text || c.subject || c.predicate || c.object || c.epistemic_type),
            p_created_by, c.workspace_id, c.tenant_id
        );
    END LOOP;

    UPDATE graph_invalidation_events
    SET completion_state = 'COMPLETED'
    WHERE event_id = v_event_id;

    RETURN v_event_id;
END;
$$ LANGUAGE plpgsql;