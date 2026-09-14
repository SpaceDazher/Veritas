-- S2-003 ingestion append-only schema.
-- Every payload table is append-only: UPDATE and DELETE are rejected by
-- trigger. Corrections append a new version bound with supersedes_snapshot_id;
-- deletion appends a tombstone row while preserving prior existence and audit.
-- Current pointers are derived views of the version chain, updated in the same
-- transaction as the appended row (the pipeline enforces this; SQL mirrors it).

CREATE TABLE IF NOT EXISTS source_descriptor (
  source_id text PRIMARY KEY,
  connector_id text NOT NULL,
  source_kind text NOT NULL,
  canonical_locator text NOT NULL UNIQUE,
  display_locator text NOT NULL DEFAULT '',
  owner text NOT NULL,
  author text,
  publisher text,
  workspace_id text NOT NULL,
  tenant_id text NOT NULL,
  classification jsonb NOT NULL,
  license jsonb NOT NULL,
  retention jsonb NOT NULL,
  lifecycle jsonb NOT NULL,
  registered_at timestamptz NOT NULL,
  registered_by text NOT NULL
);

CREATE TABLE IF NOT EXISTS source_snapshot (
  snapshot_id text PRIMARY KEY,
  source_id text NOT NULL REFERENCES source_descriptor(source_id),
  connector_id text NOT NULL,
  source_kind text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  snapshot_kind text NOT NULL CHECK (snapshot_kind IN ('content', 'tombstone')),
  tombstone_reason text,
  canonical_url text,
  canonical_message_id text,
  canonical_repository_id text,
  canonical_object_id text,
  canonical_locator text NOT NULL,
  canonicalization_version text NOT NULL,
  raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),
  normalized_sha256 text NOT NULL CHECK (normalized_sha256 ~ '^[0-9a-f]{64}$'),
  author text,
  publisher text,
  published_at timestamptz,
  event_time timestamptz,
  observed_at timestamptz NOT NULL,
  fetched_at timestamptz NOT NULL,
  parent_snapshot_id text REFERENCES source_snapshot(snapshot_id),
  supersedes_snapshot_id text REFERENCES source_snapshot(snapshot_id),
  language text,
  mime_type text,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  extraction_status text NOT NULL CHECK (extraction_status IN ('COMPLETE', 'PARTIAL', 'FAILED', 'QUARANTINED')),
  acl jsonb NOT NULL,
  license jsonb NOT NULL,
  retention jsonb NOT NULL,
  fetch_provenance jsonb NOT NULL,
  appended_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (canonical_locator, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS source_snapshot_raw_digest_idx
  ON source_snapshot (raw_sha256, canonical_locator);

CREATE TABLE IF NOT EXISTS content_segment (
  segment_id text PRIMARY KEY,
  snapshot_id text NOT NULL REFERENCES source_snapshot(snapshot_id),
  source_id text NOT NULL REFERENCES source_descriptor(source_id),
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  coordinates jsonb NOT NULL,
  text text,
  text_sha256 text NOT NULL CHECK (text_sha256 ~ '^[0-9a-f]{64}$'),
  original_language text,
  normalized_language text,
  extraction jsonb NOT NULL,
  coverage jsonb,
  embedded_instruction_classification jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('COMPLETE', 'PARTIAL', 'FAILED', 'QUARANTINED'))
);

CREATE TABLE IF NOT EXISTS source_lineage (
  lineage_id text PRIMARY KEY,
  relation text NOT NULL CHECK (relation IN ('exact_duplicate', 'mirror', 'translation', 'quotation', 'repost', 'derived')),
  upstream_snapshot_id text NOT NULL REFERENCES source_snapshot(snapshot_id),
  downstream_snapshot_id text NOT NULL REFERENCES source_snapshot(snapshot_id),
  evidence jsonb NOT NULL,
  confidence double precision CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  automated boolean NOT NULL,
  status text NOT NULL CHECK (status IN ('candidate', 'confirmed')),
  confirmed_by text,
  created_at timestamptz NOT NULL,
  CHECK (upstream_snapshot_id <> downstream_snapshot_id)
);

CREATE TABLE IF NOT EXISTS ingestion_run (
  run_id text PRIMARY KEY,
  executor_id text NOT NULL,
  pid bigint,
  nonce text NOT NULL,
  output_root text NOT NULL,
  frozen_inputs jsonb NOT NULL,
  environment jsonb NOT NULL,
  counts jsonb NOT NULL,
  started_at timestamptz,
  finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS ingestion_event (
  event_id bigserial PRIMARY KEY,
  run_id text REFERENCES ingestion_run(run_id),
  operation_id text NOT NULL,
  workspace_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS source_proposal (
  proposal_id text PRIMARY KEY,
  proposer text NOT NULL,
  candidate_locator text NOT NULL,
  proposed_source_kind text NOT NULL,
  reason text NOT NULL,
  expected_domain text NOT NULL,
  uncertainty jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('PROPOSED', 'REVIEW_REQUIRED', 'APPROVED', 'REJECTED')),
  reviewed_by text,
  decision_reason text,
  decided_at timestamptz,
  created_at timestamptz NOT NULL
);

-- Idempotency ledger: one terminal per (workspace, operation). Replays must
-- return the recorded terminal instead of re-executing.
CREATE TABLE IF NOT EXISTS ingestion_operation (
  workspace_id text NOT NULL,
  operation_id text NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'INTENT' CHECK (status IN (
    'INTENT', 'COMMITTED', 'BLOCKED_CONNECTOR', 'ACCESS_DENIED', 'TOMBSTONED',
    'QUARANTINED', 'FAILED', 'CANCELLED', 'RECONCILIATION_REQUIRED')),
  outcome jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (workspace_id, operation_id),
  CHECK ((status = 'INTENT') = (outcome IS NULL AND completed_at IS NULL))
);

-- Append-only enforcement: payload tables reject UPDATE and DELETE.
-- Exceptions (controlled, server-side-only transitions):
--   ingestion_operation: exactly one INTENT -> terminal transition;
--   source_descriptor: a single lifecycle transition to 'tombstoned'
--     (deletion of the source), with every other column immutable.
CREATE OR REPLACE FUNCTION veritas_ingestion_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'APPEND_ONLY_VIOLATION: % % on %', TG_OP, TG_TABLE_NAME, 'append-only';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION veritas_descriptor_tombstone_transition() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'APPEND_ONLY_VIOLATION: DELETE on source_descriptor';
  END IF;
  IF NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.canonical_locator IS DISTINCT FROM OLD.canonical_locator
     OR NEW.display_locator IS DISTINCT FROM OLD.display_locator
     OR NEW.owner IS DISTINCT FROM OLD.owner
     OR NEW.author IS DISTINCT FROM OLD.author
     OR NEW.publisher IS DISTINCT FROM OLD.publisher
     OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.classification IS DISTINCT FROM OLD.classification
     OR NEW.license IS DISTINCT FROM OLD.license
     OR NEW.retention IS DISTINCT FROM OLD.retention
     OR NEW.registered_at IS DISTINCT FROM OLD.registered_at
     OR NEW.registered_by IS DISTINCT FROM OLD.registered_by THEN
    RAISE EXCEPTION 'DESCRIPTOR_IMMUTABLE: only the lifecycle may transition to tombstoned';
  END IF;
  IF OLD.lifecycle->>'state' = 'tombstoned' THEN
    RAISE EXCEPTION 'DESCRIPTOR_ALREADY_TOMBSTONED';
  END IF;
  IF NEW.lifecycle->>'state' <> 'tombstoned' THEN
    RAISE EXCEPTION 'DESCRIPTOR_TRANSITION_INVALID: only enabled/blocked -> tombstoned is allowed';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION veritas_ingestion_operation_transition() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'APPEND_ONLY_VIOLATION: DELETE on ingestion_operation';
  END IF;
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
     OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'OPERATION_IDENTITY_IMMUTABLE: identity columns cannot change';
  END IF;
  IF OLD.status <> 'INTENT' THEN
    RAISE EXCEPTION 'OPERATION_ALREADY_TERMINAL: % cannot change after terminal', OLD.status;
  END IF;
  IF NEW.status = 'INTENT' THEN
    RAISE EXCEPTION 'OPERATION_TRANSITION_INVALID: INTENT cannot be modified in place';
  END IF;
  NEW.completed_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS source_descriptor_tombstone ON source_descriptor;
CREATE TRIGGER source_descriptor_tombstone
  BEFORE UPDATE OR DELETE ON source_descriptor
  FOR EACH ROW EXECUTE FUNCTION veritas_descriptor_tombstone_transition();

DROP TRIGGER IF EXISTS source_snapshot_append_only ON source_snapshot;
CREATE TRIGGER source_snapshot_append_only
  BEFORE UPDATE OR DELETE ON source_snapshot
  FOR EACH ROW EXECUTE FUNCTION veritas_ingestion_append_only();

DROP TRIGGER IF EXISTS content_segment_append_only ON content_segment;
CREATE TRIGGER content_segment_append_only
  BEFORE UPDATE OR DELETE ON content_segment
  FOR EACH ROW EXECUTE FUNCTION veritas_ingestion_append_only();

DROP TRIGGER IF EXISTS source_lineage_append_only ON source_lineage;
CREATE TRIGGER source_lineage_append_only
  BEFORE UPDATE OR DELETE ON source_lineage
  FOR EACH ROW EXECUTE FUNCTION veritas_ingestion_append_only();

DROP TRIGGER IF EXISTS ingestion_event_append_only ON ingestion_event;
CREATE TRIGGER ingestion_event_append_only
  BEFORE UPDATE OR DELETE ON ingestion_event
  FOR EACH ROW EXECUTE FUNCTION veritas_ingestion_append_only();

DROP TRIGGER IF EXISTS ingestion_operation_transition ON ingestion_operation;
CREATE TRIGGER ingestion_operation_transition
  BEFORE UPDATE OR DELETE ON ingestion_operation
  FOR EACH ROW EXECUTE FUNCTION veritas_ingestion_operation_transition();
