CREATE TABLE IF NOT EXISTS veritas_demo_tasks (
  id text PRIMARY KEY,
  title text NOT NULL,
  description text NOT NULL,
  status text NOT NULL DEFAULT 'BACKLOG',
  priority text NOT NULL DEFAULT 'Medium',
  agent text NOT NULL DEFAULT 'Unassigned',
  category text NOT NULL DEFAULT 'Platform',
  criteria jsonb NOT NULL DEFAULT '[]'::jsonb,
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS veritas_demo_events (
  id bigserial PRIMARY KEY,
  task_id text NOT NULL REFERENCES veritas_demo_tasks(id) ON DELETE RESTRICT,
  action text NOT NULL,
  detail text NOT NULL,
  revision integer NOT NULL CHECK (revision > 0),
  operation_id text NOT NULL UNIQUE,
  request_hash text,
  snapshot jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS veritas_demo_events_task_created_idx
  ON veritas_demo_events (task_id, created_at);
