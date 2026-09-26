// Separate-process participant in concurrency.test.mjs. This file is tracked
// so the cross-process claim test works in a clean checkout.
import { existsSync, writeFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

import { PostgresAgentBoardStore } from '../../../src/lib/agentboard/store.mjs';
import { isBoardError } from '../../../src/lib/agentboard/errors.mjs';

const label = process.env.S2_007_RACE_LABEL;
const barrier = process.env.S2_007_BARRIER;
const required = [
  'DATABASE_URL', 'S2_007_RACE_LABEL', 'S2_007_BARRIER', 'S2_007_TASK_ID',
  'S2_007_WORKSPACE_ID', 'S2_007_ADAPTER_ID', 'S2_007_EXPECTED_REVISION',
  'S2_007_ACTOR', 'S2_007_TTL_MS', 'S2_007_IDEMPOTENCY_KEY', 'S2_007_ARGS_DIGEST',
];
const missing = required.filter((name) => !process.env[name]);
if (missing.length > 0) {
  process.stderr.write(`race-child: missing ${missing.join(',')}\n`);
  process.exit(70);
}

function deterministicIds(namespace) {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    return `${kind}-${namespace}-${next.toString(36).padStart(6, '0')}`;
  };
}

const store = new PostgresAgentBoardStore({
  connectionString: process.env.DATABASE_URL,
  max: 2,
  seed: `s2-007-race-child-${label}`,
  ids: deterministicIds(label),
});

function report(row) {
  if (process.env.S2_007_RESULT) {
    writeFileSync(process.env.S2_007_RESULT, JSON.stringify(row), 'utf8');
  }
  process.stdout.write(`${JSON.stringify(row)}\n`);
}

try {
  writeFileSync(`${barrier}.ready.${label}`, 'ready', 'utf8');
  for (let attempt = 0; attempt < 300 && !existsSync(barrier); attempt += 1) {
    await delay(100);
  }
  if (!existsSync(barrier)) throw new Error('BARRIER_TIMEOUT');

  const result = await store.claimTask({
    taskId: process.env.S2_007_TASK_ID,
    workspaceId: process.env.S2_007_WORKSPACE_ID,
    adapterId: process.env.S2_007_ADAPTER_ID,
    ttlMs: Number(process.env.S2_007_TTL_MS),
    expectedRevision: Number(process.env.S2_007_EXPECTED_REVISION),
    actor: process.env.S2_007_ACTOR,
    actorKind: 'scheduler',
    idempotencyKey: process.env.S2_007_IDEMPOTENCY_KEY,
    argsDigest: process.env.S2_007_ARGS_DIGEST,
  });
  report({
    label, ok: true, typed: true, code: null, retryable: false,
    lease_id: result.lease_id, lease_state: result.lease.lease_state,
    fencing_token: result.fencing_token,
  });
} catch (error) {
  report({
    label, ok: false, typed: isBoardError(error), code: error?.code ?? null,
    retryable: isBoardError(error) ? error.retryable : null,
    message: String(error?.message ?? error).slice(0, 200),
  });
} finally {
  await store.close();
}
