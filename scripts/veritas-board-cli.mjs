#!/usr/bin/env node
// S2-007 LIVE Agent Board client.
//
// THIS IS NOT THE PUBLIC DEMO CLI. `scripts/veritas-cli.mjs` is the client of
// the PUBLIC_SYNTHETIC_DEMO surface (`/api/board`, `src/lib/board.ts`): a
// public planning fixture with no authentication, no tenancy, no leases, no
// scheduler and no execution. This file is the client of the LIVE board
// (`/api/agent-board`), where every request is authenticated server-side,
// every read is ACL-checked, every mutation is idempotency-keyed and every
// refusal is a typed `board-error` document.
//
// CREDENTIALS
//   * The bearer token comes from the ENVIRONMENT ONLY
//     (`VERITAS_BOARD_TOKEN`). It is never accepted as a command-line flag:
//     a flag lands in the shell history and in the process table of every
//     other process on the host.
//   * NO SECRET IS EVER PRINTED. The token is only ever placed in an
//     `Authorization` header. Errors are printed as the server's typed
//     document (code, message, retryable, detail), never as a stack trace and
//     never with request headers attached.
//   * Without a token this client sends nothing. It does not invent a
//     principal, a workspace or an identity — the server resolves those.
//
// IDEMPOTENCY
//   A mutation carries an `Idempotency-Key` header. Pass
//   `--idempotency-key <64 hex>` to control it; otherwise it is the SHA-256 of
//   the canonical request (method, path and arguments), so re-running the SAME
//   logical command replays the SAME key and the server replays its committed
//   result instead of committing twice. The command identity is part of the
//   digest, so two different commands never share a key. No randomness and no
//   clock are involved, so the behaviour is reproducible.
//
// HONEST LIMITS
//   * `create` does NOT fabricate a task: a `BoardTask` needs immutable
//     brief/policy/manifest digests that only a real producer may compute, so
//     the document is read from a file (`--file`) or passed inline
//     (`--json`) and the server validates it against
//     contracts/board-task.schema.json.
//   * This client never claims an execution happened. A refusal is reported
//     with the server's code and the process exits non-zero.
//
// EXIT CODES
//   0 success | 2 usage error | 3 transport failure (no server/reachable)
//   4 the board refused with a typed error (the code is in the JSON on stderr)
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const BASE = (process.env.VERITAS_BOARD_URL || 'http://localhost:3000/api/agent-board').replace(/\/+$/, '');
const TOKEN = process.env.VERITAS_BOARD_TOKEN || '';
const USAGE = `Usage: node scripts/veritas-board-cli.mjs <command> [flags]

Client of the LIVE Agent Board (${BASE}). Credentials come from the
environment: VERITAS_BOARD_URL, VERITAS_BOARD_TOKEN.

  capabilities                       GET  /capabilities   (discovery)
  discovery                          GET  /capabilities   (alias)
  tasks        --workspace <ws> [--state S] [--limit N]
                                         GET  /tasks
  task <task_id>                      GET  /tasks/<task_id>
  create       --file <board-task.json> | --json <document>
                                         POST /tasks
  transition  <task_id> --to <STATE> --revision <n> [--reason <text>]
                                         POST /tasks/<task_id>/transition
  claim        <task_id> --adapter <adapter_id> [--ttl-ms <n>] [--revision <n>]
                                         POST /tasks/<task_id>/claim
  dispatch-plan --workspace <ws>       POST /dispatch/plan
  outbox       --workspace <ws> [--dispatch-state S] [--limit N]
                                         GET  /outbox
  outbox-recover --workspace <ws>      POST /outbox/recover
  audit        --workspace <ws> [--task <task_id>] [--limit N]
                                         GET  /audit

Every mutation accepts --idempotency-key <64 lowercase hex characters>;
without it the key is derived from the request so a re-run replays instead of
committing twice. States are the nine board states: BACKLOG READY CLAIMED
RUNNING BLOCKED IN_REVIEW DONE FAILED CANCELLED.`;

/** Every command: its routes, its positional arguments and its flag -> argument map. */
const COMMANDS = {
  capabilities: { method: 'GET', path: '/capabilities' },
  discovery: { method: 'GET', path: '/capabilities' },
  tasks: {
    method: 'GET',
    path: '/tasks',
    flags: { workspace: 'workspace_id', state: 'state', limit: 'limit' },
    required: ['workspace_id'],
  },
  task: { method: 'GET', path: '/tasks/{task_id}', positional: ['task_id'] },
  create: { method: 'POST', path: '/tasks', flags: { file: false, json: false } },
  transition: {
    method: 'POST',
    path: '/tasks/{task_id}/transition',
    positional: ['task_id'],
    flags: { to: 'to_state', revision: 'expected_revision', reason: 'reason' },
  },
  // `tasks.claim` takes the adapter, the TTL and the revision; the workspace
  // is not a claim argument (the command resolves it from the task), so this
  // client does not offer a flag the boundary would refuse.
  claim: {
    method: 'POST',
    path: '/tasks/{task_id}/claim',
    positional: ['task_id'],
    flags: { adapter: 'adapter_id', 'ttl-ms': 'ttl_ms', revision: 'expected_revision' },
    required: ['adapter_id'],
  },
  'dispatch-plan': {
    method: 'POST',
    path: '/dispatch/plan',
    flags: { workspace: 'workspace_id' },
    required: ['workspace_id'],
  },
  outbox: {
    method: 'GET',
    path: '/outbox',
    flags: { workspace: 'workspace_id', 'dispatch-state': 'dispatch_state', limit: 'limit' },
    required: ['workspace_id'],
  },
  'outbox-recover': {
    method: 'POST',
    path: '/outbox/recover',
    flags: { workspace: 'workspace_id' },
    required: ['workspace_id'],
  },
  audit: {
    method: 'GET',
    path: '/audit',
    flags: { workspace: 'workspace_id', task: 'task_id', limit: 'limit' },
    required: ['workspace_id'],
  },
  help: { method: 'GET', path: '/capabilities' },
};

class UsageError extends Error {}

function parseArgv(argv) {
  const name = argv[0];
  const spec = COMMANDS[name];
  if (!spec) throw new UsageError(`unknown command ${String(name)}`);
  const values = {};
  const positional = [];
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    const key = eq === -1 ? token.slice(2) : token.slice(2, eq);
    if (key === 'idempotency-key') {
      values.idempotency_key = eq === -1 ? argv[(index += 1)] : token.slice(eq + 1);
      continue;
    }
    if (!Object.hasOwn(spec.flags ?? {}, key)) {
      throw new UsageError(`unknown flag --${key} for ${name}`);
    }
    const value = eq === -1 ? argv[(index += 1)] : token.slice(eq + 1);
    if (value === undefined) throw new UsageError(`--${key} needs a value`);
    // A flag mapped to `false` is consumed by the CLIENT (a local input such
    // as `--file`) and is never forwarded as a command argument.
    const target = spec.flags[key];
    if (target === false) values[key] = value;
    else values[target] = value;
  }
  for (const slot of spec.positional ?? []) {
    const value = positional.shift();
    if (value === undefined || value === '') throw new UsageError(`${name} needs <${slot}>`);
    values[slot] = value;
  }
  if (positional.length > 0) throw new UsageError(`unexpected argument ${positional[0]}`);
  // A required argument is required HERE, not discovered as a server error:
  // these commands are scoped to one workspace and the client refuses to send
  // a request whose scope is missing.
  for (const key of spec.required ?? []) {
    if (values[key] !== undefined && values[key] !== '') continue;
    // The message names the FLAG the user types, not the argument the server
    // receives: `--workspace`, not `--workspace-id`.
    const flag = Object.entries(spec.flags ?? {}).find(([, target]) => target === key)?.[0]
      ?? key.replace(/_/g, '-');
    throw new UsageError(`${name} needs --${flag}`);
  }
  return { spec, values };
}

const INTEGER_FLAGS = new Set(['limit', 'expected_revision', 'ttl_ms']);

/** Coerce the two argument kinds a flag can carry, and refuse everything else. */
function coerceArgs(values) {
  const args = {};
  for (const [key, raw] of Object.entries(values)) {
    if (key === 'idempotency_key') {
      args.idempotency_key = raw;
      continue;
    }
    if (raw === undefined) continue;
    if (INTEGER_FLAGS.has(key)) {
      if (!/^-?\d{1,9}$/.test(String(raw))) throw new UsageError(`--${key.replace(/_/g, '-')} must be an integer`);
      args[key] = Number(raw);
      continue;
    }
    if (typeof raw === 'string' && raw.length > 2000) throw new UsageError(`--${key} is too long`);
    args[key] = raw;
  }
  return args;
}

// Flags the CLIENT consumes and must never forward. `--file` names a local
// path and `--json` carries the raw document: sending either to the server
// would put a private local locator on the wire and would be refused as a
// non-canonical argument.
const CLIENT_ONLY_FLAGS = Object.freeze(['file', 'json']);

/** `create` reads a contract-valid BoardTask; it never invents digests. */
function readTaskDocument(values) {
  if (values.file && values.json) throw new UsageError('use either --file or --json, not both');
  let text;
  if (values.file) {
    try {
      text = readFileSync(values.file, 'utf8');
    } catch {
      // A missing or unreadable local file is a usage error, not a crash: no
      // stack trace, no local path dump beyond the argument the user typed.
      throw new UsageError(`--file could not be read: ${values.file}`);
    }
  } else if (values.json) {
    text = values.json;
  } else {
    throw new UsageError('create needs --file <board-task.json> or --json <document>');
  }
  return JSON.parse(text);
}

function buildRequest(name) {
  const { spec, values } = parseArgv(process.argv.slice(2));
  const args = coerceArgs(values);
  let path = spec.path;
  for (const [key, value] of Object.entries(args)) {
    if (!path.includes(`{${key}}`)) continue;
    path = path.replace(`{${key}}`, encodeURIComponent(String(value)));
    // The path already names the resource, so the argument is dropped: a
    // duplicated target is a second thing to keep in sync and the server
    // treats a body field that contradicts the path as a confused deputy.
    delete args[key];
  }
  if (name === 'create') args.task = readTaskDocument(values);
  for (const key of CLIENT_ONLY_FLAGS) delete args[key];
  // A GET carries no body, so its read filters MUST travel in the query
  // string — otherwise `--state READY` would be silently dropped and the
  // caller would read the wrong set. The keys are the route's closed
  // whitelist (`state`, `dispatch_state`, `task_id`, `limit`); the server
  // refuses anything else, so a typo fails loudly instead of lying.
  let query = '';
  if (spec.method === 'GET') {
    const filters = Object.entries(args).filter(([key]) => key !== 'idempotency_key');
    if (filters.length > 0) query = `?${new URLSearchParams(filters).toString()}`;
  }
  return { spec, path, query, args };
}

/**
 * Deterministic replay safety: the same logical request produces the same
 * key, so a re-run replays the committed result instead of committing twice.
 * The method and path are part of the digest on purpose: two different
 * commands with empty arguments must never share a key.
 */
function idempotencyKey(identity, args, given) {
  if (given !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(given)) {
      throw new UsageError('--idempotency-key must be 64 lowercase hexadecimal characters');
    }
    return given;
  }
  return createHash('sha256').update(JSON.stringify([identity, args]), 'utf8').digest('hex');
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

/** Usage is text, not a result: it is the only non-JSON thing this client prints. */
function printUsage() {
  process.stdout.write(`${USAGE}\n`);
}

function printRefusal(document, status) {
  // One JSON object, on stderr, so a pipeline reading stdout only ever sees
  // committed results. The server's typed code is the first field.
  process.stderr.write(`${JSON.stringify({ ok: false, status, error: document }, null, 2)}\n`);
}

async function main() {
  const name = process.argv[2];
  if (!name || name === 'help' || name === '--help' || name === '-h') {
    printUsage();
    return 0;
  }
  if (!Object.hasOwn(COMMANDS, name)) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: { code: 'CLI_USAGE', message: `unknown command ${name}` } }, null, 2)}\n`);
    return 2;
  }
  const { spec, path, query, args } = buildRequest(name);
  const headers = { accept: 'application/json' };
  if (TOKEN !== '') headers.authorization = `Bearer ${TOKEN}`;
  if (spec.method === 'POST') {
    headers['content-type'] = 'application/json';
    headers['idempotency-key'] = idempotencyKey(`${spec.method} ${path}`, args, args.idempotency_key);
  }
  let response;
  try {
    response = await fetch(`${BASE}${path}${query}`, {
      method: spec.method,
      headers,
      ...(spec.method === 'POST' ? { body: JSON.stringify(args) } : {}),
    });
  } catch (error) {
    // No stack dump: a transport failure is a fact about the endpoint, and a
    // stack trace would leak local paths for no benefit.
    process.stderr.write(`${JSON.stringify({
      ok: false,
      error: {
        code: 'CLI_TRANSPORT_UNREACHABLE',
        message: `the live board at ${BASE} could not be reached`,
        detail: String(error?.cause?.code ?? error?.code ?? error?.name ?? 'fetch failed'),
      },
    }, null, 2)}\n`);
    return 3;
  }
  const text = await response.text();
  let document = null;
  try {
    document = text === '' ? null : JSON.parse(text);
  } catch {
    document = null;
  }
  if (!response.ok) {
    printRefusal(document ?? { code: 'CLI_UNREADABLE_RESPONSE', message: 'the board did not answer with JSON' }, response.status);
    return 4;
  }
  print(document);
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof UsageError) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: { code: 'CLI_USAGE', message: error.message } }, null, 2)}\n`);
    process.exitCode = 2;
  } else if (error instanceof SyntaxError) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: { code: 'CLI_INPUT_NOT_JSON', message: error.message } }, null, 2)}\n`);
    process.exitCode = 2;
  } else {
    // Never a stack dump and never the token.
    process.stderr.write(`${JSON.stringify({
      ok: false,
      error: { code: 'CLI_UNEXPECTED', message: String(error?.message ?? 'unexpected client failure').slice(0, 300) },
    }, null, 2)}\n`);
    process.exitCode = 3;
  }
}
