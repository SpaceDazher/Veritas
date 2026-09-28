// S2-007 Agent Board HTTP boundary (issue #7 §5, frozen spec §3.6).
//
// WHY THIS FILE EXISTS
// `commands.mjs` is the only surface that may read or mutate the live board.
// This module is the TRANSPORT ADAPTER in front of it and owns exactly three
// transport concerns, nothing else:
//
//   1. turning a typed `BoardError.code` into an HTTP status (a translation
//      table, not a policy);
//   2. authenticating the principal SERVER-SIDE, before any argument is read;
//   3. turning `method + path (+ body)` into exactly one COMMANDS entry and
//      delegating to `commands.execute`.
//
// Everything else — states, transitions, guards, ACL, budgets, leases,
// fences, idempotency, reconciliation — stays in the frozen modules. A new
// rule must never be added here: a rule that only the HTTP layer enforces is
// a rule the CLI, the scheduler and the probes do not have.
//
// WHY THE PRINCIPAL CANNOT COME FROM THE REQUEST
// Issue §2 rule 3 (DATA IS NOT AUTHORITY) and the `principal_forgery` probe
// family: the actor is resolved from the `Authorization` header (or from a
// principal registry the host/test process installed), and the resolver is
// the only thing that may name a principal. A `principal_id` / `principal` /
// `actor` / `actor_kind` field in the body, the query string or the ambient
// environment is a FORGERY and is refused with AUTH_REQUIRED before the
// command is even named. Every other authority-shaped argument
// (`fencing_token`, `lease_id`, `budget_grant`, `capabilities`, ...) is passed
// through UNCHANGED to `commands.execute`, which owns the confused-deputy
// check ("must equal the server-resolved value, else AUTH_REQUIRED"); this
// module never merges, widens or re-interprets one.
//
// WHY THE STATUS TABLE IS EXHAUSTIVE AND CHECKED AT IMPORT TIME
// A new code in the frozen `ERROR_CODES` set without a transport decision
// would silently inherit the 500 default and hide a boundary change. The
// import-time assertion below turns that drift into an immediate, loud
// failure, exactly like the contract registry does for a missing schema.
//
// WHY A FAILURE IS NEVER A 200
// `handleRequest` returns `{ status, body }` and a body is only ever a
// contract-valid `board-error` document when a refusal happened. The single
// exception is CANCELLED: a cancelled run is a real, committed outcome (the
// task and the lease are in CANCELLED state), so it travels as 200 with the
// typed document. Every other code is 401/403/409/422/429/504/500.
//
// WHY THERE IS NO CORS AND NO PREFLIGHT
// This is a same-origin, server-to-server and CLI-to-server surface. A
// cross-origin MUTATION is refused with 403 (BLOCKED_POLICY); an unknown
// origin on a read is irrelevant because reads are ACL-checked in
// `commands.execute` against the resolved principal, never against the
// browser. There is deliberately no permissive CORS header anywhere: a
// permissive one would be a second, browser-shaped authorization story.
//
// WHY DISCOVERY IS SERVED BY `commands.capabilities()`
// The frozen spec gives the boundary a standalone `capabilities()` export for
// the discovery document, and `execute({ command: 'capabilities' })` is
// refused by `policy.assertCanonicalArguments` because a single-word command
// name does not match its dotted `COMMAND_RE`. The discovery route therefore
// calls the library's own discovery entry point, with the host's registered
// adapters, and every other route goes through `execute`. Both are library
// code: this module still decides nothing and still fails closed.
//
// WHAT IS NOT EXPOSED HERE, AND WHY
// `execution.start`, `execution.event`, `execution.collect_result`,
// `execution.cancel`, `budget.grant`, `budget.settle`, `adapters.register`,
// `adapters.health` and `dispatch.tick` are NOT routable over HTTP. They are
// the in-process control plane of the scheduler and the adapter transport:
// the first group needs the current fencing token and the live lease
// teardown, and the second group would let an external caller claim a task
// and issue a dispatch outside the bounded single-task scheduler loop. They
// stay reachable through `commands.execute` from the scheduler/adapter side
// of the process, where the fence and the actor kind are known server-side.
// Exposing them here would widen the external surface without a consumer.
//
// DETERMINISM
// No `Date.now()`, no `Math.random()`, no bare `new Date()`: the instant
// stamped on an error document comes from the store's DATABASE clock, then
// from an injected clock, and only if neither exists does the document carry
// the fixed epoch constant `EPOCH_ISO` (a visible "no authoritative clock"
// marker, never a plausible-looking lie).
import { COMMANDS, capabilities, execute } from './commands.mjs';
import { ERROR_CODES, isKnownState } from './constants.mjs';
import { assertBoardContract } from './contracts.mjs';
import {
  AuthRequired,
  BlockedPolicy,
  NeedsInput,
  ProviderFailure,
  isBoardError,
  toBoardError,
} from './errors.mjs';

// --- transport decisions ----------------------------------------------------

// The one place where a typed board refusal becomes a status code. It is a
// TRANSLATION: nothing here decides whether something is allowed.
export const HTTP_STATUS_BY_CODE = Object.freeze({
  // No authenticated server-side principal, or a payload tried to assert one.
  AUTH_REQUIRED: 401,
  // The actor is known but is not allowed to see/act on this resource, or the
  // request is not canonical, or the isolation profile cannot be proven, or
  // the adapter/registration/grant disagree on capabilities.
  ACL_DENIED: 403,
  BLOCKED_POLICY: 403,
  BLOCKED_SANDBOX: 403,
  CAPABILITY_MISMATCH: 403,
  // The request conflicts with committed state. A client MUST re-read before
  // retrying; these codes are non-retryable by contract.
  IDEMPOTENCY_CONFLICT: 409,
  REVISION_CONFLICT: 409,
  STALE_FENCE: 409,
  RECONCILIATION_REQUIRED: 409,
  UNKNOWN_OUTCOME: 409,
  // The request itself is not answerable: a malformed document, an illegal
  // edge, an unknown contract version or a missing/invalid input.
  MALFORMED_RESULT: 422,
  TRANSITION_NOT_ALLOWED: 422,
  CONTRACT_VERSION_UNKNOWN: 422,
  NEEDS_INPUT: 422,
  // A budget scope is exhausted or was never assigned. Not a client bug and
  // not a retry: an operator has to assign a budget.
  BUDGET_EXCEEDED: 429,
  // The executor did not answer in time or is not installed/reachable. The
  // caller may re-read state, but a blind re-issue of the side effect is NOT
  // authorized: the outcome may already be committed.
  TIMEOUT: 504,
  AGENT_UNAVAILABLE: 504,
  // A cancelled run is a real outcome, not a server error: the task, the
  // lease and the journal are in CANCELLED and the caller may read them.
  CANCELLED: 200,
  // Fail-closed default. PROVIDER_FAILURE, EMPTY_RESPONSE,
  // NOT_RUN_REAL_ADAPTER and NOT_RUN_DB are not in the frozen transport
  // table: none of them is a caller's mistake and none of them is fixable by
  // the caller, so they answer 500 and are logged/handled by an operator. A
  // board that cannot reach its database or has no proven real adapter is a
  // server-side fact, not a client error and never a 200.
  PROVIDER_FAILURE: 500,
  EMPTY_RESPONSE: 500,
  NOT_RUN_REAL_ADAPTER: 500,
  NOT_RUN_DB: 500,
});

// Fail-closed drift guard: a code the transport has no decision for, or a
// decision for a code that no longer exists, aborts at import time. A silent
// default is exactly the failure mode this table must not have.
{
  const known = new Set(ERROR_CODES);
  const mapped = Object.keys(HTTP_STATUS_BY_CODE);
  const undecided = ERROR_CODES.filter((code) => !mapped.includes(code));
  const unknown = mapped.filter((code) => !known.has(code));
  if (undecided.length || unknown.length) {
    throw new Error(`HTTP_STATUS_TABLE_DRIFT:undecided=${undecided.join(',')}:unknown=${unknown.join(',')}`);
  }
}

const HTTP_STATUS_DEFAULT = 500;

/**
 * Map a typed board error onto its HTTP status. A non-BoardError value is a
 * transport defect: it maps to the 500 default, never to 200.
 */
export function toHttpStatus(error) {
  if (!isBoardError(error)) return HTTP_STATUS_DEFAULT;
  const status = HTTP_STATUS_BY_CODE[error.code];
  if (status === undefined) return HTTP_STATUS_DEFAULT;
  // Defence in depth: only CANCELLED may answer 200, and only because a
  // cancellation is a committed outcome. Any other success-looking status on
  // a failure would be a lie.
  return status === 200 && error.code !== 'CANCELLED' ? HTTP_STATUS_DEFAULT : status;
}

// --- the routable surface ---------------------------------------------------

// The HTTP surface is a DELIBERATE SUBSET of COMMANDS. Each entry names one
// command and nothing else; the command set itself is the frozen list in
// commands.mjs and is re-checked at dispatch time, so this table can never
// smuggle in a command that the boundary does not implement.
//
// `mutating: true` means the route requires an `Idempotency-Key` header and
// that the same key may safely be re-issued. A `:name` segment becomes a
// command argument of that name and is authoritative: a body field of the
// same name must either be absent or carry the SAME value. `queryKeys` is a
// closed whitelist of read filters — no identity, grant, budget, approval,
// lease or fence may ever be taken from a query string. `discovery: true`
// marks the two aliases of the discovery document, which is served by the
// library's own `capabilities()` entry point (see the note below the table).
export const HTTP_ROUTES = Object.freeze([
  // --- discovery -----------------------------------------------------------
  { method: 'GET', segments: ['capabilities'], command: 'capabilities', mutating: false, queryKeys: [], discovery: true },
  { method: 'GET', segments: ['discovery'], command: 'capabilities', mutating: false, queryKeys: [], discovery: true },
  // --- reads ---------------------------------------------------------------
  { method: 'GET', segments: ['tasks'], command: 'tasks.list', mutating: false, queryKeys: ['workspace_id', 'state', 'limit'] },
  { method: 'GET', segments: ['tasks', ':task_id'], command: 'tasks.get', mutating: false, queryKeys: [] },
  { method: 'GET', segments: ['adapters'], command: 'adapters.list', mutating: false, queryKeys: ['workspace_id', 'limit'] },
  { method: 'GET', segments: ['outbox'], command: 'outbox.list', mutating: false, queryKeys: ['workspace_id', 'dispatch_state', 'limit'] },
  { method: 'GET', segments: ['audit'], command: 'audit.list', mutating: false, queryKeys: ['workspace_id', 'task_id', 'limit'] },
  // A dispatch PLAN is a pure read of tasks/adapters/budgets and commits
  // nothing, so it needs no idempotency key. The decision it returns is the
  // scheduler's proposal, never an execution.
  { method: 'POST', segments: ['dispatch', 'plan'], command: 'dispatch.plan', mutating: false, queryKeys: [] },
  // --- mutations -----------------------------------------------------------
  { method: 'POST', segments: ['tasks'], command: 'tasks.create', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['tasks', ':task_id', 'transition'], command: 'tasks.transition', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['tasks', ':task_id', 'claim'], command: 'tasks.claim', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['tasks', ':task_id', 'cancel'], command: 'tasks.cancel', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['leases', ':lease_id', 'renew'], command: 'tasks.lease.renew', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['leases', ':lease_id', 'release'], command: 'tasks.lease.release', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['leases', ':lease_id', 'reassign'], command: 'tasks.lease.reassign', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['leases', ':lease_id', 'revoke'], command: 'tasks.lease.revoke', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['outbox', 'dispatch'], command: 'outbox.dispatch', mutating: true, queryKeys: [] },
  // Recovery reconstructs canonical state and escalates unresolved rows; it
  // re-issues NO side effect and is still a write, so it stays keyed.
  { method: 'POST', segments: ['outbox', 'recover'], command: 'outbox.recover', mutating: true, queryKeys: [] },
  { method: 'POST', segments: ['reconciliations'], command: 'reconciliation.record', mutating: true, queryKeys: [] },
]);

// Commands this surface may answer WITHOUT an authenticated principal. It is
// the discovery document only: a static description of the live board's
// contract, states and capabilities, with no workspace data in it. Every other
// command is refused with AUTH_REQUIRED before it is named. `commands.mjs`
// still decides whether an anonymous principal is acceptable for discovery;
// this table only refuses to SEND an anonymous request anywhere else.
const ANONYMOUS_COMMANDS = new Set(['capabilities']);

// Reads may be attributed to the non-approving `system` actor kind, because a
// read commits nothing and is still ACL-checked against the resolved
// principal. A MUTATION must name its actor kind server-side: defaulting it
// to `system` would be an unattributed authority grant, so it is refused.
const READ_COMMANDS = new Set([
  'capabilities', 'tasks.list', 'tasks.get', 'adapters.list', 'outbox.list', 'audit.list', 'dispatch.plan',
]);

// Identity may only be asserted by the resolver. A body carrying any of these
// names is a forgery attempt, not a redundant copy of the truth.
const FORBIDDEN_BODY_KEYS = Object.freeze(['principal_id', 'principal', 'actor', 'actor_kind']);

const IDEMPOTENCY_HEADER = 'idempotency-key';
const HEX64_RE = /^[0-9a-f]{64}$/;
const MAX_TOKEN_LENGTH = 4096;
const MAX_BODY_BYTES = 1_048_576;
const MAX_QUERY_LIMIT = 200;
const EPOCH_ISO = '1970-01-01T00:00:00.000Z';
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// --- small, transport-only helpers -----------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && !(typeof Headers !== 'undefined' && value instanceof Headers)
    && !(value instanceof Map);
}

function headerValue(headers, name) {
  if (!headers) return null;
  const wanted = name.toLowerCase();
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    const direct = headers.get(name);
    return direct === null ? null : String(direct);
  }
  if (typeof Map !== 'undefined' && headers instanceof Map) {
    for (const [key, value] of headers.entries()) {
      if (String(key).toLowerCase() === wanted) return String(value);
    }
    return null;
  }
  if (isPlainObject(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      if (String(key).toLowerCase() === wanted && value !== undefined && value !== null) return String(value);
    }
  }
  return null;
}

/**
 * Reduce a request path to `/segment/segment` form. Query and fragment are
 * split off, an empty path is `/`, duplicate slashes collapse and a NUL or
 * traversal segment is refused: a URL is untrusted input, and `..` must not
 * become a path parameter before any id family is checked downstream.
 */
function normalizePath(path, basePath) {
  let raw = typeof path === 'string' ? path : '';
  const hashAt = raw.indexOf('#');
  if (hashAt !== -1) raw = raw.slice(0, hashAt);
  const queryAt = raw.indexOf('?');
  let query = '';
  if (queryAt !== -1) {
    query = raw.slice(queryAt + 1);
    raw = raw.slice(0, queryAt);
  }
  if (raw === '') raw = '/';
  if (!raw.startsWith('/')) raw = `/${raw}`;
  const base = typeof basePath === 'string' ? basePath.replace(/\/+$/, '') : '';
  if (base && base !== '/' && (raw === base || raw.startsWith(`${base}/`))) {
    raw = raw.slice(base.length) || '/';
  }
  const segments = [];
  for (const part of raw.split('/')) {
    if (part === '') continue;
    if (part === '.' || part === '..' || part.includes('\0') || part.includes('\\')) {
      throw new NeedsInput('HTTP_PATH_SEGMENT_INVALID', 'the request path is not a canonical board path');
    }
    let decoded;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      throw new NeedsInput('HTTP_PATH_SEGMENT_INVALID', 'the request path is not percent-decodable');
    }
    if (decoded === '' || decoded === '.' || decoded === '..' || decoded.includes('/') || decoded.includes('\0')) {
      throw new NeedsInput('HTTP_PATH_SEGMENT_INVALID', 'the request path is not a canonical board path');
    }
    segments.push(decoded);
  }
  return { segments, query };
}

/** Map `method + segments` onto exactly one route entry. */
function matchRoute(method, segments) {
  const wanted = String(method ?? '').toUpperCase();
  const shapeMatches = HTTP_ROUTES.filter((route) => route.segments.length === segments.length
    && route.segments.every((part, index) => part.startsWith(':') || part === segments[index]));
  if (shapeMatches.length === 0) {
    throw new NeedsInput('HTTP_ROUTE_UNKNOWN', 'no live-board route answers this path');
  }
  const route = shapeMatches.find((candidate) => candidate.method === wanted);
  if (!route) {
    throw new NeedsInput('HTTP_METHOD_NOT_ALLOWED', `method ${wanted} is not served on this path`);
  }
  const pathArgs = {};
  route.segments.forEach((part, index) => {
    if (part.startsWith(':')) pathArgs[part.slice(1)] = segments[index];
  });
  return { route, pathArgs };
}

/**
 * Read filters for the read routes. The whitelist is closed: an unknown query
 * key is refused rather than ignored, so a typo (or a smuggled authority
 * field) can never be silently dropped. Identity and authority are not
 * queryable at all — that is the whole point of this function.
 */
function readQueryArgs(query, allowed) {
  const args = {};
  if (query === '') return args;
  for (const pair of query.split('&')) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const rawKey = eq === -1 ? pair : pair.slice(0, eq);
    const rawValue = eq === -1 ? '' : pair.slice(eq + 1);
    let key;
    let value;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
      value = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    } catch {
      throw new NeedsInput('HTTP_QUERY_INVALID', 'the query string is not percent-decodable');
    }
    if (!allowed.includes(key)) {
      throw new NeedsInput('HTTP_QUERY_NOT_ALLOWED', `query parameter ${key} is not a filter of this route`);
    }
    if (value === '') {
      throw new NeedsInput('HTTP_QUERY_INVALID', `query parameter ${key} needs a value`);
    }
    if (key === 'limit') {
      if (!/^\d{1,3}$/.test(value)) {
        throw new NeedsInput('HTTP_QUERY_INVALID', 'limit must be a positive integer');
      }
      const parsed = Number(value);
      if (parsed < 1 || parsed > MAX_QUERY_LIMIT) {
        throw new NeedsInput('HTTP_QUERY_INVALID', `limit must be between 1 and ${MAX_QUERY_LIMIT}`);
      }
      args[key] = parsed;
      continue;
    }
    if (key === 'state' && !isKnownState(value)) {
      throw new NeedsInput('HTTP_QUERY_INVALID', 'state is not one of the nine board states');
    }
    args[key] = value;
  }
  return args;
}

/**
 * Parse the request body. A JSON object, an already-parsed plain object, or
 * an empty body (which is `{}` — a POST with no arguments, not a missing
 * body). Anything else, including a JSON array or a scalar, is refused: a
 * command takes a named argument object, never a positional payload.
 */
function parseBody(body) {
  if (body === null || body === undefined) return {};
  if (typeof body === 'string') {
    const text = body.trim();
    if (text === '') return {};
    if (text.length > MAX_BODY_BYTES) {
      throw new NeedsInput('HTTP_BODY_TOO_LARGE', 'the request body exceeds the bounded size');
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new NeedsInput('HTTP_BODY_NOT_JSON', 'the request body is not JSON');
    }
    if (!isPlainObject(parsed)) {
      throw new NeedsInput('HTTP_BODY_NOT_OBJECT', 'the request body must be a JSON object');
    }
    return parsed;
  }
  if (isPlainObject(body)) return { ...body };
  throw new NeedsInput('HTTP_BODY_NOT_OBJECT', 'the request body must be a JSON object');
}

/** The idempotency key is a transport-level fact and must not be ambiguous. */
function resolveIdempotencyKey(headers, body, required) {
  const header = headerValue(headers, IDEMPOTENCY_HEADER);
  const fromBody = Object.hasOwn(body, 'idempotency_key') ? body.idempotency_key : undefined;
  if (header !== null && !HEX64_RE.test(header.trim())) {
    throw new NeedsInput(
      'IDEMPOTENCY_KEY_INVALID',
      `${IDEMPOTENCY_HEADER} must be 64 lowercase hexadecimal characters`,
    );
  }
  const fromHeader = header === null ? undefined : header.trim();
  if (fromHeader !== undefined && fromBody !== undefined && fromBody !== fromHeader) {
    throw new BlockedPolicy('IDEMPOTENCY_KEY_CONFLICT', 'the header and the body name different idempotency keys');
  }
  const key = fromHeader ?? fromBody;
  if (required && key === undefined) {
    throw new NeedsInput('IDEMPOTENCY_KEY_REQUIRED', `a mutating route requires the ${IDEMPOTENCY_HEADER} header`);
  }
  return key;
}

/** A cross-origin MUTATION is refused. Reads are ACL-checked downstream. */
function assertSameOrigin(headers, { requestOrigin, mutating }) {
  if (!mutating) return true;
  const origin = headerValue(headers, 'origin');
  if (origin === null) return true;
  const expected = new Set();
  if (typeof requestOrigin === 'string' && requestOrigin !== '') expected.add(requestOrigin);
  const host = headerValue(headers, 'host');
  if (host !== null && host !== '') {
    const proto = headerValue(headers, 'x-forwarded-proto') ?? 'https';
    expected.add(`${proto}://${host}`);
  }
  // No authoritative origin at all: the request cannot be shown to be
  // same-origin, so it is refused rather than trusted.
  if (expected.size === 0) {
    throw new BlockedPolicy('HTTP_CROSS_ORIGIN_MUTATION_BLOCKED', 'the request origin could not be established');
  }
  if (!expected.has(origin)) {
    throw new BlockedPolicy('HTTP_CROSS_ORIGIN_MUTATION_BLOCKED', 'a cross-origin mutation is refused');
  }
  return true;
}

/** `Authorization: Bearer <token>` and nothing else. */
function readBearerToken(headers) {
  const raw = headerValue(headers, 'authorization');
  if (raw === null) return null;
  const value = raw.trim();
  if (value.length > MAX_TOKEN_LENGTH) return null;
  const match = /^bearer[ ]+(.+)$/i.exec(value);
  if (!match) return null;
  const token = match[1].trim();
  if (token === '' || token.length > MAX_TOKEN_LENGTH) return null;
  return token;
}

/**
 * Resolve the principal SERVER-SIDE. The only inputs are the `Authorization`
 * header and a resolver the host (or a test) installed. Nothing in the body,
 * the query or the ambient environment can name a principal. A resolver that
 * throws, or a principal record without a `principal_id`, is an
 * AUTH_REQUIRED — a resolver defect must not become a 500 that leaks detail,
 * and it must certainly not become an anonymous mutation.
 */
async function resolvePrincipal({ principalResolver, token, request }) {
  const valid = (candidate) => (isPlainObject(candidate) && typeof candidate.principal_id === 'string'
    && candidate.principal_id !== '' ? candidate : null);
  if (typeof principalResolver === 'function') {
    let resolved;
    try {
      resolved = await principalResolver({ ...request, authorization: token, token });
    } catch {
      throw new AuthRequired('AUTH_REQUIRED', 'the principal resolver did not return a principal');
    }
    if (resolved === null || resolved === undefined) return null;
    const principal = valid(resolved);
    if (principal === null) {
      throw new AuthRequired('AUTH_REQUIRED', 'the resolved principal record is not a principal');
    }
    return principal;
  }
  if (principalResolver instanceof Map || isPlainObject(principalResolver)) {
    if (token === null) return null;
    const registered = principalResolver instanceof Map
      ? principalResolver.get(token)
      : Object.hasOwn(principalResolver, token) ? principalResolver[token] : undefined;
    if (registered === null || registered === undefined) return null;
    const principal = valid(registered);
    if (principal === null) {
      throw new AuthRequired('AUTH_REQUIRED', 'the registered principal record is not a principal');
    }
    return principal;
  }
  return null;
}

/**
 * The actor kind is a server-side fact, exactly like the principal. A host
 * may register one per principal (`actorKinds`) or carry it on the resolved
 * principal record. A read may fall back to the non-approving `system` kind;
 * a mutation may not, because "somebody did this" is not an authority.
 */
function resolveActorKind(principal, command, actorKinds) {
  const registered = isPlainObject(actorKinds) && principal
    ? actorKinds[principal.principal_id]
    : undefined;
  const candidate = registered ?? principal?.actor_kind;
  if (typeof candidate === 'string' && candidate !== '') return candidate;
  if (READ_COMMANDS.has(command)) return 'system';
  throw new AuthRequired(
    'ACTOR_KIND_UNRESOLVED',
    'a mutating command needs a server-resolved actor kind for this principal',
  );
}

function normalizeInstant(value) {
  if (value instanceof Date) {
    const time = value.getTime();
    return Number.isFinite(time) ? new Date(time).toISOString() : null;
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (ISO_MS_RE.test(text)) return text;
    const parsed = Date.parse(text);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value).toISOString();
  return null;
}

/**
 * The instant on an error document: the store's DATABASE clock first (the
 * board's authority for lease and expiry decisions), then an injected clock.
 * Only when neither exists does the document carry EPOCH_ISO, which is
 * visibly not a plausible time and therefore honest about the wiring gap.
 */
async function occurredAtIso({ store, clock }) {
  if (store && typeof store.dbNow === 'function') {
    try {
      const fromDb = normalizeInstant(await store.dbNow());
      if (fromDb !== null) return fromDb;
    } catch {
      // The database clock is unavailable (that is often WHY we are here).
      // Fall through to the injected clock; never to the process clock.
    }
  }
  const read = typeof clock === 'function' ? clock
    : isPlainObject(clock) && typeof clock.now === 'function' ? () => clock.now() : null;
  if (read) {
    const injected = normalizeInstant(read());
    if (injected !== null) return injected;
  }
  return EPOCH_ISO;
}

/**
 * A refusal is always a contract-valid `board-error` document, so an API
 * consumer parses one shape for success metadata and one for refusals. The
 * document is built by the frozen error class (which redacts and bounds) and
 * validated here; if the validation ever failed, the minimal document below
 * is still schema-valid, so a client never receives an unparseable body.
 */
function errorDocument(error, occurredAt) {
  const document = isBoardError(error) ? error.toDocument(occurredAt) : {
    contractVersion: '1.0.0',
    code: 'PROVIDER_FAILURE',
    message: 'the live board failed with an untyped error',
    retryable: false,
    detail: null,
    occurred_at: occurredAt,
  };
  try {
    return assertBoardContract('board-error', document);
  } catch {
    return {
      contractVersion: '1.0.0',
      code: document.code,
      message: String(document.message).slice(0, 500),
      retryable: document.retryable === true,
      detail: null,
      occurred_at: document.occurred_at,
    };
  }
}

// WHY SERVER-SIDE CONTEXT IS FORWARDED BLINDLY
// `commands.execute` accepts containment evidence (`workspaceRoots`,
// `realpath`), the proven `sandbox`, the S2-002 `authorizer`, a mandatory
// `requireAuthorizer` flag and an injected `ids` factory. Those are facts
// about the SERVER, not about the request, so this module forwards them when
// a host supplies them and NEVER lets a request supply them: no body, query or
// header reaches them. Forwarding is not a weakening — the guards they feed
// still run, and a host that omits them gets the fail-closed answer (a
// `workspace_ref` that cannot be proven contained is refused, not admitted).
const FORWARDED_CONTEXT = Object.freeze([
  'adapters', 'clock', 'transport', 'now', 'workspaceRoots', 'realpath',
  'sandbox', 'authorizer', 'requireAuthorizer', 'ids',
]);

function forwardedContext(request) {
  const out = {};
  for (const key of FORWARDED_CONTEXT) {
    if (request?.[key] !== undefined) out[key] = request[key];
  }
  return out;
}

// --- the request entry point ------------------------------------------------

/**
 * Handle one live-board HTTP request and return `{ status, body }`.
 *
 * The order of the checks IS the security property and must not be
 * reordered: normalise the path -> authenticate the principal server-side ->
 * resolve the route -> require a store for anything but discovery -> refuse a
 * cross-origin mutation -> read the body -> reject a forged identity ->
 * require an idempotency key for a mutation -> bind the path arguments and
 * the whitelisted read filters -> resolve the actor kind server-side ->
 * delegate to `commands.execute`. Nothing is read from the store and no side
 * effect can happen before a principal exists, and an unknown path never
 * reveals whether a principal would have been allowed to see it.
 *
 * @param {object} request
 * @param {string} request.method  HTTP method (`GET`/`POST` on this surface).
 * @param {string} request.path    Path BELOW the mount point (`/tasks/<id>`).
 * @param {object} [request.headers] Plain object, Map or Headers (lowercased lookup).
 * @param {object|string|null} [request.body] Parsed object or a raw JSON string.
 * @param {object|Function} [request.principalResolver] Server-side resolver or a token->principal registry.
 * @param {object} [request.actorKinds] Server-side principal_id -> actor kind.
 * @param {object} [request.store] The store `commands.execute` may use.
 * @param {object[]} [request.adapters] Registered adapters (execution is not routed here).
 * @param {object|Function} [request.clock] Injected clock.
 * @param {object} [request.transport] Adapter transport (execution is not routed here).
 * @param {string} [request.requestOrigin] Server-computed origin of this request.
 * @param {string} [request.basePath] Mount point to strip from `path`.
 * @param {string} [request.now] Fixed instant forwarded to `commands.execute`.
 * @param {object} [request.workspaceRoots] Server-side workspace roots for the containment guard.
 * @param {Function} [request.realpath] Server-side path resolver for the containment guard.
 * @param {object} [request.sandbox] The proven isolation profile.
 * @param {Function} [request.authorizer] The S2-002 authorization consult.
 * @param {boolean} [request.requireAuthorizer] Make the S2-002 consult unconditional.
 * @param {Function} [request.ids] An injected deterministic id factory.
 * @returns {Promise<{status: number, body: object}>}
 */
export async function handleRequest(request = {}) {
  const {
    method,
    path,
    headers = null,
    body = null,
    principalResolver,
    actorKinds,
    store,
    requestOrigin,
    basePath = '',
  } = request ?? {};

  // The failure envelope is built with whatever the request supplied, so even
  // a refused-before-anything request answers with a typed document.
  const envelope = async (error) => {
    const typed = isBoardError(error) ? error : toBoardError(error);
    return {
      status: toHttpStatus(typed),
      body: errorDocument(typed, await occurredAtIso({ store, clock: request?.clock })),
    };
  };

  try {
    if (typeof method !== 'string' || method.trim() === '') {
      throw new NeedsInput('HTTP_METHOD_MISSING', 'a method is required');
    }

    const { segments, query } = normalizePath(path, basePath);
    const token = readBearerToken(headers);
    const principal = await resolvePrincipal({
      principalResolver,
      token,
      request: { method: String(method).toUpperCase(), path: `/${segments.join('/')}`, headers },
    });

    // A null principal is only ever allowed to reach the discovery route, and
    // even there the only thing that can answer is the library's own
    // static discovery document.
    const { route, pathArgs } = matchRoute(method, segments);
    if (!COMMANDS.includes(route.command)) {
      throw new BlockedPolicy('HTTP_COMMAND_NOT_REGISTERED', `${route.command} is not a live-board command`);
    }
    if (principal === null && !ANONYMOUS_COMMANDS.has(route.command)) {
      throw new AuthRequired('AUTH_REQUIRED', 'an authenticated principal is required for this route');
    }
    if (route.command !== 'capabilities' && (store === null || store === undefined)) {
      // A wiring gap, not a caller mistake: the live board has no store, so
      // there is nothing to authorize against and nothing to commit. This is
      // a server-side fact (500), never a 200 and never a silent empty page.
      throw new ProviderFailure('HTTP_STORE_MISSING', 'the live board has no configured store');
    }

    assertSameOrigin(headers, { requestOrigin, mutating: route.mutating });

    const payload = parseBody(body);
    for (const key of FORBIDDEN_BODY_KEYS) {
      if (Object.hasOwn(payload, key)) {
        throw new AuthRequired('HTTP_FORGED_PRINCIPAL_IN_BODY', `a request body may not assert ${key}`);
      }
    }
    const idempotencyKey = resolveIdempotencyKey(headers, payload, route.mutating);

    // Path segments are authoritative; a body field of the same name may
    // only repeat them. Anything else is a confused-deputy attempt on the
    // target, and it is refused instead of merged.
    const args = { ...payload, ...pathArgs };
    for (const [key, value] of Object.entries(pathArgs)) {
      if (Object.hasOwn(payload, key) && payload[key] !== value) {
        throw new BlockedPolicy(
          'ARGUMENT_TARGET_MISMATCH',
          `body field ${key} does not name the resource in the path`,
        );
      }
    }
    if (idempotencyKey !== undefined) args.idempotency_key = idempotencyKey;
    if (route.mutating && args.idempotency_key === undefined) {
      throw new NeedsInput('IDEMPOTENCY_KEY_REQUIRED', `a mutating route requires the ${IDEMPOTENCY_HEADER} header`);
    }

    const queryArgs = readQueryArgs(query, route.queryKeys);
    for (const key of Object.keys(queryArgs)) {
      if (Object.hasOwn(args, key) && args[key] !== queryArgs[key]) {
        throw new BlockedPolicy('ARGUMENT_TARGET_MISMATCH', `query filter ${key} conflicts with the body`);
      }
      args[key] = queryArgs[key];
    }

    const actorKind = resolveActorKind(principal, route.command, actorKinds);

    const result = route.discovery === true
      ? {
        ok: true,
        // The library's own discovery document: the closed command
        // vocabulary, the contract digests and the honest executor status.
        // No workspace data, no principal data, no credential.
        data: capabilities({ adapters: Array.isArray(request?.adapters) ? request.adapters : [] }),
        revision: null,
        replayed: false,
      }
      : await execute({
        command: route.command,
        args,
        principal,
        actorKind,
        store,
        ...forwardedContext(request),
      });
    // A committed command result is reported as 200. `replayed: true` in the
    // BODY — not a different status — is what distinguishes an idempotent
    // replay from a fresh commit.
    return { status: 200, body: result };
  } catch (error) {
    return envelope(error);
  }
}
