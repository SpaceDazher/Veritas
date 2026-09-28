// S2-007 Agent Board contract registry: the SINGLE validation surface.
// Every producer and consumer of a board document — Web, HTTP API, CLI,
// scheduler, store, test transport, replay harness — validates through this
// module against the same compiled JSON Schemas in contracts/. There is no
// second, independently editable payload form: a shape that is not described
// here does not exist on the boundary.
//
// Fail-closed by construction: every schema is compiled at import time and a
// missing, malformed, wrong-$id or wrong-draft schema aborts immediately
// instead of degrading to best-effort validation. Semantic rules that JSON
// Schema cannot express (digest agreement, scope containment, monotonic
// sequence, budget positivity) live in policy.mjs and are part of the same
// contract surface.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { BOARD_CONTRACT_VERSION, EXECUTION_CONTRACT_VERSION, ADAPTER_INTERFACE_VERSION } from './constants.mjs';
import { ContractVersionUnknown, MalformedResult, NeedsInput } from './errors.mjs';

const CONTRACTS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../contracts',
);

export const CONTRACT_VERSION = BOARD_CONTRACT_VERSION;

// The eight authoritative documents of the S2-007 boundary. `board-error` is
// not listed: it is referenced (and validated) through the $ref closure of the
// other documents and is exported separately below.
export const BOARD_CONTRACTS = Object.freeze([
  'board-task',
  'board-transition',
  'adapter-registration',
  'dispatch-decision',
  'execution-request',
  'execution-event',
  'execution-result',
  'board-error',
]);

export const CONTRACT_FILES = Object.freeze(Object.fromEntries(
  BOARD_CONTRACTS.map((name) => [name, `${name}.schema.json`]),
));

const ajv = new Ajv2020({ allErrors: true, strict: false, allowUnionTypes: true });

function loadSchema(name) {
  const file = path.join(CONTRACTS_DIR, CONTRACT_FILES[name]);
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(`BOARD_CONTRACT_SCHEMA_MISSING:${name}:${error.message}`);
  }
  let schema;
  try {
    schema = JSON.parse(raw);
  } catch (error) {
    throw new Error(`BOARD_CONTRACT_SCHEMA_MALFORMED:${name}:${error.message}`);
  }
  const expectedId = `https://veritas.local/contracts/${CONTRACT_FILES[name]}`;
  if (schema.$id !== expectedId) {
    throw new Error(`BOARD_CONTRACT_SCHEMA_ID_MISMATCH:${name}:expected ${expectedId}:got ${schema.$id}`);
  }
  if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') {
    throw new Error(`BOARD_CONTRACT_SCHEMA_DRAFT_UNSUPPORTED:${name}`);
  }
  return { raw, schema };
}

const loaded = new Map();
const validators = new Map();
// board-error is pulled in transitively by execution-result, so it must be
// registered before the documents that $ref it. Registration order is fixed
// and deterministic; a duplicate $id aborts at import time.
for (const name of ['board-error', 'board-task', 'board-transition', 'adapter-registration',
  'dispatch-decision', 'execution-request', 'execution-event', 'execution-result']) {
  const { raw, schema } = loadSchema(name);
  loaded.set(name, { raw, schema, sha256: createHash('sha256').update(raw, 'utf8').digest('hex') });
  validators.set(name, ajv.compile(schema));
}

export function contractDigest(name) {
  const entry = loaded.get(name);
  if (!entry) throw new NeedsInput(`UNKNOWN_BOARD_CONTRACT:${name}`);
  return `sha256:${entry.sha256}`;
}

export function allContractDigests() {
  return Object.fromEntries([...loaded.entries()].map(([name, entry]) => [name, `sha256:${entry.sha256}`]));
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function formatErrors(validate) {
  return (validate.errors ?? [])
    .slice(0, 8)
    .map((error) => `${error.instancePath || '/'} ${error.message ?? 'invalid'}`)
    .join('; ');
}

/**
 * Validate a document against one board contract.
 * Returns the document unchanged on success; throws a typed error otherwise.
 * `BoardContractViolation` is a MalformedResult so an invalid document on the
 * execution boundary can never be mistaken for a valid one.
 */
export function assertBoardContract(name, document, ErrorClass = MalformedResult) {
  const validate = validators.get(name);
  if (!validate) throw new NeedsInput(`UNKNOWN_BOARD_CONTRACT:${name}`);
  if (!isPlainObject(document)) {
    throw new ErrorClass(`BOARD_CONTRACT_SHAPE:${name}:object required`);
  }
  if (!validate(document)) {
    throw new ErrorClass(`BOARD_CONTRACT_VIOLATION:${name}:${formatErrors(validate)}`);
  }
  return document;
}

export function isBoardContractValid(name, document) {
  const validate = validators.get(name);
  return Boolean(validate) && isPlainObject(document) && validate(document) === true;
}

export function boardContractErrors(name, document) {
  const validate = validators.get(name);
  if (!validate) return [`unknown contract ${name}`];
  validate(document);
  return (validate.errors ?? []).map((error) => `${error.instancePath || '/'} ${error.message ?? 'invalid'}`);
}

// --- version handshake -----------------------------------------------------

const EXECUTION_MAJOR = EXECUTION_CONTRACT_VERSION.split('/')[1].split('.')[0];
const ADAPTER_MAJOR = ADAPTER_INTERFACE_VERSION.split('/')[1].split('.')[0];

// The version on this boundary is `<interface>/<semver>`, so the semver part
// must be taken from AFTER the last slash before it is compared. Comparing the
// whole string against a bare-semver anchor would make the same-major /
// different-minor (negotiated subset) branch unreachable and report a
// well-formed `veritas.execution/1.1.0` as "not a semantic version".
function semverOf(version) {
  if (typeof version !== 'string') return null;
  const tail = version.includes('/') ? version.slice(version.lastIndexOf('/') + 1) : version;
  return /^\d+\.\d+\.\d+$/.test(tail) ? tail : null;
}

function majorOf(version) {
  const semver = semverOf(version);
  return semver === null ? null : semver.split('.')[0];
}

/**
 * Version handshake for the execution boundary. An unknown MAJOR version is
 * rejected before any read or side effect; a higher MINOR requires the feature
 * to be listed in negotiated_capabilities before it may be relied on.
 * A board-internal document must carry exactly 1.0.0.
 */
export function assertExecutionVersion(document) {
  if (!isPlainObject(document)) throw new ContractVersionUnknown('execution payload must be an object');
  const version = document.contract_version;
  if (typeof version !== 'string' || version !== EXECUTION_CONTRACT_VERSION) {
    if (majorOf(version) === null) {
      throw new ContractVersionUnknown(`execution contract_version is not a semantic version: ${String(version)}`);
    }
    if (majorOf(version) !== EXECUTION_MAJOR) {
      throw new ContractVersionUnknown(`unsupported execution major version: ${String(version)}`);
    }
    // Same major, different minor: acceptable only as a negotiated subset. The
    // minor is read from the semver tail, not from the prefixed string.
    return { minor: semverOf(version).split('.')[1], negotiated: true };
  }
  return { minor: '0', negotiated: false };
}

export function assertAdapterVersion(version) {
  if (version !== ADAPTER_INTERFACE_VERSION) {
    throw new ContractVersionUnknown(`unsupported adapter interface version: ${String(version)}`);
  }
  return true;
}

export function assertBoardVersion(document) {
  if (!isPlainObject(document) || document.contractVersion !== BOARD_CONTRACT_VERSION) {
    throw new ContractVersionUnknown(
      `board contractVersion must be ${BOARD_CONTRACT_VERSION}, got ${String(document?.contractVersion)}`,
    );
  }
  return true;
}

// --- cross-document validation --------------------------------------------

export const BOUND_DOCUMENTS = Object.freeze(['board-task', 'board-transition', 'execution-request', 'execution-result', 'execution-event']);

/**
 * Assert that the digests a consumer holds still describe the documents it is
 * about to act on. A digest is an integrity control, not a signature and never
 * an identity: this function proves nothing changed, it does not prove who
 * changed it.
 */
export function assertDigestAgreement(expected, actual, label) {
  if (expected !== actual) {
    throw new MalformedResult(
      `DIGEST_MISMATCH:${label}`,
      `expected ${String(expected)} got ${String(actual)}; re-request instead of re-using a moved-on artifact`,
    );
  }
  return true;
}

export const CONTRACT_IDS = Object.freeze(
  Object.fromEntries(BOARD_CONTRACTS.map((name) => [name, `https://veritas.local/contracts/${CONTRACT_FILES[name]}`])),
);

export { BOARD_CONTRACT_VERSION, EXECUTION_CONTRACT_VERSION, ADAPTER_INTERFACE_VERSION };
