// S2-008 research track — the SINGLE validation path for the three frozen
// research schemas (issue SpaceDazher/Veritas#8).
//
// Serves acceptance items A2, A4 and A5. A sibling of
// src/lib/agentboard/contracts.mjs:22-71 step for step, not an edit of it:
// the board keeps its own single validation surface and this track keeps
// another, and neither of them forks the other.
//
// READ-ONLY inputs. These three files are frozen and are NOT modified by this
// track; their digests must stay exactly as recorded in
// evidence/frozen-manifest.json:
//   contracts/hypothesis-card.schema.json    sha256:43b9c81620737b81a589d8e1577b0dc89e8b19fe1ed011edb3514f893b141e97
//   contracts/research-dossier.schema.json   sha256:fdffd1c0a75f0483a5ab7244ed5463a9786fec4c23daaae8c7b5242167183773
//   contracts/calibration-record.schema.json sha256:8c7507ebe2f216a46f4c70f7a43e4713ef84f85ac0c14d97e550f953f1b7408d
// `contracts/` is a frozen target of scripts/validate-contracts.mjs, so no new
// schema, no edit and no --freeze is available to this track. If a field is
// needed that no frozen schema has, it lives in preregistration.mjs, NOT in a
// new schema file.
//
// WHAT THIS MODULE IS: the wire shape. Three documents have exactly one
// compiled form, one validator each, and one refusal class, so a
// research document that is invalid on a boundary cannot be mistaken for a
// valid one anywhere in the track.
//
// WHAT THIS MODULE IS NOT: the semantic machine. The rules a JSON Schema
// cannot express do NOT live here, and that is a decision, not an omission —
// each of them has a named owner and a second copy would be a second,
// independently editable source of truth:
//   * A4 label guard (causal assertion on observational ground truth)
//     -> src/lib/research/causality.mjs
//   * preregistration immutability, budget reservation positivity/expiry
//     -> src/lib/research/preregistration.mjs (assertNoPostResultRewrite,
//        assertBudgetReservation) over preregistrationDigest
//   * monotonic sequence (the journal prev_digest chain) and revision CAS
//     -> src/lib/research/registry.mjs (verifyChain)
//   * contract-digest agreement against evidence/frozen-manifest.json
//     -> scripts/verify-s2-008-dependencies.mjs over researchContractDigest
// Adding a guard here would need a name the judged plan §1 does not freeze;
// inventing one is `BLOCKED:` to delivery, not a unilateral addition.
//
// WHY ONE Ajv2020, AND WHAT EACH OPTION ACTUALLY DOES
// The three schemas are compiled once, at import time, with one Ajv2020
// instance configured exactly as in the board sibling (identical object,
// byte for byte): `allErrors: true, strict: false, allowUnionTypes: true`.
// A second compiler configuration in this track would be a second answer to
// "what is a valid research document".
//
//   * `allErrors` — one failure reports every violated keyword instead of
//     only the first, so an evidence record names the whole problem.
//   * `strict: false` — THIS IS THE LOAD-BEARING OPTION, and it is not
//     cosmetic. The frozen schemas are not written to Ajv's strict profile
//     and this track may not edit them. Measured on this host
//     (ajv 8.20.0, the four combinations of the two flags against all three
//     frozen files): with `strict: true` the dossier is REFUSED
//     ("strict mode: missing type \"object\" for keyword \"properties\"") and
//     the calibration record is REFUSED ("missing type \"number\" for
//     keyword \"minimum\""), so the module would not import at all. With
//     `strict: false` all three compile.
//   * `allowUnionTypes: true` — kept because the dossier really does declare
//     12 `type: ['string','null']` members and because the flag is what a
//     strict-mode Ajv consults for those members. MEASURED, NOT ASSUMED: on
//     this host the flag changes nothing for these three schemas — all four
//     combinations of the two flags either compile (strict:false) or fail
//     for the reason above (strict:true). An earlier version of this header
//     claimed the flag is MANDATORY and that dropping it "turns a
//     schema-valid document into a startup throw"; that is false for
//     ajv 8.20.0 and it is corrected here rather than left standing. The
//     flag stays because it documents intent for the 12 union members and
//     costs nothing — not because a measured failure depends on it.
//
// FAIL CLOSED, AT IMPORT, NOT PER CALL
// A missing file, unreadable bytes, malformed JSON, a non-object schema, a
// `$id` that is not the expected `https://veritas.local/contracts/<file>`, a
// draft that is not 2020-12, or a schema Ajv itself refuses aborts the
// import. There is no best-effort mode and no
// per-call fallback: after this module loads, the three validators exist or
// the process does not run at all. Per-call failures are still typed —
// an unknown contract NAME is `NeedsInput`, a document that is not a plain
// object or that violates the schema is `MalformedResult` (or the caller's
// `ErrorClass`).
//
// THE DEFAULT ERROR CLASS IS `MalformedResult`
// from src/lib/agentboard/errors.mjs, not a locally declared class. That is
// the whole point of the import: an invalid research document raises the
// board's own typed refusal, so the error taxonomy stays closed and no
// caller has to learn a second convention. `BoardError` bounds every message
// to 500 characters and redacts secret-shaped text before it is stored, so a
// schema error string that reaches an evidence file is bounded by
// construction; `researchContractErrors` bounds each line further because its
// stated purpose is an evidence record.
//
// `loadResearchContracts(dir)` is the TEST SEAM and is deliberately NOT a
// relaxed loader: it calls the same `compileResearchContracts` the import-time
// path calls, with the same five fail-closed checks and the same Ajv options.
// A test that passes against a permissive loader production does not use is
// not a test, so there is no permissive path to pass against. Its limit is
// stated rather than hidden: it catches STRUCTURAL breakage (missing,
// malformed, wrong `$id`, wrong draft, uncompilable). A schema that is
// well-formed and merely *changed* still compiles — that is what the digest
// on the same surface is for, and why the digest and the validator are
// exported together.
//
// THE COMPILED SCHEMA OBJECT IS NOT EXPORTED
// The judged plan freezes no accessor for it, so there is none here. A sibling
// module that needs a compiled enum (causality.mjs reads `card_type` and
// `relation_strength`) reads the frozen file bytes itself: the schema is the
// frozen single source of truth, and reading the same file twice does not
// create a second editable copy. A second *written-out* copy of an enum would.
//
// Owner: W1 (contracts & causality). Budget: part of W1's <= 700 lines.
// State: IMPLEMENTED. Every frozen signature in plan §1 is present, and the
// bodies do the real work; nothing here throws NOT_IMPLEMENTED.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { MalformedResult, NeedsInput } from '../agentboard/errors.mjs';

const CONTRACTS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../contracts',
);

// The canonical `$id` prefix every frozen contract declares. Frozen, not
// configurable: an id is the document's identity on the wire, so a file whose
// id points somewhere else is a different document, not a variant.
const CONTRACT_ID_BASE = 'https://veritas.local/contracts/';

// The three authoritative research documents, in the fixed compile order.
// The order is the track's own reading order — the card that carries the
// preregistered hypothesis, the dossier that reports the run, the calibration
// record that would report a measured outcome — and it is frozen so a
// duplicate `$id`, a partially registered reference or an evidence record
// listing digests always has one deterministic order. `calibration-record`
// is version 1, not `calibration-record-v2`: the v2 schema is a different
// document, used by S2-006, and is NOT part of this track's validation
// surface.
export const RESEARCH_CONTRACTS = Object.freeze([
  'hypothesis-card',
  'research-dossier',
  'calibration-record',
]);

/**
 * Contract name -> schema file name, derived from RESEARCH_CONTRACTS.
 * @type {Readonly<Record<string, string>>}
 */
export const RESEARCH_CONTRACT_FILES = Object.freeze(Object.fromEntries(
  RESEARCH_CONTRACTS.map((name) => [name, `${name}.schema.json`]),
));

/**
 * Contract name -> the `$id` each schema MUST declare. A schema whose `$id`
 * does not match is a startup throw, not a warning.
 * @type {Readonly<Record<string, string>>}
 */
export const RESEARCH_CONTRACT_IDS = Object.freeze(Object.fromEntries(
  RESEARCH_CONTRACTS.map((name) => [name, `${CONTRACT_ID_BASE}${RESEARCH_CONTRACT_FILES[name]}`]),
));

// Identical to the board sibling's Ajv configuration (src/lib/agentboard/
// contracts.mjs:47), option for option. `allErrors` so a single failure
// reports every violated keyword; `strict` off because the frozen schemas
// were not written to Ajv's strict profile and the track may not edit them —
// that flag is the one that decides whether this module imports at all (see
// the header matrix); `allowUnionTypes` for the dossier's 12
// `type: ['string','null']` members, which this host's Ajv tolerates either
// way and which is kept to match the sibling exactly.
const AJV_OPTIONS = Object.freeze({ allErrors: true, strict: false, allowUnionTypes: true });

// Per-line bound for the strings `researchContractErrors` hands to an evidence
// record. The `instancePath` is the first thing in the line, so the path
// survives the bound; what is cut is Ajv's own prose about a value, which is
// the only part that could quote content.
const MAX_ERROR_LINE = 240;

// How many formatted errors ride in a thrown message. The board sibling
// bounds at 8 for the same reason: an unbounded Ajv error array inside a
// BoardError is a payload, not a diagnosis. The unbounded form stays
// available through researchContractErrors.
const MAX_MESSAGE_ERRORS = 8;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function bound(text, max) {
  const value = String(text ?? '');
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function formatError(error) {
  return bound(`${error.instancePath || '/'} ${error.message ?? 'invalid'}`, MAX_ERROR_LINE);
}

function formatErrors(validate) {
  return (validate.errors ?? [])
    .slice(0, MAX_MESSAGE_ERRORS)
    .map(formatError)
    .join('; ');
}

/**
 * Read one frozen schema from `dir` and refuse everything that is not
 * exactly the document the manifest names. Every failure is a labelled throw
 * at load time; none of them returns a partially usable schema.
 */
function readContractSource(name, dir) {
  const file = path.join(dir, RESEARCH_CONTRACT_FILES[name]);
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(`RESEARCH_CONTRACT_SCHEMA_MISSING:${name}:${error.message}`, { cause: error });
  }
  let schema;
  try {
    schema = JSON.parse(raw);
  } catch (error) {
    throw new Error(`RESEARCH_CONTRACT_SCHEMA_MALFORMED:${name}:${error.message}`, { cause: error });
  }
  if (!isPlainObject(schema)) {
    throw new Error(`RESEARCH_CONTRACT_SCHEMA_MALFORMED:${name}:a JSON Schema must be an object`);
  }
  // A `$id` that is not exactly this file's own expected id is refused. That
  // single check is also what makes a duplicated `$id` unreachable: the three
  // expected ids are distinct by construction (RESEARCH_CONTRACT_FILES maps
  // three distinct names to three distinct files), so two files can only
  // present the same id if at least one of them fails this comparison. No
  // separate duplicate scan is kept, because it could never fire and a check
  // that cannot fire is decoration; if a future file map ever made two names
  // share an expected id, Ajv's own duplicate-key throw would be wrapped as
  // _MALFORMED below rather than passing silently.
  const expectedId = RESEARCH_CONTRACT_IDS[name];
  if (schema.$id !== expectedId) {
    throw new Error(
      `RESEARCH_CONTRACT_SCHEMA_ID_MISMATCH:${name}:expected ${expectedId}:got ${String(schema.$id)}`,
    );
  }
  if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') {
    throw new Error(`RESEARCH_CONTRACT_SCHEMA_DRAFT_UNSUPPORTED:${name}:got ${String(schema.$schema)}`);
  }
  return { raw, schema };
}

/**
 * Compile all three frozen schemas out of one directory with ONE Ajv2020 and
 * the import-time fail-closed checks. Shared by the import-time path and by
 * `loadResearchContracts`, so the test seam cannot drift from production.
 */
function compileResearchContracts(dir) {
  if (typeof dir !== 'string' || dir.length === 0) {
    throw new Error(`RESEARCH_CONTRACT_SCHEMA_DIR_INVALID:${String(dir)}`);
  }
  const root = path.resolve(dir);
  const ajv = new Ajv2020(AJV_OPTIONS);
  const entries = new Map();
  for (const name of RESEARCH_CONTRACTS) {
    const { raw, schema } = readContractSource(name, root);
    let validate;
    try {
      validate = ajv.compile(schema);
    } catch (error) {
      // A schema that parses, carries the right $id and the right draft and
      // still cannot be compiled is malformed as a SCHEMA, not as JSON. It
      // must abort, never fall back to "no validation".
      throw new Error(
        `RESEARCH_CONTRACT_SCHEMA_MALFORMED:${name}:ajv refused to compile: ${String(error?.message ?? error)}`,
        { cause: error },
      );
    }
    entries.set(name, Object.freeze({
      name,
      raw,
      schema,
      sha256: createHash('sha256').update(raw, 'utf8').digest('hex'),
      validate,
    }));
  }
  return { dir: root, entries };
}

// --- import time: compile or die -------------------------------------------

const importTime = compileResearchContracts(CONTRACTS_DIR);
const loaded = importTime.entries;

/**
 * The wire digest of one research contract's raw schema bytes.
 *
 * A digest is an integrity control, not a signature: it proves the bytes did
 * not move, it does not prove who moved them. It is the ONLY thing that
 * catches a schema which is well-formed, compiles, and has quietly changed —
 * so it is exported next to the validator rather than as a separate
 * bookkeeping API.
 *
 * @param {string} name A member of RESEARCH_CONTRACTS.
 * @returns {string} `sha256:<64 hex>`, the same convention as
 *   `contractDigest` in src/lib/agentboard/contracts.mjs and
 *   `toWireDigest` in src/lib/agentboard/constants.mjs.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} UNKNOWN_RESEARCH_CONTRACT.
 */
export function researchContractDigest(name) {
  const entry = loaded.get(name);
  if (!entry) throw new NeedsInput(`UNKNOWN_RESEARCH_CONTRACT:${String(name)}`);
  return `sha256:${entry.sha256}`;
}

/**
 * Every research contract digest, for the evidence record.
 * @returns {Record<string, string>} contract name -> `sha256:<64 hex>`, in
 *   the fixed RESEARCH_CONTRACTS order.
 */
export function allResearchContractDigests() {
  return Object.fromEntries(
    [...loaded.entries()].map(([name, entry]) => [name, `sha256:${entry.sha256}`]),
  );
}

/**
 * Validate a document against one research contract.
 *
 * Returns the document unchanged on success so it can be used inline at a
 * boundary. On failure it throws an instance of `ErrorClass`, which defaults
 * to `MalformedResult` from src/lib/agentboard/errors.mjs, so an invalid
 * research document on a boundary can never be mistaken for a valid one.
 *
 * This is SCHEMA VALIDATION ONLY. A card that satisfies this still has to
 * pass the A4 label guard in causality.mjs, and a run still has to pass the
 * comparator: "valid wire shape" is not "admissible" and the two are not
 * merged here, because a schema cannot express either rule.
 *
 * @param {string} name A member of RESEARCH_CONTRACTS.
 * @param {object} document The candidate document.
 * @param {Function} [ErrorClass=MalformedResult] The BoardError subclass
 *   `MalformedResult`, imported from src/lib/agentboard/errors.mjs, so the
 *   default is the plan's literal default and not a second convention.
 *   A class from src/lib/agentboard/errors.mjs is expected, so the error
 *   taxonomy stays closed.
 * @returns {object} The same document, unchanged, on success.
 * @throws {import('../agentboard/errors.mjs').NeedsInput} UNKNOWN_RESEARCH_CONTRACT.
 * @throws {Error} `ErrorClass`, carrying the first formatted Ajv errors.
 */
export function assertResearchContract(name, document, ErrorClass = MalformedResult) {
  const validate = loaded.get(name)?.validate;
  if (!validate) throw new NeedsInput(`UNKNOWN_RESEARCH_CONTRACT:${String(name)}`);
  if (!isPlainObject(document)) {
    throw new ErrorClass(`RESEARCH_CONTRACT_SHAPE:${name}:object required`);
  }
  if (!validate(document)) {
    throw new ErrorClass(`RESEARCH_CONTRACT_VIOLATION:${name}:${formatErrors(validate)}`);
  }
  return document;
}

/**
 * Boolean form of assertResearchContract. Never throws, never returns a
 * "probably fine" value: a boolean is the whole answer. An unknown contract
 * name is `false`, not an exception — the question asked was "is this
 * document valid?", and the answer to that is no.
 * @param {string} name A member of RESEARCH_CONTRACTS.
 * @param {object} document The candidate document.
 * @returns {boolean} true only when the document satisfies the contract.
 */
export function isResearchContractValid(name, document) {
  const validate = loaded.get(name)?.validate;
  return Boolean(validate) && isPlainObject(document) && validate(document) === true;
}

/**
 * The contract errors of a document, for an evidence record.
 *
 * Every line starts with the JSON Pointer of the offending value and is
 * bounded to {@link MAX_ERROR_LINE} characters, so the result is safe to put
 * in `evidence/*.json` and to print. It never contains the document's values
 * beyond what Ajv's own message quotes about the failing keyword.
 *
 * @param {string} name A member of RESEARCH_CONTRACTS.
 * @param {object} document The candidate document.
 * @returns {ReadonlyArray<string>} One `instancePath message` string per
 *   Ajv error, bounded and secret-free. Empty when the document is valid.
 */
export function researchContractErrors(name, document) {
  const validate = loaded.get(name)?.validate;
  if (!validate) return [`unknown contract ${String(name)}`];
  validate(document);
  return (validate.errors ?? []).map(formatError);
}

/**
 * Compile the three research schemas from an arbitrary directory.
 *
 * This is the test seam for drift and tamper: it is the SAME compiler and
 * the SAME fail-closed checks as the import-time path, so a test cannot pass
 * against a permissive loader that production does not use. It is a handle
 * over its OWN compilation — it never swaps the module-level validators, so
 * a test that loads a tampered copy cannot leave the process validating
 * against the tampered schema afterwards.
 *
 * @param {string} dir Absolute path of the directory holding the three
 *   `<name>.schema.json` files. A tampered copy is expected to be a real
 *   directory with real bytes; the four drift cases the tests exercise are a
 *   missing file, malformed JSON, a wrong `$id` and a wrong draft.
 * @returns {object} A frozen validator handle exposing, at minimum, the same
 *   contract names, digests, `$id` checks and draft checks as the import-time
 *   surface: `{ dir, contracts, files, ids, digests, raw, schema, validate,
 *   errors, assert }`.
 * @throws {Error} RESEARCH_CONTRACT_SCHEMA_DIR_INVALID / _MISSING /
 *   _MALFORMED / _ID_MISMATCH / _DRAFT_UNSUPPORTED,
 *   mirroring the board sibling's fail-closed behaviour with this track's
 *   codes. Plain `Error`, not a BoardError: these fire while the process is
 *   still loading its validation surface, so no caller exists yet to catch a
 *   typed refusal, and BoardError's closed code enum has no member for "your
 *   own schema directory is broken".
 */
export function loadResearchContracts(dir) {
  const handle = compileResearchContracts(dir);
  const entryOf = (name) => {
    const entry = handle.entries.get(name);
    if (!entry) throw new NeedsInput(`UNKNOWN_RESEARCH_CONTRACT:${String(name)}`);
    return entry;
  };
  return Object.freeze({
    dir: handle.dir,
    contracts: RESEARCH_CONTRACTS,
    files: RESEARCH_CONTRACT_FILES,
    ids: RESEARCH_CONTRACT_IDS,
    digests: Object.freeze(Object.fromEntries(
      [...handle.entries.entries()].map(([name, entry]) => [name, `sha256:${entry.sha256}`]),
    )),
    /** The exact bytes the digest was taken over. */
    raw(name) {
      return entryOf(name).raw;
    },
    /** The parsed schema. A read-only view of the frozen contract. */
    schema(name) {
      return entryOf(name).schema;
    },
    /** The compiled Ajv validator, so a test can assert the same failures. */
    validator(name) {
      return entryOf(name).validate;
    },
    /** Boolean validation against THIS compilation. */
    validate(name, document) {
      const validate = handle.entries.get(name)?.validate;
      return Boolean(validate) && isPlainObject(document) && validate(document) === true;
    },
    /** Formatted errors against THIS compilation. */
    errors(name, document) {
      const validate = handle.entries.get(name)?.validate;
      if (!validate) return [`unknown contract ${String(name)}`];
      validate(document);
      return (validate.errors ?? []).map(formatError);
    },
    /** Throwing validation against THIS compilation. */
    assert(name, document, ErrorClass = MalformedResult) {
      const validate = handle.entries.get(name)?.validate;
      if (!validate) throw new NeedsInput(`UNKNOWN_RESEARCH_CONTRACT:${String(name)}`);
      if (!isPlainObject(document)) {
        throw new ErrorClass(`RESEARCH_CONTRACT_SHAPE:${name}:object required`);
      }
      if (!validate(document)) {
        throw new ErrorClass(`RESEARCH_CONTRACT_VIOLATION:${name}:${formatErrors(validate)}`);
      }
      return document;
    },
  });
}
