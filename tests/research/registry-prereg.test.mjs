// S2-008 — the three boundaries under the six probes: the single validation
// path, the file ledger and the preregistration (issue SpaceDazher/Veritas#8).
//
// OWNER: the `tests: registry-prereg` worker. This file is the ONLY thing it
// created and the ONLY thing it may edit. It patches no source file: every
// refusal below is a property of `src/lib/research/{contracts,registry,
// preregistration}.mjs` as they stand, and a failing assertion is information
// about the property, not a licence to change the module.
//
// WHAT THIS FILE PROVES, IN THE ISSUE'S OWN TERMS
//   A2  a document that is not valid is never returned as valid, and the
//       comparator's fail-closed rule has its input enforced at the boundary
//       (`contracts.mjs`), not re-implemented here
//   A3  the ledger is not a second state path: a replay writes nothing, a CAS
//       is a compare-and-swap, and the ordering is idempotency -> read -> CAS
//       (+ fence) -> journal -> marker -> head
//   A4  the label guard and the causal guard are `causality.mjs` /
//       `dataset.mjs` and stay in dataset.test.mjs. What of A4 belongs to a
//       POST-RESULT CLAIM is here, because it is a property of the
//       preregistration document and not of the comparator: a hypothesis
//       rewritten after its result is refused, and the lawful path is a new
//       document kind
//   A5  same base => same outcome: the last two tests run the same driver in
//       TWO processes and compare the bytes, and one test re-opens a purged
//       base and re-derives the same record ids and head digest
//
// THE MAP FROM THE TICKET'S WORDING TO THE CODE
//   "single validation surface"        -> contracts.mjs:345/366/384
//   "aborts at import"                 -> contracts.mjs:286, exercised in a
//                                         child process (see the import test)
//   "idempotency / CAS / append-only"  -> registry.mjs:638, :693, :1421
//   "budget reservation + release"     -> registry.mjs:1250, preregistration.mjs:1109
//   "fencing of a stale writer"        -> registry.mjs:670
//   "no outcome recorded != no effect" -> registry.mjs:965
//   "frozen before run 1"              -> preregistration.mjs:608, :819
//   "mutation after run 1"             -> preregistration.mjs:918
//   "a new document kind"              -> preregistration.mjs:1001, :1058
//   "the holdout opens exactly once"   -> preregistration.mjs:429 + registry.mjs:1099
//   "the seed plan is a pure function" -> preregistration.mjs:365, :398
//
// THIS SUITE IS A TRIPWIRE, AND THAT WAS MEASURED
// 30 green tests prove nothing on their own, so every property above was
// re-checked by ablating the module it belongs to in a COPY of the tree (the
// repository was never modified): 20 mutations — the idempotency ledger
// switched off, the CAS switched off, the grant ceiling switched off, the
// expiry switched off, fencing switched off, the journal rewritten instead of
// appended, an uncommitted tail returned as history, the two absences
// collapsed, an implicit zero reported, the document gate neutered, the
// one-shot rule unchecked, the seed plan made random, both ordering checks
// switched off one at a time, the in-place check off, the amendment admitted as
// a decision basis, the rewrite refusal off, the error surface emptied, Ajv
// set to strict mode, and the record stamped from the process clock — and 20 of
// 20 turned this suite red, with the unmutated control green. The one that
// first stayed green (the ordering check, because the other check was covering
// for it) is why the ordering test now separates a RESULT-only journal from a
// RUN-only one.
//
// FOUR THINGS THIS FILE DELIBERATELY DOES NOT CLAIM
//  1. THERE IS NO OUTBOX HERE. The research ledger refuses the board's
//     dispatch outbox by name (registry.mjs:85, refusal N4): there is no
//     dispatch state machine to drain. The append-only surfaces that DO exist
//     are the journal, the idempotency/marker chain and the reconciliation
//     rows, and those are what the "append-only" tests below pin. Reading an
//     operations-chain test as an outbox test would be the exact substitution
//     this repository forbids.
//  2. THE ORDERING PROOF READS EACH ROW'S OWN `index`
//     (preregistration.mjs:592), not its position in the array the caller
//     passed, and it does not re-verify the chain digests: it trusts
//     `registry.mjs#readJournal`, whose contract is committed rows in index
//     order. The tests below therefore build HONEST journals (ascending
//     indices) and assert the refusals on those. A caller that fabricates a
//     journal is outside the boundary, and saying so is cheaper than implying
//     a proof that is not there.
//  3. A COMMIT/TREE-SHA BINDING IS NOT PROVEN HERE. A5's "bound to a commit
//     SHA, a tree SHA and a raw run id" is carried by `runner.mjs` and the
//     committed evidence records, and harness.test.mjs already reads those
//     files. What this file proves is the half it owns: a repeat run on the
//     same base reproduces the same record ids and the same head digest.
//  4. "RELEASED EXACTLY ONCE" IS ENFORCED BY THE GRANT CEILING, NOT BY A FLAG.
//     The ledger has no `released` state: what it refuses is any second settle
//     that would spend the remainder again, and what it journals is what it was
//     told. A zero-unit release is therefore a row that moves nothing. The
//     budget test says this out loud instead of leaving the gap to be
//     discovered.
//
// HOUSE RULES OBSERVED HERE
//   * Offline and deterministic. No network, no LLM, no credentials. Every
//     clock is an INJECTED literal and every id comes from a counter, so two
//     processes produce the same bytes; nothing reads `Date.now()`.
//   * The one `Date.parse` in this file is a PARSE OF A LITERAL.
//   * Scratch lives under the OS temp dir (`mkdtempSync`) and is removed in
//     `after`; nothing is written inside the repository.
//   * No test relaxes a threshold, skips a case or catches-and-ignores. Where
//     a property is narrower than the ticket's word, the test says which.
//   * Nothing here weakens another suite: the corpus path, the label seal and
//     the causal guard stay in dataset.test.mjs, the comparator stays in
//     comparator.test.mjs.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { canonicalDigest, canonicalize } from '../../src/lib/verifier/canonical-json.mjs';
import {
  allResearchContractDigests,
  assertResearchContract,
  isResearchContractValid,
  loadResearchContracts,
  researchContractDigest,
  researchContractErrors,
  RESEARCH_CONTRACT_FILES,
  RESEARCH_CONTRACT_IDS,
  RESEARCH_CONTRACTS,
} from '../../src/lib/research/contracts.mjs';
import {
  acquireLock,
  appendRecord,
  headDigest,
  openRegistry,
  purgeRegistry,
  putExperiment,
  readJournal,
  recordHoldoutRead,
  recordSpend,
  releaseLock,
  recoverTornTail,
  snapshotDigest,
  verifyChain,
} from '../../src/lib/research/registry.mjs';
import {
  AMENDMENT_KIND,
  PREREGISTRATION_KIND,
  PREREGISTRATION_RULE,
  assertAmendmentNotDecisionBasis,
  assertBudgetReservation,
  assertNoPostResultRewrite,
  assertPreregisteredBeforeRun,
  assertPreregistration,
  assertSeedSetFrozen,
  createAmendment,
  loadPreregistration,
  preregistrationDigest,
  seedCountOf,
  stoppingRuleOf,
} from '../../src/lib/research/preregistration.mjs';
import {
  BlockedPolicy, BudgetExceeded, IdempotencyConflict, MalformedResult, NeedsInput,
  ReconciliationRequired, RevisionConflict, StaleFence, isBoardError,
} from '../../src/lib/agentboard/errors.mjs';
import { PREREGISTRATION, HOLDOUT_UNSEAL_DIGEST } from './fixtures/fixture-measurement-set.mjs';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const CONTRACTS_DIR = path.join(REPO, 'contracts');

// Two INJECTED instants, written as literals in both forms. The fixture set's
// own instant is the base; the second one is after the preregistration's
// decision point and after its budget reservation expires, which is how the
// holdout and budget rules get exercised without a clock that moves.
const AT = '2026-01-01T00:30:00.000Z';
const AT_NS = Date.parse(AT) * 1e6;
const AFTER_DECISION = '2026-01-01T02:00:00.000Z';
const AFTER_DECISION_NS = Date.parse(AFTER_DECISION) * 1e6;
const DECISION_POINT = '2026-01-01T01:00:00.000Z';
const RUN_ID = 's2-008-run-a';

const HEX64 = /^[0-9a-f]{64}$/;
const SCRATCH_ROOTS = [];

/**
 * The injected fixed clock. `nowNs` and `iso` describe the SAME literal
 * instant; nothing here samples a process clock.
 * @param {string} iso An ISO-8601 UTC instant.
 * @returns {{nowNs: () => number, iso: () => string}} The injected clock.
 */
function fixedClock(iso) {
  const ns = Date.parse(iso) * 1e6;
  return Object.freeze({ nowNs: () => ns, iso: () => iso });
}

/**
 * A deterministic id factory, scoped by the test's own label so two ledgers in
 * one process never collide and two processes produce identical ids.
 * @param {string} scope The label, e.g. 'idem'.
 * @returns {(kind: string) => string} The factory `openRegistry` consumes.
 */
function deterministicIds(scope) {
  const counters = new Map();
  return (kind) => {
    const next = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, next);
    return `${scope}${next}`;
  };
}

/**
 * A fresh, empty registry root under the OS temp dir, removed in `after`.
 * A new directory per test is what makes the tests independent of each other
 * and of their own leftovers: a repeat run cannot pass on residue.
 * @param {string} name A label for the failure text.
 * @param {string} [iso] The injected instant.
 * @returns {object} An open registry handle.
 */
function freshRegistry(name, iso = AT) {
  const root = mkdtempSync(path.join(tmpdir(), `s2-008-registry-${name}-`));
  SCRATCH_ROOTS.push(root);
  return openRegistry({ root, clock: fixedClock(iso), ids: deterministicIds(name) });
}

/** A standalone scratch directory under the OS temp dir, removed in `after`. */
function freshDir(name) {
  const dir = mkdtempSync(path.join(tmpdir(), `s2-008-${name}-`));
  SCRATCH_ROOTS.push(dir);
  return dir;
}

after(() => {
  for (const root of SCRATCH_ROOTS) rmSync(root, { recursive: true, force: true });
});

/**
 * One journalled record. The payload is the caller's return value verbatim, so
 * what a reader sees is exactly what was written.
 * @param {string} kind An UPPER_SNAKE record kind.
 * @param {object} [extra] Extra payload members.
 * @returns {object} The payload.
 */
function payload(kind, extra = {}) {
  return { kind, ...extra };
}

/**
 * Run a command and return the typed refusal it raised.
 * @param {Function} fn The call that must refuse.
 * @returns {Error} The thrown error.
 */
function refusal(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new assert.AssertionError({ message: 'the call REFUSED to refuse: nothing was thrown' });
}

/**
 * Assert a call raises a typed BoardError of `Class` whose MESSAGE names
 * `prefix`, and return the error so a test can read its recordable payload.
 * @param {Function} fn The call that must refuse.
 * @param {Function} Class The expected BoardError subclass.
 * @param {string} prefix The code the message must start with.
 * @returns {Error} The thrown error.
 */
function typedRefusal(fn, Class, prefix) {
  const error = refusal(fn);
  assert.ok(isBoardError(error), `the refusal is not a BoardError: ${error?.constructor?.name} ${String(error?.message)}`);
  assert.ok(error instanceof Class, `expected ${Class.name}, got ${error.constructor.name}: ${String(error.message)}`);
  assert.ok(String(error.message).startsWith(prefix), `expected the message to start with ${prefix}, got ${String(error.message)}`);
  return error;
}

/** A canonical deep copy: JSON round-trip drops nothing canonical-json keeps. */
function copy(document) {
  return JSON.parse(JSON.stringify(document));
}

/**
 * A preregistration that may be MUTATED without the self-seal firing first.
 *
 * The fixture carries `preregistration_digest`, so any moved member is caught
 * by `PREREGISTRATION_SEAL_MISMATCH` and the test would prove nothing about the
 * field it meant to move. The seal is a real control and is exercised on its
 * own; here it is removed so each refusal names the field under test.
 * @param {object} [document] The document to unseal. Defaults to the fixture.
 * @returns {object} A mutable, still admissible preregistration.
 */
function unsealed(document = PREREGISTRATION) {
  const next = copy(document);
  delete next.preregistration_digest;
  delete next.expected_table_digest;
  return next;
}

// --- documents for the three frozen contracts ------------------------------

const DOSSIER_ARTIFACT_NAMES = Object.freeze([
  'source-map', 'claim-register', 'support-contradiction-map', 'expert-lenses', 'timeline',
  'evidence-map', 'hypothesis-cards', 'alternative-explanations', 'dated-forecasts',
  'unknowns', 'next-experiments', 'human-review-package',
]);

/** A NOT_RUN research dossier: the honest shape for a delivered, unmeasured run. */
function researchDossier() {
  return {
    version: '1.0.0',
    id: 'rds-s2-008-01',
    brief_ref: 'tbr-s2-008-01',
    status: 'HUMAN_REVIEW',
    execution_status: 'NOT_RUN',
    artifacts: Object.fromEntries(DOSSIER_ARTIFACT_NAMES.map((name) => [name, {
      id: `art-${name}`, path: null, sha256: null, status: 'NOT_RUN', acceptance_case: 'ACC-S2-008-NOT-RUN',
    }])),
    metrics: { status: 'NOT_MEASURED', denominator: 0, reason: 'the delivered campaign reports NOT_MEASURED' },
    selection_claim: 'No empirical selection; no claim of absolute superiority.',
    human_decision_ref: 'hmd-s2-008-01',
    limitations: ['the holdout partition was opened exactly once, after the declared trials'],
  };
}

/** A MEASURED calibration record: a real, independent, one-evaluator measurement. */
function calibrationRecord() {
  return {
    contractVersion: '1.0.0',
    calibration_id: 'cal-s2-008-01',
    corpus_version: '1.0.0',
    corpus_sha256: 'a'.repeat(64),
    outcome_definition: { metric: 'extraction_accuracy', threshold: 0.5, description: 'the frozen outcome definition' },
    numerator: 7,
    denominator: 8,
    missing_count: 0,
    uncertainty: { method: 'wilson', confidence_interval: { lower: 0.4, upper: 0.9, confidence_level: 0.95 } },
    evaluator_independence: { independent_evaluators: 1, blind_to_producer: true, separate_processes: true },
    status: 'MEASURED',
    measured_at: AT,
    measured_by: 'prn-evaluator-01',
  };
}

/** One valid document per frozen contract, keyed by contract name. */
function validDocuments() {
  return new Map([
    ['hypothesis-card', PREREGISTRATION.card],
    ['research-dossier', researchDossier()],
    ['calibration-record', calibrationRecord()],
  ]);
}

/** The frozen schema file of a contract name, read from the frozen target. */
function frozenSchema(name) {
  return JSON.parse(readFileSync(path.join(CONTRACTS_DIR, RESEARCH_CONTRACT_FILES[name]), 'utf8'));
}

// ===========================================================================
// contracts.mjs — the single validation path
// ===========================================================================

describe('contracts.mjs — one compiled form, one refusal class per document', () => {
  test('the three frozen contracts are compiled at import and admit a valid document each', () => {
    assert.deepEqual([...RESEARCH_CONTRACTS], ['hypothesis-card', 'research-dossier', 'calibration-record']);
    for (const [name, document] of validDocuments()) {
      // The SAME object back, so a caller can use the result inline at a
      // boundary; and a boolean that is a whole answer, never "probably fine".
      assert.equal(assertResearchContract(name, document), document, `${name}: the document was not returned unchanged`);
      assert.equal(isResearchContractValid(name, document), true, name);
      assert.deepEqual([...researchContractErrors(name, document)], [], `${name} reported errors on a valid document`);
      // Two calls, one answer: a validator whose error state leaked between
      // calls would make the boolean form depend on history.
      assert.equal(isResearchContractValid(name, document), true, `${name} flipped on the second call`);
    }
  });

  test('every required field of the three frozen contracts is enforced', () => {
    let checked = 0;
    for (const [name, document] of validDocuments()) {
      const required = frozenSchema(name).required;
      assert.ok(Array.isArray(required) && required.length > 0, `${name} declares no required fields`);
      for (const field of required) {
        const without = copy(document);
        delete without[field];
        const error = typedRefusal(() => assertResearchContract(name, without), MalformedResult, `RESEARCH_CONTRACT_VIOLATION:${name}`);
        // The refusal is BOUNDED to eight formatted errors (contracts.mjs:182),
        // so a field named only in the ninth is a refusal that reads as if it
        // were about something else. The unbounded form is
        // `researchContractErrors`, and a required member must be named in one
        // of the two.
        const named = String(error.message).includes(`'${field}'`)
          || researchContractErrors(name, without).some((line) => line.includes(`'${field}'`));
        assert.ok(named, `${name}: removing the required field ${field} was refused without naming it`);
        checked += 1;
      }
    }
    // The three schemas are FROZEN, so a change in this total is a change to a
    // frozen target and must be read, not absorbed.
    assert.equal(checked, 17 + 10 + 13, 'the three frozen schemas declare 40 required members in total');
  });

  test('an invalid document throws MalformedResult and is never returned as valid', () => {
    for (const [name, document] of validDocuments()) {
      const invalid = copy(document);
      // `additionalProperties: false` in all three, so a member nobody
      // declared is a violation of the FROZEN surface, not of this track.
      invalid.not_a_frozen_member = 'NOT IN THE FROZEN SCHEMA';
      const error = typedRefusal(() => assertResearchContract(name, invalid), MalformedResult, 'RESEARCH_CONTRACT_VIOLATION');
      assert.equal(error.code, 'MALFORMED_RESULT', 'the refusal left the closed BoardError taxonomy');
      assert.equal(isResearchContractValid(name, invalid), false, `${name}: an invalid document read as valid`);
      assert.ok(error.message.length <= 500, 'the refusal message is not bounded by BoardError');
      // A falsy "valid" is the whole answer; there is no third state to read.
      assert.equal(typeof isResearchContractValid(name, invalid), 'boolean');
    }
    // A non-object is a refusal too, on a different code, and never a document.
    for (const shape of [null, 'a string', 42, [], undefined]) {
      typedRefusal(() => assertResearchContract('hypothesis-card', shape), MalformedResult, 'RESEARCH_CONTRACT_SHAPE');
      assert.equal(isResearchContractValid('hypothesis-card', shape), false);
    }
    // An unknown contract NAME is NeedsInput, not a validation verdict, and the
    // boolean form answers "no" rather than throwing.
    typedRefusal(() => assertResearchContract('board-task', {}), NeedsInput, 'UNKNOWN_RESEARCH_CONTRACT');
    assert.equal(isResearchContractValid('board-task', {}), false);
    // The caller's own error class is honoured, so a caller that needs a
    // different member of the closed set does not get a second convention.
    typedRefusal(() => assertResearchContract('hypothesis-card', {}, NeedsInput), NeedsInput, 'RESEARCH_CONTRACT_VIOLATION');
  });

  test('the digest and the validator ship together, and the digest re-derives from the raw bytes', () => {
    const digests = allResearchContractDigests();
    assert.deepEqual(Object.keys(digests), [...RESEARCH_CONTRACTS], 'the digest map is not in the frozen compile order');
    for (const name of RESEARCH_CONTRACTS) {
      const raw = readFileSync(path.join(CONTRACTS_DIR, RESEARCH_CONTRACT_FILES[name]), 'utf8');
      const expected = `sha256:${createHash('sha256').update(raw, 'utf8').digest('hex')}`;
      // Re-derived here rather than trusted: a digest reported by the module it
      // is supposed to vouch for proves nothing on its own.
      assert.equal(digests[name], expected, `${name}: the digest does not describe the committed bytes`);
      assert.match(digests[name].slice('sha256:'.length), HEX64, name);
      assert.equal(researchContractDigest(name), expected, name);
      assert.equal(researchContractDigest(name), digests[name], `${name}: two calls disagreed`);
    }
    typedRefusal(() => researchContractDigest('calibration-record-v2'), NeedsInput, 'UNKNOWN_RESEARCH_CONTRACT');
  });

  test('a wrong $id or a malformed schema ABORTS THE IMPORT, in a real child process', () => {
    // `loadResearchContracts` is a seam, and a seam cannot prove an abort that
    // happens in another process. So this test stages the real import: the
    // module resolves its schemas from `../../../contracts` relative to ITSELF
    // (contracts.mjs:130-133), so a copy of the file three levels under a
    // tampered `contracts/` directory imports THAT directory. The two sibling
    // dependencies and `node_modules` are symlinked, so nothing is copied and
    // nothing in the repository is touched.
    const stage = (tamper) => {
      const root = freshDir('import-abort');
      const leaf = path.join(root, 'pkg', 'a', 'b', 'c', 'd');
      const schemas = path.join(root, 'pkg', 'a', 'contracts');
      mkdirSync(leaf, { recursive: true });
      mkdirSync(schemas, { recursive: true });
      for (const name of RESEARCH_CONTRACTS) {
        copyFileSync(path.join(CONTRACTS_DIR, RESEARCH_CONTRACT_FILES[name]), path.join(schemas, RESEARCH_CONTRACT_FILES[name]));
      }
      copyFileSync(path.join(REPO, 'src', 'lib', 'research', 'contracts.mjs'), path.join(leaf, 'contracts.mjs'));
      for (const sibling of ['agentboard', 'verifier']) {
        symlinkSync(path.join(REPO, 'src', 'lib', sibling), path.join(root, 'pkg', 'a', 'b', 'c', sibling), 'dir');
      }
      symlinkSync(path.join(REPO, 'node_modules'), path.join(root, 'node_modules'), 'dir');
      tamper(schemas);
      return path.join(leaf, 'contracts.mjs');
    };
    const importIt = (file) => execFileSync(process.execPath, [
      '--input-type=module',
      '-e',
      `const m = await import(${JSON.stringify(`file://${file}`)}); process.stdout.write('IMPORTED:' + m.RESEARCH_CONTRACTS.join(','));`,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

    // The control first: the staged copy imports, so a failure below is the
    // tamper and not the staging.
    assert.equal(importIt(stage(() => {})), 'IMPORTED:hypothesis-card,research-dossier,calibration-record');

    const rewrite = (name, change) => (schemas) => {
      const file = path.join(schemas, RESEARCH_CONTRACT_FILES[name]);
      const schema = JSON.parse(readFileSync(file, 'utf8'));
      writeFileSync(file, `${JSON.stringify(change(schema))}\n`);
    };
    const cases = [
      ['RESEARCH_CONTRACT_SCHEMA_ID_MISMATCH', rewrite('hypothesis-card', (schema) => ({ ...schema, $id: 'https://example.com/hypothesis-card.schema.json' }))],
      ['RESEARCH_CONTRACT_SCHEMA_DRAFT_UNSUPPORTED', rewrite('calibration-record', (schema) => ({ ...schema, $schema: 'http://json-schema.org/draft-07/schema' }))],
      ['RESEARCH_CONTRACT_SCHEMA_MALFORMED', (schemas) => writeFileSync(path.join(schemas, RESEARCH_CONTRACT_FILES['research-dossier']), '{ "type": object }')],
      ['RESEARCH_CONTRACT_SCHEMA_MISSING', (schemas) => unlinkSync(path.join(schemas, RESEARCH_CONTRACT_FILES['research-dossier']))],
      ['RESEARCH_CONTRACT_SCHEMA_MALFORMED', rewrite('hypothesis-card', (schema) => ({ ...schema, properties: { broken: { pattern: 7 } } }))],
    ];
    for (const [code, tamper] of cases) {
      const file = stage(tamper);
      let failed = null;
      try {
        importIt(file);
      } catch (error) {
        failed = error;
      }
      assert.notEqual(failed, null, `${code}: the tampered copy IMPORTED anyway`);
      assert.notEqual(failed.status, 0, `${code}: the process exited 0`);
      assert.match(String(failed.stderr), new RegExp(code), `${code}: the abort did not name the code`);
    }
  });

  test('the loader seam is the SAME fail-closed compiler, not a permissive one', () => {
    const staged = () => {
      const dir = freshDir('contracts-seam');
      for (const name of RESEARCH_CONTRACTS) {
        copyFileSync(path.join(CONTRACTS_DIR, RESEARCH_CONTRACT_FILES[name]), path.join(dir, RESEARCH_CONTRACT_FILES[name]));
      }
      return dir;
    };
    const handle = loadResearchContracts(staged());
    // Same names, same ids, same digests as the import-time surface: a test
    // passing against a DIFFERENT compiler would prove nothing about the one
    // that runs in production.
    assert.deepEqual([...handle.contracts], [...RESEARCH_CONTRACTS]);
    assert.deepEqual({ ...handle.digests }, allResearchContractDigests());
    assert.deepEqual({ ...handle.ids }, { ...RESEARCH_CONTRACT_IDS });
    for (const [name, document] of validDocuments()) {
      assert.equal(handle.validate(name, document), true, name);
      assert.equal(handle.assert(name, document), document, name);
      assert.deepEqual([...handle.errors(name, document)], [], name);
      assert.equal(handle.raw(name), readFileSync(path.join(CONTRACTS_DIR, RESEARCH_CONTRACT_FILES[name]), 'utf8'), `${name}: the seam read other bytes`);
    }
    assert.equal(handle.validate('hypothesis-card', { card_id: 'hyc-x' }), false, 'the seam accepted an invalid document');

    // The five structural defects, refused at LOAD, in the seam's own codes.
    const structural = [
      ['RESEARCH_CONTRACT_SCHEMA_MISSING', (dir) => unlinkSync(path.join(dir, RESEARCH_CONTRACT_FILES['research-dossier']))],
      ['RESEARCH_CONTRACT_SCHEMA_MALFORMED', (dir) => writeFileSync(path.join(dir, RESEARCH_CONTRACT_FILES['calibration-record']), 'not json')],
      ['RESEARCH_CONTRACT_SCHEMA_MALFORMED', (dir) => writeFileSync(path.join(dir, RESEARCH_CONTRACT_FILES['calibration-record']), '[]')],
      ['RESEARCH_CONTRACT_SCHEMA_ID_MISMATCH', (dir) => {
        const file = path.join(dir, RESEARCH_CONTRACT_FILES['hypothesis-card']);
        writeFileSync(file, JSON.stringify({ ...JSON.parse(readFileSync(file, 'utf8')), $id: 'https://example.com/card.json' }));
      }],
      ['RESEARCH_CONTRACT_SCHEMA_DRAFT_UNSUPPORTED', (dir) => {
        const file = path.join(dir, RESEARCH_CONTRACT_FILES['hypothesis-card']);
        writeFileSync(file, JSON.stringify({ ...JSON.parse(readFileSync(file, 'utf8')), $schema: 'http://json-schema.org/draft-07/schema' }));
      }],
    ];
    for (const [code, tamper] of structural) {
      const dir = staged();
      tamper(dir);
      const error = refusal(() => loadResearchContracts(dir));
      assert.ok(String(error.message).startsWith(code), `expected ${code}, got ${String(error.message)}`);
      assert.equal(isBoardError(error), false, 'a broken schema directory is a load-time failure, not a BoardError: no caller exists yet to catch one');
    }
    // A broken schema DIRECTORY is a load-time failure and a plain Error, not
    // a BoardError: no caller exists yet to catch a typed refusal, and the
    // closed code enum has no member for "your own schema directory is
    // broken". The assertion is on the code, not on the class. A RELATIVE
    // path is deliberately absent from this list: it is resolved against the
    // process cwd, so it is a different directory rather than an invalid input.
    for (const dir of ['', null, 42, undefined, {}]) {
      const error = refusal(() => loadResearchContracts(dir));
      assert.equal(isBoardError(error), false, `a bad directory raised a BoardError: ${String(error.message)}`);
      assert.ok(String(error.message).startsWith('RESEARCH_CONTRACT_SCHEMA_DIR_INVALID'), String(error.message));
    }
  });
});

// ===========================================================================
// registry.mjs — the ledger
// ===========================================================================

describe('registry.mjs — an injected clock, an idempotency ledger and a CAS', () => {
  test('openRegistry refuses a relative root, a frozen target and a missing injected clock or id factory', () => {
    typedRefusal(() => openRegistry({ root: 'results/s2-008/x', clock: fixedClock(AT), ids: deterministicIds('x') }), NeedsInput, 'REGISTRY_ROOT_NOT_ABSOLUTE');
    typedRefusal(() => openRegistry({ root: '', clock: fixedClock(AT), ids: deterministicIds('x') }), NeedsInput, 'REGISTRY_ROOT_REQUIRED');
    typedRefusal(() => openRegistry({ root: freshDir('no-clock'), ids: deterministicIds('x') }), MalformedResult, 'REGISTRY_CLOCK_NOT_INJECTED');
    typedRefusal(() => openRegistry({ root: freshDir('no-ids'), clock: fixedClock(AT) }), MalformedResult, 'REGISTRY_ID_FACTORY_NOT_INJECTED');
    // `contracts/` and `evidence/` are frozen targets and `.git` is delivery's:
    // a registry that could purge them is a registry nobody should run. The
    // check is BEFORE the directory is created, which is asserted, not assumed.
    const protectedRoot = path.join(CONTRACTS_DIR, 's2-008-must-not-exist');
    typedRefusal(() => openRegistry({ root: protectedRoot, clock: fixedClock(AT), ids: deterministicIds('x') }), BlockedPolicy, 'REGISTRY_ROOT_PROTECTED');
    assert.equal(existsSync(protectedRoot), false, 'the refusal created a directory inside a frozen target');
    // A plain object is not a handle: the identity symbol is checked, not the
    // shape, so a hand-rolled twin is refused instead of half-worked.
    typedRefusal(() => putExperiment({ root: freshDir('foreign') }, { key: 'k', args: {}, expectedRevision: 0, mutate: () => ({}) }), NeedsInput, 'REGISTRY_NOT_OPEN');
  });

  test('the same key twice writes ONE record with an IDENTICAL digest and reports a replay', () => {
    const ledger = freshRegistry('idem');
    const first = putExperiment(ledger, {
      key: 's2-008-trial-01',
      args: { trial: 'trl-s2-008-01' },
      expectedRevision: 0,
      mutate: () => payload('TRIAL', { trial: 'trl-s2-008-01', campaign_id: 'cmp-1', outcome: 'POSITIVE' }),
    });
    assert.equal(first.replayed, false);
    assert.equal(first.revision, 1);
    const afterFirst = snapshotDigest(ledger);

    const second = putExperiment(ledger, {
      key: 's2-008-trial-01',
      args: { trial: 'trl-s2-008-01' },
      expectedRevision: 0,
      mutate: () => payload('TRIAL', { trial: 'trl-s2-008-01', campaign_id: 'cmp-1', outcome: 'POSITIVE' }),
    });
    assert.equal(second.replayed, true, 'the second call with the same key and the same arguments was not a replay');
    // The FIRST call hands back the caller's own object; the REPLAY hands back
    // the STORED one, which is the canonical form, so the two are equal as
    // documents and not by reference. Asserting reference identity here would
    // be asserting a detail of key order rather than a property.
    assert.deepEqual(second.result, first.result, 'the replay returned a different payload');
    assert.equal(canonicalDigest(second.result), canonicalDigest(first.result));
    assert.equal(second.headDigest, first.headDigest, 'the replay moved the head digest');
    assert.equal(second.revision, first.revision, 'the replay bumped the revision');
    // One record, one marker, one line each: the idempotency ledger is
    // consulted BEFORE the head and the journal, so the second call wrote
    // nothing at all.
    assert.equal(readJournal(ledger).length, 1);
    assert.equal(verifyChain(ledger).markers.length, 1);
    assert.equal(snapshotDigest(ledger), afterFirst, 'the replay changed the ledger bytes');
    assert.equal(ledger.revision(), 1);
    assert.equal(headDigest(ledger), first.headDigest);
    // The returned result IS the journalled payload, verbatim.
    assert.deepEqual(readJournal(ledger)[0].payload, first.result);
    // A repeat of a replay is still a replay.
    assert.equal(putExperiment(ledger, { key: 's2-008-trial-01', args: { trial: 'trl-s2-008-01' }, expectedRevision: 0, mutate: () => payload('TRIAL') }).replayed, true);
    assert.equal(readJournal(ledger).length, 1);
  });

  test('the same key with DIFFERENT arguments is refused and writes nothing', () => {
    const ledger = freshRegistry('idem-args');
    putExperiment(ledger, { key: 'k1', args: { trial: 'trl-1' }, expectedRevision: 0, mutate: () => payload('TRIAL', { trial: 'trl-1' }) });
    const before = snapshotDigest(ledger);
    const error = typedRefusal(
      () => putExperiment(ledger, { key: 'k1', args: { trial: 'trl-2' }, expectedRevision: 1, mutate: () => payload('TRIAL', { trial: 'trl-2' }) }),
      IdempotencyConflict,
      'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_ARGUMENTS',
    );
    assert.equal(error.code, 'IDEMPOTENCY_CONFLICT');
    assert.equal(snapshotDigest(ledger), before, 'a refused key reuse changed the ledger');
    assert.equal(readJournal(ledger).length, 1, 'a refused key reuse journalled a second record');
    // Key order is irrelevant to the digest, so a re-ordered call is a replay
    // and NOT a conflict: that is what makes the key a canonical one.
    const reordered = putExperiment(ledger, { key: 'k1', args: { trial: 'trl-1' }, expectedRevision: 0, mutate: () => payload('TRIAL', { trial: 'trl-1' }) });
    assert.equal(reordered.replayed, true);
  });

  test('a stale expectedRevision is a CAS conflict, and the correct revision still writes', () => {
    const ledger = freshRegistry('cas');
    putExperiment(ledger, { key: 'k1', args: { a: 1 }, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1 }) });
    const before = snapshotDigest(ledger);
    typedRefusal(
      () => putExperiment(ledger, { key: 'k2', args: { a: 2 }, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 2 }) }),
      RevisionConflict,
      'REVISION_CONFLICT',
    );
    assert.equal(snapshotDigest(ledger), before, 'a CAS conflict changed the ledger');
    assert.equal(readJournal(ledger).length, 1);
    // Last-write-wins is not the alternative offered here: the caller's
    // expectation is the gate, and the correct one goes through.
    const written = putExperiment(ledger, { key: 'k2', args: { a: 2 }, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2 }) });
    assert.equal(written.revision, 2);
    assert.equal(readJournal(ledger).length, 2);
    assert.equal(verifyChain(ledger).ok, true);
    // The argument guard is part of the same fail-closed surface.
    for (const expected of [-1, 1.5, '1', null, undefined]) {
      typedRefusal(() => putExperiment(ledger, { key: 'kx', args: {}, expectedRevision: expected, mutate: () => payload('TRIAL') }), NeedsInput, 'putExperiment.expectedRevision');
    }
    typedRefusal(() => putExperiment(ledger, { key: 'k', args: 'not an object', expectedRevision: 2, mutate: () => payload('TRIAL') }), NeedsInput, 'putExperiment.args');
    typedRefusal(() => putExperiment(ledger, { key: '', args: {}, expectedRevision: 2, mutate: () => payload('TRIAL') }), NeedsInput, 'idempotency key');
    typedRefusal(() => putExperiment(ledger, { key: 'k', args: {}, expectedRevision: 2, mutate: 'not a function' }), NeedsInput, 'putExperiment: mutate must be a function');
    typedRefusal(() => putExperiment(ledger, { key: 'k', args: {}, expectedRevision: 2, mutate: () => 42 }), MalformedResult, 'REGISTRY_PAYLOAD_NOT_AN_OBJECT');
    typedRefusal(() => putExperiment(ledger, { key: 'k', args: {}, expectedRevision: 2, mutate: () => ({ value: Number.NaN }) }), MalformedResult, 'REGISTRY_VALUE_NOT_CANONICAL');
    typedRefusal(() => putExperiment(ledger, { key: 'k', args: {}, expectedRevision: 2, mutate: () => ({ kind: 'not_upper_snake' }) }), MalformedResult, 'REGISTRY_RECORD_KIND_MALFORMED');
  });

  test('the journal and the marker chain are APPEND-ONLY, byte for byte', () => {
    const ledger = freshRegistry('append-only');
    putExperiment(ledger, { key: 'k1', args: {}, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1 }) });
    const journalAfterOne = readFileSync(ledger.journalPath, 'utf8');
    const markersAfterOne = readFileSync(ledger.operationsPath, 'utf8');
    putExperiment(ledger, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2 }) });
    putExperiment(ledger, { key: 'k3', args: {}, expectedRevision: 2, mutate: () => payload('RESULT', { n: 3, campaign_id: 'cmp-1', outcome: 'NEGATIVE' }) });
    const journalAfterThree = readFileSync(ledger.journalPath, 'utf8');
    const markersAfterThree = readFileSync(ledger.operationsPath, 'utf8');
    // Prefix extension, not a rewrite: an UPDATE path would break this.
    assert.ok(journalAfterThree.startsWith(journalAfterOne), 'the journal rewrote bytes that were already committed');
    assert.ok(markersAfterThree.startsWith(markersAfterOne), 'the idempotency ledger rewrote a committed marker');
    assert.equal(journalAfterThree.trim().split('\n').length, 3);
    assert.equal(markersAfterThree.trim().split('\n').length, 3);
    // Every committed record is exactly its own canonical form, so a
    // whitespace or key-order edit is detectable rather than invisible.
    for (const line of journalAfterThree.trim().split('\n')) assert.equal(line, canonicalize(JSON.parse(line)));
    for (const line of markersAfterThree.trim().split('\n')) assert.equal(line, canonicalize(JSON.parse(line)));
    // `appendRecord` exists for the two callers the narrow writers do not
    // cover, and an IDENTICAL record is a replay, not a second fact.
    const access = { kind: 'ACCESS', trial: 'trl-s2-008-01', partition: 'HOLDOUT', unseal_digest: 'c'.repeat(64), read_at: AT, at: AT };
    const first = appendRecord(ledger, access);
    const replayed = appendRecord(ledger, access);
    assert.equal(replayed.recordId, first.recordId);
    assert.equal(replayed.digest, first.digest);
    assert.equal(first.index, 3);
    assert.equal(first.prev_digest, readJournal(ledger)[2].digest, 'the appended record is not chained to the committed head');
    assert.equal(appendRecord(ledger, { ...access, trial: 'trl-s2-008-02' }).index, 4);
    assert.equal(verifyChain(ledger).ok, true);
  });

  test('a re-written byte, a forged tail and a rewound head are all DETECTED, and none of them is history', () => {
    // (a) a byte re-written in the middle of a committed line
    const rewritten = freshRegistry('rewrite');
    putExperiment(rewritten, { key: 'k1', args: {}, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1 }) });
    putExperiment(rewritten, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2 }) });
    const original = readFileSync(rewritten.journalPath, 'utf8');
    // A single extra space inside the first committed line: byte-identical as
    // a JSON value, different as bytes, and therefore a defect the chain must
    // see (a stored line is byte-exactly its own canonical form).
    writeFileSync(rewritten.journalPath, original.replace('{', '{ '));
    const chain = verifyChain(rewritten);
    assert.equal(chain.ok, false, 'a re-spaced journal line verified clean');
    assert.equal(chain.brokenAt, 0, 'the first non-canonical line was not reported as the break');
    typedRefusal(() => putExperiment(rewritten, { key: 'k3', args: {}, expectedRevision: 2, mutate: () => payload('TRIAL') }), ReconciliationRequired, 'JOURNAL_NOT_COMMITTED');

    // (b) a complete but UNCOMMITTED line appended by hand: chain-valid, and
    //     still not history, because no head covers it.
    const forged = freshRegistry('forged');
    putExperiment(forged, { key: 'k1', args: {}, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1 }) });
    const lines = readFileSync(forged.journalPath, 'utf8').trim().split('\n');
    const last = JSON.parse(lines[0]);
    const forgedRecord = {
      index: last.index + 1,
      record_id: 'rec-forged',
      kind: 'RESULT',
      campaign_id: 'cmp-forged',
      key: 'forged',
      operation: 'putExperiment',
      at: AT,
      payload: { kind: 'RESULT', outcome: 'POSITIVE' },
      document: null,
      document_contract: null,
      prev_digest: last.digest,
    };
    writeFileSync(forged.journalPath, `${lines.join('\n')}\n${JSON.stringify(forgedRecord)}\n`);
    assert.equal(verifyChain(forged).ok, false, 'an uncommitted tail verified clean');
    assert.equal(readJournal(forged).length, 1, 'an uncommitted tail was returned as history');
    typedRefusal(() => putExperiment(forged, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL') }), ReconciliationRequired, 'JOURNAL_NOT_COMMITTED');

    // (c) a head rewound below what the journal holds: the interleaved
    //     two-writer shape, DETECTED rather than accepted.
    const rewound = freshRegistry('rewound');
    putExperiment(rewound, { key: 'k1', args: {}, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1 }) });
    putExperiment(rewound, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2 }) });
    const head = JSON.parse(readFileSync(rewound.headPath, 'utf8'));
    writeFileSync(rewound.headPath, `${JSON.stringify({ ...head, revision: 1, record_count: 1, marker_count: 1 })}\n`);
    const rewoundChain = verifyChain(rewound);
    assert.equal(rewoundChain.ok, false);
    assert.equal(rewoundChain.uncommittedFrom, 1, 'the uncovered tail was not reported');
    assert.equal(rewoundChain.markers.ok, false, 'the marker chain reported clean over an uncovered marker');
    assert.equal(readJournal(rewound).length, 1);
    typedRefusal(() => putExperiment(rewound, { key: 'k3', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL') }), ReconciliationRequired, 'JOURNAL_NOT_COMMITTED');
  });

  test('recovery truncates to the last marked record and records a RECONCILIATION, never a silent zero', () => {
    const ledger = freshRegistry('recover');
    putExperiment(ledger, { key: 'k1', args: {}, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1, campaign_id: 'cmp-1' }) });
    putExperiment(ledger, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2, campaign_id: 'cmp-1' }) });
    // A half-written record: the crash window between the journal append and
    // the operation marker.
    writeFileSync(ledger.journalPath, `${readFileSync(ledger.journalPath, 'utf8')}{"index":2,"kind":"TRI`);
    const recovered = recoverTornTail(ledger);
    assert.equal(recovered.torn, true);
    assert.equal(recovered.truncatedFrom, 2);
    assert.equal(recovered.droppedRecords, 0, 'the half-written record was never a record, so nothing complete was dropped');
    assert.equal(recovered.keptRecords, 2);
    assert.notEqual(recovered.reconciliationRow, null, 'a torn tail was recovered with no reconciliation row');
    assert.equal(recovered.reconciliationRow.payload.reason, 'TORN_TAIL');
    assert.equal(recovered.reconciliationRow.payload.resolution, 'EFFECT_UNDETERMINED');
    assert.ok(recovered.reconciliationRow.payload.detail.torn_bytes > 0, 'the row does not say how many bytes were dropped');
    // Truncation bumps the revision, so the stale writer that owned the old
    // expectation cannot write on top of a recovered ledger.
    assert.ok(recovered.revision > 2);
    typedRefusal(() => putExperiment(ledger, { key: 'k9', args: {}, expectedRevision: 2, mutate: () => payload('TRIAL') }), RevisionConflict, 'REVISION_CONFLICT');
    assert.equal(verifyChain(ledger).ok, true);
    assert.equal(readJournal(ledger).length, 3, 'the reconciliation row is not in the journal');
    // A second recovery on a clean ledger is a no-op that says so.
    const again = recoverTornTail(ledger);
    assert.equal(again.torn, false);
    assert.equal(again.reconciliationRow, null);
    assert.equal(again.droppedRecords, 0);
  });

  test('a journalled document must NAME one of the three frozen contracts and satisfy it', () => {
    const ledger = freshRegistry('document-gate');
    // The happy path: a real hypothesis card, validated by the single surface.
    const accepted = putExperiment(ledger, {
      key: 'card',
      args: { card_id: PREREGISTRATION.card.card_id },
      expectedRevision: 0,
      mutate: () => payload('CARD', { campaign_id: 'cmp-1', document_contract: 'hypothesis-card', document: copy(PREREGISTRATION.card) }),
    });
    assert.equal(accepted.result.document_contract, 'hypothesis-card');
    assert.equal(readJournal(ledger)[0].document_contract, 'hypothesis-card');

    const before = snapshotDigest(ledger);
    const revision = ledger.revision();
    const cases = [
      ['REGISTRY_DOCUMENT_CONTRACT_MISSING', NeedsInput, () => payload('CARD', { document: { card_id: 'hyc-x' } })],
      ['UNKNOWN_RESEARCH_CONTRACT', NeedsInput, () => payload('CARD', { document: {}, document_contract: 'board-task' })],
      ['RESEARCH_CONTRACT_VIOLATION', MalformedResult, () => payload('CARD', { document: { card_id: 'not-a-card' }, document_contract: 'hypothesis-card' })],
      // A contract name with no document is a bug, not a lenient default.
      ['REGISTRY_DOCUMENT_CONTRACT_MISSING', NeedsInput, () => payload('CARD', { document_contract: 'hypothesis-card' })],
    ];
    for (const [code, Class, mutate] of cases) {
      typedRefusal(() => putExperiment(ledger, { key: `refused-${code}-${Class.name}`, args: { code }, expectedRevision: revision, mutate }), Class, code);
      assert.equal(snapshotDigest(ledger), before, `${code}: a refused document changed the ledger`);
      assert.equal(ledger.revision(), revision, `${code}: a refused document bumped the revision`);
    }
  });

  test('a budget reservation must exist, must be positive, and an over-grant settle writes nothing', () => {
    const ledger = freshRegistry('budget');
    const beforeAny = snapshotDigest(ledger);
    // An unassigned budget is not a zero, and a free model is not an
    // authorization: the refusal is BUDGET_RESERVATION_MISSING, not a settle of 0.
    const missing = typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-absent', key: 's0', args: { units: 1 } }), BudgetExceeded, 'BUDGET_RESERVATION_MISSING');
    assert.equal(missing.code, 'BUDGET_EXCEEDED');
    assert.equal(snapshotDigest(ledger), beforeAny, 'a settle against no reservation changed the ledger');

    putExperiment(ledger, {
      key: 'reserve',
      args: { reservation_id: 'rsv-1' },
      expectedRevision: 0,
      mutate: () => payload('BUDGET_RESERVATION', {
        campaign_id: 'cmp-1', reservation_id: 'rsv-1', granted_units: 8, spent_units: 0, currency: 'trial_runs', expires_at: DECISION_POINT,
      }),
    });
    // Units are a finite number >= 0: a missing budget is not zero, and a
    // negative one is not a credit.
    for (const units of [undefined, null, -1, Number.NaN, Number.POSITIVE_INFINITY, '3']) {
      typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-1', key: `bad-${String(units)}`, args: { units } }), NeedsInput, 'recordSpend.args.units');
    }
    const overSpent = recordSpend(ledger, { reservationId: 'rsv-1', key: 'spend-3', args: { units: 3 } });
    assert.equal(overSpent.spent_units, 3);
    assert.equal(overSpent.replayed, false);
    // A replayed settle writes nothing and never double-charges.
    const replayed = recordSpend(ledger, { reservationId: 'rsv-1', key: 'spend-3', args: { units: 3 } });
    assert.equal(replayed.replayed, true);
    assert.equal(replayed.spendRecordId, overSpent.spendRecordId);
    assert.equal(replayed.spent_units, 3, 'a replayed settle re-charged the reservation');
    const beforeOver = snapshotDigest(ledger);
    typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-1', key: 'spend-9', args: { units: 9 } }), BudgetExceeded, 'BUDGET_EXCEEDED');
    assert.equal(snapshotDigest(ledger), beforeOver, 'an over-grant settle changed the journal');
    // An unreadable expiry is not "never expires".
    putExperiment(ledger, { key: 'reserve-bad', args: {}, expectedRevision: ledger.revision(), mutate: () => payload('BUDGET_RESERVATION', { campaign_id: 'cmp-1', reservation_id: 'rsv-bad', granted_units: 4, spent_units: 0, currency: 'trial_runs', expires_at: 'whenever' }) });
    typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-bad', key: 'spend-bad', args: { units: 1 } }), MalformedResult, 'BUDGET_RESERVATION_EXPIRES_AT_MALFORMED');
  });

  test('a released remainder cannot be released twice, and a replayed release is not a second release', () => {
    const ledger = freshRegistry('release');
    putExperiment(ledger, {
      key: 'reserve',
      args: {},
      expectedRevision: 0,
      mutate: () => payload('BUDGET_RESERVATION', {
        campaign_id: 'cmp-1', reservation_id: 'rsv-1', granted_units: 8, spent_units: 0, currency: 'trial_runs', expires_at: DECISION_POINT,
      }),
    });
    recordSpend(ledger, { reservationId: 'rsv-1', key: 'spend-3', args: { units: 3 } });
    const release = recordSpend(ledger, { reservationId: 'rsv-1', key: 'release-5', args: { units: 5, released: true } });
    assert.equal(release.spent_units, 8);
    assert.equal(readJournal(ledger).at(-1).payload.remaining_units, 0, 'the released remainder is not zero after the release');

    const beforeSecond = snapshotDigest(ledger);
    typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-1', key: 'release-5-again', args: { units: 5, released: true } }), BudgetExceeded, 'BUDGET_EXCEEDED');
    assert.equal(snapshotDigest(ledger), beforeSecond, 'a double release changed the journal');
    // A settle after the remainder is gone is refused, not silently clamped.
    typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-1', key: 'spend-1-after', args: { units: 1 } }), BudgetExceeded, 'BUDGET_EXCEEDED');
    // The same release replayed is a replay: one release, one row.
    assert.equal(recordSpend(ledger, { reservationId: 'rsv-1', key: 'release-5', args: { units: 5, released: true } }).replayed, true);
    const releases = readJournal(ledger).filter((record) => record.kind === 'BUDGET_RELEASE');
    assert.equal(releases.length, 1, 'more than one release row exists');
    // DOCUMENTED LIMIT, asserted so a reader sees it in code rather than in a
    // report: "released exactly once" is enforced by the GRANT CEILING, not by
    // a released flag. A zero-unit release is therefore journalled (it moves no
    // units and leaves the remainder at zero); what is refused is any release
    // that would spend the remainder twice. The ticket's double-release
    // property holds for every release that spends units.
    const zero = recordSpend(ledger, { reservationId: 'rsv-1', key: 'release-0', args: { units: 0, released: true } });
    assert.equal(zero.spent_units, 8, 'a zero-unit release moved the spend');
    assert.equal(readJournal(ledger).at(-1).payload.remaining_units, 0);
  });

  test('an EXPIRED reservation is a reconciliation committed BEFORE the throw, and a retry is not a zero', () => {
    // The clock is after `expires_at`, so the reservation is expired on ARRIVAL.
    const ledger = freshRegistry('expired', AFTER_DECISION);
    putExperiment(ledger, {
      key: 'reserve',
      args: {},
      expectedRevision: 0,
      mutate: () => payload('BUDGET_RESERVATION', {
        campaign_id: 'cmp-1', reservation_id: 'rsv-x', granted_units: 4, spent_units: 0, currency: 'trial_runs', expires_at: DECISION_POINT,
      }),
    });
    const error = typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-x', key: 'spend-1', args: { units: 1 } }), ReconciliationRequired, 'BUDGET_RESERVATION_EXPIRED');
    assert.equal(error.retryable, false, 'an expired reservation must not be advertised as retryable');
    // The reconciliation row is COMMITTED even though the call threw: the
    // outcome is undetermined and that fact is durable.
    const rows = readJournal(ledger);
    const reconciliation = rows.filter((record) => record.kind === 'RECONCILIATION');
    assert.equal(reconciliation.length, 1, 'the expiry committed no reconciliation row');
    assert.equal(reconciliation[0].payload.reason, 'BUDGET_RESERVATION_EXPIRED');
    assert.equal(reconciliation[0].payload.resolution, 'EFFECT_UNDETERMINED');
    assert.equal(reconciliation[0].payload.detail.observed_at, AFTER_DECISION);
    assert.equal(rows.filter((record) => record.kind === 'BUDGET_SPEND' || record.kind === 'BUDGET_RELEASE').length, 0, 'an expired settle wrote a spend row');
    // A blind retry under the SAME key and under a NEW one is refused the same
    // way and adds no second row: the reconciliation is not a retry queue.
    typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-x', key: 'spend-1', args: { units: 1 } }), ReconciliationRequired, 'BUDGET_RESERVATION_EXPIRED');
    typedRefusal(() => recordSpend(ledger, { reservationId: 'rsv-x', key: 'spend-2', args: { units: 1 } }), ReconciliationRequired, 'BUDGET_RESERVATION_EXPIRED');
    assert.equal(readJournal(ledger).filter((record) => record.kind === 'RECONCILIATION').length, 1, 'retries accumulated reconciliation rows');
    assert.equal(readJournal(ledger).filter((record) => record.kind === 'BUDGET_SPEND').length, 0, 'a retry produced a spend row');
    assert.equal(verifyChain(ledger).ok, true);
    // The campaign is now RECONCILIATION_REQUIRED, which is a THIRD answer and
    // not a zero and not a clean failure.
    assert.equal(ledger.campaignOutcome('cmp-1').status, 'RECONCILIATION_REQUIRED');
  });

  test('a stale writer is FENCED: a token that is not the next one writes nothing', () => {
    const ledger = freshRegistry('fence');
    putExperiment(ledger, { key: 'k1', args: {}, expectedRevision: 0, mutate: () => payload('TRIAL', { n: 1 }) });
    // A writer that read the head when the committed fence was 0 presents 1.
    const stale = ledger.head().fence;
    assert.equal(stale, 1, 'the first commit did not advance the fence');
    putExperiment(ledger, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2 }) });
    const before = snapshotDigest(ledger);
    // The other writer already moved the fence on: the stale token is refused.
    typedRefusal(() => putExperiment(ledger, { key: 'k3', args: { fence: stale }, expectedRevision: 2, mutate: () => payload('TRIAL') }), StaleFence, 'FENCE_NOT_CURRENT');
    // A token beyond the next one is refused as well: no queueing, no gaps.
    typedRefusal(() => putExperiment(ledger, { key: 'k4', args: { fence: ledger.head().fence + 3 }, expectedRevision: 2, mutate: () => payload('TRIAL') }), StaleFence, 'FENCE_NOT_NEXT');
    for (const fence of [0, -1, 1.5]) {
      typedRefusal(() => putExperiment(ledger, { key: `kf-${String(fence)}`, args: { fence }, expectedRevision: 2, mutate: () => payload('TRIAL') }), StaleFence, 'FENCE_MALFORMED');
    }
    // A numeric STRING is read as the token it spells, so a stale token spelled
    // as '1' is a stale token, not a malformed one. Both are refused; the
    // message says which, so a caller can tell a typo from a stale writer.
    typedRefusal(() => putExperiment(ledger, { key: 'kf-string', args: { fence: '1' }, expectedRevision: 2, mutate: () => payload('TRIAL') }), StaleFence, 'FENCE_NOT_CURRENT');
    assert.equal(snapshotDigest(ledger), before, 'a fenced write changed the ledger');
    assert.equal(readJournal(ledger).length, 2);
    // The revision CAS remains the mandatory gate, so a stale writer is
    // refused on both counts rather than on the fence alone.
    const currentFence = ledger.head().fence + 1;
    typedRefusal(() => putExperiment(ledger, { key: 'k5', args: { fence: currentFence }, expectedRevision: 1, mutate: () => payload('TRIAL') }), RevisionConflict, 'REVISION_CONFLICT');
    // The next token is accepted, and the fence advances by exactly one.
    const accepted = putExperiment(ledger, { key: 'k6', args: { fence: currentFence }, expectedRevision: 2, mutate: () => payload('TRIAL', { n: 3 }) });
    assert.equal(accepted.replayed, false);
    assert.equal(ledger.head().fence, currentFence);
    assert.equal(verifyChain(ledger).ok, true);
    // `fencing_token` is the S2-007 spelling of the same member.
    typedRefusal(() => putExperiment(ledger, { key: 'k7', args: { fencing_token: 1 }, expectedRevision: 3, mutate: () => payload('TRIAL') }), StaleFence, 'FENCE_NOT_CURRENT');
  });

  test("'no outcome recorded' is DISTINGUISHABLE from 'no effect', and from a first-class NULL", () => {
    const ledger = freshRegistry('outcome');
    // (a) nothing was ever recorded for this campaign.
    const nothing = ledger.campaignOutcome('cmp-1');
    assert.equal(nothing.status, 'NO_CAMPAIGN_RECORDS');
    assert.equal(nothing.outcome, null);
    assert.equal(nothing.implicit_zero, false, 'an absent record was reported as an implicit zero');
    assert.equal(nothing.record_count, 0);

    // (b) the campaign completed and recorded NO result: a missing outcome,
    //     which is a claim nobody made.
    putExperiment(ledger, { key: 'c1', args: {}, expectedRevision: 0, mutate: () => payload('CAMPAIGN_COMPLETE', { campaign_id: 'cmp-1' }) });
    const noOutcome = ledger.campaignOutcome('cmp-1');
    assert.equal(noOutcome.status, 'NO_OUTCOME_RECORDED');
    assert.equal(noOutcome.outcome, null);
    assert.equal(noOutcome.implicit_zero, false);
    assert.equal(noOutcome.result_record_ids.length, 0);
    assert.notEqual(noOutcome.status, nothing.status, 'a campaign with no records reads like a completed campaign with no result');

    // (c) a first-class NULL result: an outcome WAS recorded, and it is null.
    //     It must not be readable as "nothing was found".
    putExperiment(ledger, { key: 'c2', args: {}, expectedRevision: 1, mutate: () => payload('RESULT', { campaign_id: 'cmp-1', outcome: 'NULL' }) });
    const recordedNull = ledger.campaignOutcome('cmp-1');
    assert.equal(recordedNull.status, 'OUTCOME_RECORDED');
    assert.equal(recordedNull.outcome, 'NULL');
    assert.equal(recordedNull.implicit_zero, false);
    assert.equal(recordedNull.result_record_ids.length, 1);
    assert.notEqual(recordedNull.status, noOutcome.status, 'a recorded NULL is indistinguishable from no recorded outcome');
    assert.ok(recordedNull.result_record_ids[0].startsWith('rec-'), 'the outcome does not name the record that carries it');

    // (d) a NEGATIVE result is equally first-class, and a later result is the
    //     one reported, so an overwritten verdict cannot hide behind an older
    //     row.
    putExperiment(ledger, { key: 'c3', args: {}, expectedRevision: 2, mutate: () => payload('RESULT', { campaign_id: 'cmp-1', outcome: 'NEGATIVE' }) });
    putExperiment(ledger, { key: 'c4', args: {}, expectedRevision: 3, mutate: () => payload('RESULT', { campaign_id: 'cmp-1', outcome: 'INFRA' }) });
    const infra = ledger.campaignOutcome('cmp-1');
    assert.equal(infra.outcome, 'INFRA', 'an infra result is not a first-class outcome');
    assert.equal(infra.result_record_ids.length, 3, 'the earlier results stopped being recorded');
    assert.equal(infra.implicit_zero, false);
    // A campaign nobody wrote about is still its own answer.
    assert.equal(ledger.campaignOutcome('cmp-absent').status, 'NO_CAMPAIGN_RECORDS');
  });

  test('A5 the same base, purged and re-run, reproduces the same ids and the same head digest', () => {
    const ledger = freshRegistry('repeat');
    const command = { key: 's2-008-trial-01', args: { trial: 'trl-s2-008-01' }, expectedRevision: 0, mutate: () => payload('TRIAL', { trial: 'trl-s2-008-01', campaign_id: 'cmp-1', outcome: 'POSITIVE' }) };
    const firstRun = putExperiment(ledger, command);
    const firstJournal = readFileSync(ledger.journalPath, 'utf8');
    const firstRecordId = readJournal(ledger)[0].record_id;

    // The purge is the half that makes a repeat run meaningful: without it the
    // second run would fail on the first run's leftovers instead of on the
    // property. It is idempotent, and the second call removes nothing.
    const firstPurge = purgeRegistry(ledger);
    assert.equal(firstPurge.purged, true);
    assert.ok(firstPurge.removedFiles > 0);
    const secondPurge = purgeRegistry(ledger);
    assert.equal(secondPurge.purged, false, 'a second purge reported work');
    assert.equal(secondPurge.removedFiles, 0);
    assert.equal(secondPurge.snapshotDigest, firstPurge.snapshotDigest, 'a second purge moved the snapshot digest');
    assert.equal(ledger.revision(), 0, 'a purge is not a commit');
    assert.equal(readJournal(ledger).length, 0);

    // A NEW process would do exactly this: re-open the same root with the same
    // injected clock and the same id factory, and write the same command.
    const reopened = openRegistry({ root: ledger.root, clock: fixedClock(AT), ids: deterministicIds('repeat') });
    const secondRun = putExperiment(reopened, command);
    assert.equal(secondRun.headDigest, firstRun.headDigest, 'a repeat run on the same base moved the head digest');
    assert.equal(secondRun.revision, firstRun.revision);
    assert.equal(readJournal(reopened)[0].record_id, firstRecordId, 'a repeat run minted a different record id');
    assert.equal(readFileSync(reopened.journalPath, 'utf8'), firstJournal, 'a repeat run wrote different journal bytes');

    // A root this module did not create is never purged: a marker of another
    // kind is a refusal, not a cleanup.
    const foreign = freshDir('foreign-root');
    writeFileSync(path.join(foreign, 'registry.json'), `${JSON.stringify({ kind: 'somebody-elses-ledger' })}\n`);
    typedRefusal(() => openRegistry({ root: foreign, clock: fixedClock(AT), ids: deterministicIds('foreign') }), BlockedPolicy, 'REGISTRY_ROOT_MARKER_MISMATCH');

    // The advisory lock is an optimisation: correctness never depends on it,
    // and it is not part of any digest.
    const lock = acquireLock(reopened);
    assert.equal(lock.held, true);
    const withLock = snapshotDigest(reopened);
    assert.equal(acquireLock(reopened).held, false, 'two callers both believe they hold the lock');
    assert.equal(snapshotDigest(reopened), withLock, 'the lock moved a digest');
    assert.equal(releaseLock(reopened).released, true);
    assert.equal(releaseLock(reopened).released, false, 'releasing twice is not a release');
    // A locked ledger still writes: the lock is not the gate, the CAS is.
    assert.equal(putExperiment(reopened, { key: 'k2', args: {}, expectedRevision: 1, mutate: () => payload('TRIAL', { n: 2 }) }).revision, 2);
  });
});

// ===========================================================================
// preregistration.mjs — frozen before trial one
// ===========================================================================

describe('preregistration.mjs — frozen before run 1, and never moved after it', () => {
  test('the preregistration is admissible, self-consistent and carries no result', () => {
    assert.equal(PREREGISTRATION.kind, PREREGISTRATION_KIND);
    assert.equal(PREREGISTRATION.rule, PREREGISTRATION_RULE);
    assert.equal(assertPreregistration(PREREGISTRATION), PREREGISTRATION);
    assert.equal(stoppingRuleOf(PREREGISTRATION).kind, 'FIXED_TRIALS');
    assert.equal(stoppingRuleOf(PREREGISTRATION).early_stop, false, 'FIXED_TRIALS with an early stop is a peek');
    assert.equal(seedCountOf(PREREGISTRATION), PREREGISTRATION.seed_count);
    // The self-seal is the TRACK digest, over the twelve named members.
    const digest = preregistrationDigest(PREREGISTRATION);
    assert.match(digest, HEX64, 'the digest is not 64 bare hex characters');
    assert.equal(PREREGISTRATION.preregistration_digest, digest);
    // Every digest-covered member is PRESENT, or the digest would be over a
    // partial projection and a removed member would be invisible.
    for (const field of [
      'card_id', 'card_digest', 'metric', 'frozen_baseline', 'seed_rule', 'seed_count',
      'seeds_digest', 'stopping_rule', 'budget_reservation', 'noise_rule', 'multiplicity_rule',
      'inference_mode',
    ]) {
      assert.ok(Object.hasOwn(PREREGISTRATION, field), `digest-covered field absent: ${field}`);
      const without = copy(PREREGISTRATION);
      delete without[field];
      // The refusal is `MALFORMED_RESULT`; the code and the field it names
      // travel in `message` and `detail` respectively, so both are read.
      const error = typedRefusal(() => preregistrationDigest(without), MalformedResult, 'PREREGISTRATION_FIELD_MISSING');
      assert.match(String(error.detail), new RegExp(`absent: ${field}`), `the refusal does not name ${field}`);
    }
    // A moved digest-covered member moves the digest, and the seal catches it
    // before any other rule does.
    const movedBudget = { ...copy(PREREGISTRATION), budget_reservation: { ...PREREGISTRATION.budget_reservation, granted_units: 9 } };
    assert.notEqual(preregistrationDigest(movedBudget), digest);
    typedRefusal(() => assertPreregistration(movedBudget), MalformedResult, 'PREREGISTRATION_SEAL_MISMATCH');
    // A member OUTSIDE the projection is outside the digest, by design: the
    // whole-document comparison inside `assertNoPostResultRewrite` is what
    // sees those, and a test that claimed otherwise would be inventing a rule.
    assert.equal(preregistrationDigest({ ...copy(PREREGISTRATION), title: 'a different title' }), digest);
    // A preregistration carrying a RESULT does not load: a document composed
    // after a result is not a preregistration.
    for (const key of ['result', 'results', 'verdict', 'observed', 'supersedes', 'superseded_by']) {
      const error = typedRefusal(() => assertPreregistration({ ...unsealed(), [key]: 'anything' }), MalformedResult, 'PREREGISTRATION_CARRIES_A_RESULT');
      assert.match(`${error.message} ${String(error.detail)}`, new RegExp(`\\b${key}\\b`), `the refusal does not name ${key}`);
    }
    for (const bad of [null, 'a string', 42, []]) {
      typedRefusal(() => assertPreregistration(bad), MalformedResult, 'PREREGISTRATION_NOT_AN_OBJECT');
    }
  });

  test('a preregistration that is not LOADABLE is not a preregistration', () => {
    const dir = freshDir('corpus');
    typedRefusal(() => loadPreregistration(dir), MalformedResult, 'PREREGISTRATION_MISSING');
    writeFileSync(path.join(dir, 'preregistration.json'), '{ not json');
    typedRefusal(() => loadPreregistration(dir), MalformedResult, 'PREREGISTRATION_UNPARSEABLE');
    writeFileSync(path.join(dir, 'preregistration.json'), JSON.stringify(PREREGISTRATION, null, 2));
    const loaded = loadPreregistration(dir);
    assert.equal(loaded.card_id, PREREGISTRATION.card_id);
    assert.equal(loaded.preregistration_digest, preregistrationDigest(loaded));
    // An in-file mutation is caught by the seal the moment it is read back.
    writeFileSync(path.join(dir, 'preregistration.json'), JSON.stringify({ ...loaded, metric: { ...loaded.metric, direction: 'TARGET_INTERVAL' } }));
    typedRefusal(() => loadPreregistration(dir), MalformedResult, 'PREREGISTRATION_SEAL_MISMATCH');
    for (const arg of [undefined, null, 42, '']) {
      typedRefusal(() => loadPreregistration(arg), MalformedResult, 'PREREGISTRATION_DIR_INVALID');
    }
  });

  test('A3 the preregistration is recorded BEFORE the run: the journal proves the order', () => {
    const digest = preregistrationDigest(PREREGISTRATION);
    const honest = [
      { index: 0, kind: 'PREREGISTRATION', preregistration_digest: digest },
      { index: 1, kind: 'RUN_STARTED', run_id: RUN_ID },
      { index: 2, kind: 'RESULT', preregistration_digest: digest, outcome: 'POSITIVE' },
    ];
    assert.equal(assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID, journal: honest }).digest, digest);
    // A second run of the SAME preregistration stays legal: what is refused is
    // a preregistration recorded after the fact, not a second run.
    assert.equal(
      assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: 's2-008-run-b', journal: [...honest, { index: 3, kind: 'RUN_STARTED', run_id: 's2-008-run-b' }] }).digest,
      digest,
    );
    // A preregistration row AFTER the result is refused, and named as such.
    // This journal has NO row for `runId`, so the ONLY check that can fire is
    // the result-ordering one: without that separation, a test asserting the
    // message would pass on the run-ordering rule and prove nothing.
    const afterResult = [
      { index: 0, kind: 'RESULT', preregistration_digest: digest, outcome: 'POSITIVE' },
      { index: 1, kind: 'PREREGISTRATION', preregistration_digest: digest },
    ];
    const latePrereg = typedRefusal(() => assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID, journal: afterResult }), BlockedPolicy, 'PREREGISTRATION_AFTER_RESULT');
    assert.match(String(latePrereg.detail), /a result under it was recorded/, 'the refusal does not say the preregistration followed a RESULT');
    // And after the run's FIRST row, with no result yet: the rule is "before
    // trial one", not "before the verdict". This journal has no RESULT row, so
    // again only the run-ordering check can fire.
    const afterRunStart = [
      { index: 0, kind: 'RUN_STARTED', run_id: RUN_ID },
      { index: 1, kind: 'PREREGISTRATION', preregistration_digest: digest },
    ];
    const lateRun = typedRefusal(() => assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID, journal: afterRunStart }), BlockedPolicy, 'PREREGISTRATION_AFTER_RESULT');
    assert.match(String(lateRun.detail), new RegExp(`began at 0`), 'the refusal does not say the preregistration followed the run');
    // No row for this digest at all: the ordering was never proved.
    typedRefusal(() => assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID, journal: [honest[1]] }), BlockedPolicy, 'PREREGISTRATION_NOT_IN_JOURNAL');
    // A journal that is PRESENT but is not an array is refused, never ignored:
    // a silently weaker path would make the whole proof optional.
    typedRefusal(() => assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID, journal: 'not-an-array' }), NeedsInput, 'JOURNAL_MALFORMED');
    typedRefusal(() => assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID, journal: [honest[0], 'not-a-row'] }), MalformedResult, 'JOURNAL_ROW_MALFORMED');
    // A run id that is not one is refused, not normalised.
    for (const runId of [undefined, null, 42, 'RUN A', '-leading-dash', `${'x'.repeat(201)}`]) {
      typedRefusal(() => assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId, journal: honest }), NeedsInput, 'RUN_ID_INVALID');
    }
    // WITHOUT a journal the weaker documented path is taken, and the test says
    // so out loud: that is admissibility, not the cross-process ordering proof.
    assert.equal(assertPreregisteredBeforeRun({ prereg: PREREGISTRATION, runId: RUN_ID }).digest, digest);
  });

  test('A4/P3 a hypothesis moved after the result throws, and the refusal is RECORDED', () => {
    const base = copy(PREREGISTRATION);
    // An unedited canonical copy is admitted: the guard refuses MOVEMENT, not
    // the act of reading the frozen document twice.
    assert.equal(assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: base, resultRecorded: true }).digest, preregistrationDigest(PREREGISTRATION));

    // (a) the rewrite the frozen schema cannot catch: same card_id, still
    //     schema-valid, only the digest moves it.
    const rewritten = { ...copy(base), card: { ...copy(base.card), test_design: 'REWRITTEN AFTER THE RESULT: report the best seed only.' } };
    assert.equal(rewritten.card.card_id, base.card.card_id, 'the rewrite changed the card id');
    assert.equal(isResearchContractValid('hypothesis-card', rewritten.card), true, 'the frozen schema refuses the rewritten card, so this test would prove the wrong thing');
    const stale = typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: rewritten, resultRecorded: true }), BlockedPolicy, 'HYPOTHESIS_REWRITE_AFTER_RESULT');
    assert.equal(stale.rejection.card_digest_stale, true, 'the record does not say the card digest was left stale');
    assert.deepEqual(stale.rejection.moved_fields, ['card'], 'the record does not name the moved member');
    assert.deepEqual(stale.rejection.moved_digest_fields, [], 'the twelve-field projection cannot see an embedded card, and the record must not claim it did');
    assert.equal(stale.rejection.action, 'REJECTED_AMENDMENT_REQUIRED');
    assert.equal(stale.rejection.result_recorded, true);

    // (b) the forgery that also re-seals `card_digest`: the twelve-field
    //     digest moves too, and it is STILL a refusal.
    const resealed = { ...rewritten, card_digest: canonicalDigest(rewritten.card) };
    assert.notEqual(preregistrationDigest(resealed), preregistrationDigest(PREREGISTRATION));
    const bothCaught = typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: resealed, resultRecorded: true }), BlockedPolicy, 'HYPOTHESIS_REWRITE_AFTER_RESULT');
    assert.equal(bothCaught.rejection.card_digest_stale, false, 'a re-sealed card is not stale');
    assert.deepEqual(bothCaught.rejection.moved_digest_fields, ['card_digest']);

    // (c) the same OBJECT on both sides: the original bytes are already gone,
    //     so the comparison would trivially agree. Refused before any digest.
    typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: PREREGISTRATION, resultRecorded: true }), BlockedPolicy, 'PREREGISTRATION_MUTATED_IN_PLACE');

    // (d) moved with NO result recorded: still refused, as a SEALED move, and
    //     it does not claim a result that does not exist.
    const noResult = { ...copy(base), budget_reservation: { ...base.budget_reservation, granted_units: 9 } };
    const sealed = typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: noResult, resultRecorded: false }), RevisionConflict, 'PREREGISTRATION_SEALED_MOVED');
    assert.equal(sealed.rejection.result_recorded, false);
    assert.deepEqual(sealed.rejection.moved_digest_fields, ['budget_reservation']);

    // (e) `resultRecorded` is read fail-closed: an absent or non-boolean value
    //     is read as TRUE, the safe direction.
    for (const resultRecorded of [undefined, null, 'yes', 0]) {
      typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: { ...base, title: 'moved' }, resultRecorded }), BlockedPolicy, 'HYPOTHESIS_REWRITE_AFTER_RESULT');
    }

    // (f) a proposed document that cannot even be digested is still a REWRITE
    //     and still a typed refusal, never a raw TypeError from the reused
    //     gate. OBSERVED, NOT ASSERTED AS DESIRABLE: the record then carries
    //     `next_canonical: true` beside `whole_digest_after: null`
    //     (src/lib/research/preregistration.mjs:964), because the non-canonical
    //     branch is unreachable while `preregistrationDigest` re-types the
    //     gate's error first. The fields that carry the decision are asserted;
    //     the one that does not is reported to the owner, not pinned here.
    const uncanonical = { ...base, metric: { ...base.metric, direction: Number.NaN } };
    const typed = typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: uncanonical, resultRecorded: true }), BlockedPolicy, 'HYPOTHESIS_REWRITE_AFTER_RESULT');
    assert.equal(typed.rejection.digest_after, null, 'an undigestable document reported a digest');
    assert.equal(typed.rejection.whole_digest_after, null, 'an undigestable document reported a whole-document digest');
    assert.deepEqual(typed.rejection.moved_digest_fields, ['metric'], 'the record does not name the member that could not be digested');
    // A digest-covered field REMOVED from the proposed document is a rewrite
    // that names the field, not a load failure.
    const amputated = { ...copy(base) };
    delete amputated.inference_mode;
    typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: amputated, resultRecorded: true }), BlockedPolicy, 'HYPOTHESIS_REWRITE_AFTER_RESULT');
    typedRefusal(() => assertNoPostResultRewrite({ prereg: PREREGISTRATION, next: 'not a document', resultRecorded: true }), MalformedResult, 'NEXT_DOCUMENT_NOT_AN_OBJECT');
    // No arguments at all reaches the same typed refusal as any other bad
    // call, because the frozen signature carries a `= {}` default.
    typedRefusal(() => assertNoPostResultRewrite({}), MalformedResult, 'PREREGISTRATION_NOT_AN_OBJECT');
  });

  test('a post-result hypothesis is a NEW DOCUMENT KIND, never an edit of the preregistration', () => {
    const base = copy(PREREGISTRATION);
    const digest = preregistrationDigest(PREREGISTRATION);
    const amendment = createAmendment({ prereg: PREREGISTRATION, reason: 'a post-result design change is a new document', newCardId: 'hyc-s2-008-02' });

    assert.deepEqual(Object.keys(amendment).sort(), ['amendment_digest', 'amendment_id', 'card_id', 'kind', 'reason', 'supersedes']);
    assert.equal(amendment.kind, AMENDMENT_KIND, 'the amendment is not its own document kind');
    assert.notEqual(amendment.kind, PREREGISTRATION_KIND);
    assert.match(amendment.amendment_id, /^amd-[0-9a-f]{24}$/, 'the amendment id is not in the amd- namespace');
    assert.notEqual(amendment.amendment_id, PREREGISTRATION.card_id);
    assert.equal(amendment.supersedes, digest, 'the amendment does not name what it supersedes');
    assert.equal(amendment.card_id, 'hyc-s2-008-02');
    assert.match(amendment.amendment_digest, HEX64);
    // The id and the digest are CONTENT-DERIVED, so two runs of the same base
    // produce the same document: the ledger treats an identical amendment as
    // the same record rather than inventing a second one.
    const twice = createAmendment({ prereg: PREREGISTRATION, reason: 'a post-result design change is a new document', newCardId: 'hyc-s2-008-02' });
    assert.deepEqual(twice, amendment, 'two identical amendments differ, so A5 cannot bind one');
    // A different reason is a different document: the reason is in the id's
    // preimage.
    assert.notEqual(createAmendment({ prereg: PREREGISTRATION, reason: 'another reason, same card', newCardId: 'hyc-s2-008-02' }).amendment_id, amendment.amendment_id);

    // A bare amendment is a RECORD and the closed-shape check admits it.
    assert.equal(assertAmendmentNotDecisionBasis(amendment, PREREGISTRATION), amendment);
    // Presenting it as an input to a verdict is the refusal, and it names the
    // member that made it a decision input.
    const asBasis = typedRefusal(() => assertAmendmentNotDecisionBasis({ ...amendment, verdict: 'POSITIVE' }, PREREGISTRATION), BlockedPolicy, 'AMENDMENT_AS_DECISION_BASIS');
    assert.match(String(asBasis.detail), /verdict/, 'the refusal does not name the offending member');
    // A forged id or digest is a malformed amendment, not a valid one.
    typedRefusal(() => assertAmendmentNotDecisionBasis({ ...amendment, amendment_id: `amd-${'0'.repeat(24)}` }, PREREGISTRATION), MalformedResult, 'AMENDMENT_ID_MISMATCH');
    typedRefusal(() => assertAmendmentNotDecisionBasis({ ...amendment, amendment_digest: 'b'.repeat(64) }, PREREGISTRATION), MalformedResult, 'AMENDMENT_DIGEST_MISMATCH');
    typedRefusal(() => assertAmendmentNotDecisionBasis({ ...amendment, kind: PREREGISTRATION_KIND }, PREREGISTRATION), MalformedResult, 'AMENDMENT_KIND_UNEXPECTED');
    // An amendment that does not react to THIS preregistration is refused.
    const other = { ...base };
    delete other.preregistration_digest;
    delete other.expected_table_digest;
    other.budget_reservation = { ...other.budget_reservation, granted_units: 9 };
    assert.notEqual(preregistrationDigest(other), digest);
    typedRefusal(() => assertAmendmentNotDecisionBasis(amendment, other), BlockedPolicy, 'AMENDMENT_SUPERSEDES_MISMATCH');
    // Reusing the amended card id is refused twice over: at creation, and
    // because it makes the rewrite undetectable by construction.
    typedRefusal(() => createAmendment({ prereg: PREREGISTRATION, reason: 'reuse the amended card id', newCardId: PREREGISTRATION.card_id }), BlockedPolicy, 'AMENDMENT_SAME_CARD_ID');
    // The reason is bounded, one line, and refused when the repository's own
    // redactor would rewrite it: an amendment is the last place a credential
    // should end up. The test is a SHAPE test, not a scanner, and the
    // boundary it draws is the house rule — a variable name and where it
    // lives are admissible, a value that looks like a credential is not. The
    // strings below are SYNTHETIC shapes with no value behind them.
    for (const secret of ['the token is sk-aaaaaaaaaaaaaaaaaaaaaaaa', 'api_key=aaaaaaaaaaaaaaaa', 'see /home/example/.env for the value', 'Authorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaa']) {
      typedRefusal(() => createAmendment({ prereg: PREREGISTRATION, reason: secret, newCardId: 'hyc-s2-008-03' }), MalformedResult, 'AMENDMENT_REASON_SECRET_SHAPED');
    }
    for (const allowed of ['DEEPSEEK_API_KEY is read from the local .env file', 'the baseline digest lives in corpus/s2-008/manifest.json']) {
      assert.equal(createAmendment({ prereg: PREREGISTRATION, reason: allowed, newCardId: 'hyc-s2-008-03' }).reason, allowed);
    }
    typedRefusal(() => createAmendment({ prereg: PREREGISTRATION, reason: 'two\nlines', newCardId: 'hyc-s2-008-03' }), MalformedResult, 'AMENDMENT_REASON_NOT_ONE_LINE');
    typedRefusal(() => createAmendment({ prereg: PREREGISTRATION, reason: '', newCardId: 'hyc-s2-008-03' }), MalformedResult, 'AMENDMENT_REASON_REQUIRED');
    typedRefusal(() => createAmendment({ prereg: PREREGISTRATION, reason: 'x'.repeat(241), newCardId: 'hyc-s2-008-03' }), MalformedResult, 'AMENDMENT_REASON_TOO_LONG');
    typedRefusal(() => createAmendment({ prereg: PREREGISTRATION, reason: 'a valid reason', newCardId: 'not-a-card-id' }), MalformedResult, 'AMENDMENT_CARD_ID_INVALID');
  });

  test('P1 the holdout opens EXACTLY ONCE: the rule is frozen and the ledger counts it', () => {
    // (a) the FROZEN RULE. A preregistration that would authorise a peek, or
    //     a second open, or a decision "on significance", does not load.
    const bad = {
      HOLDOUT_ACCESS_NOT_ONE_SHOT: { max_opens: 2 },
      HOLDOUT_ACCESS_NOT_ONE_SHOT_0: { max_opens: 0 },
      HOLDOUT_ACCESS_PARTITION_INVALID: { partition: 'PRIMARY' },
      PREREGISTRATION_FIELD_INVALID: { decision_point: 'ON_SIGNIFICANCE' },
      PREREGISTRATION_FIELD_INVALID_SEAL: { unseal_digest: 'not-a-digest' },
      PREREGISTRATION_FIELD_INVALID_LABELS: { labels_digest: undefined },
    };
    for (const [label, patch] of Object.entries(bad)) {
      const access = { ...copy(PREREGISTRATION.holdout_access), ...patch };
      for (const [key, value] of Object.entries(patch)) if (value === undefined) delete access[key];
      const error = typedRefusal(
        () => assertPreregistration({ ...unsealed(), holdout_access: access }),
        MalformedResult,
        label.startsWith('HOLDOUT') ? label.replace('_0', '') : 'PREREGISTRATION_FIELD_INVALID',
      );
      assert.match(`${error.message} ${String(error.detail)}`, /holdout_access/, `${label}: the refusal does not name holdout_access`);
    }
    // One open, at a named decision point, with the unseal digest and the
    // sealed label digest frozen: the shape the preregistration actually has.
    const access = PREREGISTRATION.holdout_access;
    assert.equal(access.partition, 'HOLDOUT');
    assert.equal(access.max_opens, 1);
    assert.ok(['AFTER_DECLARED_TRIALS', 'AFTER_ANALYSIS_FROZEN'].includes(access.decision_point));

    // (b) the EXECUTABLE ONE-SHOT, on a clock at the decision point.
    const ledger = freshRegistry('one-shot', AFTER_DECISION);
    const unseal = access.unseal_digest.replace(/^sha256:/, '');
    assert.equal(unseal, HOLDOUT_UNSEAL_DIGEST.replace(/^sha256:/, ''), 'the fixture unseal digest moved');
    const open = recordHoldoutRead(ledger, {
      trial: 'trl-s2-008-01', unsealDigest: unseal, partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: access.max_opens, caseId: 's2-008-case-01',
    });
    assert.equal(open.opens_after, 1);
    // A RETRIED read by the SAME trial is the same read, not a second open: a
    // crash-and-restart retry of the very read the rule exists to catch must
    // not be a violation.
    const retried = recordHoldoutRead(ledger, {
      trial: 'trl-s2-008-01', unsealDigest: unseal, partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: access.max_opens, caseId: 's2-008-case-01',
    });
    assert.equal(retried.replayed, true);
    assert.equal(retried.accessRecordId, open.accessRecordId);
    assert.equal(retried.opens_after, 1, 'a retried read counted as a second open');
    const before = snapshotDigest(ledger);
    // A second open of the PARTITION under a fresh digest: refused, and nothing
    // written. Counting only by digest would let this through.
    typedRefusal(() => recordHoldoutRead(ledger, { trial: 'trl-s2-008-02', unsealDigest: canonicalDigest({ other: 'partition' }), partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: access.max_opens }), BlockedPolicy, 'HOLDOUT_OPEN_BUDGET_EXCEEDED');
    // The same one-shot digest presented by a DIFFERENT trial is the digest
    // rule, which is a different refusal with a different code.
    typedRefusal(() => recordHoldoutRead(ledger, { trial: 'trl-s2-008-09', unsealDigest: unseal, partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: access.max_opens }), BlockedPolicy, 'HOLDOUT_UNSEAL_DIGEST_REPLAYED');
    assert.equal(snapshotDigest(ledger), before, 'a refused open changed the ledger');
    assert.equal(readJournal(ledger).filter((record) => record.kind === 'ACCESS').length, 1);
    const accessRecord = readJournal(ledger).find((record) => record.kind === 'ACCESS');
    assert.equal(accessRecord.payload.partition, 'HOLDOUT');
    assert.equal(accessRecord.payload.max_opens, 1);
    assert.equal(accessRecord.payload.read_at, AFTER_DECISION, 'the access record is not stamped by the injected clock');
    assert.equal(accessRecord.payload.decision_point, DECISION_POINT);

    // (c) a read BEFORE the decision point is refused, writes nothing, and
    //     returns no case data at all.
    const early = freshRegistry('peek', AT);
    const peek = typedRefusal(() => recordHoldoutRead(early, { trial: 'trl-s2-008-01', unsealDigest: unseal, partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: 1 }), BlockedPolicy, 'HOLDOUT_READ_BEFORE_DECISION_POINT');
    assert.match(`${peek.message} ${String(peek.detail)}`, new RegExp(DECISION_POINT), 'the refusal does not name the decision point it enforced');
    assert.equal(readJournal(early).length, 0, 'a refused peek left an ACCESS record');
    // (d) an unreadable open budget is not an open budget, a caller may not
    //     stamp its own instant, and a digest that is not 64 hex is malformed.
    for (const maxOpens of [0, -1, 1.5, '1', null]) {
      typedRefusal(() => recordHoldoutRead(early, { trial: 'trl-1', unsealDigest: unseal, maxOpens }), BlockedPolicy, 'HOLDOUT_MAX_OPENS_INVALID');
    }
    typedRefusal(() => recordHoldoutRead(early, { trial: 'trl-1', unsealDigest: unseal, readAt: '2030-01-01T00:00:00.000Z' }), BlockedPolicy, 'HOLDOUT_READ_AT_NOT_INJECTED_CLOCK');
    typedRefusal(() => recordHoldoutRead(early, { trial: 'trl-1', unsealDigest: 'abc' }), BlockedPolicy, 'HOLDOUT_UNSEAL_DIGEST_MALFORMED');
    assert.equal(readJournal(early).length, 0);
  });

  test('P2 the seed plan is a PURE function of the frozen rule', () => {
    // The test re-derives the plan ITSELF from the rule and hands it back: a
    // plan the module accepts because it is the rule's own function, not
    // because the module compared seeds to something it read from a run.
    const rules = [
      { kind: 'SEQUENTIAL', start: 11, stride: 7, count: 4 },
      { kind: 'FIXED_LIST', seeds: [3, 1, 2, 9] },
      { kind: 'HASH_FROM_LABEL', label: 's2-008', modulus: 1024, count: 3 },
    ];
    const derive = (rule) => {
      if (rule.kind === 'SEQUENTIAL') return Array.from({ length: rule.count }, (_unused, index) => rule.start + index * rule.stride);
      if (rule.kind === 'FIXED_LIST') return [...rule.seeds];
      // The hash rule is a function of a LABEL and an index, and of nothing
      // else: no clock, no file, no metric, no result.
      return Array.from({ length: rule.count }, (_unused, index) => Number.parseInt(canonicalDigest(`${rule.label}:${index}`).slice(0, 8), 16) % rule.modulus);
    };
    for (const rule of rules) {
      const seeds = derive(rule);
      const prereg = { ...unsealed(), seed_rule: rule, seed_count: seeds.length, seeds_digest: canonicalDigest(seeds) };
      assert.equal(assertSeedSetFrozen(seeds, prereg), seeds, `${rule.kind}: the rule's own plan was refused`);
      assert.equal(seedCountOf(prereg), seeds.length);
      // The published digest is the digest of that plan: `seeds_digest` is a
      // function of the rule, not a free number.
      assert.equal(prereg.seeds_digest, canonicalDigest(seeds));
      // Same rule, second call: the same plan. Determinism, not luck.
      assert.deepEqual(derive(rule), derive(rule));
      assert.equal(assertSeedSetFrozen(derive(rule), prereg).length, seeds.length);
      // A `seeds_digest` that does not describe the derived plan is refused,
      // and a `seed_count` that disagrees with it is refused by name.
      typedRefusal(() => assertSeedSetFrozen(seeds, { ...prereg, seeds_digest: 'c'.repeat(64) }), MalformedResult, 'SEEDS_DIGEST_MISMATCH');
      typedRefusal(() => assertSeedSetFrozen(seeds, { ...prereg, seed_count: seeds.length + 1 }), MalformedResult, 'SEED_COUNT_MISMATCH');
      // Substitutions: one member changed, the set reordered, one extra, one
      // missing. All four are substitutions, and the message names which.
      const substituted = [...seeds];
      substituted[0] = rule.kind === 'HASH_FROM_LABEL'
        ? (substituted[0] + 1) % rule.modulus
        : (typeof substituted[0] === 'number' ? substituted[0] + 101 : `${substituted[0]}-substituted`);
      if (!substituted.includes(1) || rule.kind !== 'FIXED_LIST' || substituted[0] !== 1) {
        const refused = typedRefusal(() => assertSeedSetFrozen(substituted, prereg), BlockedPolicy, 'SEED_SUBSTITUTION');
        assert.ok(/SEED_SUBSTITUTION:(substituted|reordered)/.test(String(refused.message)), `${rule.kind}: the refusal does not classify the substitution`);
        assert.ok(String(refused.detail).includes('"index":0'), `${rule.kind}: the refusal does not say WHICH seed moved`);
      }
      typedRefusal(() => assertSeedSetFrozen([...seeds].reverse(), prereg), BlockedPolicy, 'SEED_SUBSTITUTION:reordered');
      typedRefusal(() => assertSeedSetFrozen([...seeds, 909090], prereg), BlockedPolicy, 'SEED_SUBSTITUTION');
      typedRefusal(() => assertSeedSetFrozen(seeds.slice(1), prereg), BlockedPolicy, 'SEED_SUBSTITUTION');
      typedRefusal(() => assertSeedSetFrozen('not an array', prereg), NeedsInput, 'SEED_SET_MISSING');
      typedRefusal(() => assertSeedSetFrozen([...seeds.slice(0, -1), Number.NaN], prereg), MalformedResult, 'SEED_ELEMENT_INVALID');
    }
    // A CHANGED rule changes the accepted set: the plan cannot be a stored
    // array that a later edit can rewrite while the digest stays put.
    const fixed = derive(rules[1]);
    const prereg = { ...unsealed(), seed_rule: rules[1], seed_count: fixed.length, seeds_digest: canonicalDigest(fixed) };
    const reorderedRule = { kind: 'FIXED_LIST', seeds: [...fixed].reverse() };
    typedRefusal(
      () => assertSeedSetFrozen(fixed, { ...prereg, seed_rule: reorderedRule }),
      MalformedResult,
      'SEEDS_DIGEST_MISMATCH',
    );
    // The published fixture plan is the one in force, and it is the fixture's
    // own list — not a "best seed" picked after a result.
    assert.deepEqual([...assertSeedSetFrozen([...PREREGISTRATION.seed_rule.seeds], PREREGISTRATION)], [...PREREGISTRATION.seed_rule.seeds]);
    assert.equal(PREREGISTRATION.seed_rule.best_seed_selection, 'FORBIDDEN');
  });

  test('P4 the budget is explicit, positive and checked against an INJECTED clock', () => {
    const reservation = PREREGISTRATION.budget_reservation;
    // A live reservation grants, and reports the headroom AFTER the request,
    // so the return value is not an authorisation to spend it.
    const live = assertBudgetReservation(reservation, { nowNs: AT_NS });
    assert.equal(live.granted, true);
    assert.equal(live.remaining_units, reservation.granted_units, 'the liveness check reported an authorisation');
    assert.equal(live.reservation_id, reservation.reservation_id);
    assert.equal(assertBudgetReservation(reservation, AT_NS).remaining_units, reservation.granted_units, 'a bare integer reading was refused');
    assert.equal(assertBudgetReservation(reservation, AT).remaining_units, reservation.granted_units, 'an ISO reading was refused');
    // A request inside the grant leaves the remainder after the request.
    assert.equal(assertBudgetReservation({ ...reservation, requested_units: 3 }, { nowNs: AT_NS }).remaining_units, reservation.granted_units - 3);
    // Over the grant is BudgetExceeded, and never a partial grant.
    typedRefusal(() => assertBudgetReservation({ ...reservation, requested_units: reservation.granted_units + 1 }, { nowNs: AT_NS }), BudgetExceeded, 'BUDGET_EXCEEDED');
    typedRefusal(() => assertBudgetReservation({ ...reservation, spent_units: reservation.granted_units + 1 }, { nowNs: AT_NS }), BudgetExceeded, 'BUDGET_EXCEEDED');
    // EXPIRED is a reconciliation carrying a recordable row, and the row says
    // out loud that a retry is forbidden and the answer is not a zero.
    const expired = typedRefusal(() => assertBudgetReservation(reservation, { nowNs: AFTER_DECISION_NS }), ReconciliationRequired, 'BUDGET_RESERVATION_EXPIRED');
    assert.equal(expired.retryable, false);
    const row = expired.reconciliation;
    assert.equal(row.reason, 'BUDGET_RESERVATION_EXPIRED');
    assert.equal(row.action, 'RECONCILE');
    assert.equal(row.retry, 'FORBIDDEN');
    assert.equal(row.zero_result, false);
    assert.equal(row.reservation_id, reservation.reservation_id);
    assert.equal(row.granted_units, reservation.granted_units);
    assert.equal(row.currency, reservation.currency);
    assert.equal(row.observed_now_ns, AFTER_DECISION_NS);
    // No injected clock means no budget decision at all: the absence of a clock
    // is NeedsInput, never a grant, and a clock that is present but unreadable
    // is a different code so a caller can tell the two apart.
    const clocks = [
      [undefined, 'CLOCK_INJECTION_REQUIRED'],
      [null, 'CLOCK_INJECTION_REQUIRED'],
      [{}, 'CLOCK_INJECTION_REQUIRED'],
      [{ iso: AT }, 'CLOCK_INJECTION_REQUIRED'],
      ['yesterday', 'CLOCK_INVALID'],
      [Number.NaN, 'CLOCK_INVALID'],
      [-1, 'CLOCK_INVALID'],
    ];
    for (const [now, code] of clocks) {
      typedRefusal(() => assertBudgetReservation(reservation, now), NeedsInput, code);
    }
    // And the reservation itself must be positive, finite and expiring: a
    // non-positive grant or a missing expiry is a preregistration that does not
    // load, not a budget of zero.
    for (const patch of [{ granted_units: 0 }, { granted_units: -1 }, { granted_units: 1.5 }, { expires_at: null }, { expires_at: undefined }, { reservation_id: '' }, { currency: '' }]) {
      const document = unsealed();
      const next = { ...document.budget_reservation, ...patch };
      for (const [key, value] of Object.entries(patch)) if (value === undefined) delete next[key];
      typedRefusal(() => assertPreregistration({ ...document, budget_reservation: next }), MalformedResult, 'PREREGISTRATION_FIELD_INVALID');
    }
    // An expiry already in the past is admissible as a DOCUMENT; it is the
    // settle that is refused, and the refusal is the reconciliation above.
    assert.equal(assertPreregistration(unsealed()).budget_reservation.reservation_id, reservation.reservation_id);
  });
});

// ===========================================================================
// A5 — the same base, in two processes
// ===========================================================================

describe('A5 — determinism of the two modules across processes', () => {
  test('two processes on the same base print the same preregistration digest, seed plan and head digest', () => {
    // The strongest claim this file can make with the least ceremony: run the
    // REAL modules in a REAL second process, on a fresh root, and compare the
    // bytes. A wall clock, a random id or a `Date.now()` anywhere on the
    // decision path would break this.
    const driver = [
      `const { PREREGISTRATION } = await import(${JSON.stringify(new URL('./fixtures/fixture-measurement-set.mjs', import.meta.url).pathname)});`,
      `const P = await import(${JSON.stringify(new URL('../../src/lib/research/preregistration.mjs', import.meta.url).pathname)});`,
      `const G = await import(${JSON.stringify(new URL('../../src/lib/research/registry.mjs', import.meta.url).pathname)});`,
      'const out = [];',
      "out.push(['prereg_digest', P.preregistrationDigest(PREREGISTRATION)]);",
      "out.push(['seeds', P.assertSeedSetFrozen([...PREREGISTRATION.seed_rule.seeds], PREREGISTRATION).join(',')]);",
      'out.push([\'seed_count\', P.seedCountOf(PREREGISTRATION)]);',
      "out.push(['stopping', P.stoppingRuleOf(PREREGISTRATION).kind]);",
      `const at = ${JSON.stringify(AT)}; const ms = Date.parse(at);`,
      'let n = 0;',
      "const ledger = G.openRegistry({ root: process.argv[1], clock: { nowNs: () => ms * 1e6, iso: () => at }, ids: (kind) => `${kind}${(n += 1)}` });",
      "const put = G.putExperiment(ledger, { key: 's2-008-cross-process', args: { trial: 'trl-s2-008-01' }, expectedRevision: 0, mutate: () => ({ kind: 'TRIAL', trial: 'trl-s2-008-01', campaign_id: 'cmp-1', outcome: 'POSITIVE' }) });",
      "out.push(['record_id', ledger.recordsOfKind('TRIAL')[0].record_id]);",
      "out.push(['head', put.headDigest]);",
      'out.push([\'chain\', G.verifyChain(ledger).ok]);',
      "process.stdout.write(`${out.map((row) => row.join('=')).join('\\n')}\\n`);",
    ].join('\n');
    const run = () => {
      const root = freshDir('cross-process');
      return execFileSync(process.execPath, ['--input-type=module', '-e', driver, root], { cwd: REPO, encoding: 'utf8' });
    };
    const first = run();
    const second = run();
    assert.equal(first, second, 'two processes on the same base disagree');
    const rows = Object.fromEntries(first.trim().split('\n').map((line) => line.split('=')));
    // The values are the ones the in-process tests already assert, so a drift
    // between the two is a drift in the module, not in the harness.
    assert.equal(rows.prereg_digest, preregistrationDigest(PREREGISTRATION));
    assert.equal(rows.seeds, [...PREREGISTRATION.seed_rule.seeds].join(','));
    assert.equal(rows.seed_count, String(PREREGISTRATION.seed_count));
    assert.equal(rows.stopping, 'FIXED_TRIALS');
    assert.equal(rows.chain, 'true');
    assert.match(rows.head, /^sha256:[0-9a-f]{64}$/);
    assert.match(rows.record_id, /^rec-/);
  });

  test('neither module reads the process clock or a random source', () => {
    // The property every determinism claim above rests on. Comments AND string
    // literals are stripped first, because these modules DISCUSS
    // `Date.now()` and `Math.random()` in prose and in refusal messages while
    // promising never to call either. LIMIT, stated: this is a textual
    // tripwire for the three obvious forms, not a proof of absence. Stripping
    // literals can only hide a call, never invent one, so the failure mode is
    // a missed violation rather than a false alarm.
    const stripCommentsAndLiterals = (source) => source
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .split('\n')
      .map((line) => line.replace(/(^|[^:])\/\/.*$/, '$1'))
      .join('\n')
      .replace(/'(?:\\.|[^'\\])*'/g, "''")
      .replace(/"(?:\\.|[^"\\])*"/g, '""')
      .replace(/`(?:\\.|[^`\\])*`/g, '``');
    const files = ['contracts.mjs', 'registry.mjs', 'preregistration.mjs'];
    for (const name of files) {
      const code = stripCommentsAndLiterals(readFileSync(path.join(REPO, 'src', 'lib', 'research', name), 'utf8'));
      for (const [pattern, what] of [[/\bDate\.now\s*\(/, 'Date.now()'], [/\bMath\.random\s*\(/, 'Math.random()'], [/new Date\s*\(\s*\)/, 'new Date() with no argument']]) {
        assert.equal(pattern.test(code), false, `src/lib/research/${name} reads ${what} on a decision path`);
      }
      // The one legitimate time use is a PARSE of a literal, which is a pure
      // function of its argument. `contracts.mjs` has no clock at all, so it is
      // asserted not to need one.
      assert.equal(/\bDate\.parse\s*\(/.test(code), name !== 'contracts.mjs', `src/lib/research/${name}: the ISO-instant parse surface changed`);
    }
  });
});
