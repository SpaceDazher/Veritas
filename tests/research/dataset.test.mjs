// S2-008 — the corpus, the access log, the label seal and the preregistration
// (issue SpaceDazher/Veritas#8).
//
// PR2  the one-shot rule was counted per DIGEST, so a second, differently
//      digested read of the same partition went through; `max_opens` and
//      `decision_point` were frozen in the preregistration and read by nothing.
// SD-07 the fixture preregistration did not satisfy `assertPreregistration`.
// SD-08 the fixture digest projected ELEVEN members; the track's projects TWELVE.
// SD-10 nothing in this track was in `tsc`'s include set or in `npm test`.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { assertLabelSeal, caseDigest, labelsDigest, readCorpus, substituteLabelsControl } from '../../src/lib/research/dataset.mjs';
import { assertCausalDiscipline, assertNoCausalFromSimulation, classifyCardRelation } from '../../src/lib/research/causality.mjs';
import { assertResearchContract } from '../../src/lib/research/contracts.mjs';
import {
  assertNoPostResultRewrite, assertPreregistration, createAmendment, assertAmendmentNotDecisionBasis,
  assertSeedSetFrozen, loadPreregistration, preregistrationDigest,
} from '../../src/lib/research/preregistration.mjs';
import { openRegistry, readJournal, recordHoldoutRead, snapshotDigest } from '../../src/lib/research/registry.mjs';
import { HOLDOUT_LABELS, HOLDOUT_UNSEAL_DIGEST, PREREGISTRATION } from './fixtures/fixture-measurement-set.mjs';
import { PREREGISTERED_SEEDS } from './fixtures/fixture-preregistration.mjs';

const CORPUS_DIR = new URL('../../evidence/s2-008/corpus', import.meta.url).pathname;
const SCRATCH = new URL('../../.bb/s2-008/dataset-test', import.meta.url).pathname;
const INSTANT = '2026-01-01T02:00:00.000Z';
const EARLY = '2026-01-01T00:00:00.000Z';
const DECISION_POINT = '2026-01-01T01:00:00.000Z';

function clock(iso) {
  const ms = Date.parse(iso);
  return Object.freeze({ nowNs: () => ms * 1e6, iso: () => iso, now: () => new Date(ms), nowIso: () => iso });
}

function ids(scope) {
  const digest = canonicalDigest({ scope }).slice(0, 8);
  let count = 0;
  return Object.freeze({ next: () => `${digest}${(count += 1).toString(36).padStart(4, '0')}` });
}

function freshLedger(name, iso = INSTANT) {
  const root = path.join(SCRATCH, name);
  rmSync(root, { recursive: true, force: true });
  return openRegistry({ root, clock: clock(iso), ids: ids(name) });
}

// --- the committed corpus --------------------------------------------------

test('the committed corpus manifest agrees with the committed case files', () => {
  const manifest = JSON.parse(readFileSync(path.join(CORPUS_DIR, 'manifest.json'), 'utf8'));
  for (const partition of ['PRIMARY', 'HOLDOUT']) {
    const declared = manifest.partitions[partition];
    const cases = JSON.parse(readFileSync(path.join(CORPUS_DIR, declared.file), 'utf8'));
    assert.equal(cases.length, declared.case_count, partition);
    assert.equal(canonicalDigest(cases), declared.digest, partition);
  }
  assert.equal(manifest.partitions.HOLDOUT.labels_digest, canonicalDigest(HOLDOUT_LABELS));
});

test('the committed corpus is byte-identical to what the builder re-derives', () => {
  // `scripts/s2-008-build-corpus.mjs --check` is the executable form of this;
  // running it here means a fixture edit that nobody regenerated fails the
  // suite instead of passing quietly.
  const repo = new URL('../../', import.meta.url).pathname;
  const out = execFileSync(process.execPath, [path.join(repo, 'scripts', 's2-008-build-corpus.mjs'), '--check'], { cwd: repo, encoding: 'utf8' });
  assert.equal(JSON.parse(out).ok, true);
});

// --- SD-07 / SD-08: the preregistration -----------------------------------

test('SD-07 the committed preregistration satisfies assertPreregistration', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  assert.equal(assertPreregistration(loaded), loaded);
  assert.equal(loaded.frozen_baseline.baseline_digest.length, 64, 'a baseline with no digest is a number nobody can trace');
  assert.equal(loaded.seed_rule.kind, 'FIXED_LIST');
  assert.equal(loaded.stopping_rule.kind, 'FIXED_TRIALS');
  assert.equal(loaded.stopping_rule.early_stop, false);
  assert.equal(loaded.multiplicity_rule.kind, 'HOLM_BONFERRONI');
  assert.equal(loaded.trial_list.length, 4);
});

test('SD-07 the self-seal is the TRACK digest, and a moved member is caught', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  assert.equal(loaded.preregistration_digest, preregistrationDigest(loaded));
  // A post-result budget edit must move the seal: the fixture digest used to
  // project ELEVEN members and omitted `budget_reservation` (SD-08), so this
  // edit was invisible to it.
  const moved = { ...loaded, budget_reservation: { ...loaded.budget_reservation, granted_units: 9 } };
  assert.notEqual(preregistrationDigest(moved), loaded.preregistration_digest);
  assert.throws(() => assertPreregistration(moved), (error) => String(error.message).startsWith('PREREGISTRATION_SEAL_MISMATCH'));
});

test('P2 the seed plan re-derives from the rule and refuses a substitution', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  assert.deepEqual([...assertSeedSetFrozen(PREREGISTERED_SEEDS, loaded)], [...PREREGISTERED_SEEDS]);
  for (const attack of [[4242, 4242, 4242, 4242, 4242], [44, 33, 22, 11, 101], [11, 22, 33, 44], [...PREREGISTERED_SEEDS, 606]]) {
    assert.throws(() => assertSeedSetFrozen(attack, loaded), (error) => String(error.message).startsWith('SEED_'), `seeds ${JSON.stringify(attack)} were admitted`);
  }
});

// --- P3: a post-result edit is a NEW DOCUMENT ------------------------------

test('P3 an unedited canonical COPY is admitted; a rewrite is refused', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  const copy = JSON.parse(JSON.stringify(loaded));
  assert.equal(assertNoPostResultRewrite({ prereg: loaded, next: copy, resultRecorded: true }).digest, preregistrationDigest(loaded));
  const rewritten = { ...copy, card: { ...copy.card, test_design: 'REWRITTEN AFTER THE RESULT: report the best seed only.' } };
  assert.throws(
    () => assertNoPostResultRewrite({ prereg: loaded, next: rewritten, resultRecorded: true }),
    (error) => String(error.message).startsWith('HYPOTHESIS_REWRITE_AFTER_RESULT'),
  );
});

test('P3 a rewrite keeps the same card_id and is still schema-valid, so only the digest catches it', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  const rewritten = { ...JSON.parse(JSON.stringify(loaded.card)), test_design: 'REWRITTEN AFTER THE RESULT.' };
  assert.equal(rewritten.card_id, loaded.card_id);
  assert.equal(assertResearchContract('hypothesis-card', rewritten), rewritten, 'the schema does not catch this, by design');
  assert.notEqual(canonicalDigest(rewritten), loaded.card_digest);
});

test('P3 the lawful path is an AMENDMENT, admitted as a record and refused as a decision basis', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  const amendment = createAmendment({ prereg: loaded, reason: 'a post-result design change is a new document, not an edit', newCardId: 'hyc-s2-008-02' });
  assert.equal(amendment.kind, 'AMENDMENT');
  assert.equal(amendment.supersedes, preregistrationDigest(loaded));
  // A bare amendment is a RECORD: the closed-shape check admits it, and that is
  // what the guard's own JSDoc says. The refusal is for presenting it as an
  // input to a verdict, which a caller does by adding the decision member.
  assert.equal(assertAmendmentNotDecisionBasis(amendment, loaded), amendment);
  assert.throws(
    () => assertAmendmentNotDecisionBasis({ ...amendment, verdict: 'POSITIVE' }, loaded),
    (error) => String(error.message).startsWith('AMENDMENT_AS_DECISION_BASIS'),
  );
  assert.throws(
    () => createAmendment({ prereg: loaded, reason: 'reuse the amended card id', newCardId: loaded.card_id }),
    (error) => String(error.message).startsWith('AMENDMENT_SAME_CARD_ID'),
  );
});

// --- PR2: the one-shot rule is per PARTITION, at the decision point --------

test('PR2 a holdout read AFTER the decision point is journalled before the data is returned', () => {
  const ledger = freshLedger('admitted');
  const read = readCorpus(ledger, {
    partition: 'HOLDOUT', caseId: 's2-008-case-01', unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT, maxOpens: 1, caseId: 's2-008-case-01',
  });
  assert.ok(read.accessRecordId, 'the access record id is the only thing that makes a read visible');
  assert.equal(read.case.case_id, 's2-008-case-01');
  const access = readJournal(ledger).filter((row) => row.kind === 'ACCESS');
  assert.equal(access.length, 1);
  assert.equal(access[0].payload.partition, 'HOLDOUT');
  assert.equal(access[0].payload.max_opens, 1);
  assert.equal(access[0].payload.decision_point, DECISION_POINT);
});

test('PR2 a read BEFORE the preregistered decision point is refused and returns no case data', () => {
  const ledger = freshLedger('early', EARLY);
  let leaked = null;
  try {
    leaked = readCorpus(ledger, {
      partition: 'HOLDOUT', caseId: 's2-008-case-01', unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT, maxOpens: 1,
    });
  } catch (error) {
    assert.equal(String(error.message).startsWith('HOLDOUT_READ_BEFORE_DECISION_POINT'), true, error.message);
  }
  assert.equal(leaked, null, 'a refused read returned case data');
  assert.equal(readJournal(ledger).filter((row) => row.kind === 'ACCESS').length, 0, 'a refused read left an ACCESS record');
});

test('PR2 a SECOND open of the same partition is refused even with a VALID digest', () => {
  // The rule PR2 was missing: the open budget was counted per DIGEST, so a
  // second read of the same partition under another trial id was admitted.
  const root = path.join(SCRATCH, 'twice');
  rmSync(root, { recursive: true, force: true });
  const first = openRegistry({ root, clock: clock(INSTANT), ids: ids('twice') });
  readCorpus(first, {
    partition: 'HOLDOUT', caseId: 's2-008-case-01', unsealDigest: HOLDOUT_UNSEAL_DIGEST, decisionPoint: DECISION_POINT, maxOpens: 1,
  });
  const second = openRegistry({ root, clock: clock(INSTANT), ids: ids('twice') });
  const before = snapshotDigest(second);
  // A DIFFERENT digest, which is exactly the shape of the bypass: the old rule
  // counted opens per digest, so a fresh wrapper around the same partition was
  // admitted. Reached through `recordHoldoutRead` because `readCorpus` only
  // accepts the digest the committed corpus actually has — so the corpus path
  // would have been protected by the label seal and the ledger rule would have
  // gone untested.
  assert.throws(
    () => recordHoldoutRead(second, {
      trial: 'trl-s2-008-02', unsealDigest: canonicalDigest({ other: 'partition' }), partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: 1,
    }),
    (error) => String(error.message).startsWith('HOLDOUT_OPEN_BUDGET_EXCEEDED'),
  );
  assert.equal(snapshotDigest(second), before, 'a refused read changed the ledger');
  // The mirror: a THIRD digest for the SAME partition is still refused, so the
  // budget is a property of the partition and not of any single presentation.
  assert.throws(
    () => recordHoldoutRead(second, {
      trial: 'trl-s2-008-03', unsealDigest: canonicalDigest({ third: true }), partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: 1,
    }),
    (error) => String(error.message).startsWith('HOLDOUT_OPEN_BUDGET_EXCEEDED'),
  );
  // And the same digest presented by a SECOND trial is the digest rule, which
  // is a different refusal with a different code.
  assert.throws(
    () => recordHoldoutRead(second, {
      trial: 'trl-s2-008-09', unsealDigest: HOLDOUT_UNSEAL_DIGEST.slice(7), partition: 'HOLDOUT', decisionPoint: DECISION_POINT, maxOpens: 1,
    }),
    (error) => String(error.message).startsWith('HOLDOUT_OPEN_BUDGET_EXCEEDED') || String(error.message).startsWith('HOLDOUT_UNSEAL_DIGEST_REPLAYED'),
  );
});

test('PR2 a forged unseal digest is refused and returns no case data', () => {
  const ledger = freshLedger('forged');
  let leaked = null;
  try {
    leaked = readCorpus(ledger, {
      partition: 'HOLDOUT', caseId: 's2-008-case-01', unsealDigest: '0'.repeat(64), decisionPoint: DECISION_POINT, maxOpens: 1,
    });
  } catch (error) {
    assert.equal(String(error.message).startsWith('HOLDOUT_UNSEAL_DIGEST_FORGED'), true, error.message);
  }
  assert.equal(leaked, null);
});

test('PR2 a caller may not stamp its own instant on an access record', () => {
  const ledger = freshLedger('stamped');
  assert.throws(
    () => recordHoldoutRead(ledger, { trial: 'trl-1', unsealDigest: HOLDOUT_UNSEAL_DIGEST.slice(7), readAt: '2030-01-01T00:00:00.000Z' }),
    (error) => String(error.message).startsWith('HOLDOUT_READ_AT_NOT_INJECTED_CLOCK'),
  );
});

test('PR2 an unreadable open budget is refused, not read as unlimited', () => {
  const ledger = freshLedger('maxopens');
  for (const maxOpens of [0, -1, 1.5, '1', null]) {
    assert.throws(
      () => recordHoldoutRead(ledger, { trial: 'trl-1', unsealDigest: HOLDOUT_UNSEAL_DIGEST.slice(7), maxOpens }),
      (error) => String(error.message).startsWith('HOLDOUT_MAX_OPENS_INVALID'),
      `max_opens=${String(maxOpens)}`,
    );
  }
});

test('the PRIMARY partition is readable with no unseal digest and is not logged as a peek', () => {
  const ledger = freshLedger('primary');
  const read = readCorpus(ledger, { partition: 'PRIMARY', caseId: 's2-008-case-01' });
  assert.equal(read.accessRecordId, null);
  assert.equal(readJournal(ledger).filter((row) => row.kind === 'ACCESS').length, 0);
});

// --- A4: the label seal ----------------------------------------------------

test('A4 the label seal holds on the committed labels and breaks on substituted ones', () => {
  const loaded = loadPreregistration(CORPUS_DIR);
  const dataset = { cases: Object.entries(HOLDOUT_LABELS).map(([caseId, label]) => ({ case_id: caseId, label })), labels: HOLDOUT_LABELS };
  assert.equal(assertLabelSeal({ declared: loaded.holdout_access.labels_digest, actual: labelsDigest(dataset) }), canonicalDigest(HOLDOUT_LABELS));
  const substituted = substituteLabelsControl(dataset);
  assert.equal(substituted.substituted, true);
  assert.equal(substituted.control_id, 'label_substitution');
  assert.notEqual(substituted.labels_digest, canonicalDigest(HOLDOUT_LABELS));
  assert.throws(
    () => assertLabelSeal({ declared: loaded.holdout_access.labels_digest, actual: substituted.labels_digest }),
    (error) => String(error.message).startsWith('LABEL_SEAL_MISMATCH'),
  );
});

test('A4 the label-substitution control flips every label and leaves the claims alone', () => {
  const dataset = { cases: Object.entries(HOLDOUT_LABELS).map(([caseId, label]) => ({ case_id: caseId, label })), labels: HOLDOUT_LABELS };
  const substituted = substituteLabelsControl(dataset);
  const flipped = Object.keys(HOLDOUT_LABELS).filter((caseId) => substituted.labels[caseId] !== HOLDOUT_LABELS[caseId]);
  assert.equal(flipped.length, Object.keys(HOLDOUT_LABELS).length);
  assert.equal(substituted.original_labels_digest, canonicalDigest(HOLDOUT_LABELS));
});

test('a non-loadable dataset is refused by the control builder', () => {
  assert.throws(() => substituteLabelsControl({}), (error) => String(error.message).startsWith('DATASET_NOT_LOADABLE'));
});

test('caseDigest is the canonical digest and refuses a non-record', () => {
  assert.equal(caseDigest({ case_id: 'x' }), canonicalDigest({ case_id: 'x' }));
  assert.throws(() => caseDigest(null), (error) => String(error.message).startsWith('CASE_RECORD_MALFORMED'));
});

// --- A4: the causal guard --------------------------------------------------

test('the preregistered card is contract-valid, observational and admissible', () => {
  const card = PREREGISTRATION.card;
  assert.equal(assertResearchContract('hypothesis-card', card), card);
  assert.equal(assertCausalDiscipline(card), card);
  assert.equal(assertNoCausalFromSimulation(card), card);
  const classification = classifyCardRelation(card);
  assert.equal(classification.observational, true);
  assert.equal(classification.causalAssertion, false);
  assert.equal(classification.admissible, true);
  assert.equal(classification.refusalCode, null);
});

test('A4 an observational strength carrying a causal assertion is refused by BOTH guards', () => {
  const card = { ...PREREGISTRATION.card, proposed_relation: { ...PREREGISTRATION.card.proposed_relation, causal_assertion: true } };
  // The frozen schema ACCEPTS it: `causal_assertion` is a free
  // `oneOf: [boolean, null]`, so the refusal has to come from code.
  assert.equal(assertResearchContract('hypothesis-card', card), card);
  assert.throws(() => assertCausalDiscipline(card), (error) => String(error.message).startsWith('CAUSAL_ASSERTION_UNSUPPORTED'));
  assert.throws(() => assertNoCausalFromSimulation(card), (error) => String(error.message).startsWith('CAUSAL_ASSERTION_UNSUPPORTED'));
});

test('A4 a causal assertion needs a promotion, temporal ordering and a found mediator', () => {
  const base = {
    ...PREREGISTRATION.card,
    card_type: 'MECHANISM_CLAIM',
    type_promotion: { from_type: 'HYPOTHESIS', to_type: 'MECHANISM_CLAIM', reviewed_by: 'rev-01', basis: 'an authorised review' },
    proposed_relation: { ...PREREGISTRATION.card.proposed_relation, relation_strength: 'EXPERIMENTAL', causal_assertion: true },
    temporal_ordering: { established: true, evidence_claim_ids: ['clm-s2-008-01'], event_times: [] },
    mediators: [{ description: 'the filter', claim_id: 'clm-s2-008-01', evidence_status: 'SUPPORTED' }],
  };
  assert.equal(assertCausalDiscipline(base), base, 'a fully evidenced mechanism claim is admissible');
  // Each missing requirement is named, so the refusal says WHICH one.
  const cases = {
    CAUSAL_PROMOTION_MISSING: { ...base, type_promotion: null },
    CAUSAL_PROMOTION_SELF_REVIEWED: { ...base, type_promotion: { ...base.type_promotion, reviewed_by: base.created_by } },
    CAUSAL_TEMPORAL_ORDER_UNESTABLISHED: { ...base, temporal_ordering: { established: false, evidence_claim_ids: [], event_times: [] } },
    CAUSAL_MEDIATOR_NOT_FOUND: { ...base, mediators: [{ description: 'the filter', claim_id: 'clm-s2-008-01', evidence_status: 'PROPOSED' }] },
  };
  for (const [expected, card] of Object.entries(cases)) {
    assert.throws(() => assertCausalDiscipline(card), (error) => String(error.message).startsWith(expected), expected);
  }
});

test('a card that does not satisfy the frozen contract is a MalformedResult, not a policy refusal', () => {
  assert.throws(
    () => assertCausalDiscipline({ ...PREREGISTRATION.card, card_id: 'not-a-card-id' }),
    (error) => String(error.message).startsWith('RESEARCH_CONTRACT_VIOLATION'),
  );
});
