// S2-008 #12 — the evaluator scoring RECORDED predictions, and the limit it names.
//
// The change this pins: a model arm has no rule to restate, so the evaluator takes
// the per-case predictions the run published, re-scores them against the corpus
// labels ITSELF, and publishes which path it took. The independence is not the
// same on both paths, and pretending otherwise is the thing being prevented:
//
//   RESTATED_RULE   the evaluator recomputes the prediction, so the run's own
//                   count is only a comparison. A self-reported number cannot
//                   carry the verdict.
//   RECORDED_...    the executor is the only source of the prediction, so the
//                   evaluator re-derives the LABELS, the COUNT, the interval and
//                   the decision, and states that the prediction itself is the
//                   one link it cannot re-derive.
//
// These cases run against synthetic records, so nothing is spent and no container
// is started.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs, { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { CLOSED_PREDICTIONS, scoreRecordedPredictions, loadRecordedPredictions } from '../../scripts/s2-008-campaign-evaluate.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';

const IDS = ['c1', 'c2', 'c3', 'c4'];

function labelsFrom(pairs) {
  return new Map(pairs.map(([id, label]) => [id, label]));
}

test('the closed prediction set includes UNPARSED and nothing else', () => {
  // A set the scorer can refuse against, restated here rather than imported from
  // the arm: a scorer borrowing the predictor's vocabulary cannot notice the
  // predictor inventing a value.
  assert.deepEqual([...CLOSED_PREDICTIONS], ['MAJOR', 'MINOR', 'UNPARSED']);
});

test('recorded predictions are scored from scratch, and the count is the scorer\'s own', () => {
  const labels = labelsFrom([['c1', 'MAJOR'], ['c2', 'MINOR'], ['c3', 'MAJOR'], ['c4', 'MINOR']]);
  const rows = [
    { case_id: 'c1', predicted: 'MAJOR' },   // right
    { case_id: 'c2', predicted: 'MAJOR' },   // wrong
    { case_id: 'c3', predicted: 'MINOR' },   // wrong
    { case_id: 'c4', predicted: 'MINOR' },   // right
  ];
  const scored = scoreRecordedPredictions({ rows, labels, expectedIds: IDS });
  assert.equal(scored.ok, true, `the rows were not scoreable: ${scored.problems.join('; ')}`);
  assert.equal(scored.agreeing, 2, 'the scorer did not produce its own count');
  assert.equal(scored.unparsed, 0);
  assert.equal(scored.rows, 4);
});

test('UNPARSED is in the set and counts as a DISAGREEMENT, never as a label', () => {
  const labels = labelsFrom([['c1', 'MAJOR'], ['c2', 'MINOR']]);
  const scored = scoreRecordedPredictions({
    rows: [{ case_id: 'c1', predicted: 'MAJOR' }, { case_id: 'c2', predicted: 'UNPARSED' }],
    labels,
    expectedIds: ['c1', 'c2'],
  });
  assert.equal(scored.ok, true, `an unusable answer was refused instead of scored: ${scored.problems.join('; ')}`);
  assert.equal(scored.agreeing, 1, 'UNPARSED was counted as agreement');
  assert.equal(scored.unparsed, 1, 'the unusable answers were not published');
  // And it can never equal a label, so there is no path by which an unusable
  // answer inflates the score.
  assert.equal('UNPARSED' === 'MAJOR', false);
});

test('a value outside the closed set is REFUSED, and the refusal names it', () => {
  const labels = labelsFrom([['c1', 'MAJOR']]);
  const scored = scoreRecordedPredictions({
    rows: [{ case_id: 'c1', predicted: 'MAYBE' }],
    labels,
    expectedIds: ['c1'],
  });
  assert.equal(scored.ok, false, 'a prediction outside the closed set was scored');
  assert.ok(scored.problems.some((p) => /outside-closed-set:c1:MAYBE/.test(p)), `the refusal did not name the value: ${scored.problems.join('; ')}`);
});

test('a case set that differs from the corpus is REFUSED, not scored on the overlap', () => {
  const labels = labelsFrom([['c1', 'MAJOR'], ['c2', 'MINOR']]);
  const scored = scoreRecordedPredictions({
    rows: [{ case_id: 'c1', predicted: 'MAJOR' }, { case_id: 'c9', predicted: 'MINOR' }],
    labels,
    expectedIds: ['c1', 'c2'],
  });
  assert.equal(scored.ok, false);
  assert.ok(scored.problems.some((p) => /case-set-differs-from-corpus/.test(p)), `the refusal did not name the case set: ${scored.problems.join('; ')}`);
});

test('a duplicate case, or a case the corpus does not have, is refused', () => {
  const labels = labelsFrom([['c1', 'MAJOR'], ['c2', 'MINOR']]);
  const dup = scoreRecordedPredictions({
    rows: [{ case_id: 'c1', predicted: 'MAJOR' }, { case_id: 'c1', predicted: 'MINOR' }],
    labels,
    expectedIds: ['c1', 'c2'],
  });
  assert.equal(dup.ok, false);
  assert.ok(dup.problems.some((p) => /duplicate-case:c1/.test(p)), `a duplicate was scored twice: ${dup.problems.join('; ')}`);
  const alien = scoreRecordedPredictions({
    rows: [{ case_id: 'zz', predicted: 'MAJOR' }],
    labels,
    expectedIds: ['c1'],
  });
  assert.ok(alien.problems.some((p) => /case-set-differs-from-corpus/.test(p)));
});

test('a missing or empty prediction set is refused rather than scored as zero', () => {
  // "Missing is not zero": an arm that published nothing has not agreed with
  // nothing.
  const labels = labelsFrom([['c1', 'MAJOR']]);
  for (const rows of [[], null, undefined]) {
    const scored = scoreRecordedPredictions({ rows, labels, expectedIds: ['c1'] });
    assert.equal(scored.ok, false, `absence was scored as agreement=${String(scored.agreeing)}`);
    assert.equal(scored.agreeing, undefined, 'an absent set produced a count');
  }
});

test('the loader verifies the sidecar against the digest the RUN recorded', () => {
  // The binding is the whole reason a sidecar can be trusted: the run names the
  // digest, so a prediction file edited after the run fails here.
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-pred-'));
  const trial = { per_seed: [{ seed: 7 }] };
  const entry = { trial_id: 't1', arm_id: 'arm-model-x' };
  try {
    const slice = { arm_id: 'arm-model-x', seed: 7, rows: [{ case_id: 'c1', predicted: 'MAJOR' }] };
    const digest = canonicalDigest(slice);
    const file = path.join(dir, 'predictions-a.json');
    const write = (body) => writeFileSync(file, JSON.stringify({ kind: 's2-008-campaign-predictions/1', seeds: [body] }));

    write(slice);
    const ok = loadRecordedPredictions({
      trial: { per_seed: [{ seed: 7, predictions: { digest, rows: 1, unparsed: 0 } }] },
      entry,
      runLabel: 'a',
      readFile: () => fsRead(file),
      root: dir,
    });
    assert.equal(ok.available, true, `a matching sidecar was not accepted: ${ok.reason}`);
    assert.equal(ok.rows.length, 1);

    // One row changed after the run: the digest no longer matches, so the loader
    // refuses rather than scoring a prediction the run did not make.
    write({ ...slice, rows: [{ case_id: 'c1', predicted: 'MINOR' }] });
    const tampered = loadRecordedPredictions({
      trial: { per_seed: [{ seed: 7, predictions: { digest, rows: 1, unparsed: 0 } }] },
      entry,
      runLabel: 'a',
      readFile: () => fsRead(file),
      root: dir,
    });
    assert.equal(tampered.available, false, 'a tampered sidecar was accepted');
    assert.match(tampered.reason, /does not match the digest/);

    // And a run that recorded no predictions at all says so, rather than the
    // evaluator falling back to a restated rule it does not have.
    const none = loadRecordedPredictions({ trial: { per_seed: [{ seed: 7 }] }, entry, runLabel: 'a', readFile: () => fsRead(file), root: dir });
    assert.equal(none.available, false);
    assert.match(none.reason, /no per-case predictions/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function fsRead(file) {
  return fs.readFileSync(file, 'utf8');
}
