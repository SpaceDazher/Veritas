// S2-006 wave 2B: rubric decision rules, frozen fixture corpus integrity and
// the §3 module whitelist. Offline only (no network, no LLM, no wall clock).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createHmac } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { canonicalDigest, canonicalize } from '../../src/lib/verifier/canonical-json.mjs';
import {
  evaluateStatement,
  evaluateScenario,
  collapseEvidenceFamilies,
  assessNovelty,
  NOVELTY_VALUES,
  REASON_CODES,
  VERDICTS,
} from '../../src/lib/verifier/rubric.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CORPUS = path.join(ROOT, 'corpus', 's2-006');
const HMAC_KEY = 's2-006-fixture-hmac-key';
const HEX64 = /^[0-9a-f]{64}$/;

function compile(schemaNames) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const compiled = new Map();
  for (const name of schemaNames) {
    const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', `${name}.schema.json`), 'utf8'));
    ajv.addSchema(schema, schema.$id);
    compiled.set(name, ajv.getSchema(schema.$id));
  }
  return compiled;
}

function validate(compiled, name, payload) {
  const fn = compiled.get(name);
  assert.ok(fn, `${name} did not compile`);
  const ok = fn(payload) === true;
  return { ok, errors: ok ? [] : fn.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ') };
}

function sha256Bytes(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

// ---- frozen corpus load ------------------------------------------------------

const rubricBytes = fs.readFileSync(path.join(CORPUS, 'rubric-v1.json'));
const rubric = JSON.parse(rubricBytes);
const manifestBytes = fs.readFileSync(path.join(CORPUS, 'manifest.json'));
const manifest = JSON.parse(manifestBytes);
const caseFiles = manifest.cases.map((entry) => {
  const bytes = fs.readFileSync(path.join(CORPUS, 'cases', `${entry.caseId}.json`));
  const file = JSON.parse(bytes);
  return { caseId: entry.caseId, bytes, manifestEntry: entry, record: file.case, scenario: file.scenario };
});
const labelSets = {};
for (const annotator of ['a', 'b']) {
  const sets = JSON.parse(fs.readFileSync(path.join(CORPUS, 'labels', `annotator-${annotator}.json`), 'utf8'));
  for (const set of sets) labelSets[set.annotationSetId] = set;
}
const adjudications = JSON.parse(fs.readFileSync(path.join(CORPUS, 'adjudication.json'), 'utf8'));

describe('S2-006 frozen rubric v1', () => {
  const compiled = compile(['rubric']);

  test('rubric-v1.json validates against contracts/rubric.schema.json', () => {
    const result = validate(compiled, 'rubric', rubric);
    assert.equal(result.ok, true, result.errors);
  });

  test('rubric carries exactly the seven spec §7 classes with operative rules', () => {
    assert.deepEqual([...rubric.classes.map((c) => c.name)].sort(), [
      'causal_status', 'contradiction', 'entailment', 'evidence_family',
      'novelty', 'scope_difference', 'staleness',
    ]);
    for (const c of rubric.classes) {
      assert.ok(c.examples.length >= 1 && c.counterexamples.length >= 1, `${c.name} needs examples/counterexamples`);
      assert.ok(c.ambiguityRule.length > 20 && c.abstentionRule.length > 20, `${c.name} needs operative rules`);
    }
    // §7 semantic anchors present in the operative text
    const entailment = rubric.classes.find((c) => c.name === 'entailment');
    assert.match(entailment.definition, /Topic overlap alone is never entailment/);
    assert.match(entailment.definition, /never auto-converted into support/);
    const contradiction = rubric.classes.find((c) => c.name === 'contradiction');
    assert.match(contradiction.definition, /compatible population, geography, period and units/);
    const novelty = rubric.classes.find((c) => c.name === 'novelty');
    assert.match(novelty.definition, /novel_to_selected_corpus, similar_prior_found, NOT_ASSESSED/);
  });
});

describe('S2-006 frozen fixture corpus (45 cases, stratum fixture)', () => {
  const compiled = compile(['corpus-case', 'annotation-manifest']);

  test('corpus holds 45 fixture cases with synthetic licensing and provenance', () => {
    assert.equal(caseFiles.length, 45);
    assert.equal(manifest.cases.length, 45);
    for (const { record, scenario } of caseFiles) {
      assert.equal(record.stratum, 'fixture');
      assert.equal(record.license, 'synthetic');
      assert.equal(record.provenance.lineage, 'SYNTHETIC');
      assert.equal(record.locator, null);
      assert.match(record.sourceFamily, /^fixture-family-\d{2}$/);
      assert.match(record.semanticTemplate, /^template-\d{2}$/);
      assert.ok(scenario.statement.length > 0);
      assert.ok(HEX64.test(record.textDigest));
    }
  });

  test('every case record validates against contracts/corpus-case.schema.json', () => {
    for (const { record } of caseFiles) {
      const result = validate(compiled, 'corpus-case', record);
      assert.equal(result.ok, true, `${record.caseId}: ${result.errors}`);
    }
  });

  test('textDigest is the canonical-json-v1 digest of the frozen scenario bytes', () => {
    for (const { record, scenario } of caseFiles) {
      assert.equal(record.textDigest, canonicalDigest(scenario), `${record.caseId} textDigest drift`);
    }
  });

  test('manifest matches the frozen case bytes and split assignments', () => {
    const { externalStratum, ...manifestForSchema } = manifest;
    const { ok, errors } = validate(compiled, 'annotation-manifest', manifestForSchema);
    assert.equal(ok, true, errors);
    for (const { caseId, bytes, manifestEntry } of caseFiles) {
      assert.equal(manifestEntry.caseSha256, sha256Bytes(bytes), `${caseId}: case bytes drift`);
    }
    const byId = new Map(caseFiles.map((c) => [c.caseId, c]));
    for (const a of manifest.splitAssignments) {
      assert.equal(byId.get(a.caseId).record.contractVersion, '1.0.0');
      assert.ok(['dev', 'calibration', 'locked_test'].includes(a.split));
    }
  });

  test('externalStratum honestly reports NEEDS_INPUT / evaluator_not_independent', () => {
    // Ticket-required honesty field (documented deviation: not yet in the
    // wave-1 manifest schema, therefore stripped before schema validation).
    assert.equal(manifest.externalStratum.status, 'NEEDS_INPUT');
    assert.equal(manifest.externalStratum.reason, 'evaluator_not_independent');
    assert.match(manifest.externalStratum.note, /fixture stratum only/);
  });

  test('splits are pairwise disjoint by source family AND semantic template (non-vacuously reused within splits)', () => {
    const fams = { dev: new Set(), calibration: new Set(), locked_test: new Set() };
    const tmpl = { dev: new Set(), calibration: new Set(), locked_test: new Set() };
    const famCount = { dev: new Map(), calibration: new Map(), locked_test: new Map() };
    for (const { record } of caseFiles) {
      const s = manifest.splitAssignments.find((a) => a.caseId === record.caseId).split;
      fams[s].add(record.sourceFamily);
      tmpl[s].add(record.semanticTemplate);
      famCount[s].set(record.sourceFamily, (famCount[s].get(record.sourceFamily) ?? 0) + 1);
    }
    const splits = ['dev', 'calibration', 'locked_test'];
    for (let i = 0; i < splits.length; i += 1) {
      for (let j = i + 1; j < splits.length; j += 1) {
        for (const f of fams[splits[i]]) assert.ok(!fams[splits[j]].has(f), `family ${f} leaks between ${splits[i]} and ${splits[j]}`);
        for (const t of tmpl[splits[i]]) assert.ok(!tmpl[splits[j]].has(t), `template ${t} leaks between ${splits[i]} and ${splits[j]}`);
      }
    }
    // non-vacuous: some family is genuinely reused inside a split, so the
    // disjointness check has power
    const reused = splits.some((s) => [...famCount[s].values()].some((n) => n > 1));
    assert.ok(reused, 'family reuse within at least one split expected');
  });

  test('locked_test carries the structural minimum of 20+ cases', () => {
    const locked = manifest.splitAssignments.filter((a) => a.split === 'locked_test');
    assert.ok(locked.length >= 20, `locked_test=${locked.length}`);
    assert.equal(locked.length, 23);
  });

  test('categories cover every spec §6.4 class', () => {
    const required = [
      'positive', 'negative', 'ambiguous', 'contradictory', 'missing_source',
      'private', 'stale', 'future', 'multilingual', 'numeric', 'unit',
      'negation', 'causal', 'abstention',
    ];
    const observed = new Set(caseFiles.map((c) => c.scenario.category));
    for (const r of required) assert.ok(observed.has(r), `category ${r} missing`);
    // texts are overtly synthetic: no real-source claims are being made
    for (const c of caseFiles) {
      assert.equal(c.record.license, 'synthetic');
    }
  });
});

describe('S2-006 frozen label sets and adjudication', () => {
  const compiled = compile(['annotation-set', 'adjudication-record']);

  test('two annotators x three splits validate as annotation-sets with full blinding', () => {
    const ids = Object.keys(labelSets);
    assert.equal(ids.length, 6);
    for (const set of Object.values(labelSets)) {
      const result = validate(compiled, 'annotation-set', set);
      assert.equal(result.ok, true, `${set.annotationSetId}: ${result.errors}`);
      assert.ok(Object.values(set.blindAssignment).every(Boolean), `${set.annotationSetId} not blind`);
      assert.equal(set.annotatorRole, 'annotator');
    }
    const aIds = ids.filter((id) => id.startsWith('ans-s2006-a-'));
    const bIds = ids.filter((id) => id.startsWith('ans-s2006-b-'));
    assert.equal(aIds.length, 3);
    assert.equal(bIds.length, 3);
  });

  test('raw label digests bind to exact label bytes; set signatures verify over the exact binding digest', () => {
    for (const set of Object.values(labelSets)) {
      const labels = [...set.labels].sort((x, y) => x.caseId.localeCompare(y.caseId));
      for (const l of labels) {
        const digest = canonicalDigest({
          annotationSetId: set.annotationSetId, annotatorId: l.annotatorId,
          caseId: l.caseId, label: l.label, labeledAt: l.labeledAt,
        });
        assert.equal(l.labelDigest, digest, `${set.annotationSetId}/${l.caseId} label digest broken`);
      }
      const binding = canonicalDigest({
        annotationSetId: set.annotationSetId, split: set.split,
        corpusVersion: set.corpusVersion, sourceDigest: set.sourceDigest,
        rubricDigest: set.rubricDigest, labels,
      });
      const expected = createHmac('sha256', HMAC_KEY).update(binding, 'utf8').digest('hex');
      assert.equal(set.signature.digest, expected, `${set.annotationSetId}: signature does not verify`);
      assert.equal(set.signature.scheme, 'hmac-sha256');
      assert.match(set.signature.keyRef, /custody:\/\//);
    }
  });

  test('the two annotators disagree on at least 3 cases and every disagreement is adjudicated to a raw vote', () => {
    const byCase = (set) => new Map(set.labels.map((l) => [l.caseId, l.label]));
    const disagreements = [];
    for (const split of ['dev', 'calibration', 'locked_test']) {
      const a = byCase(labelSets[`ans-s2006-a-${split === 'locked_test' ? 'locked' : split}`]);
      const b = byCase(labelSets[`ans-s2006-b-${split === 'locked_test' ? 'locked' : split}`]);
      for (const [caseId, label] of a) {
        if (b.get(caseId) !== label) disagreements.push(caseId);
      }
    }
    assert.ok(disagreements.length >= 3, `disagreements=${disagreements.length}`);
    assert.deepEqual(disagreements.sort(), adjudications.map((r) => r.caseId).sort());
    for (const rec of adjudications) {
      const result = validate(compiled, 'adjudication-record', rec);
      assert.equal(result.ok, true, `${rec.adjudicationId}: ${result.errors}`);
      const votes = rec.retainedRawLabels.map((l) => l.label);
      assert.ok(votes.includes(rec.decision), 'adjudicated decision must retain a raw vote, never invent one');
      assert.equal(rec.adjudicatorIdentity.role, 'adjudicator');
      assert.notEqual(rec.adjudicatorIdentity.principalId, 'prn-annotator-a');
      assert.notEqual(rec.adjudicatorIdentity.principalId, 'prn-annotator-b');
    }
  });

  test('adjudications are bound to this exact manifest, rubric and thresholds', () => {
    const thresholds = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', 's2-006-thresholds.json'), 'utf8'));
    for (const rec of adjudications) {
      assert.equal(rec.versions.annotationManifestDigest, sha256Bytes(manifestBytes));
      assert.equal(rec.versions.rubricDigest, sha256Bytes(rubricBytes));
      assert.equal(rec.versions.thresholdsDigest, canonicalDigest(thresholds));
    }
  });

  test('manifest label digests match the combined raw label bytes per case', () => {
    for (const { caseId, manifestEntry } of caseFiles) {
      const split = manifest.splitAssignments.find((a) => a.caseId === caseId).split;
      const setId = split === 'locked_test' ? 'locked' : split;
      const a = labelSets[`ans-s2006-a-${setId}`].labels.find((l) => l.caseId === caseId);
      const b = labelSets[`ans-s2006-b-${setId}`].labels.find((l) => l.caseId === caseId);
      assert.ok(a && b, `${caseId}: two raw labels required`);
      const combined = canonicalDigest({
        caseId,
        labels: [a, b].map((e) => ({
          caseId: e.caseId, label: e.label, labelDigest: e.labelDigest, annotatorId: e.annotatorId, labeledAt: e.labeledAt,
        })),
      });
      assert.equal(combined, manifestEntry.labelsSha256, `${caseId} labelsSha drift`);
    }
  });

  test('annotator-a carries the fixture expectation; annotator-b introduces realistic deviations only', () => {
    for (const { caseId, scenario } of caseFiles) {
      const split = manifest.splitAssignments.find((a) => a.caseId === caseId).split;
      const setId = split === 'locked_test' ? 'locked' : split;
      const a = labelSets[`ans-s2006-a-${setId}`].labels.find((l) => l.caseId === caseId);
      assert.equal(a.label, scenario.expected.verdict, `${caseId}: annotator-a must carry the frozen expectation`);
    }
  });
});

describe('S2-006 rubric decision rules (spec §7 probe table)', () => {
  const expectedVerdict = (caseId) => {
    const f = caseFiles.find((c) => c.caseId === caseId);
    return { verdict: f.scenario.expected.verdict, reasonCodes: f.scenario.expected.reasonCodes, scenario: f.scenario };
  };
  const expectCase = (caseId) => {
    const { verdict, reasonCodes, scenario } = expectedVerdict(caseId);
    const result = evaluateScenario(scenario);
    assert.equal(result.verdict, verdict, `${caseId}: verdict`);
    assert.deepEqual(result.reasonCodes, reasonCodes, `${caseId}: reason codes`);
    return result;
  };

  test('probe B: number, unit and negation drift -> semantic mismatch with the exact reason code', () => {
    assert.equal(expectCase('case-s2006-03').verdict, 'INSUFFICIENT_EVIDENCE'); // 25% vs 15%
    assert.deepEqual(expectCase('case-s2006-03').reasonCodes, ['number_unit_drift']);
    assert.deepEqual(expectCase('case-s2006-04').reasonCodes, ['number_unit_drift']); // 12 weeks vs 12 months
    assert.deepEqual(expectCase('case-s2006-25').reasonCodes, ['number_unit_drift']); // 85% vs 58%
    assert.deepEqual(expectCase('case-s2006-26').reasonCodes, ['number_unit_drift']); // 14 months vs 14 weeks
    assert.deepEqual(expectCase('case-s2006-05').reasonCodes, ['negation_drift']);
    assert.deepEqual(expectCase('case-s2006-27').reasonCodes, ['negation_drift']);
    assert.deepEqual(expectCase('case-s2006-06').reasonCodes, ['modality_drift']);
    assert.deepEqual(expectCase('case-s2006-28').reasonCodes, ['modality_drift']);
  });

  test('probe A: topic overlap is never SUPPORTED', () => {
    for (const caseId of ['case-s2006-02', 'case-s2006-24']) {
      const r = expectCase(caseId);
      assert.notEqual(r.verdict, 'SUPPORTED');
      assert.equal(r.verdict, 'PARTIALLY_SUPPORTED');
      assert.ok(r.reasonCodes.includes('topic_overlap'));
    }
  });

  test('probe C: population/geography/scope differences are scope_difference, never CONTRADICTED', () => {
    for (const caseId of ['case-s2006-07', 'case-s2006-13', 'case-s2006-31', 'case-s2006-32']) {
      const r = expectCase(caseId);
      assert.notEqual(r.verdict, 'CONTRADICTED', caseId);
      assert.ok(r.reasonCodes.includes('scope_difference'), caseId);
    }
  });

  test('compatible-scope polarity flip with a contradicting span -> CONTRADICTED', () => {
    for (const caseId of ['case-s2006-12', 'case-s2006-29', 'case-s2006-30']) {
      const r = expectCase(caseId);
      assert.equal(r.verdict, 'CONTRADICTED');
      assert.deepEqual(r.reasonCodes, []);
    }
  });

  test('probe D: correlation/temporal co-occurrence without causal basis never becomes mechanism', () => {
    for (const caseId of ['case-s2006-19', 'case-s2006-40']) {
      const r = expectCase(caseId);
      assert.notEqual(r.verdict, 'SUPPORTED', caseId);
      assert.ok(r.reasonCodes.includes('causal_overclaim'), caseId);
    }
    // interventional markers keep support but the verdict stays advisory
    for (const caseId of ['case-s2006-20', 'case-s2006-41']) {
      const r = expectCase(caseId);
      assert.equal(r.verdict, 'SUPPORTED');
      assert.deepEqual(r.reasonCodes, []);
    }
  });

  test('probe E: convincing output with no cited spans -> INSUFFICIENT_EVIDENCE (missing_citation)', () => {
    for (const caseId of ['case-s2006-10', 'case-s2006-22', 'case-s2006-42']) {
      const r = expectCase(caseId);
      assert.equal(r.verdict, 'INSUFFICIENT_EVIDENCE');
      assert.deepEqual(r.reasonCodes, ['missing_citation']);
    }
    // cited but unavailable source: typed missingness, never a semantic pass
    const r = expectCase('case-s2006-08');
    assert.deepEqual(r.reasonCodes, ['missing_citation']);
    assert.equal(r.missingness.kind, 'source_unavailable');
    assert.equal(expectCase('case-s2006-33').missingness.kind, 'source_unavailable');
  });

  test('staleness: stale/future/revoked evidence -> STALE_INPUT with the exact reason code', () => {
    assert.deepEqual([expectCase('case-s2006-09').reasonCodes, expectCase('case-s2006-15').reasonCodes, expectCase('case-s2006-35').reasonCodes],
      [['stale_source'], ['stale_source'], ['stale_source']]);
    assert.deepEqual([expectCase('case-s2006-16').reasonCodes, expectCase('case-s2006-36').reasonCodes],
      [['future_source'], ['future_source']]);
    assert.deepEqual(expectCase('case-s2006-37').reasonCodes, ['revoked_source']);
  });

  test('probe O: novelty outcomes are closed to the spec enum; world-novelty claims are OUT_OF_SCOPE', () => {
    for (const args of [
      { scope: 'worldwide', priorArtInSelectedCorpus: true },
      { scope: 'worldwide', priorArtInSelectedCorpus: false },
      { scope: 'selected_corpus', priorArtInSelectedCorpus: false },
      { scope: 'selected_corpus', priorArtInSelectedCorpus: true },
      { corpusScopeProvided: false },
      {},
    ]) {
      assert.ok(NOVELTY_VALUES.includes(assessNovelty(args)), JSON.stringify(args));
    }
    assert.equal(assessNovelty({ scope: 'selected_corpus', priorArtInSelectedCorpus: false }), 'novel_to_selected_corpus');
    assert.equal(assessNovelty({ scope: 'selected_corpus', priorArtInSelectedCorpus: true }), 'similar_prior_found');
    assert.equal(assessNovelty({ scope: 'worldwide', priorArtInSelectedCorpus: false }), 'NOT_ASSESSED');
    const r = expectCase('case-s2006-44'); // "first worldwide ..."
    assert.equal(r.verdict, 'OUT_OF_SCOPE');
    assert.deepEqual(r.reasonCodes, ['out_of_scope']);
    const bounded = expectCase('case-s2006-45'); // corpus-bounded novelty
    assert.equal(bounded.verdict, 'SUPPORTED');
    assert.equal(bounded.noveltyAssessment, 'novel_to_selected_corpus');
  });

  test('probe F: ten retellings of one upstream collapse into one evidence family', () => {
    const retellings = Array.from({ length: 10 }, (_, i) => ({ sourceFamily: 'fixture-family-43', text: `Retelling ${i}` }));
    assert.deepEqual(collapseEvidenceFamilies(retellings), { families: ['fixture-family-43'], independentCount: 1 });
    const withIndependent = [...retellings, { sourceFamily: 'fixture-family-99', text: 'other' }];
    assert.deepEqual(collapseEvidenceFamilies(withIndependent), { families: ['fixture-family-43', 'fixture-family-99'], independentCount: 2 });
    // unknown lineage never creates additional independence
    assert.equal(collapseEvidenceFamilies([{ text: 'a' }, { text: 'b' }]).independentCount, 0);
    // and an independence claim over collapsed support downgrades to PARTIALLY_SUPPORTED + family_collapse
    assert.deepEqual(expectCase('case-s2006-43').reasonCodes, ['family_collapse']);
    assert.equal(expectCase('case-s2006-43').verdict, 'PARTIALLY_SUPPORTED');
    assert.deepEqual(expectCase('case-s2006-21').reasonCodes, ['family_collapse']);
  });

  test('probe G (content discipline): a private span yields BLOCKED_POLICY and its text never enters the result', () => {
    for (const caseId of ['case-s2006-14', 'case-s2006-34']) {
      const { scenario } = expectedVerdict(caseId);
      const result = evaluateScenario(scenario);
      assert.equal(result.verdict, 'BLOCKED_POLICY');
      assert.deepEqual(result.reasonCodes, ['policy_block']);
      assert.equal(result.missingness.kind, 'policy_refusal');
      const serialized = canonicalize(result);
      for (const s of scenario.supportingSpans) {
        assert.ok(!serialized.includes(s.text), `${caseId}: private span text leaked into the verification result`);
      }
    }
  });

  test('multilingual/translation: numbers must survive translation; preserved numbers support via frozen alignments', () => {
    assert.equal(expectCase('case-s2006-17').verdict, 'SUPPORTED');
    assert.equal(expectCase('case-s2006-38').verdict, 'SUPPORTED');
    assert.deepEqual(expectCase('case-s2006-18').reasonCodes, ['number_unit_drift']);
    assert.deepEqual(expectCase('case-s2006-39').reasonCodes, ['number_unit_drift']);
  });

  test('the rubric reproduces the full frozen expectation table over all 45 cases', () => {
    let exact = 0;
    for (const { scenario } of caseFiles) {
      const r = evaluateScenario(scenario);
      if (r.verdict === scenario.expected.verdict && JSON.stringify(r.reasonCodes) === JSON.stringify(scenario.expected.reasonCodes)) exact += 1;
    }
    assert.equal(exact, 45);
  });

  test('engine output is closed: verdicts, reason codes and rubric identity', () => {
    for (const { scenario } of caseFiles) {
      const r = evaluateScenario(scenario);
      assert.ok(VERDICTS.includes(r.verdict));
      for (const rc of r.reasonCodes) assert.ok(REASON_CODES.includes(rc), rc);
      assert.equal(r.rubricId, 'rub-s2006-semantic-v1');
      assert.equal(r.rubricVersion, '1.0.0');
    }
  });

  test('evaluateStatement rejects a non-statement input (fail closed)', () => {
    assert.throws(() => evaluateStatement({ statement: '' }), /statement/);
    assert.throws(() => evaluateStatement({}), /statement/);
  });
});

describe('S2-006 module whitelist (spec §3)', () => {
  test('candidate-path modules never import producer semantics', () => {
    for (const file of ['rubric.mjs', 'calibration.mjs', 'comparator.mjs']) {
      const src = fs.readFileSync(path.join(ROOT, 'src', 'lib', 'verifier', file), 'utf8');
      // import/export-from statements only — prose comments may name the
      // forbidden modules to document the rule itself
      const importLines = src.split('\n').filter((l) => /^\s*(?:import|export)\b/.test(l));
      for (const line of importLines) {
        assert.doesNotMatch(line, /synthesis|claims/, `${file} imports producer semantics: ${line.trim()}`);
      }
    }
  });

  test('the producer heuristic adapter is the single sanctioned reuse point (spec §9.2)', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'lib', 'verifier', 'baselines.mjs'), 'utf8');
    assert.match(src, /import \{ entailmentOf \} from '\.\.\/synthesis\/synthesis\.mjs';/);
    assert.match(src, /import \{ compareClaims \} from '\.\.\/claims\/contradiction\.mjs';/);
  });
});
