// S2-004 frozen corpus builder (deterministic).
// Emits corpus/s2-004/cases/<case_id>.json and corpus/s2-004/manifest.json.
// Running twice yields byte-identical output; the committed manifest pins the
// SHA-256 of every case. Each case contains the immutable input (segment
// texts, snapshot time model, lineage) and an independently authored oracle
// (annotator identity `prn-corpus-annotator`, distinct from the producer and
// from the rule-based extractor) with expected claims, abstentions and
// decisions. The producer of the implementation cannot change a locked oracle
// without breaking the manifest digests (todo §10).
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CASES_DIR = path.join(ROOT, 'corpus/s2-004/cases');
const MANIFEST_PATH = path.join(ROOT, 'corpus/s2-004/manifest.json');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const T0 = '2026-01-15T08:00:00.000Z';
const PUBLISHED = '2026-01-05T09:00:00.000Z';
const OBSERVED = '2026-01-05T09:00:00.000Z';
const FETCHED = '2026-01-06T09:00:00.000Z';

let seq = 0;
const cases = [];

function snapshot(overrides = {}) {
  return {
    snapshot_id: 'snp-1',
    published_at: PUBLISHED,
    event_time: null,
    observed_at: OBSERVED,
    fetched_at: FETCHED,
    lineage_type: 'original',
    parent_snapshot_ids: [],
    ...overrides,
  };
}

function acl(overrides = {}) {
  return { visibility: 'project', workspace_id: 'ws-corpus', tenant_id: 'tn-corpus', allowed_workspace_ids: [], allowed_principal_ids: [], ...overrides };
}

function instruction(overrides = {}) {
  return { present: false, classification: 'none', confidence: 1, note: null, ...overrides };
}

// oracle claim: what an independent annotator expects the extractor to record
function oclaim(overrides = {}) {
  return {
    normalized_text: null,
    epistemic_type: 'FACT_CLAIM',
    polarity: 'affirmative',
    units: null,
    denominator: null,
    value_range: null,
    population: null,
    geography: null,
    period: null,
    exclusions: [],
    qualifiers_includes: [],
    lifecycle: 'PROPOSED',
    span_text: null,
    ...overrides,
  };
}

function addCase(caseId, category, severity, definition) {
  seq += 1;
  const doc = {
    schemaVersion: 1,
    case_id: caseId,
    case_number: seq,
    category,
    severity,
    input: {
      workspace_id: 'ws-corpus',
      tenant_id: 'tn-corpus',
      operation_actor: 'prn-extractor',
      segments: definition.segments,
      lineage: definition.lineage ?? null,
      lenses: definition.lenses ?? [],
      lens_candidates: definition.lens_candidates ?? [],
      review: definition.review ?? null,
      invalidation: definition.invalidation ?? null,
    },
    contradiction: definition.contradiction ?? null,
    translation_check: definition.translation_check ?? null,
    expected: definition.expected,
    oracle: {
      authored_by: 'prn-corpus-annotator',
      convention: 'docs/claims/S2-004-CLAIM-GRAPH-CONTRACT.md extraction conventions v1.0.0',
    },
  };
  cases.push(doc);
}

function seg(text, overrides = {}) {
  return {
    segment_id: `seg-${sha256(text).slice(0, 12)}`,
    snapshot: snapshot(overrides.snapshot ?? {}),
    text,
    acl: acl(overrides.acl ?? {}),
    embedded_instruction_classification: instruction(overrides.embedded_instruction_classification ?? {}),
    ...(overrides.segment_id ? { segment_id: overrides.segment_id } : {}),
  };
}

const Y = (y) => ({ start: `${y}-01-01T00:00:00.000Z`, end: `${y}-12-31T23:59:59.999Z` });
const RANGE = (a, b) => ({ start: `${a}-01-01T00:00:00.000Z`, end: `${b}-12-31T23:59:59.999Z` });
const BY = (y) => ({ start: null, end: `${y}-12-31T23:59:59.999Z` });

// ===== category 1: atomic extraction (24 cases) ==============================

const ATOMIC = [
  // [text, oracle claims, abstention count]
  ['Wind and solar generated 22% of EU electricity in 2024.', [oclaim({
    normalized_text: 'Wind and solar generated 22% of EU electricity in 2024.',
    units: '%', denominator: 'of EU electricity', geography: 'EU', period: Y(2024),
    value_range: { min: 22, max: 22 },
    qualifiers_includes: ['unit:%', 'denominator:of EU electricity'],
    span_text: 'Wind and solar generated 22% of EU electricity in 2024.',
  })], 0],
  ['Coal plants emitted 830 tonnes of CO2 in Germany in 2023.', [oclaim({
    normalized_text: 'Coal plants emitted 830 tonnes of CO2 in Germany in 2023.',
    units: 'tonnes', geography: 'Germany', period: Y(2023),
    value_range: { min: 830, max: 830 },
    qualifiers_includes: ['unit:tonnes'],
    span_text: 'Coal plants emitted 830 tonnes of CO2 in Germany in 2023.',
  })], 0],
  ['The bridge spans 2.4 kilometers across the valley.', [oclaim({
    normalized_text: 'The bridge spans 2.4 kilometers across the valley.',
    units: 'km', value_range: { min: 2.4, max: 2.4 }, geography: null,
    qualifiers_includes: ['unit:km'],
    span_text: 'The bridge spans 2.4 kilometers across the valley.',
  })], 0],
  ['Households consumed 4100 kWh on average in 2022.', [oclaim({
    normalized_text: 'Households consumed 4100 kWh on average in 2022.',
    units: 'kWh', population: 'Households', period: Y(2022), value_range: { min: 4100, max: 4100 },
    qualifiers_includes: ['unit:kWh'],
    span_text: 'Households consumed 4100 kWh on average in 2022.',
  })], 0],
  ['Unemployment fell to 5.1% in Poland in 2024.', [oclaim({
    normalized_text: 'Unemployment fell to 5.1% in Poland in 2024.',
    units: '%', geography: 'Poland', period: Y(2024), value_range: { min: 5.1, max: 5.1 },
    qualifiers_includes: ['unit:%'],
    span_text: 'Unemployment fell to 5.1% in Poland in 2024.',
  })], 0],
  ['The company reported 340 employees in 2024.', [oclaim({
    normalized_text: 'The company reported 340 employees in 2024.',
    period: Y(2024), value_range: { min: 340, max: 340 }, units: null, population: 'employees',
    span_text: 'The company reported 340 employees in 2024.',
  })], 0],
  ['Solar capacity reached 1.2 tonnes of installed panels. Battery costs are falling.',
    [
      oclaim({ normalized_text: 'Solar capacity reached 1.2 tonnes of installed panels.', units: 'tonnes', value_range: { min: 1.2, max: 1.2 }, qualifiers_includes: ['unit:tonnes'], span_text: 'Solar capacity reached 1.2 tonnes of installed panels.' }),
      oclaim({ normalized_text: 'Battery costs are falling.', subject: 'Battery costs', predicate: 'are', object: 'falling', span_text: 'Battery costs are falling.' }),
    ], 0],
  ['City water use was 95 cubic meters per person. Nothing else happened.',
    [
      oclaim({ normalized_text: 'City water use was 95 cubic meters per person.', units: 'cubic meters', value_range: { min: 95, max: 95 }, denominator: 'per person', qualifiers_includes: ['unit:cubic meters', 'denominator:per person'], span_text: 'City water use was 95 cubic meters per person.' }),
    ], 1],
  ['This is unclear.', [], 1],
  ['It was recorded in 2021.', [], 1],
  ['Rainfall measured 700 millimeters in 2020, and the harvest was strong.', [oclaim({
    normalized_text: 'Rainfall measured 700 millimeters in 2020, and the harvest was strong.',
    units: 'millimeters', period: Y(2020), value_range: { min: 700, max: 700 },
    qualifiers_includes: ['unit:millimeters'],
    span_text: 'Rainfall measured 700 millimeters in 2020, and the harvest was strong.',
  })], 0],
  ['Observatories recorded 42 meteors per hour in 2023.', [oclaim({
    normalized_text: 'Observatories recorded 42 meteors per hour in 2023.',
    epistemic_type: 'OBSERVATION', period: Y(2023), value_range: { min: 42, max: 42 },
    denominator: 'per hour', span_text: 'Observatories recorded 42 meteors per hour in 2023.',
  })], 0],
  ['The census counted 380000 people in 2021.', [oclaim({
    normalized_text: 'The census counted 380000 people in 2021.',
    period: Y(2021), value_range: { min: 380000, max: 380000 }, units: 'people',
    qualifiers_includes: ['unit:people'],
    span_text: 'The census counted 380000 people in 2021.',
  })], 0],
  ['Water was recorded freezing at 0 degrees Celsius in the experiment.', [oclaim({
    normalized_text: 'Water was recorded freezing at 0 degrees Celsius in the experiment.',
    epistemic_type: 'OBSERVATION', units: '°C', value_range: { min: 0, max: 0 },
    qualifiers_includes: ['unit:°C'],
    span_text: 'Water was recorded freezing at 0 degrees Celsius in the experiment.',
  })], 0],
  ['The route measures 120 miles in total.', [oclaim({
    normalized_text: 'The route measures 120 miles in total.',
    units: 'miles', value_range: { min: 120, max: 120 }, qualifiers_includes: ['unit:miles'],
    span_text: 'The route measures 120 miles in total.',
  })], 0],
  ['The marathon record stands at 2 hours 30 minutes.', [oclaim({
    normalized_text: 'The marathon record stands at 2 hours 30 minutes.',
    units: 'hours', value_range: { min: 2, max: 2 },
    qualifiers_includes: ['unit:hours'],
    span_text: 'The marathon record stands at 2 hours 30 minutes.',
  })], 0],
  ['Exports totaled 50000 USD in 2024.', [oclaim({
    normalized_text: 'Exports totaled 50000 USD in 2024.',
    units: 'USD', period: Y(2024), value_range: { min: 50000, max: 50000 },
    qualifiers_includes: ['unit:USD'],
    span_text: 'Exports totaled 50000 USD in 2024.',
  })], 0],
  ['Imports from China fell by 12% in 2023.', [oclaim({
    normalized_text: 'Imports from China fell by 12% in 2023.',
    units: '%', geography: 'China', period: Y(2023), value_range: { min: 12, max: 12 },
    qualifiers_includes: ['unit:%'],
    span_text: 'Imports from China fell by 12% in 2023.',
  })], 0],
  ['The survey of 2000 respondents found 48% approval in 2024.', [oclaim({
    normalized_text: 'The survey of 2000 respondents found 48% approval in 2024.',
    epistemic_type: 'OBSERVATION', units: '%', denominator: 'of 2000 respondents',
    period: Y(2024), value_range: { min: 48, max: 48 },
    qualifiers_includes: ['unit:%', 'denominator:of 2000 respondents'],
    span_text: 'The survey of 2000 respondents found 48% approval in 2024.',
  })], 0],
  ['Deaths declined by 300 cases in 2024.', [oclaim({
    normalized_text: 'Deaths declined by 300 cases in 2024.',
    units: 'cases', period: Y(2024), value_range: { min: 300, max: 300 },
    qualifiers_includes: ['unit:cases'],
    span_text: 'Deaths declined by 300 cases in 2024.',
  })], 0],
  ['Industry output grew 3.2% in 2024, excluding construction.', [oclaim({
    normalized_text: 'Industry output grew 3.2% in 2024, excluding construction.',
    units: '%', period: Y(2024), value_range: { min: 3.2, max: 3.2 },
    exclusions: ['construction'],
    qualifiers_includes: ['unit:%', 'exclusions:1'],
    span_text: 'Industry output grew 3.2% in 2024, excluding construction.',
  })], 0],
  ['Schools enrolled 1200 students in 2024.', [oclaim({
    normalized_text: 'Schools enrolled 1200 students in 2024.',
    units: 'students', population: 'students', period: Y(2024), value_range: { min: 1200, max: 1200 },
    qualifiers_includes: ['unit:students'],
    span_text: 'Schools enrolled 1200 students in 2024.',
  })], 0],
  ['Farms produced 5000 tonnes of grain in 2023, except organic farms.', [oclaim({
    normalized_text: 'Farms produced 5000 tonnes of grain in 2023, except organic farms.',
    units: 'tonnes', period: Y(2023), value_range: { min: 5000, max: 5000 },
    exclusions: ['organic farms'],
    qualifiers_includes: ['unit:tonnes', 'exclusions:1'],
    span_text: 'Farms produced 5000 tonnes of grain in 2023, except organic farms.',
  })], 0],
  ['Tickets sold reached 90000 USD across Europe in 2024.', [oclaim({
    normalized_text: 'Tickets sold reached 90000 USD across Europe in 2024.',
    units: 'USD', geography: 'Europe', period: Y(2024), value_range: { min: 90000, max: 90000 },
    qualifiers_includes: ['unit:USD'],
    span_text: 'Tickets sold reached 90000 USD across Europe in 2024.',
  })], 0],
];
for (const [text, claims, abstentions] of ATOMIC) {
  addCase(`s4-atom-${String(seq + 1).padStart(3, '0')}`, 'atomic_extraction', 'medium', {
    segments: [seg(text)],
    expected: {
      claims,
      abstentions: Array.from({ length: abstentions }, () => ({ reason: 'ambiguous' })),
    },
  });
}

// ===== category 2: opinion / hypothesis / forecast (16) =======================

const OPINION = [
  ['Dr. Muller believes solar is overrated.', 'EXPERT_OPINION', 'affirmative', null, null],
  ['The authors argue that carbon taxes should be higher.', 'EXPERT_OPINION', 'affirmative', null, null],
  ['In my view, nuclear power is the best approach.', 'EXPERT_OPINION', 'affirmative', null, null],
  ['The editorial board thinks the reform is overdue.', 'EXPERT_OPINION', 'affirmative', null, null],
  ['She recommends delaying the auction.', 'EXPERT_OPINION', 'affirmative', null, null, {}, 1],
  ['Inflation might be caused by supply shocks.', 'HYPOTHESIS', 'affirmative', 'possibility', null],
  ['The decline could be explained by measurement error.', 'HYPOTHESIS', 'affirmative', 'possibility', null],
  ['The model needs revision if this hypothesis is correct.', 'HYPOTHESIS', 'affirmative', 'conditional', null],
  ['Researchers hypothesize that sleep affects memory consolidation.', 'HYPOTHESIS', 'affirmative', 'indicative', null],
  ['One may suppose that the effect is temporary.', 'HYPOTHESIS', 'affirmative', 'possibility', null],
  ['The IEA forecasts that renewables will reach 46% by 2030.', 'FORECAST', 'affirmative', 'indicative', BY(2030), { units: '%', value_range: { min: 46, max: 46 }, qualifiers_includes: ['unit:%'] }],
  ['Analysts predict that sales will grow to 50000 USD by 2028.', 'FORECAST', 'affirmative', 'indicative', BY(2028), { units: 'USD', value_range: { min: 50000, max: 50000 }, qualifiers_includes: ['unit:USD'] }],
  ['The bank expects that inflation will fall to 2% by 2026.', 'FORECAST', 'affirmative', 'indicative', BY(2026), { units: '%', value_range: { min: 2, max: 2 }, qualifiers_includes: ['unit:%'] }],
  ['The ministry forecasts that demand will rise, but the horizon is absent.', 'FORECAST', 'affirmative', 'indicative', null],
  ['Demand is projected to grow, but the report omits the horizon.', 'FORECAST', 'affirmative', 'indicative', null],
  ['The economy behaves like an ideal gas under pressure.', 'ANALOGY', 'affirmative', 'indicative', null],
];
for (const [text, type, polarity, modality, period, extra = {}, expectedAbstentions = 0] of OPINION) {
  if (expectedAbstentions > 0) {
    addCase(`s4-opin-${String(seq + 1).padStart(3, '0')}`, 'opinion_hypothesis_forecast', 'medium', {
      segments: [seg(text)],
      expected: { claims: [], abstentions: [{ reason: 'ambiguous' }] },
    });
    continue;
  }
  const quarantined = type === 'FORECAST' && period === null;
  addCase(`s4-opin-${String(seq + 1).padStart(3, '0')}`, 'opinion_hypothesis_forecast', quarantined ? 'high' : 'medium', {
    segments: [seg(text)],
    expected: {
      claims: [oclaim({
        normalized_text: text,
        epistemic_type: type,
        polarity,
        modality,
        period,
        units: extra.units ?? null,
        value_range: extra.value_range ?? null,
        lifecycle: quarantined ? 'QUARANTINED' : 'PROPOSED',
        qualifiers_includes: [...(quarantined ? ['missing_forecast_horizon'] : []), ...(extra.qualifiers_includes ?? [])],
        span_text: text,
      })],
      abstentions: [],
    },
  });
}

// ===== category 3: numeric / unit / qualifier / time traps (16) ================

const TRAPS = [
  ['The IEA does not expect coal generation to recover.', oclaim({
    normalized_text: 'The IEA does not expect coal generation to recover.',
    polarity: 'negated',
    span_text: 'The IEA does not expect coal generation to recover.',
  })],
  ['The study does not support the drug.', oclaim({
    normalized_text: 'The study does not support the drug.',
    polarity: 'negated', subject: 'The study', predicate: 'does not', object: 'support the drug',
    span_text: 'The study does not support the drug.',
  })],
  ['The plant never missed a deadline in 2024.', oclaim({
    normalized_text: 'The plant never missed a deadline in 2024.',
    polarity: 'negated', period: Y(2024),
    span_text: 'The plant never missed a deadline in 2024.',
  })],
  ['Revenue did not decline by 5% in 2024.', oclaim({
    normalized_text: 'Revenue did not decline by 5% in 2024.',
    polarity: 'negated', units: '%', period: Y(2024), value_range: { min: 5, max: 5 },
    qualifiers_includes: ['unit:%'],
    span_text: 'Revenue did not decline by 5% in 2024.',
  })],
  ['Growth ranged between 3 and 5% in 2024.', oclaim({
    normalized_text: 'Growth ranged between 3 and 5% in 2024.',
    units: '%', period: Y(2024), value_range: { min: 3, max: 5 },
    qualifiers_includes: ['unit:%'],
    span_text: 'Growth ranged between 3 and 5% in 2024.',
  })],
  ['Temperatures varied from 18 to 24 degrees Celsius in 2024.', oclaim({
    normalized_text: 'Temperatures varied from 18 to 24 degrees Celsius in 2024.',
    units: '°C', period: Y(2024), value_range: { min: 18, max: 24 },
    qualifiers_includes: ['unit:°C'],
    span_text: 'Temperatures varied from 18 to 24 degrees Celsius in 2024.',
  })],
  ['Prices moved between 10 and 12 USD in 2024.', oclaim({
    normalized_text: 'Prices moved between 10 and 12 USD in 2024.',
    units: 'USD', period: Y(2024), value_range: { min: 10, max: 12 },
    qualifiers_includes: ['unit:USD'],
    span_text: 'Prices moved between 10 and 12 USD in 2024.',
  })],
  ['The error rate is 2 percent at most.', oclaim({
    normalized_text: 'The error rate is 2 percent at most.',
    units: '%', value_range: { min: 2, max: 2 },
    qualifiers_includes: ['unit:%'],
    span_text: 'The error rate is 2 percent at most.',
  })],
  ['Mortality fell to 3 per 1000 people in 2024.', oclaim({
    normalized_text: 'Mortality fell to 3 per 1000 people in 2024.',
    denominator: 'per 1000 people', period: Y(2024),
    value_range: { min: 3, max: 3 },
    qualifiers_includes: ['denominator:per 1000 people'],
    span_text: 'Mortality fell to 3 per 1000 people in 2024.',
  })],
  ['12% of the 500 patients responded in 2024.', oclaim({
    normalized_text: '12% of the 500 patients responded in 2024.',
    units: '%', denominator: 'of 500 patients', period: Y(2024),
    value_range: { min: 12, max: 12 },
    qualifiers_includes: ['unit:%', 'denominator:of 500 patients'],
    span_text: '12% of the 500 patients responded in 2024.',
  })],
  ['9 out of 10 households had access in 2024.', oclaim({
    normalized_text: '9 out of 10 households had access in 2024.',
    denominator: 'out of 10 households', period: Y(2024),
    value_range: { min: 9, max: 9 },
    qualifiers_includes: ['denominator:out of 10 households'],
    span_text: '9 out of 10 households had access in 2024.',
  })],
  ['Coverage reached 80% of adults in 2024.', oclaim({
    normalized_text: 'Coverage reached 80% of adults in 2024.',
    units: '%', denominator: 'of adults', period: Y(2024),
    value_range: { min: 80, max: 80 },
    qualifiers_includes: ['unit:%', 'denominator:of adults'],
    span_text: 'Coverage reached 80% of adults in 2024.',
  })],
  ['Exports grew 12% in 2024, except agricultural goods, measured in nominal USD terms.', oclaim({
    normalized_text: 'Exports grew 12% in 2024, except agricultural goods, measured in nominal USD terms.',
    units: '%', period: Y(2024), value_range: { min: 12, max: 12 },
    exclusions: ['agricultural goods'],
    qualifiers_includes: ['unit:%', 'exclusions:1', 'measurement:nominal USD terms'],
    span_text: 'Exports grew 12% in 2024, except agricultural goods, measured in nominal USD terms.',
  })],
  ['Output rose 4% in real terms in 2024.', oclaim({
    normalized_text: 'Output rose 4% in real terms in 2024.',
    units: '%', period: Y(2024), value_range: { min: 4, max: 4 },
    qualifiers_includes: ['unit:%', 'measurement:real terms'],
    span_text: 'Output rose 4% in real terms in 2024.',
  })],
  ['The reform started in 2019 and finished in 2023.', oclaim({
    normalized_text: 'The reform started in 2019 and finished in 2023.',
    period: RANGE(2019, 2023),
    span_text: 'The reform started in 2019 and finished in 2023.',
  })],
  ['The archive fetched the note after the fact, but imports never become event time.', oclaim({
    normalized_text: 'The archive fetched the note after the fact, but imports never become event time.',
    polarity: 'negated',
    span_text: 'The archive fetched the note after the fact, but imports never become event time.',
  })],
];
for (const [text, oracle] of TRAPS) {
  addCase(`s4-trap-${String(seq + 1).padStart(3, '0')}`, 'numeric_unit_qualifier_time', 'high', {
    segments: [seg(text)],
    expected: { claims: [oracle], abstentions: [] },
  });
}

// ===== category 4: translation / citation / upstream lineage (12) ==============

function lineageCase(caseId, segments, collapsed, unknown, oracleClaims, severity = 'high') {
  addCase(caseId, 'translation_citation_upstream_lineage', severity, {
    segments,
    lineage: { rule: 'collapse by upstream roots; non-original lineage follows its root; unknown never independent', expected_collapsed_family_count: collapsed, expected_unknown_lineage_count: unknown },
    expected: { claims: oracleClaims, abstentions: [] },
  });
}

const UPSTREAM_TEXT = 'Solar capacity in Spain reached 14 gigawatts in 2023.';
lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg(UPSTREAM_TEXT, { segment_id: 'seg-up-main', snapshot: snapshot({ snapshot_id: 'snp-up' }) }),
    seg(UPSTREAM_TEXT, { segment_id: 'seg-up-syn1', snapshot: snapshot({ snapshot_id: 'snp-syn-1', lineage_type: 'syndication', parent_snapshot_ids: ['snp-up'] }) }),
    seg(UPSTREAM_TEXT, { segment_id: 'seg-up-syn2', snapshot: snapshot({ snapshot_id: 'snp-syn-2', lineage_type: 'citation', parent_snapshot_ids: ['snp-up'] }) }),
  ],
  1, 0,
  [oclaim({ normalized_text: UPSTREAM_TEXT, units: 'GW', value_range: { min: 14, max: 14 }, geography: 'Spain', period: Y(2023), qualifiers_includes: ['unit:GW'], span_text: UPSTREAM_TEXT })]);

lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg(UPSTREAM_TEXT, { snapshot: snapshot({ snapshot_id: 'snp-up2' }) }),
    seg('Solar capacity in Spain reached 14 GW in 2023.', { snapshot: snapshot({ snapshot_id: 'snp-ind', lineage_type: 'original', parent_snapshot_ids: [] }) }),
  ],
  2, 0,
  [
    oclaim({ normalized_text: UPSTREAM_TEXT, units: 'GW', value_range: { min: 14, max: 14 }, geography: 'Spain', period: Y(2023), qualifiers_includes: ['unit:GW'], span_text: UPSTREAM_TEXT }),
    oclaim({ normalized_text: 'Solar capacity in Spain reached 14 GW in 2023.', units: 'GW', value_range: { min: 14, max: 14 }, geography: 'Spain', period: Y(2023), qualifiers_includes: ['unit:GW'], span_text: 'Solar capacity in Spain reached 14 GW in 2023.' }),
  ]);

lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg('A mysterious report claims yields doubled in 2024.', { snapshot: snapshot({ snapshot_id: 'snp-myst', lineage_type: 'unknown' }) }),
    seg('A second mysterious report claims yields doubled in 2024.', { snapshot: snapshot({ snapshot_id: 'snp-myst-2', lineage_type: 'unknown' }) }),
  ],
  0, 2,
  [
    oclaim({ normalized_text: 'A mysterious report claims yields doubled in 2024.', period: Y(2024), span_text: 'A mysterious report claims yields doubled in 2024.' }),
    oclaim({ normalized_text: 'A second mysterious report claims yields doubled in 2024.', period: Y(2024), span_text: 'A second mysterious report claims yields doubled in 2024.' }),
  ]);

lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg('The original study found a 6% effect in 2024.', { snapshot: snapshot({ snapshot_id: 'snp-orig' }) }),
    seg('The original study found a 6% effect in 2024, as cited by a magazine.', { snapshot: snapshot({ snapshot_id: 'snp-cite', lineage_type: 'citation', parent_snapshot_ids: ['snp-orig'] }) }),
    seg('The original study found a 6% effect in 2024, per the press release.', { snapshot: snapshot({ snapshot_id: 'snp-mirror', lineage_type: 'dataset_mirror', parent_snapshot_ids: ['snp-orig'] }) }),
  ],
  1, 0,
  [
    oclaim({ normalized_text: 'The original study found a 6% effect in 2024.', epistemic_type: 'OBSERVATION', period: Y(2024), units: '%', value_range: { min: 6, max: 6 }, qualifiers_includes: ['unit:%'], span_text: 'The original study found a 6% effect in 2024.' }),
    oclaim({ normalized_text: 'The original study found a 6% effect in 2024, as cited by a magazine.', epistemic_type: 'OBSERVATION', period: Y(2024), units: '%', value_range: { min: 6, max: 6 }, qualifiers_includes: ['unit:%'], span_text: 'The original study found a 6% effect in 2024, as cited by a magazine.' }),
    oclaim({ normalized_text: 'The original study found a 6% effect in 2024, per the press release.', epistemic_type: 'OBSERVATION', period: Y(2024), units: '%', value_range: { min: 6, max: 6 }, qualifiers_includes: ['unit:%'], span_text: 'The original study found a 6% effect in 2024, per the press release.' }),
  ]);

// translation flip: negation changed
addCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`, 'translation_citation_upstream_lineage', 'high', {
  segments: [seg('The study does not support the drug.')],
  expected: {
    claims: [oclaim({
      normalized_text: 'The study does not support the drug.',
      polarity: 'negated', span_text: 'The study does not support the drug.',
    })],
    abstentions: [],
  },
  translation_check: {
    original_text: 'The study does not support the drug.',
    translated_text: 'The study supports the drug.',
    expected_relation: 'CONTRADICTS',
    expected_translated_lifecycle: 'QUARANTINED',
  },
});

lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg('Wind output was 40 terawatt hours in 2023.', { segment_id: 'seg-w-main', snapshot: snapshot({ snapshot_id: 'snp-w' }) }),
    seg('Wind output was 40 terawatt hours in 2023.', { segment_id: 'seg-w-syn', snapshot: snapshot({ snapshot_id: 'snp-w-syn', lineage_type: 'syndication', parent_snapshot_ids: ['snp-w'] }) }),
    seg('Wind output was 40 terawatt hours in 2023.', { segment_id: 'seg-w-syn2', snapshot: snapshot({ snapshot_id: 'snp-w-syn2', lineage_type: 'syndication', parent_snapshot_ids: ['snp-w'] }) }),
    seg('Wind output was 40 terawatt hours in 2023.', { segment_id: 'seg-w-ind', snapshot: snapshot({ snapshot_id: 'snp-w-ind', lineage_type: 'original', parent_snapshot_ids: [] }) }),
  ],
  2, 0,
  [oclaim({ normalized_text: 'Wind output was 40 terawatt hours in 2023.', units: 'TWh', period: Y(2023), value_range: { min: 40, max: 40 }, qualifiers_includes: ['unit:TWh'], span_text: 'Wind output was 40 terawatt hours in 2023.' })]);

lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg('Report A says costs dropped 8% in 2024.', { snapshot: snapshot({ snapshot_id: 'snp-a', lineage_type: 'unknown' }) }),
    seg('Report B says costs dropped 8% in 2024.', { snapshot: snapshot({ snapshot_id: 'snp-b' }) }),
  ],
  1, 1,
  [
    oclaim({ normalized_text: 'Report A says costs dropped 8% in 2024.', units: '%', period: Y(2024), value_range: { min: 8, max: 8 }, span_text: 'Report A says costs dropped 8% in 2024.' }),
    oclaim({ normalized_text: 'Report B says costs dropped 8% in 2024.', units: '%', period: Y(2024), value_range: { min: 8, max: 8 }, span_text: 'Report B says costs dropped 8% in 2024.' }),
  ]);

lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
  [
    seg('A wire story: the port handled 2 million containers in 2023.', { segment_id: 'seg-wire-main', snapshot: snapshot({ snapshot_id: 'snp-wire', lineage_type: 'original', parent_snapshot_ids: [] }) }),
    seg('A wire story: the port handled 2 million containers in 2023.', { segment_id: 'seg-wire-s1', snapshot: snapshot({ snapshot_id: 'snp-wire-s1', lineage_type: 'syndication', parent_snapshot_ids: ['snp-wire'] }) }),
    seg('A wire story: the port handled 2 million containers in 2023.', { segment_id: 'seg-wire-s2', snapshot: snapshot({ snapshot_id: 'snp-wire-s2', lineage_type: 'translation', parent_snapshot_ids: ['snp-wire'] }) }),
    seg('A wire story: the port handled 2 million containers in 2023.', { segment_id: 'seg-wire-s3', snapshot: snapshot({ snapshot_id: 'snp-wire-s3', lineage_type: 'dataset_mirror', parent_snapshot_ids: ['snp-wire'] }) }),
  ],
  1, 0,
  [oclaim({ normalized_text: 'A wire story: the port handled 2 million containers in 2023.', period: Y(2023), value_range: { min: 2, max: 2 }, span_text: 'A wire story: the port handled 2 million containers in 2023.' })]);

for (let i = 0; i < 4; i += 1) {
  const year = 2020 + i;
  const providerName = ['Alpha', 'Beta', 'Gamma', 'Delta'][i];
  const text = `Provider ${providerName} reported 60% uptime in ${year}.`;
  lineageCase(`s4-lin-${String(seq + 1).padStart(3, '0')}`,
    [
      seg(text, { segment_id: `seg-p-${i}-main`, snapshot: snapshot({ snapshot_id: `snp-p-${i}`, lineage_type: 'original', parent_snapshot_ids: [] }) }),
      seg(text, { segment_id: `seg-p-${i}-syn`, snapshot: snapshot({ snapshot_id: `snp-p-${i}-syn`, lineage_type: 'syndication', parent_snapshot_ids: [`snp-p-${i}`] }) }),
    ],
    1, 0,
    [oclaim({ normalized_text: text, units: '%', period: Y(year), value_range: { min: 60, max: 60 }, qualifiers_includes: ['unit:%'], span_text: text })]);
}

// ===== category 5: contradiction / scope (12) ==================================

function contradictionCase(caseId, textA, textB, oracleA, oracleB, expectedRelation, severity = 'high') {
  addCase(caseId, 'contradiction_scope', severity, {
    segments: [seg(textA), seg(textB)],
    contradiction: { expected_relation: expectedRelation },
    expected: { claims: [oracleA, oracleB], abstentions: [] },
  });
}

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% in Germany in 2024.',
  'Inflation does not equal 4% in Germany in 2024.',
  oclaim({ normalized_text: 'Inflation equals 4% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% in Germany in 2024.' }),
  oclaim({ normalized_text: 'Inflation does not equal 4% in Germany in 2024.', polarity: 'negated', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation does not equal 4% in Germany in 2024.' }),
  'CONTRADICTS');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% in Germany in 2024.',
  'Inflation equals 9% in Germany in 2024.',
  oclaim({ normalized_text: 'Inflation equals 4% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% in Germany in 2024.' }),
  oclaim({ normalized_text: 'Inflation equals 9% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 9, max: 9 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 9% in Germany in 2024.' }),
  'CONTRADICTS');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% in Germany in 2015.',
  'Inflation equals 9% in Germany in 2024.',
  oclaim({ normalized_text: 'Inflation equals 4% in Germany in 2015.', units: '%', geography: 'Germany', period: Y(2015), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% in Germany in 2015.' }),
  oclaim({ normalized_text: 'Inflation equals 9% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 9, max: 9 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 9% in Germany in 2024.' }),
  'SCOPE_DIFFERENCE');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% among adults in 2024.',
  'Inflation equals 9% among children in 2024.',
  oclaim({ normalized_text: 'Inflation equals 4% among adults in 2024.', units: '%', population: 'adults', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% among adults in 2024.' }),
  oclaim({ normalized_text: 'Inflation equals 9% among children in 2024.', units: '%', population: 'children', period: Y(2024), value_range: { min: 9, max: 9 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 9% among children in 2024.' }),
  'SCOPE_DIFFERENCE');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'The route is 100 kilometers long.',
  'The route is 70 miles long.',
  oclaim({ normalized_text: 'The route is 100 kilometers long.', units: 'km', value_range: { min: 100, max: 100 }, qualifiers_includes: ['unit:km'], span_text: 'The route is 100 kilometers long.' }),
  oclaim({ normalized_text: 'The route is 70 miles long.', units: 'miles', value_range: { min: 70, max: 70 }, qualifiers_includes: ['unit:miles'], span_text: 'The route is 70 miles long.' }),
  'CONVERTED_COMPARISON');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% in Germany in 2024.',
  'Unemployment equals 9% in Germany in 2024.',
  oclaim({ normalized_text: 'Inflation equals 4% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% in Germany in 2024.' }),
  oclaim({ normalized_text: 'Unemployment equals 9% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 9, max: 9 }, qualifiers_includes: ['unit:%'], span_text: 'Unemployment equals 9% in Germany in 2024.' }),
  'INDEPENDENT');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'The study does not support the drug.',
  'The study supports the drug.',
  oclaim({ normalized_text: 'The study does not support the drug.', polarity: 'negated', subject: 'The study', predicate: 'does not', object: 'support the drug', span_text: 'The study does not support the drug.' }),
  oclaim({ normalized_text: 'The study supports the drug.', subject: 'The study', predicate: 'supports', object: 'the drug', span_text: 'The study supports the drug.' }),
  'CONTRADICTS');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Growth ranged between 3 and 5% in 2024.',
  'Growth equaled 4% in 2024.',
  oclaim({ normalized_text: 'Growth ranged between 3 and 5% in 2024.', units: '%', period: Y(2024), value_range: { min: 3, max: 5 }, qualifiers_includes: ['unit:%'], span_text: 'Growth ranged between 3 and 5% in 2024.' }),
  oclaim({ normalized_text: 'Growth equaled 4% in 2024.', units: '%', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Growth equaled 4% in 2024.' }),
  'COMPATIBLE');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% in France in 2024.',
  'Inflation equals 9% in Germany in 2024.',
  oclaim({ normalized_text: 'Inflation equals 4% in France in 2024.', units: '%', geography: 'France', period: Y(2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% in France in 2024.' }),
  oclaim({ normalized_text: 'Inflation equals 9% in Germany in 2024.', units: '%', geography: 'Germany', period: Y(2024), value_range: { min: 9, max: 9 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 9% in Germany in 2024.' }),
  'SCOPE_DIFFERENCE');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Revenue grew 12% in 2024, except agricultural goods.',
  'Revenue fell 3% in 2024, except agricultural goods.',
  oclaim({ normalized_text: 'Revenue grew 12% in 2024, except agricultural goods.', units: '%', period: Y(2024), value_range: { min: 12, max: 12 }, exclusions: ['agricultural goods'], qualifiers_includes: ['unit:%', 'exclusions:1'], span_text: 'Revenue grew 12% in 2024, except agricultural goods.' }),
  oclaim({ normalized_text: 'Revenue fell 3% in 2024, except agricultural goods.', units: '%', period: Y(2024), value_range: { min: 3, max: 3 }, exclusions: ['agricultural goods'], qualifiers_includes: ['unit:%', 'exclusions:1'], span_text: 'Revenue fell 3% in 2024, except agricultural goods.' }),
  'CONTRADICTS');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'Inflation equals 4% in Germany from 2020 to 2024.',
  'Inflation equals 9% in Germany in 2022.',
  oclaim({ normalized_text: 'Inflation equals 4% in Germany from 2020 to 2024.', units: '%', geography: 'Germany', period: RANGE(2020, 2024), value_range: { min: 4, max: 4 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 4% in Germany from 2020 to 2024.' }),
  oclaim({ normalized_text: 'Inflation equals 9% in Germany in 2022.', units: '%', geography: 'Germany', period: Y(2022), value_range: { min: 9, max: 9 }, qualifiers_includes: ['unit:%'], span_text: 'Inflation equals 9% in Germany in 2022.' }),
  'CONTRADICTS');

contradictionCase(`s4-con-${String(seq + 1).padStart(3, '0')}`,
  'The dam holds 500 tonnes of water.',
  'The dam holds 400 tonnes of water.',
  oclaim({ normalized_text: 'The dam holds 500 tonnes of water.', units: 'tonnes', value_range: { min: 500, max: 500 }, qualifiers_includes: ['unit:tonnes'], span_text: 'The dam holds 500 tonnes of water.' }),
  oclaim({ normalized_text: 'The dam holds 400 tonnes of water.', units: 'tonnes', value_range: { min: 400, max: 400 }, qualifiers_includes: ['unit:tonnes'], span_text: 'The dam holds 400 tonnes of water.' }),
  'CONTRADICTS');

// ===== category 6: expert lens isolation (8) ===================================

function lensCase(caseId, lenses, candidatesOracle, severity = 'medium', candidatesOverride) {
  addCase(caseId, 'expert_lens_isolation', severity, {
    segments: [],
    lenses,
    lens_candidates: candidatesOverride ?? lensCase.candidates,
    expected: { claims: [], abstentions: [], lens: candidatesOracle },
  });
}

// constant candidate fixture: trusted expert's claim base 1.0, plain claim
// base 1.2 — a lens must ONLY be able to reorder via its ranking weight
lensCase.candidates = [
  { claim_id: 'clm-trusted', base_rank: 1.0, expert_id: 'exp-1', epistemic_type: 'EXPERT_OPINION', evidence_family_count: 0, lifecycle: 'PROPOSED', calibration: 'NOT_MEASURED' },
  { claim_id: 'clm-plain', base_rank: 1.2, expert_id: 'exp-other', epistemic_type: 'FACT_CLAIM', evidence_family_count: 4, lifecycle: 'PROPOSED', calibration: 'NOT_MEASURED' },
];

function lens(overrides = {}) {
  return {
    contractVersion: '1.0.0',
    lens_id: 'len-x',
    owner_workspace_id: 'ws-corpus',
    owner_principal_id: 'prn-user-1',
    expert_id: 'exp-1',
    domain: 'energy economics',
    task_class: 'fact_checking',
    weight: 0.9,
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_until: '2027-01-01T00:00:00.000Z',
    rationale: 'annotator-issued fixture',
    issuer: 'prn-admin',
    revoked_at: null,
    revocation_reason: null,
    created_at: T0,
    ...overrides,
  };
}

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso' })],
  { expected_top: 'clm-trusted', expected_influence: 'ranking_only', protected_fields_preserved: true });

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso-2', owner_principal_id: 'prn-user-2' })],
  { expected_top: 'clm-plain', expected_influence: 'none_for_user1', protected_fields_preserved: true });

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso-3', revoked_at: '2026-01-10T00:00:00.000Z', revocation_reason: 'probe' })],
  { expected_top: 'clm-plain', expected_influence: 'revoked_excluded', protected_fields_preserved: true });

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso-4', task_class: 'forecasting' })],
  { expected_top: 'clm-plain', expected_influence: 'task_class_mismatch', protected_fields_preserved: true });

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso-5', valid_until: '2026-01-14T00:00:00.000Z' })],
  { expected_top: 'clm-plain', expected_influence: 'expired', protected_fields_preserved: true });

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso-6', expert_id: 'exp-9' })],
  { expected_top: 'clm-plain', expected_influence: 'expert_mismatch', protected_fields_preserved: true });

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [lens({ lens_id: 'len-iso-7', expert_id: 'exp-2' }), lens({ lens_id: 'len-iso-8', expert_id: 'exp-2', weight: 0.5 })],
  { expected_top: 'clm-trusted', expected_influence: 'ranking_only', protected_fields_preserved: true },
  'medium',
  lensCase.candidates.map((c) => (c.claim_id === 'clm-trusted' ? { ...c, expert_id: 'exp-2' } : c)));

lensCase(`s4-lens-${String(seq + 1).padStart(3, '0')}`,
  [],
  { expected_top: 'clm-plain', expected_influence: 'no_lenses', protected_fields_preserved: true });

// ===== category 7: invalidation / revision / retraction (8) ====================

function invalidationCase(caseId, text, triggerType, expectedStaleCount, severity = 'high') {
  // full oracle: same conventions as the atomic category
  const oracle = {
    'Wind and solar generated 22% of EU electricity in 2024.': oclaim({ normalized_text: 'Wind and solar generated 22% of EU electricity in 2024.', units: '%', denominator: 'of EU electricity', geography: 'EU', period: Y(2024), value_range: { min: 22, max: 22 }, qualifiers_includes: ['unit:%', 'denominator:of EU electricity'], span_text: 'Wind and solar generated 22% of EU electricity in 2024.' }),
    'Coal plants emitted 830 tonnes of CO2 in Germany in 2023.': oclaim({ normalized_text: 'Coal plants emitted 830 tonnes of CO2 in Germany in 2023.', units: 'tonnes', geography: 'Germany', period: Y(2023), value_range: { min: 830, max: 830 }, qualifiers_includes: ['unit:tonnes'], span_text: 'Coal plants emitted 830 tonnes of CO2 in Germany in 2023.' }),
    'The bridge spans 2.4 kilometers across the valley.': oclaim({ normalized_text: 'The bridge spans 2.4 kilometers across the valley.', units: 'km', value_range: { min: 2.4, max: 2.4 }, qualifiers_includes: ['unit:km'], span_text: 'The bridge spans 2.4 kilometers across the valley.' }),
    'Unemployment fell to 5.1% in Poland in 2024.': oclaim({ normalized_text: 'Unemployment fell to 5.1% in Poland in 2024.', units: '%', geography: 'Poland', period: Y(2024), value_range: { min: 5.1, max: 5.1 }, qualifiers_includes: ['unit:%'], span_text: 'Unemployment fell to 5.1% in Poland in 2024.' }),
    'Households consumed 4100 kWh on average in 2022.': oclaim({ normalized_text: 'Households consumed 4100 kWh on average in 2022.', units: 'kWh', population: 'Households', period: Y(2022), value_range: { min: 4100, max: 4100 }, qualifiers_includes: ['unit:kWh'], span_text: 'Households consumed 4100 kWh on average in 2022.' }),
    'The company reported 340 employees in 2024.': oclaim({ normalized_text: 'The company reported 340 employees in 2024.', period: Y(2024), value_range: { min: 340, max: 340 }, units: null, population: 'employees', span_text: 'The company reported 340 employees in 2024.' }),
    'City water use was 95 cubic meters per person.': oclaim({ normalized_text: 'City water use was 95 cubic meters per person.', units: 'cubic meters', value_range: { min: 95, max: 95 }, denominator: 'per person', qualifiers_includes: ['unit:cubic meters', 'denominator:per person'], span_text: 'City water use was 95 cubic meters per person.' }),
    'Exports totaled 50000 USD in 2024.': oclaim({ normalized_text: 'Exports totaled 50000 USD in 2024.', units: 'USD', period: Y(2024), value_range: { min: 50000, max: 50000 }, qualifiers_includes: ['unit:USD'], span_text: 'Exports totaled 50000 USD in 2024.' }),
  }[text];
  addCase(caseId, 'invalidation_revision_retraction', severity, {
    segments: [seg(text)],
    invalidation: { trigger_type: triggerType, expected_stale_descendants: expectedStaleCount },
    expected: {
      claims: [oracle],
      abstentions: [],
    },
  });
}

invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'Wind and solar generated 22% of EU electricity in 2024.', 'content_segment_tombstone', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'Coal plants emitted 830 tonnes of CO2 in Germany in 2023.', 'content_segment_correction', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'The bridge spans 2.4 kilometers across the valley.', 'source_snapshot_retraction', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'Unemployment fell to 5.1% in Poland in 2024.', 'claim_correction', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'Households consumed 4100 kWh on average in 2022.', 'source_snapshot_tombstone', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'The company reported 340 employees in 2024.', 'claim_revocation', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'City water use was 95 cubic meters per person.', 'retention_expiry', 1);
invalidationCase(`s4-inv-${String(seq + 1).padStart(3, '0')}`, 'Exports totaled 50000 USD in 2024.', 'access_restriction', 1);

// ---- write -------------------------------------------------------------------

const total = cases.length;
if (total !== 96) {
  // fail loudly at build time: the matrix in todo §10 is mandatory
  const byCategory = {};
  for (const c of cases) byCategory[c.category] = (byCategory[c.category] ?? 0) + 1;
  throw new Error(`corpus must contain exactly 96 cases, built ${total}: ${JSON.stringify(byCategory)}`);
}

fs.mkdirSync(CASES_DIR, { recursive: true });
for (const existing of fs.readdirSync(CASES_DIR)) fs.unlinkSync(path.join(CASES_DIR, existing));
for (const c of cases) {
  fs.writeFileSync(path.join(CASES_DIR, `${c.case_id}.json`), `${JSON.stringify(c, null, 2)}\n`);
}

const manifest = {
  schemaVersion: 1,
  ticket: 'S2-004',
  corpusVersion: '1.0.0',
  caseCount: cases.length,
  categoryCounts: cases.reduce((acc, c) => {
    acc[c.category] = (acc[c.category] ?? 0) + 1;
    return acc;
  }, {}),
  caseSha256: Object.fromEntries(cases.map((c) => [c.case_id, sha256(fs.readFileSync(path.join(CASES_DIR, `${c.case_id}.json`)))])),
  oracle: { authored_by: 'prn-corpus-annotator', locked: true },
  split: {
    dev: cases.filter((c) => c.case_number <= 32).map((c) => c.case_id),
    calibration: cases.filter((c) => c.case_number > 32 && c.case_number <= 64).map((c) => c.case_id),
    locked_test: cases.filter((c) => c.case_number > 64).map((c) => c.case_id),
  },
};
fs.writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify({ ok: true, caseCount: cases.length, categoryCounts: manifest.categoryCounts, manifest: path.relative(ROOT, MANIFEST_PATH) }, null, 2));
