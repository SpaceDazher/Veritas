// S2-004 contradiction engine (todo §7).
//
// A contradiction must consider proposition, polarity, units, population,
// geography, period, method and qualifiers. Different periods, populations or
// conditions are NOT a direct contradiction without proven overlap. Numeric
// values are only compared through explicit unit conversion with a rule
// version while preserving the original values. Absence of a found
// contradiction never implies truth. Engine suggestions stay PROPOSED until
// policy requires review.
export const UNIT_CONVERSION_RULES = Object.freeze([
  { from: '%', to: 'share', rule_version: '1.0.0', convert: (v) => v / 100 },
  { from: 'share', to: '%', rule_version: '1.0.0', convert: (v) => v * 100 },
  { from: 'km', to: 'miles', rule_version: '1.0.0', convert: (v) => v * 0.621371 },
  { from: 'miles', to: 'km', rule_version: '1.0.0', convert: (v) => v * 1.609344 },
  { from: '°C', to: '°F', rule_version: '1.0.0', convert: (v) => v * 9 / 5 + 32 },
  { from: '°F', to: '°C', rule_version: '1.0.0', convert: (v) => (v - 32) * 5 / 9 },
  { from: 'kg', to: 'tonnes', rule_version: '1.0.0', convert: (v) => v / 1000 },
  { from: 'tonnes', to: 'kg', rule_version: '1.0.0', convert: (v) => v * 1000 },
]);

export function convertValue(value, from, to) {
  if (from === to) return { value, rule_version: 'identity' };
  const rule = UNIT_CONVERSION_RULES.find((r) => r.from === from && r.to === to);
  if (!rule) return null;
  return { value: rule.convert(value), rule_version: rule.rule_version };
}

function periodsOverlap(a, b) {
  if (!a && !b) return { overlap: true, proven: false };
  if (!a || !b) return { overlap: false, proven: true };
  const aStart = a.start ? Date.parse(a.start) : -Infinity;
  const aEnd = a.end ? Date.parse(a.end) : Infinity;
  const bStart = b.start ? Date.parse(b.start) : -Infinity;
  const bEnd = b.end ? Date.parse(b.end) : Infinity;
  return { overlap: aStart <= bEnd && bStart <= aEnd, proven: true };
}

const FRAME_STOP = new Set([
  'the', 'a', 'an', 'of', 'in', 'on', 'at', 'to', 'by', 'for', 'and', 'or',
  'is', 'are', 'was', 'were', 'does', 'do', 'did', 'has', 'have', 'had',
  'not', 'no', 'never', 'without', 'cannot', 'neither', 'nor', 'fails',
  'between', 'among', 'from', 'over', 'across', 'within', 'with',
  // units/quantities never identify a proposition frame
  'percent', 'usd', 'eur', 'kg', 'kwh', 'gw', 'twh', 'tonne', 'tonnes', 'km',
  'mile', 'miles', 'meter', 'meters', 'metre', 'metres', 'hour', 'hours',
  'day', 'days', 'month', 'months', 'year', 'years', 'people', 'patient',
  'patients', 'respondent', 'respondents', 'student', 'students',
  'household', 'households', 'company', 'companies', 'firm', 'firms', 'job',
  'jobs', 'case', 'cases', 'death', 'deaths',
]);

// quantity-free, function-word-free, lightly stemmed token frame of a phrase
function frame(text) {
  return String(text ?? '')
    .toLowerCase()
    .replace(/\d+(?:[.,]\d+)?/g, ' ')
    .split(/[^a-z]+/)
    .filter((t) => t && !FRAME_STOP.has(t))
    .map((t) => (t.length > 3 && t.endsWith('s') ? t.slice(0, -1) : t));
}

function framesOverlap(a, b) {
  const sa = new Set(a);
  const sb = new Set(b);
  if (sa.size === 0 || sb.size === 0) return true; // generic frame
  for (const t of sa) if (sb.has(t)) return true;
  return false;
}

// Compares two claim revisions. Returns:
//   { relation: 'CONTRADICTS', basis, scope_intersection }
//   { relation: 'SCOPE_DIFFERENCE', reason, scope_intersection }
//   { relation: 'INDEPENDENT', reason }
export function compareClaims(claimA, claimB) {
  // the proposition must at least talk about the same subject
  const subject = framesOverlap(frame(claimA.subject), frame(claimB.subject));
  if (!subject) {
    return { relation: 'INDEPENDENT', reason: 'different proposition' };
  }

  const population = framesOverlap(frame(claimA.population), frame(claimB.population))
    ? { overlap: true, proven: Boolean(claimA.population && claimB.population) }
    : { overlap: false, proven: Boolean(claimA.population && claimB.population) };
  const geography = framesOverlap(frame(claimA.geography), frame(claimB.geography))
    ? { overlap: true, proven: Boolean(claimA.geography && claimB.geography) }
    : { overlap: false, proven: Boolean(claimA.geography && claimB.geography) };
  const period = periodsOverlap(claimA.period, claimB.period);
  const object = framesOverlap(frame(claimA.object), frame(claimB.object));
  const scope_intersection = {
    population_overlap: population.overlap,
    geography_overlap: geography.overlap,
    period_overlap: period.overlap,
    units_compatible: claimA.units === claimB.units
      || (claimA.units === null || claimB.units === null)
      || Boolean(convertValue(0, claimA.units ?? '', claimB.units ?? '')),
  };

  // scope guard: different populations, geographies or periods without proven
  // overlap never produce a direct contradiction (probe H)
  if (population.proven && !population.overlap) {
    return { relation: 'SCOPE_DIFFERENCE', reason: 'disjoint populations', scope_intersection };
  }
  if (geography.proven && !geography.overlap) {
    return { relation: 'SCOPE_DIFFERENCE', reason: 'disjoint geographies', scope_intersection };
  }
  if (period.proven && !period.overlap) {
    return { relation: 'SCOPE_DIFFERENCE', reason: 'disjoint periods', scope_intersection };
  }
  if (!object) {
    return { relation: 'INDEPENDENT', reason: 'different proposition', scope_intersection };
  }

  // polarity flip on the same proposition with overlapping scope:
  // the polarity-insensitive frames of the full propositions must coincide
  if (claimA.polarity !== claimB.polarity && polarityInsensitiveFramesOverlap(claimA.normalized_text, claimB.normalized_text)) {
    return { relation: 'CONTRADICTS', basis: 'polarity_flip', scope_intersection };
  }

  // numeric comparison — only via explicit, versioned unit conversion
  if (claimA.value_range && claimB.value_range) {
    let a = claimA.value_range;
    let b = claimB.value_range;
    let conversion = null;
    if (claimA.units !== claimB.units) {
      const forward = convertValue(a.min, claimA.units, claimB.units);
      if (forward) {
        conversion = { rule_version: forward.rule_version, from: claimA.units, to: claimB.units };
        a = { min: forward.value, max: convertValue(a.max, claimA.units, claimB.units).value };
      } else {
        return { relation: 'SCOPE_DIFFERENCE', reason: 'incommensurable units', scope_intersection };
      }
    }
    const numericDisjoint = a.max < b.min || b.max < a.min;
    if (numericDisjoint && claimA.polarity === claimB.polarity) {
      return { relation: 'CONTRADICTS', basis: 'disjoint_value_ranges', scope_intersection: { ...scope_intersection, units_compatible: true }, conversion };
    }
    if (!numericDisjoint) {
      return { relation: 'SCOPE_DIFFERENCE', reason: 'compatible value ranges', scope_intersection };
    }
  }

  if (claimA.polarity !== claimB.polarity) {
    return { relation: 'CONTRADICTS', basis: 'polarity_flip', scope_intersection };
  }
  return { relation: 'SCOPE_DIFFERENCE', reason: 'no contradiction found', scope_intersection };
}

const NEGATION_TOKENS = new Set(['not', 'no', 'never', 'without', 'cannot', 'neither', 'nor', 'fails', 'does', 'do', 'did']);

function polarityInsensitiveFramesOverlap(a, b) {
  const strip = (text) => frame(text).filter((t) => !NEGATION_TOKENS.has(t));
  return framesOverlap(strip(a), strip(b));
}

// Scans a set of claims and returns candidate CONTRADICTS claim edges
// (relation + exact basis + scope intersection). Suggestions are candidates:
// the caller submits them via linkClaims, which keeps them reviewable.
export function findContradictions(claims) {
  const results = [];
  for (let i = 0; i < claims.length; i += 1) {
    for (let j = i + 1; j < claims.length; j += 1) {
      const comparison = compareClaims(claims[i], claims[j]);
      if (comparison.relation === 'CONTRADICTS') {
        results.push({
          source_claim_id: claims[i].claim_id,
          source_revision: claims[i].revision,
          target_claim_id: claims[j].claim_id,
          target_revision: claims[j].revision,
          relation: 'CONTRADICTS',
          direction: 'bidirectional',
          basis: comparison.basis,
          scope_intersection: comparison.scope_intersection,
          conversion: comparison.conversion ?? null,
        });
      }
    }
  }
  return results;
}
