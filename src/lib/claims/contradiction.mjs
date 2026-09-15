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

function textsOverlap(a, b) {
  if (!a || !b) return { overlap: true, proven: false };
  const na = a.toLowerCase().trim();
  const nb = b.toLowerCase().trim();
  if (na === nb) return { overlap: true, proven: true };
  return { overlap: na.includes(nb) || nb.includes(na), proven: true };
}

// Compares two claim revisions. Returns:
//   { relation: 'CONTRADICTS', basis, scope_intersection }
//   { relation: 'SCOPE_DIFFERENCE', reason, scope_intersection }
//   { relation: 'INDEPENDENT', reason }
export function compareClaims(claimA, claimB) {
  // the proposition must at least talk about the same subject and object
  const subject = textsOverlap(claimA.subject, claimB.subject);
  const object = textsOverlap(claimA.object, claimB.object);
  if (!subject.overlap || !object.overlap) {
    return { relation: 'INDEPENDENT', reason: 'different proposition' };
  }

  const population = textsOverlap(claimA.population, claimB.population);
  const geography = textsOverlap(claimA.geography, claimB.geography);
  const period = periodsOverlap(claimA.period, claimB.period);
  const scope_intersection = {
    population_overlap: population.overlap,
    geography_overlap: geography.overlap,
    period_overlap: period.overlap,
    units_compatible: claimA.units === claimB.units || Boolean(convertValue(0, claimA.units ?? '', claimB.units ?? '')) && (claimA.units !== null || claimB.units === null),
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

  // polarity flip on the same proposition with overlapping scope
  if (claimA.polarity !== claimB.polarity && textsEquivalent(claimA.normalized_text, claimB.normalized_text, { ignorePolarity: true })) {
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

function textsEquivalent(a, b, { ignorePolarity = false } = {}) {
  let na = a.toLowerCase().replace(/\s+/g, ' ').trim();
  let nb = b.toLowerCase().replace(/\s+/g, ' ').trim();
  if (ignorePolarity) {
    for (const cue of ['not ', 'no ', 'never', 'cannot', 'does not', 'do not', "doesn't", "don't"]) {
      na = na.split(cue).join(' ');
      nb = nb.split(cue).join(' ');
    }
    na = na.replace(/\s+/g, ' ').trim();
    nb = nb.replace(/\s+/g, ' ').trim();
  }
  return na === nb;
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
