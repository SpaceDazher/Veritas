// S2-004 atomic claim extraction (deterministic, rule-based).
//
// Trust model (todo §4): the source text and every field derived from it are
// UNTRUSTED DATA. Extraction rules are fixed in this file; segment text can
// never change extraction behavior, extend authority or assign itself an
// epistemic type (probe I). Embedded instructions in a segment cause a
// policy_blocked abstention — the data stays inert.
//
// One verifiable proposition per claim. Exact source span (byte offsets into
// the immutable segment text) and the span digest are recorded before any
// normalization. Negation (polarity), ranges, units, denominators, modality,
// population, geography, period, qualifiers and exclusions are preserved —
// losing any of them is a hard fail (todo §11).
//
// Time model (todo §4.6): published_at / event_time / observed_at / fetched_at
// come exclusively from the snapshot of the segment. The import (decision)
// clock never becomes an event or forecast time (probe C).
//
// Ambiguity produces QUARANTINED claims or abstentions — never guesses.
import {
  claimValidators,
  canonicalDigestOfClaim,
  claimContentDigest,
  canonicalJson,
  deterministicClaimId,
  sha256Hex,
  spanDigest,
} from './validation.mjs';

const FORECAST_CUES = [
  'is expected to', 'are expected to', 'is projected to', 'are projected to',
  'is forecast', 'are forecast', 'will reach', 'will grow', 'will rise',
  'will fall', 'will decline', 'will increase', 'will decrease', 'predicts that',
  'predict that', 'predicted that', 'forecasts that', 'forecast that', 'projected to',
];
const HYPOTHESIS_CUES = [
  'hypothes', 'may be caused', 'might be', 'could be explained', 'plausible',
  'assume', 'assumes', 'suppose', 'if this is correct', 'hypothetical',
  'conjecture', 'speculat',
];
const ANALOGY_CUES = [
  'similar to', 'analogous', 'acts like', 'behaves like', 'is like a',
  'can be compared to', 'as if', 'mirrors',
];
const MECHANISM_CUES = [
  'because', 'causes', 'cause of', 'caused by', 'leads to', 'due to', 'results in',
  'explains', 'mechanism', 'driven by', 'triggers', 'prevents', 'attributable to',
];
const OPINION_CUES = [
  'believes', 'believe that', 'argues', 'argue that', 'in my view',
  'in our view', 'opinion', 'thinks', 'considers', 'should be',
  'i am convinced', 'we are convinced', 'recommends', 'overrated',
  'underrated', 'best approach', 'worst approach',
];
const OBSERVATION_CUES = [
  'observed', 'measured that', 'recorded', 'survey found', 'survey of',
  'samples showed', 'data show', 'data shows', 'study found', 'reported that',
];
const NEGATION_CUES = [
  'not ', 'no ', 'never', 'cannot', 'can not', 'does not', 'do not',
  'did not', 'is not', 'are not', 'was not', 'were not', 'has not',
  'have not', 'without', 'fails to', 'failed to', 'neither', 'nor ',
];
const POSSIBILITY_CUES = ['may', 'might', 'could', 'possibly', 'perhaps'];
const NECESSITY_CUES = ['must', 'required to', 'is required', 'obligated'];
const CONDITIONAL_CUES = ['if ', 'unless', 'provided that', 'in case of'];

const UNITS = [
  [/%|percent|per cent\b/i, '%'],
  [/\bpercentage points?\b/i, 'percentage points'],
  [/\bbasis points?\b/i, 'basis points'],
  [/\bUSD\b|\bdollars?\b/i, 'USD'],
  [/\bEUR\b|\beuros?\b/i, 'EUR'],
  [/\bkg\b|\bkilograms?\b/i, 'kg'],
  [/\bkWh\b|\bkilowatt hours?\b/i, 'kWh'],
  [/\bgigawatts?\b|\bGW\b/i, 'GW'],
  [/\bterawatt hours?\b|\bTWh\b/i, 'TWh'],
  [/\bcubic meters?\b/i, 'cubic meters'],
  [/\bmillimeters?\b/i, 'millimeters'],
  [/\btonnes?\b|\bmetric tons?\b/i, 'tonnes'],
  [/\bkm\b|\bkilometers?\b|\bkilometres?\b/i, 'km'],
  [/\bmiles?\b/i, 'miles'],
  [/\bmeters?\b|\bmetres?\b/i, 'meters'],
  [/\bdegrees Celsius\b|°C/i, '°C'],
  [/\bhours?\b/i, 'hours'],
  [/\bdays?\b/i, 'days'],
  [/\bmonths?\b/i, 'months'],
  [/\byears?\b/i, 'years'],
  [/\bpeople\b|\bpersons?\b/i, 'people'],
  [/\bpatients?\b/i, 'patients'],
  [/\brespondents?\b/i, 'respondents'],
  [/\bstudents?\b/i, 'students'],
  [/\bhouseholds?\b/i, 'households'],
  [/\bcompanies?\b|\bfirms?\b/i, 'companies'],
  [/\bjobs?\b/i, 'jobs'],
  [/\bcases\b/i, 'cases'],
  [/\bdeaths?\b/i, 'deaths'],
];

const POPULATION_PATTERNS = [
  /\badults\b(?:\s+(?:aged|over|under|between)[^,.;]*)?/i,
  /\bchildren(?:\s+under\s+\d+)?/i,
  /\bpatients?\b(?:\s+(?:with|over|under|aged)[^,.;]*)?/i,
  /\brespondents?\b/i,
  /\bstudents?\b/i,
  /\bhouseholds?\b/i,
  /\bwomen(?:\s+over\s+\d+)?/i,
  /\bmen(?:\s+over\s+\d+)?/i,
  /\bemployees?\b/i,
  /\bfirms\b/i,
  /\bhouseholds\b/i,
  /\bcapital\b/i,
];

function matchFirst(text, cues) {
  const lower = ` ${text.toLowerCase()} `;
  for (const cue of cues) {
    const idx = lower.indexOf(cue.startsWith(' ') ? cue : ` ${cue}`);
    if (idx >= 0) {
      return { cue, index: idx };
    }
  }
  return null;
}

// The denominator region ("per 1000 people", "of the 500 patients") must not
// leak its numbers or group words into the claim's value, unit or population.
function maskDenominators(text) {
  return text
    .replace(/\b(?:per|out of|of)\s+(?:the\s+)?[\d,]+\s+\w+/gi, ' ')
    .replace(/\bper\s+(?!cent\b)(?!the\b)(?:the\s+)?[a-z]\w*(?:\s+[\d,]+\s+\w+)?/gi, ' ')
    .replace(/\bof\s+((?:the\s+)?[A-Za-z][\w-]*(?:\s+[\w-]+){0,3}?)(?:,|\s+in\s+|\s+during\s+|\s+between\s+|\s+according\s+|$)/gi, ' ');
}

// Years are period markers, never claim values: "grew 4% from 2020 to 2024"
// must not produce value_range {2020,2024}.
function maskYears(text) {
  return text.replace(/\b(?:19|20)\d{2}\b/g, ' ');
}

function extractUnit(text) {
  const masked = maskDenominators(text);
  for (const [pattern, canonical] of UNITS) {
    if (pattern.test(masked)) return canonical;
  }
  return null;
}

function extractNumbers(text) {
  const masked = maskYears(maskDenominators(text));
  const numbers = [];
  const re = /(\d+(?:[.,]\d+)?)/g;
  let m;
  while ((m = re.exec(masked)) !== null) {
    numbers.push(Number.parseFloat(m[1].replace(',', '.')));
  }
  return numbers;
}

function extractValueRange(text) {
  const masked = maskYears(maskDenominators(text));
  // "between 3 and 5", "3 to 5", "3-5", "1.5–2.5 percent"
  let m = masked.match(/\bbetween\s+(\d+(?:[.,]\d+)?)\s+and\s+(\d+(?:[.,]\d+)?)/i);
  if (m) return { min: num(m[1]), max: num(m[2]) };
  m = masked.match(/(\d+(?:[.,]\d+)?)\s*(?:-|–|—|to)\s*(\d+(?:[.,]\d+)?)/i);
  if (m) return { min: num(m[1]), max: num(m[2]) };
  const single = masked.match(/(\d+(?:[.,]\d+)?)/);
  if (single) {
    const v = num(single[1]);
    return { min: v, max: v };
  }
  return null;
}

function num(s) {
  return Number.parseFloat(String(s).replace(',', '.'));
}

function extractDenominator(text) {
  let m = text.match(/\bper\s+([\d,]+)\s+(\w+)/i);
  if (m) return `per ${m[1]} ${m[2]}`;
  m = text.match(/\bout of\s+([\d,]+)\s+(\w+)/i);
  if (m) return `out of ${m[1]} ${m[2]}`;
  m = text.match(/\bof\s+(?:the\s+)?([\d,]+)\s+(\w+)/i);
  if (m) return `of ${m[1]} ${m[2]}`;
  // unit-rate denominator without digits: "42 meteors per hour"
  m = text.match(/\bper\s+(?!cent\b|the\b)([a-z]\w*)\b/i);
  if (m) return `per ${m[1].trim()}`;
  // percentage share of a base: "22% of EU electricity" -> "of EU electricity"
  if (/%|percent|per cent/i.test(text)) {
    m = text.match(/\bof\s+((?:the\s+)?[A-Za-z][\w-]*(?:\s+[\w-]+){0,3}?)\s*(?:,|\s+in\s+|\s+during\s+|\s+between\s+|\s+according\s+|$)/);
    if (m) return `of ${m[1].trim()}`;
  }
  return null;
}

function extractExclusions(text) {
  const exclusions = [];
  const re = /\b(?:except|excluding|but not in|other than)\s+([^,.;]+)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    exclusions.push(m[1].trim().replace(/\s+/g, ' '));
  }
  return exclusions;
}

function extractPopulation(text) {
  const masked = maskDenominators(text);
  for (const pattern of POPULATION_PATTERNS) {
    const m = masked.match(pattern);
    if (m) return m[0].trim().replace(/\s+/g, ' ');
  }
  return null;
}

const GEOGRAPHIES = [
  'Germany', 'France', 'Spain', 'Italy', 'Poland', 'Europe', 'the European Union',
  'the EU', 'EU', 'the United States', 'the US', 'USA', 'China', 'India', 'Japan',
  'Brazil', 'Africa', 'Asia', 'Latin America', 'the Nordic countries', 'Sweden',
  'Norway', 'Denmark', 'Finland', 'the Netherlands', 'Austria', 'Switzerland',
  'the United Kingdom', 'the UK', 'Canada', 'Australia', 'global',
];

function extractGeography(text) {
  const m = text.match(/\b(?:in|across|throughout|within)\s+((?:the\s+)?[A-Z][A-Za-z]*(?:\s+[A-Z][A-Za-z]*)*)/);
  if (m) {
    const candidate = m[1];
    for (const geo of GEOGRAPHIES) {
      if (candidate === geo || candidate.endsWith(geo)) return geo;
    }
    return candidate;
  }
  for (const geo of GEOGRAPHIES) {
    if (new RegExp(`\\b${geo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(text)) return geo;
  }
  return null;
}

function extractPeriod(text) {
  // absolute years only; relative periods become qualifiers, never guesses
  let m = text.match(/\bbetween\s+(\d{4})\s+and\s+(\d{4})\b/i);
  if (m) return { start: `${m[1]}-01-01T00:00:00.000Z`, end: `${m[2]}-12-31T23:59:59.999Z` };
  m = text.match(/\bfrom\s+(\d{4})\s+to\s+(\d{4})\b/i);
  if (m) return { start: `${m[1]}-01-01T00:00:00.000Z`, end: `${m[2]}-12-31T23:59:59.999Z` };
  m = text.match(/\b(?:started|began) in (\d{4}) and (?:finished|ended) in (\d{4})\b/i);
  if (m) return { start: `${m[1]}-01-01T00:00:00.000Z`, end: `${m[2]}-12-31T23:59:59.999Z` };
  m = text.match(/\bin\s+(\d{4})\b/i);
  if (m) return { start: `${m[1]}-01-01T00:00:00.000Z`, end: `${m[1]}-12-31T23:59:59.999Z` };
  m = text.match(/\bby\s+(\d{4})\b/i);
  if (m) return { start: null, end: `${m[1]}-12-31T23:59:59.999Z` };
  m = text.match(/\bsince\s+(\d{4})\b/i);
  if (m) return { start: `${m[1]}-01-01T00:00:00.000Z`, end: null };
  return null;
}

function extractForecastHorizon(text) {
  const m = text.match(/\bby\s+(early\s+)?(\d{4})\b/i) ?? text.match(/\bin\s+(\d{4})\b/i);
  return m ? m[2] ?? m[0] : null;
}

function classifyEpistemicType(sentence) {
  if (matchFirst(sentence, FORECAST_CUES)) return 'FORECAST';
  if (matchFirst(sentence, HYPOTHESIS_CUES)) return 'HYPOTHESIS';
  if (matchFirst(sentence, ANALOGY_CUES)) return 'ANALOGY';
  if (matchFirst(sentence, MECHANISM_CUES)) return 'MECHANISM_CLAIM';
  if (matchFirst(sentence, OPINION_CUES)) return 'EXPERT_OPINION';
  if (matchFirst(sentence, OBSERVATION_CUES)) return 'OBSERVATION';
  return 'FACT_CLAIM';
}

function detectPolarity(sentence) {
  return matchFirst(sentence, NEGATION_CUES) ? 'negated' : 'affirmative';
}

function detectModality(sentence) {
  if (matchFirst(sentence, CONDITIONAL_CUES)) return 'conditional';
  if (matchFirst(sentence, NECESSITY_CUES)) return 'necessity';
  if (matchFirst(sentence, POSSIBILITY_CUES)) return 'possibility';
  return 'indicative';
}

// Subject/predicate/object triple: deterministic splitting conventions,
// documented in docs/claims/S2-004-CLAIM-GRAPH-CONTRACT.md. The corpus oracle
// annotations follow the same conventions, so field accuracy is measurable.
const VERB_CUES = [
  ' is ', ' are ', ' was ', ' were ', ' has ', ' have ', ' had ',
  ' reports ', ' reported ', ' shows ', ' showed ', ' generated ', ' generates ',
  ' produce ', ' produces ', ' produced ', ' emit ', ' emits ', ' emitted ',
  ' consume ', ' consumes ', ' consumed ', ' increased ', ' decreased ',
  ' grew ', ' fell ', ' rose ', ' declined ', ' reached ', ' accounts for ',
  ' equals ', ' costs ', ' represents ', ' will ', ' believes ',
  ' argues ', ' predicts ', ' forecasts ', ' forecast ', ' found ', ' measured ',
  ' observed ', ' recorded ', ' causes ', ' leads to ', ' results in ',
  ' behaves ', ' acts ', ' expects ', ' expect ', ' might be ', ' may be ', ' could be ',
  ' does not expect ', ' does not ', ' caused by ', ' covers ', ' surveyed ', ' accounts ',
  ' supports ', ' support ', ' opposes ', ' contradicts ', ' confirms ', ' denies ',
  ' rejects ', ' suggests ', ' indicates ', ' concludes ',
  ' spans ', ' argue ', ' argues ', ' froze ', ' counted ', ' measures ',
  ' claims ', ' says ', ' recommends ', ' hypothesize ', ' doubled ',
  ' holds ', ' stands at ', ' totaled ', ' missed ', ' ranged ',
  ' varied ', ' moved ', ' responded ', ' started ', ' decline ', ' enrolled ',
  ' equaled ', ' handled ', ' fetched ', ' needs ',
];

// measurement-basis qualifiers: "measured in nominal USD terms", "in real terms"
const MEASUREMENT_QUALIFIER = /\b(?:measured )?in ((?:nominal|real)[^,.;]*? terms)\b/i;

const ABBREVIATIONS = new Set([
  'dr', 'mr', 'mrs', 'ms', 'prof', 'sr', 'jr', 'st', 'vs', 'etc', 'e.g', 'i.e',
  'ltd', 'inc', 'co', 'no', 'approx', 'cf', 'al', 'fig', 'jan', 'feb', 'mar',
  'apr', 'jun', 'jul', 'aug', 'sep', 'sept', 'oct', 'nov', 'dec',
]);

// earliest-position verb cue (list order must not decide the split point).
// `text` must already be space-padded by the caller; no re-padding here —
// indices are used to slice the padded string.
function earliestCue(text, cues) {
  const lower = text.toLowerCase();
  let best = null;
  for (const cue of cues) {
    const idx = lower.indexOf(` ${cue.trim()} `);
    if (idx >= 0 && (best === null || idx < best.index || (idx === best.index && cue.length > best.cue.length))) {
      best = { cue: cue.trim(), index: idx };
    }
  }
  return best;
}

function splitTriple(sentence) {
  const padded = ` ${sentence.trim()} `;
  const cueMatch = earliestCue(padded, VERB_CUES);
  if (!cueMatch || cueMatch.index <= 0) {
    return null; // no verb cue -> ambiguous -> abstention
  }
  const cue = ` ${cueMatch.cue} `;
  const subject = padded.slice(0, cueMatch.index).trim().replace(/^the\s+/i, '');
  const rest = padded.slice(cueMatch.index + 1).trim();
  const verbTokens = cue.trim().split(' ').length;
  const restTokens = rest.split(/\s+/);
  const predicate = restTokens.slice(0, verbTokens).join(' ');
  const object = restTokens.slice(verbTokens).join(' ').replace(/[.,;]$/, '');
  return {
    subject: subject || 'unspecified',
    predicate: predicate || cue.trim(),
    object: object || 'unspecified',
  };
}

function splitSentences(text) {
  const sentences = [];
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if ((ch === '.' || ch === '!' || ch === '?') && (i + 1 === text.length || text[i + 1] === ' ' || text[i + 1] === '\n')) {
      // don't split decimals ("3.5") or known abbreviations ("Dr.", "e.g.")
      if (ch === '.') {
        if (/\d/.test(text[i - 1] ?? '') && /\d/.test(text[i + 2] ?? '')) continue;
        const token = text.slice(Math.max(0, text.lastIndexOf(' ', i - 1) + 1), i).toLowerCase();
        if (ABBREVIATIONS.has(token) || /^[a-z]$/.test(token)) continue;
      }
      const end = i + 1;
      const raw = text.slice(start, end);
      if (raw.trim().length > 0) sentences.push({ start, end, text: raw });
      start = end;
      while (start < text.length && /[\s]/.test(text[start])) start += 1;
      i = start - 1;
    }
  }
  if (start < text.length && text.slice(start).trim().length > 0) {
    sentences.push({ start, end: text.length, text: text.slice(start) });
  }
  return sentences;
}

export function extractPropositionsFromSentence(sentenceText) {
  const trimmed = sentenceText.trim().replace(/\s+/g, ' ');
  const qualifiers = [];
  const assumptions = [];
  const exclusions = extractExclusions(trimmed);

  // unresolved anaphora: a claim must be self-contained
  if (/^(This|It|They|He|She|We|Those|These)\b/.test(trimmed)) {
    return { abstention: 'ambiguous', reason: 'unresolved anaphora' };
  }
  if (/\bdepending on\b/i.test(trimmed)) {
    return { abstention: 'ambiguous', reason: 'conditional on unspecified factors' };
  }
  if (qualifiers.length > 2 || exclusions.length > 2) {
    return { abstention: 'ambiguous', reason: 'too many qualifier clauses' };
  }

  const triple = splitTriple(trimmed);
  if (!triple) {
    return { abstention: 'ambiguous', reason: 'no proposition structure' };
  }

  const epistemicType = classifyEpistemicType(trimmed);
  const polarity = detectPolarity(trimmed);
  const modality = detectModality(trimmed);
  const units = extractUnit(trimmed);
  const valueRange = extractValueRange(trimmed);
  const denominator = extractDenominator(trimmed);
  const population = extractPopulation(trimmed);
  const geography = extractGeography(trimmed);
  const period = extractPeriod(trimmed);
  const hasNumbers = extractNumbers(trimmed).length > 0;

  if (units) qualifiers.push(`unit:${units}`);
  if (denominator) qualifiers.push(`denominator:${denominator}`);
  if (exclusions.length > 0) qualifiers.push(`exclusions:${exclusions.length}`);
  if (modality !== 'indicative') qualifiers.push(`modality:${modality}`);
  const measurement = trimmed.match(MEASUREMENT_QUALIFIER);
  if (measurement) qualifiers.push(`measurement:${measurement[1].trim()}`);

  // a numeric claim without units when the sentence carries a unit word that
  // our table missed would be a silent loss — quarantine for review instead
  if (hasNumbers && !units && /\d\s*(%|kg|km|miles|USD|EUR|hours|days|years)/i.test(trimmed)) {
    return { abstention: 'ambiguous', reason: 'unrecognized unit on numeric value' };
  }

  const uncertainty = epistemicType === 'HYPOTHESIS'
    ? { type: 'epistemic', description: 'hypothesis, not established fact' }
    : valueRange && valueRange.min !== valueRange.max
      ? { type: 'aleatory', description: 'range reported by the source' }
      : undefined;

  // forecast hygiene: a forecast without any horizon is quarantined, and the
  // horizon must come from the text, never from the import clock (probe C)
  let quarantine = null;
  let effectivePeriod = period;
  if (epistemicType === 'FORECAST') {
    const horizon = extractForecastHorizon(trimmed);
    if (!horizon) {
      quarantine = 'forecast without explicit horizon';
      qualifiers.push('missing_forecast_horizon');
    } else if (!effectivePeriod) {
      effectivePeriod = { start: null, end: `${horizon}-12-31T23:59:59.999Z` };
    }
  }

  const proposition = {
    epistemicType,
    polarity,
    modality,
    normalizedText: trimmed,
    originalText: trimmed,
    ...triple,
    qualifiers,
    assumptions,
    exclusions,
    units,
    denominator,
    valueRange,
    population,
    geography,
    period: effectivePeriod,
    uncertainty,
  };
  if (quarantine) return { proposition, quarantine };
  return { proposition };
}

export function extractFromSegment(segment, snapshot) {
  if (!segment.text || segment.status !== 'COMPLETE') {
    return {
      abstentions: [{ segment_id: segment.segment_id, reason: 'insufficient_context' }],
      propositions: [],
    };
  }
  const classification = segment.embedded_instruction_classification ?? { present: false };
  if (classification.present && classification.classification !== 'none') {
    // data stays inert: embedded instructions never assign types or authority
    return {
      abstentions: [{ segment_id: segment.segment_id, reason: 'policy_blocked' }],
      propositions: [],
    };
  }

  const propositions = [];
  const abstentions = [];
  for (const sentence of splitSentences(segment.text)) {
    const result = extractPropositionsFromSentence(sentence.text);
    if (result.abstention) {
      abstentions.push({ segment_id: segment.segment_id, reason: result.abstention === 'ambiguous' ? 'ambiguous' : 'insufficient_context', span: { start: sentence.start, end: sentence.end }, detail: result.reason });
      continue;
    }
    const propStartInSentence = sentence.text.indexOf(sentence.text.trim());
    propositions.push({
      ...result.proposition,
      span: {
        start: sentence.start + (propStartInSentence >= 0 ? propStartInSentence : 0),
        end: sentence.end,
      },
      quarantine: result.quarantine ?? null,
    });
  }
  return { propositions, abstentions };
}

// ---- pure extraction over a request ----------------------------------------

export function runClaimExtraction(request, context) {
  const abstentions = [];
  const malformedOutput = [];
  const proposedClaims = [];

  if (request.segment_ids.length !== request.segment_hashes.length) {
    malformedOutput.push({
      raw_output: canonicalJson({ segment_ids: request.segment_ids.length, segment_hashes: request.segment_hashes.length }),
      parse_error: 'SEGMENT_HASH_LENGTH_MISMATCH',
    });
    return {
      contractVersion: '1.0.0',
      request_id: request.request_id,
      proposed_claims: [],
      abstentions: [],
      malformed_output: malformedOutput,
      audit_binding: context.auditBinding,
      status: 'FAILED',
      completed_at: context.now(),
    };
  }

  for (let i = 0; i < request.segment_ids.length; i += 1) {
    const segmentId = request.segment_ids[i];
    const expectedHash = request.segment_hashes[i];
    const segment = context.resolveSegment(segmentId);
    if (!segment) {
      abstentions.push({ segment_id: segmentId, reason: 'insufficient_context' });
      continue;
    }
    // untrusted input: exact hash binding before any extraction
    if (segment.text_sha256 !== expectedHash) {
      malformedOutput.push({
        raw_output: `segment ${segmentId} digest mismatch`,
        parse_error: 'SEGMENT_HASH_MISMATCH',
      });
      continue;
    }
    const snapshot = context.resolveSnapshot(segment.snapshot_id);
    const { propositions, abstentions: segmentAbstentions } = extractFromSegment(segment, snapshot);
    abstentions.push(...segmentAbstentions.map(({ span, detail, ...rest }) => rest));

    for (const prop of propositions) {
      const evidenceDigest = spanDigest(segment.text, prop.span.start, prop.span.end);
      const claim = {
        contractVersion: '1.0.0',
        claim_id: null,
        revision: 1,
        workspace_id: request.workspace_id,
        tenant_id: segment.acl?.tenant_id ?? 'tn-default',
        acl: segment.acl ?? {
          visibility: 'project',
          workspace_id: request.workspace_id,
          tenant_id: 'tn-default',
          allowed_workspace_ids: [],
          allowed_principal_ids: [],
        },
        epistemic_type: prop.epistemicType,
        polarity: prop.polarity,
        modality: prop.modality,
        normalized_text: prop.normalizedText,
        original_text: prop.originalText,
        subject: prop.subject,
        predicate: prop.predicate,
        object: prop.object,
        qualifiers: prop.qualifiers,
        uncertainty: prop.uncertainty ?? undefined,
        method: {
          name: request.extractor,
          version: request.extractor_version,
          config_digest: undefined,
        },
        assumptions: prop.assumptions,
        exclusions: prop.exclusions,
        units: prop.units,
        denominator: prop.denominator ?? null,
        value_range: prop.valueRange,
        population: prop.population,
        geography: prop.geography,
        period: prop.period,
        // four distinct times, all from the snapshot (todo §4.6)
        event_time: snapshot?.event_time ?? null,
        published_at: snapshot?.published_at ?? null,
        observed_at: snapshot?.observed_at,
        fetched_at: snapshot?.fetched_at,
        language: segment.normalized_language ?? segment.original_language ?? 'en',
        translation_status: 'original',
        lifecycle: prop.quarantine ? 'QUARANTINED' : 'PROPOSED',
      };
      claim.method.config_digest = request.seed ?? sha256Hex({ prompt_version: request.prompt_version, parameters: request.parameters });
      proposedClaims.push({
        claim,
        source_span: { segment_id: segment.segment_id, start: prop.span.start, end: prop.span.end },
        segment_revision: segment.revision ?? 1,
        evidence_digest: evidenceDigest,
        quarantine_reason: prop.quarantine,
      });
    }
  }

  const status = malformedOutput.length > 0
    ? 'FAILED'
    : proposedClaims.length === 0 && abstentions.length > 0
      ? 'QUARANTINED'
      : 'COMPLETED';

  return {
    contractVersion: '1.0.0',
    request_id: request.request_id,
    proposed_claims: proposedClaims,
    abstentions,
    malformed_output: malformedOutput,
    audit_binding: context.auditBinding,
    status,
    completed_at: context.now(),
  };
}

// ---- atomic execution: claim + evidence edge + audit, or nothing ------------

export async function executeClaimExtraction(request, context) {
  const result = runClaimExtraction(request, context);
  // FAILED and QUARANTINED results propose nothing: there is no partial state
  // to commit, so no operation is recorded and nothing reaches the graph
  if (result.status === 'FAILED' || result.status === 'QUARANTINED') {
    return { claims: [], edges: [], result };
  }
  const outcome = await context.store.commitExtraction({
    request,
    result,
    actor: request.actor,
    operationId: context.auditBinding.operation_id,
    idempotencyKey: request.idempotency_key,
  });
  return { claims: outcome.claims, edges: outcome.edges, result: outcome.result };
}
