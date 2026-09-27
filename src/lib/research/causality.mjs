// S2-008 research track — the A4 causal label guard (issue SpaceDazher/Veritas#8).
//
// Serves acceptance item A4: PROOF that an observational result cannot be read
// as causal. The negative control that proves it is a LABEL SUBSTITUTION: take
// a card whose ground truth is observational, set its causal claim, and the
// guard must FAIL. Evidence id `label_substitution`.
//
// WHY THIS IS CODE AND NOT SCHEMA
// contracts/hypothesis-card.schema.json has NO `allOf` and NO conditional
// `if/then`. It is `additionalProperties: false` and its
// `proposed_relation.causal_assertion` is a free
// `oneOf: [{type: boolean}, {type: null}]`. Its own `description` states the
// rule — "May only be true for MECHANISM_CLAIM with mediator and temporal
// ordering evidence; otherwise null" — but a JSON Schema cannot express it
// here: `temporal_ordering`, `mediators` and `type_promotion` are all
// OPTIONAL, and the schema is frozen and read-only for this track. The
// schemas are the wire shape; THIS MODULE is the rule. That split is
// deliberate and is recorded rather than hidden: an unexpressed rule that
// nobody implements is a fail-open, and this is the one that would turn a
// simulation into a causal proof.
//
// THE ENUMS ARE READ FROM THE COMPILED SCHEMA, NEVER RE-DECLARED
// `RESEARCH_CARD_TYPES` and `RESEARCH_RELATION_STRENGTHS` are read at import
// out of the compiled hypothesis-card contract (contracts.mjs), not written
// out again here. A second copy of an enum is a second, independently
// editable source of truth, and the schema is the frozen one.
//
// `OBSERVATIONAL_RELATION_STRENGTHS` is the subset of the compiled
// `relation_strength` enum that describes OBSERVED STRUCTURE ONLY, and every
// member of it is refused a causal assertion. The membership is derived from
// the schema's own description of the member ("Observed structure only:
// correlation/analogy never recorded as causal_strength") rather than from an
// opinion in this file, and W1 pins the exact membership in
// tests/research/causality.test.mjs against the compiled enum, so the set is
// a test-asserted fact and not a comment.
//
// WHAT `causal_assertion === true` REQUIRES (all of it, or BlockedPolicy):
//   * `card_type === 'MECHANISM_CLAIM'`.
//   * a non-null `type_promotion` to `MECHANISM_CLAIM` carrying a review
//     basis, whose `reviewed_by` is NOT the card's `created_by`: a producer
//     may never promote its own card (the S1-011 rule the schema records in
//     `type_promotion.description`).
//   * `temporal_ordering.established === true`.
//   * at least one mediator whose `evidence_status` is a FOUND status
//     (SUPPORTED; PROPOSED and NOT_FOUND do not count).
//
// WHAT IS REFUSED
//   * any observational `relation_strength` carrying a causal assertion ->
//     `BlockedPolicy('CAUSAL_ASSERTION_UNSUPPORTED')`.
//   * the track's own `inference_mode` is ASSOCIATIONAL and is published in
//     the preregistration. Nothing in this module ever produces a causal
//     conclusion from the deterministic transport; it only refuses one that was
//     claimed without the evidence.
//
// Owner: W1 (contracts & causality). Budget: part of W1's <= 700 lines.
// State: IMPLEMENTED. The exported signatures are the ones plan §1 froze and
// none was renamed. The enums below are READ from the compiled contract at
// import, never re-declared.
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { BlockedPolicy, MalformedResult } from '../agentboard/errors.mjs';
import { loadResearchContracts, assertResearchContract } from './contracts.mjs';

// The compiled contract, read once at import. `schema()` is a read-only view of
// the frozen bytes; the enum walk below therefore cannot drift from the schema
// without the import failing. The directory is resolved the way contracts.mjs
// resolves it, from this file's own location, so there is no configured path
// that could point the enum at a different schema than the validator uses.
const CARD = 'hypothesis-card';
const COMPILED = loadResearchContracts(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../contracts'),
);

function enumAt(path) {
  let node = COMPILED.schema(CARD);
  for (const key of path) {
    node = node?.[key];
    if (node === undefined) throw new Error(`RESEARCH_CARD_SHAPE_MOVED:${path.join('.')}`);
  }
  if (!Array.isArray(node?.enum)) throw new Error(`RESEARCH_CARD_ENUM_ABSENT:${path.join('.')}`);
  return Object.freeze([...node.enum]);
}

/** The card type the A4 guard requires for a causal assertion. @type {string} */
const CAUSAL_CARD_TYPE = 'MECHANISM_CLAIM';

/** The only `evidence_status` that counts as a found mediator. @type {string} */
const FOUND_MEDIATOR_STATUS = 'SUPPORTED';

const cardTypes = enumAt(['properties', 'card_type']);
const relationStrengths = enumAt(['properties', 'proposed_relation', 'properties', 'relation_strength']);

// The OBSERVATIONAL subset. The frozen schema puts every member of
// `relation_strength` in ONE property with ONE description, so the description
// states the RULE ("observed structure only: correlation/analogy never recorded
// as causal_strength") and the per-member membership is the frozen ORDER the
// judged plan states in prose. The order is written down here and PINNED by
// tests/research/causality.test.mjs against the compiled enum: a pin that fails
// is a schema change to be re-reviewed, not a set to be edited in place. The
// description itself is checked at import, so a schema edit that drops the
// sentence aborts the import instead of silently reclassifying a strength.
const OBSERVATIONAL_MARKER = 'observed structure only';
const OBSERVATIONAL_STRENGTH_ORDER = Object.freeze([
  'ANALOGICAL_STRUCTURE', 'TEMPORAL_CO-OCCURRENCE', 'CORRELATION_EVIDENCE',
]);
const strengthsWithDescription = COMPILED.schema(CARD)
  .properties.proposed_relation.properties.relation_strength;
if (!String(strengthsWithDescription.description ?? '').toLowerCase().includes(OBSERVATIONAL_MARKER)) {
  throw new Error('RESEARCH_CARD_OBSERVATIONAL_MARKER_MOVED:the relation_strength description no longer states which members are observed structure only');
}
for (const strength of OBSERVATIONAL_STRENGTH_ORDER) {
  if (!relationStrengths.includes(strength)) {
    throw new Error(`RESEARCH_CARD_ENUM_CHANGED:${strength} is no longer a member of relation_strength`);
  }
}
const observational = Object.freeze(relationStrengths.filter((strength) => OBSERVATIONAL_STRENGTH_ORDER.includes(strength)));

/**
 * The compiled `card_type` enum of contracts/hypothesis-card.schema.json, read
 * at import from the compiled contract. Never re-declared here.
 * @type {ReadonlyArray<string>}
 */
export const RESEARCH_CARD_TYPES = cardTypes;

/**
 * The compiled `proposed_relation.relation_strength` enum of
 * contracts/hypothesis-card.schema.json, read at import from the compiled
 * contract. Never re-declared here.
 * @type {ReadonlyArray<string>}
 */
export const RESEARCH_RELATION_STRENGTHS = relationStrengths;

/**
 * The observational subset of RESEARCH_RELATION_STRENGTHS: members that
 * describe observed structure only and can therefore never carry a causal
 * assertion. Derived from the compiled enum and pinned by
 * tests/research/causality.test.mjs, not hand-maintained.
 * @type {ReadonlyArray<string>}
 */
export const OBSERVATIONAL_RELATION_STRENGTHS = observational;

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function bounded(value) {
  return String(value ?? '').slice(0, 200);
}

/**
 * Classify a hypothesis card's claimed relation without deciding anything.
 * A pure, total, read-only projection used by the comparator, the expected
 * value table and the label-substitution control alike, so all three classify
 * a card the same way.
 *
 * @param {object} card A document that already satisfies
 *   contracts/hypothesis-card.schema.json.
 * @returns {{
 *   cardId: string, cardType: string, relationStrength: string,
 *   causalAssertion: boolean, observational: boolean, promotionTo: string|null,
 *   promotedByProducer: boolean, temporalOrderingEstablished: boolean,
 *   mediatorStatuses: ReadonlyArray<string>, admissible: boolean,
 *   refusalCode: string|null
 * }} The classification. `admissible: false` always carries a
 *   `refusalCode`; `admissible: true` always carries `refusalCode: null`.
 */
export function classifyCardRelation(card) {
  if (!isPlainObject(card)) {
    throw new MalformedResult('HYPOTHESIS_CARD_SHAPE_INVALID', `expected a card object, got ${typeof card}`);
  }
  const relation = isPlainObject(card.proposed_relation) ? card.proposed_relation : {};
  const relationStrength = typeof relation.relation_strength === 'string' ? relation.relation_strength : '';
  // The frozen schema allows `true | null`; `false` is a caller mistake and is
  // read as "no assertion" rather than as an admissible non-claim, so the
  // classification below can never report a causal assertion that is not one.
  const causalAssertion = relation.causal_assertion === true;
  const promotion = isPlainObject(card.type_promotion) ? card.type_promotion : null;
  const promotionTo = promotion !== null && typeof promotion.to_type === 'string' ? promotion.to_type : null;
  const promotedByProducer = promotion !== null
    && typeof promotion.reviewed_by === 'string'
    && typeof card.created_by === 'string'
    && promotion.reviewed_by === card.created_by;
  const temporalOrderingEstablished = isPlainObject(card.temporal_ordering)
    && card.temporal_ordering.established === true;
  const mediators = Array.isArray(card.mediators) ? card.mediators : [];
  const mediatorStatuses = Object.freeze(mediators.map((mediator) => (
    isPlainObject(mediator) && typeof mediator.evidence_status === 'string' ? mediator.evidence_status : 'ABSENT'
  )));

  let refusalCode = null;
  if (causalAssertion) {
    if (!relationStrength) refusalCode = 'CAUSAL_ASSERTION_UNSUPPORTED:no_relation_strength';
    else if (observational.includes(relationStrength)) refusalCode = `CAUSAL_ASSERTION_UNSUPPORTED:${relationStrength}`;
    else if (card.card_type !== CAUSAL_CARD_TYPE) refusalCode = 'CAUSAL_PROMOTION_MISSING';
    else if (promotion === null || promotionTo !== CAUSAL_CARD_TYPE || typeof promotion.basis !== 'string' || promotion.basis.trim() === '') {
      refusalCode = 'CAUSAL_PROMOTION_MISSING';
    } else if (promotedByProducer) refusalCode = 'CAUSAL_PROMOTION_SELF_REVIEWED';
    else if (!temporalOrderingEstablished) refusalCode = 'CAUSAL_TEMPORAL_ORDER_UNESTABLISHED';
    else if (!mediatorStatuses.includes(FOUND_MEDIATOR_STATUS)) refusalCode = 'CAUSAL_MEDIATOR_NOT_FOUND';
  }
  return Object.freeze({
    cardId: typeof card.card_id === 'string' ? card.card_id : '',
    cardType: typeof card.card_type === 'string' ? card.card_type : '',
    relationStrength,
    causalAssertion,
    observational: observational.includes(relationStrength),
    promotionTo,
    promotedByProducer,
    temporalOrderingEstablished,
    mediatorStatuses,
    admissible: refusalCode === null,
    refusalCode,
  });
}

/**
 * Assert the full causal discipline of a card: every requirement listed in the
 * file header must hold, or the call throws. This is the A4 guard.
 *
 * @param {object} card A document that already satisfies
 *   contracts/hypothesis-card.schema.json.
 * @returns {object} The same card, unchanged, when the discipline holds.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'CAUSAL_ASSERTION_UNSUPPORTED' when an observational relation_strength
 *   carries a causal assertion; 'CAUSAL_PROMOTION_MISSING',
 *   'CAUSAL_PROMOTION_SELF_REVIEWED', 'CAUSAL_TEMPORAL_ORDER_UNESTABLISHED'
 *   or 'CAUSAL_MEDIATOR_NOT_FOUND' for the specific missing requirement.
 * @throws {import('../agentboard/errors.mjs').MalformedResult} when the card
 *   does not satisfy its frozen contract (via assertResearchContract).
 */
export function assertCausalDiscipline(card) {
  const valid = assertResearchContract(CARD, card, MalformedResult);
  const classification = classifyCardRelation(valid);
  if (classification.refusalCode !== null) {
    const [code, detail] = classification.refusalCode.split(':');
    throw new BlockedPolicy(code, `${detail === undefined ? classification.refusalCode : `${code}: ${bounded(detail)}`} on card ${bounded(classification.cardId)} (relation_strength=${bounded(classification.relationStrength || 'absent')})`);
  }
  return valid;
}

/**
 * The narrower, always-on refusal: no simulation may ever be read as causal
 * proof. Called on every card the track produces, not only on the ones that
 * claim a causal assertion, so the transport's own limit is checked rather
 * than assumed.
 *
 * @param {object} card A document that already satisfies
 *   contracts/hypothesis-card.schema.json.
 * @returns {object} The same card, unchanged, when no causal claim is present
 *   or when the claim carries its full evidence.
 * @throws {import('../agentboard/errors.mjs').BlockedPolicy}
 *   'CAUSAL_ASSERTION_UNSUPPORTED' with the offending `relation_strength`
 *   named in the detail.
 */
export function assertNoCausalFromSimulation(card) {
  const valid = assertResearchContract(CARD, card, MalformedResult);
  const classification = classifyCardRelation(valid);
  if (classification.observational && classification.causalAssertion) {
    throw new BlockedPolicy(
      'CAUSAL_ASSERTION_UNSUPPORTED',
      `relation_strength ${bounded(classification.relationStrength)} is observed structure only and can never carry a causal assertion (card ${bounded(classification.cardId)})`,
    );
  }
  return valid;
}
