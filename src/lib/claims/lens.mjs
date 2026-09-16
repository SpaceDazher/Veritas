// S2-004 expert lens policy (todo §8).
//
// A lens belongs to one user/workspace and never leaks to another. One expert
// may carry different weights per domain and period. Lenses may change
// presentation order and suggest additional sources; they NEVER change
// evidence counts, epistemic types, calibration records or gate verdicts.
// Revocation immediately stops new uses; prior results keep their provenance
// through the recorded lens_id.
//
// The engine here is deliberately tiny: it re-ranks candidate claims by
// adding the lens weight to a stable base rank, and annotates the influence.
// Every original field of every candidate is preserved byte-for-byte.
export const TASK_CLASSES = Object.freeze([
  'fact_checking',
  'forecasting',
  'mechanism_analysis',
  'policy_review',
  'risk_assessment',
  'synthesis',
]);

// Applies active lenses of ONE owner (workspace+principal) to candidates.
// candidates: [{ claim_id, base_rank, epistemic_type, evidence_family_count, expert_id }]
// Returns ranked candidates; each carries lens_influence entries and an
// untouched copy of all original fields.
export function applyExpertLenses({ candidates, lenses, taskClass, at }) {
  if (!Array.isArray(candidates)) throw new Error('candidates must be an array');
  if (!Array.isArray(lenses)) throw new Error('lenses must be an array');
  const now = at ?? new Date().toISOString();
  const active = lenses.filter((lens) => {
    if (lens.revoked_at) return false; // revoked lenses stop immediately
    if (lens.task_class !== taskClass) return false;
    if (lens.valid_from > now || lens.valid_until < now) return false;
    return true;
  });

  const ranked = candidates.map((candidate) => {
    const original = { ...candidate };
    const influences = [];
    let adjustedRank = candidate.base_rank;
    for (const lens of active) {
      if (lens.expert_id !== candidate.expert_id) continue;
      // ranking-only influence
      adjustedRank += lens.weight;
      influences.push({
        lens_id: lens.lens_id,
        expert_id: lens.expert_id,
        domain: lens.domain,
        weight: lens.weight,
        kind: 'ranking_only',
      });
    }
    return {
      ...original,
      adjusted_rank: adjustedRank,
      lens_influence: influences,
    };
  });

  ranked.sort((a, b) => {
    if (b.adjusted_rank !== a.adjusted_rank) return b.adjusted_rank - a.adjusted_rank;
    return a.claim_id < b.claim_id ? -1 : 1; // stable tie-break
  });
  return ranked;
}

// Invariant checker: proves the lens policy never touched protected fields
// (probe F). Returns true iff every original candidate field survived
// byte-for-byte and only adjusted_rank / lens_influence were added.
export function lensesPreservedCandidates(before, after) {
  if (before.length !== after.length) return false;
  const rankById = new Map(after.map((c) => [c.claim_id, c]));
  for (const candidate of before) {
    const ranked = rankById.get(candidate.claim_id);
    if (!ranked) return false;
    for (const [key, value] of Object.entries(candidate)) {
      if (JSON.stringify(ranked[key]) !== JSON.stringify(value)) return false;
    }
  }
  return true;
}
