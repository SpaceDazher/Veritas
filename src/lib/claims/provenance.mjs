// S2-004 source independence and upstream collapse (todo §6).
//
// Ten reprints of one upstream piece are ONE evidence family. Citations,
// translations, syndication and common-dataset lineage never count as
// independent confirmation. Unknown origin stays UNKNOWN_LINEAGE and is never
// counted as independent. Automatic near-duplicate merging is forbidden while
// S2-003 marks it NOT_CALIBRATED — the engine may only propose a candidate
// relation for review. Raw counts, collapsed counts, unknown-lineage counts
// and the collapse rule set are published next to every aggregate.
export const LINEAGE_TYPES = Object.freeze([
  'original',
  'citation',
  'translation',
  'syndication',
  'dataset_mirror',
  'unknown',
]);

// Lineage types that never add independent support, no matter how many
// distinct sources carry them.
export const NON_INDEPENDENT_LINEAGE = Object.freeze([
  'citation',
  'translation',
  'syndication',
  'dataset_mirror',
]);

export function isUnknownLineage(lineageType) {
  return lineageType === undefined || lineageType === null || lineageType === 'unknown';
}

export function collapseSourceFamilies(edges, { snapshotResolver }) {
  if (!snapshotResolver) throw new Error('collapseSourceFamilies requires a snapshotResolver');
  const families = new Map(); // root signature -> family
  const members = [];
  let unknownLineageCount = 0;

  for (const edge of edges) {
    const upstream = edge.upstream_snapshot_ids ?? [];
    const roots = new Set();
    let unknown = false;
    let nonIndependent = false;
    for (const snapshotId of upstream) {
      const chain = resolveUpstreamChain(snapshotId, snapshotResolver);
      if (chain.unknownLineage) unknown = true;
      if (chain.nonIndependent) nonIndependent = true;
      for (const root of chain.roots) roots.add(root);
    }
    if (unknown) unknownLineageCount += 1;

    // A family key exists only for known, original lineage. Citations,
    // translations, syndication and mirrors join the family of their root;
    // unknown lineage can never join or form a family.
    let familyId;
    if (unknown) {
      familyId = `fam-unknown-${edge.edge_id}`;
    } else if (nonIndependent && roots.size === 0) {
      familyId = `fam-unknown-${edge.edge_id}`;
    } else {
      const signature = [...roots].sort().join('|');
      familyId = `fam-${Buffer.from(signature).toString('hex').slice(0, 24)}`;
    }
    let family = families.get(familyId);
    if (!family) {
      family = { family_id: familyId, member_edge_ids: [], roots: [...roots].sort(), independent: !unknown && roots.size > 0 };
      families.set(familyId, family);
    }
    family.member_edge_ids.push(edge.edge_id);
    members.push({ edge_id: edge.edge_id, family_id: familyId, roots: [...roots].sort(), unknown_lineage: unknown, non_independent_lineage: nonIndependent });
  }

  const familyList = [...families.values()];
  return {
    raw_source_count: edges.length,
    collapsed_family_count: familyList.filter((f) => f.independent).length,
    unknown_lineage_count: unknownLineageCount,
    families: familyList,
    members,
    rule: 'upstream roots resolved through the snapshot lineage chain; citation/translation/syndication/dataset_mirror lineage collapses into its root family; unknown lineage never counts as independent; near-duplicates are candidates for review, never auto-merged',
  };
}

function resolveUpstreamChain(snapshotId, snapshotResolver, seen = new Set()) {
  const roots = new Set();
  let unknownLineage = false;
  let nonIndependent = false;
  const queue = [snapshotId];
  while (queue.length) {
    const id = queue.shift();
    if (seen.has(id)) continue;
    seen.add(id);
    const snapshot = snapshotResolver(id);
    if (!snapshot) {
      unknownLineage = true;
      roots.add(id);
      continue;
    }
    const lineageType = snapshot.lineage_type ?? 'unknown';
    if (lineageType === 'unknown') unknownLineage = true;
    if (NON_INDEPENDENT_LINEAGE.includes(lineageType)) nonIndependent = true;
    const parents = snapshot.parent_snapshot_ids ?? snapshot.parent_snapshot_id ? [snapshot.parent_snapshot_ids ?? snapshot.parent_snapshot_id].flat() : [];
    if (!parents || parents.length === 0) {
      if (lineageType === 'original') {
        roots.add(id);
      } else {
        // a non-original snapshot without a resolvable parent chain cannot
        // prove independence
        unknownLineage = true;
      }
      continue;
    }
    for (const parent of parents) queue.push(parent);
  }
  return { roots, unknownLineage, nonIndependent };
}

// Near-duplicate candidates: proposed for review only (todo §6, S2-003
// NOT_CALIBRATED carries over). Returns candidate claim-edge proposals with
// relation DUPLICATES_CANDIDATE; the caller must submit them through
// linkClaims for explicit review, they are never applied automatically.
export function proposeDuplicateCandidates(claims, options = {}) {
  const { digestIndex } = options;
  const candidates = [];
  const byNormalized = new Map();
  for (const claim of claims) {
    const key = digestIndex ? digestIndex(claim) : claim.normalized_text.toLowerCase().replace(/\s+/g, ' ');
    if (!byNormalized.has(key)) byNormalized.set(key, []);
    byNormalized.get(key).push(claim);
  }
  for (const group of byNormalized.values()) {
    if (group.length < 2) continue;
    const head = group[0];
    for (const other of group.slice(1)) {
      candidates.push({
        source_claim_id: head.claim_id,
        source_revision: head.revision,
        target_claim_id: other.claim_id,
        target_revision: other.revision,
        relation: 'DUPLICATES_CANDIDATE',
        direction: 'bidirectional',
        requires_review: true,
      });
    }
  }
  return candidates;
}
