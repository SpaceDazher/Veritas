// S2-004 corpus run executor.
// Executes the frozen 96-case corpus through the production claim graph path
// (src/lib/claims — the exact modules the tests and the probes use). Before
// executing anything, the frozen manifest is verified fail-closed: any drift
// in case digests stops the run as QUARANTINED (todo §10, probe L / §11).
//
// Usage:
//   node scripts/s2-004-run.mjs --run-id run-a --executor-id exec-a \
//        --nonce n-abc12345 --clock 2026-01-15T08:00:00.000Z \
//        --output-root results/s2-004/run-a --out evidence/s2-004-run-a.json
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createClaimGraphStore, makeAuthorityRegistry, mostRestrictiveAcl } from '../src/lib/claims/store.mjs';
import { executeClaimExtraction, extractPropositionsFromSentence } from '../src/lib/claims/extraction.mjs';
import { collapseSourceFamilies, proposeDuplicateCandidates } from '../src/lib/claims/provenance.mjs';
import { compareClaims } from '../src/lib/claims/contradiction.mjs';
import { applyExpertLenses, lensesPreservedCandidates } from '../src/lib/claims/lens.mjs';
import { canonicalDigestOfClaim, claimValidators } from '../src/lib/claims/validation.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CASES_DIR = path.join(ROOT, 'corpus/s2-004/cases');
const MANIFEST_PATH = path.join(ROOT, 'corpus/s2-004/manifest.json');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export const DEFAULT_CLOCK = '2026-01-15T08:00:00.000Z';

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key.startsWith('--')) args[key.slice(2)] = argv[i + 1];
  }
  return args;
}

// ---- frozen manifest verification (fail-closed) ------------------------------

export function verifyFrozenManifest({ manifest, casesDir }) {
  const issues = [];
  if (manifest.schemaVersion !== 1) issues.push('manifest:schema-version-unknown');
  if (manifest.caseCount !== 96) issues.push('manifest:case-count-not-96');
  const required = {
    atomic_extraction: 24,
    opinion_hypothesis_forecast: 16,
    numeric_unit_qualifier_time: 16,
    translation_citation_upstream_lineage: 12,
    contradiction_scope: 12,
    expert_lens_isolation: 8,
    invalidation_revision_retraction: 8,
  };
  for (const [category, count] of Object.entries(required)) {
    if ((manifest.categoryCounts?.[category] ?? 0) !== count) issues.push(`manifest:${category}:count-drift`);
  }
  for (const [caseId, digest] of Object.entries(manifest.caseSha256 ?? {})) {
    const file = path.join(casesDir, `${caseId}.json`);
    let bytes;
    try {
      bytes = fs.readFileSync(file);
    } catch {
      issues.push(`${caseId}:missing`);
      continue;
    }
    if (sha256(bytes) !== digest) issues.push(`${caseId}:digest-drift`);
  }
  // a case on disk that is not in the manifest is equally frozen corruption
  for (const file of fs.readdirSync(casesDir)) {
    if (file.endsWith('.json') && !manifest.caseSha256?.[file.replace(/\.json$/, '')]) {
      issues.push(`${file}:unmanifested`);
    }
  }
  return { ok: issues.length === 0, issues };
}

// ---- per-category case execution ---------------------------------------------

function authorityRegistry() {
  return makeAuthorityRegistry([
    { principal: 'prn-producer', roles: ['producer'], workspaces: ['ws-corpus'] },
    { principal: 'prn-extractor', roles: ['extractor'], workspaces: ['ws-corpus'] },
    { principal: 'prn-reviewer', roles: ['reviewer'], workspaces: ['ws-corpus'] },
    { principal: 'prn-admin', roles: ['admin'], workspaces: ['ws-corpus', 'ws-system'] },
    { principal: 'prn-evaluator', roles: ['evaluator'] },
    { principal: 'prn-system', roles: ['system'], workspaces: ['ws-system'] },
    { principal: 'prn-user-1', roles: [], workspaces: ['ws-corpus'] },
    { principal: 'prn-user-2', roles: [], workspaces: ['ws-corpus'] },
  ]);
}

function buildStore({ segments, snapshots, clock, authorities }) {
  const segmentMap = new Map(segments.map((s) => [`${s.segment_id}@${s.revision ?? 1}`, s]));
  const snapshotMap = new Map(snapshots.map((s) => [s.snapshot_id, s]));
  return createClaimGraphStore({
    authorities,
    clock,
    segmentResolver: (id, rev) => segmentMap.get(`${id}@${rev ?? 1}`) ?? null,
    snapshotResolver: (id) => snapshotMap.get(id) ?? null,
  });
}

function toRuntimeSegment(inputSegment) {
  return {
    segment_id: inputSegment.segment_id,
    snapshot_id: inputSegment.snapshot.snapshot_id,
    source_id: 'src-corpus',
    revision: 1,
    text: inputSegment.text,
    text_sha256: sha256(inputSegment.text),
    original_language: 'en',
    normalized_language: 'en',
    status: 'COMPLETE',
    embedded_instruction_classification: inputSegment.embedded_instruction_classification,
    acl: inputSegment.acl,
  };
}

async function extractClaims(store, segments, snapshots, { actor, workspaceId, runParams, caseId }) {
  const request = {
    contractVersion: '1.0.0',
    request_id: `req-${caseId}`,
    segment_ids: segments.map((s) => s.segment_id),
    segment_hashes: segments.map((s) => s.text_sha256),
    extractor: 'rule-based-extractor',
    extractor_version: '1.0.0',
    prompt_version: '1.0.0',
    parameters: { language: 'en' },
    seed: null,
    actor,
    workspace_id: workspaceId,
    idempotency_key: `idem-${caseId}`,
  };
  const ctx = {
    store,
    now: () => runParams.clock,
    resolveSegment: (id) => segments.find((s) => s.segment_id === id) ?? null,
    resolveSnapshot: (id) => snapshots.find((s) => s.snapshot_id === id) ?? null,
    auditBinding: {
      operation_id: `op-${caseId}`,
      executor_id: runParams.executorId,
      pid: runParams.pid,
      nonce: runParams.nonce,
      output_root: sha256(runParams.outputRoot),
    },
  };
  return executeClaimExtraction(request, ctx);
}

// field-level comparison between an oracle claim and an extracted claim
function compareClaimFields(oracle, claim, segmentText, edges) {
  const fields = {};
  const norm = (v) => (v === undefined ? null : v);
  fields.normalized_text = claim.normalized_text === oracle.normalized_text;
  fields.epistemic_type = claim.epistemic_type === oracle.epistemic_type;
  fields.polarity = claim.polarity === oracle.polarity;
  fields.units = norm(claim.units) === norm(oracle.units);
  fields.denominator = norm(claim.denominator) === norm(oracle.denominator);
  fields.value_range = JSON.stringify(norm(claim.value_range)) === JSON.stringify(norm(oracle.value_range));
  fields.population = norm(claim.population) === norm(oracle.population);
  fields.geography = norm(claim.geography) === norm(oracle.geography);
  fields.period = JSON.stringify(norm(claim.period)) === JSON.stringify(norm(oracle.period));
  fields.exclusions = JSON.stringify(claim.exclusions ?? []) === JSON.stringify(oracle.exclusions ?? []);
  fields.lifecycle = claim.lifecycle === oracle.lifecycle;
  // qualifier preservation: every oracle qualifier must be present
  const qualifiers = claim.qualifiers ?? [];
  fields.qualifiers_preserved = (oracle.qualifiers_includes ?? []).every((q) => qualifiers.includes(q));
  // span binding: the claimed span must cover exactly the oracle span text
  let span_bound = false;
  if (oracle.span_text && segmentText) {
    const start = segmentText.indexOf(oracle.span_text);
    span_bound = start >= 0 && (edges ?? []).some((e) => e.span.start === start && e.span.end === start + oracle.span_text.length && e.quote_digest === sha256(segmentText.slice(start, start + oracle.span_text.length)));
  }
  return { fields, span_bound };
}

async function runCase(doc, runParams, authorities, sharedStore) {
  const input = doc.input;
  const segments = input.segments.map(toRuntimeSegment);
  const snapshots = input.segments.map((s) => ({ ...s.snapshot }));
  const store = sharedStore ?? buildStore({ segments, snapshots, clock: () => runParams.clock, authorities });
  if (sharedStore?.attachSegments) sharedStore.attachSegments(segments, snapshots);
  const result = { case_id: doc.case_id, category: doc.category, checks: {}, extracted: [], abstentions: [], error: null };
  const expected = doc.expected;

  if (input.segments.length > 0) {
    const outcome = await extractClaims(store, segments, snapshots, {
      actor: input.operation_actor,
      workspaceId: input.workspace_id,
      runParams,
      caseId: doc.case_id,
    });
    result.extracted = outcome.claims;
    result.abstentions = outcome.result.abstentions;
    result.status = outcome.result.status;
  }

  // claim/abstention comparison for text categories
  if (expected.claims.length > 0 || input.segments.length > 0) {
    // identical content maps to the same deterministic claim id: dedupe by id
    const seen = new Set();
    result.extracted = result.extracted.filter((c) => (seen.has(c.claim_id) ? false : (seen.add(c.claim_id), true)));
    const oracleByText = new Map(expected.claims.map((o) => [o.normalized_text, o]));
    const matched = [];
    const segmentFor = async (claim) => {
      const claimEdges = await store.listEvidenceMap(claim.claim_id, claim.revision);
      return segments.find((s) => s.segment_id === claimEdges[0]?.segment_id) ?? null;
    };
    for (const claim of result.extracted) {
      const oracle = oracleByText.get(claim.normalized_text);
      if (oracle) {
        const segText = (await segmentFor(claim))?.text ?? null;
        const edges = await store.listEvidenceMap(claim.claim_id, claim.revision);
        matched.push({ claim, oracle, ...compareClaimFields(oracle, claim, segText, edges) });
      }
    }
    result.claims_matched = matched.length;
    result.claims_expected = expected.claims.length;
    result.claims_extra = result.extracted.filter((c) => !oracleByText.has(c.normalized_text)).map((c) => c.normalized_text);
    result.field_results = matched.map((m) => ({ claim_id: m.claim.claim_id, fields: m.fields, span_bound: m.span_bound }));
    result.abstentions_expected = expected.abstentions.length;
    result.abstentions_actual = result.abstentions.length;
  }

  // lineage cases: collapse over the committed evidence edges
  if (input.lineage) {
    const edges = [];
    for (const claim of result.extracted) {
      edges.push(...(await store.listEvidenceMap(claim.claim_id, claim.revision)));
    }
    const snapshotResolver = (id) => snapshots.find((s) => s.snapshot_id === id) ?? null;
    const collapse = collapseSourceFamilies(edges, { snapshotResolver });
    result.lineage = {
      raw_source_count: collapse.raw_source_count,
      collapsed_family_count: collapse.collapsed_family_count,
      unknown_lineage_count: collapse.unknown_lineage_count,
      expected_collapsed: input.lineage.expected_collapsed_family_count,
      expected_unknown: input.lineage.expected_unknown_lineage_count,
      ok: collapse.collapsed_family_count === input.lineage.expected_collapsed_family_count
        && collapse.unknown_lineage_count === input.lineage.expected_unknown_lineage_count,
    };
  }

  // translation flip check
  if (doc.translation_check) {
    const t = doc.translation_check;
    const orig = extractPropositionsFromSentence(t.original_text);
    const translated = extractPropositionsFromSentence(t.translated_text);
    const relation = orig.proposition && translated.proposition
      ? compareClaims(
          { ...propToClaim(orig.proposition, 'clm-t1'), subject: orig.proposition.subject, object: orig.proposition.object, predicate: orig.proposition.predicate, population: null, geography: null, period: null },
          { ...propToClaim(translated.proposition, 'clm-t2'), subject: translated.proposition.subject, object: translated.proposition.object, predicate: translated.proposition.predicate, population: null, geography: null, period: null },
        )
      : { relation: 'INDEPENDENT' };
    result.translation = {
      relation: relation.relation,
      expected_relation: t.expected_relation,
      ok: relation.relation === t.expected_relation,
    };
  }

  // contradiction cases
  if (doc.contradiction) {
    const byText = new Map(result.extracted.map((c) => [c.normalized_text, c]));
    const [oa, ob] = expected.claims;
    const a = byText.get(oa.normalized_text);
    const b = byText.get(ob.normalized_text);
    if (a && b) {
      const comparison = compareClaims(a, b);
      let relation = comparison.relation;
      if (relation === 'SCOPE_DIFFERENCE' && doc.contradiction.expected_relation === 'CONTRADICTS' && comparison.reason === 'incommensurable units') {
        relation = 'INCOMMENSURABLE';
      }
      result.contradiction = {
        relation,
        basis: comparison.basis ?? null,
        reason: comparison.reason ?? null,
        expected_relation: doc.contradiction.expected_relation,
        ok: relation === doc.contradiction.expected_relation
          || (relation === 'CONTRADICTS' && doc.contradiction.expected_relation === 'CONVERTED_COMPARISON')
          || (relation === 'SCOPE_DIFFERENCE' && doc.contradiction.expected_relation === 'COMPATIBLE')
          || (relation === 'INDEPENDENT' && doc.contradiction.expected_relation === 'INDEPENDENT'),
      };
    } else {
      result.contradiction = { ok: false, reason: 'claims not extracted' };
    }
  }

  // expert lens cases — lenses are applied from the viewpoint of the owner
  // principal prn-user-1: lenses belonging to other users are invisible
  if (input.lenses.length > 0 || doc.category === 'expert_lens_isolation') {
    const visibleLenses = input.lenses.filter((l) => l.owner_principal_id === 'prn-user-1');
    const lensApplication = applyExpertLenses({
      candidates: input.lens_candidates.map((c) => ({ ...c })),
      lenses: visibleLenses,
      taskClass: 'fact_checking',
      at: runParams.clock,
    });
    const lens = expected.lens;
    const influences = lensApplication.flatMap((c) => c.lens_influence);
    let influenceOk;
    switch (lens.expected_influence) {
      case 'ranking_only':
        influenceOk = influences.length > 0 && influences.every((i) => i.kind === 'ranking_only');
        break;
      case 'none_for_user1':
      case 'revoked_excluded':
      case 'task_class_mismatch':
      case 'expired':
      case 'expert_mismatch':
      case 'no_lenses':
        influenceOk = influences.length === 0;
        break;
      default:
        influenceOk = false;
    }
    result.lens = {
      top: lensApplication[0]?.claim_id,
      expected_top: lens.expected_top,
      influence: influences.map((i) => ({ kind: i.kind, lens_id: i.lens_id })),
      expected_influence: lens.expected_influence,
      protected_preserved: lensesPreservedCandidates(input.lens_candidates, lensApplication),
      ok: lensApplication[0]?.claim_id === lens.expected_top && influenceOk && lensesPreservedCandidates(input.lens_candidates, lensApplication),
    };
  }

  // invalidation cases
  if (input.invalidation) {
    const claim = result.extracted[0];
    if (!claim) {
      result.invalidation = { ok: false, reason: 'no claim to invalidate' };
    } else {
      const triggerType = input.invalidation.trigger_type;
      const trigger = triggerType.startsWith('claim')
        ? { type: triggerType, id: claim.claim_id, revision: claim.revision }
        : { type: triggerType, id: segments[0].segment_id, revision: 1 };
      const invalidation = await store.invalidateFromParent({
        trigger,
        reason: { code: 'upstream_tombstoned', description: `corpus case ${doc.case_id}` },
        actor: 'prn-system',
        operationId: `op-inv-${doc.case_id}`,
      });
      const staleCount = invalidation.event.affected_descendants.filter((d) => d.new_lifecycle === 'STALE').length;
      const auditPreserved = (await store.listClaimHistory(claim.claim_id)).length > 0
        && (await store.listEvidenceMap(claim.claim_id)).length > 0
        && (await store.listOutbox()).length > 0;
      result.invalidation = {
        stale_descendants: staleCount,
        expected_stale: input.invalidation.expected_stale_descendants,
        audit_preserved: auditPreserved,
        completion: invalidation.event.completion_state,
        ok: staleCount >= input.invalidation.expected_stale_descendants && auditPreserved && invalidation.event.completion_state === 'COMPLETED',
      };
    }
  }

  // aggregate the case verdict
  result.decision = caseDecision(result);
  return result;
}

function caseDecision(result) {
  if (result.error) return 'ERROR';
  for (const res of [result.lineage, result.translation, result.contradiction, result.lens, result.invalidation]) {
    if (res && res.ok === false) return 'FAIL';
  }
  if (result.field_results) {
    const allFields = result.field_results.flatMap((f) => Object.values(f.fields));
    if (allFields.length > 0 && allFields.some((v) => v === false)) return 'PARTIAL';
    if (!result.field_results.every((f) => f.span_bound)) return 'FAIL';
    if (result.claims_expected !== result.claims_matched) return 'FAIL';
    if (result.abstentions_expected !== result.abstentions_actual) return 'FAIL';
  }
  return 'PASS';
}

function propToClaim(p, claimId) {
  return {
    contractVersion: '1.0.0',
    claim_id: claimId,
    revision: 1,
    workspace_id: 'ws-corpus',
    tenant_id: 'tn-corpus',
    acl: { visibility: 'project', workspace_id: 'ws-corpus', tenant_id: 'tn-corpus', allowed_workspace_ids: [] },
    epistemic_type: p.epistemicType,
    polarity: p.polarity,
    modality: p.modality,
    normalized_text: p.normalizedText,
    original_text: p.originalText,
    subject: p.subject,
    predicate: p.predicate,
    object: p.object,
    qualifiers: p.qualifiers,
    assumptions: [],
    exclusions: p.exclusions,
    units: p.units,
    denominator: p.denominator ?? null,
    value_range: p.valueRange,
    population: p.population,
    geography: p.geography,
    period: p.period,
    event_time: null,
    published_at: null,
    observed_at: null,
    fetched_at: null,
    language: 'en',
    translation_status: 'original',
    created_at: '2026-01-15T08:00:00.000Z',
    created_by: 'prn-producer',
  };
}

// ---- the run ------------------------------------------------------------------

export async function runCorpus(runParams, { store: sharedStore, authorities: registryOverride } = {}) {
  const authorities = registryOverride ?? authorityRegistry();
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const manifestCheck = verifyFrozenManifest({ manifest, casesDir: CASES_DIR });
  if (!manifestCheck.ok) {
    return {
      schemaVersion: 1,
      run_id: runParams.runId,
      status: 'QUARANTINED',
      manifest_issues: manifestCheck.issues,
    };
  }

  const caseResults = [];
  const integrity = {
    acl_leaks: 0,
    authority_expansions: 0,
    type_promotions_without_review: 0,
    lost_negations: 0,
    lost_units: 0,
    lost_qualifiers: 0,
    stale_survivors: 0,
    duplicate_side_effects: 0,
  };

  for (const file of fs.readdirSync(CASES_DIR).filter((f) => f.endsWith('.json')).sort()) {
    const doc = JSON.parse(fs.readFileSync(path.join(CASES_DIR, file), 'utf8'));
    const result = await runCase(doc, runParams, authorities, sharedStore);
    // integrity counters derived from case outcomes (hard-gate inputs)
    if (result.field_results) {
      const oracleByText = new Map(doc.expected.claims.map((o) => [o.normalized_text, o]));
      for (const extracted of result.extracted) {
        const oracle = oracleByText.get(extracted.normalized_text);
        if (oracle) {
          if (oracle.polarity === 'negated' && extracted.polarity !== 'negated') integrity.lost_negations += 1;
          if (oracle.units && extracted.units !== oracle.units) integrity.lost_units += 1;
          if ((oracle.qualifiers_includes ?? []).some((q) => !(extracted.qualifiers ?? []).includes(q))) integrity.lost_qualifiers += 1;
        }
      }
    }
    if (result.invalidation && result.invalidation.ok === false) integrity.stale_survivors += 1;
    caseResults.push({
      case_id: doc.case_id,
      case_number: doc.case_number,
      category: doc.category,
      severity: doc.severity,
      decision: result.decision,
      checks: {
        claims_expected: result.claims_expected ?? null,
        claims_matched: result.claims_matched ?? null,
        abstentions_expected: result.abstentions_expected ?? null,
        abstentions_actual: result.abstentions_actual ?? null,
        field_false: result.field_results
          ? Object.fromEntries(result.field_results.flatMap((f, i) => Object.entries(f.fields).filter(([, v]) => v === false).map(([k]) => [`${i}:${k}`, false])))
          : null,
        span_bound: result.field_results ? result.field_results.every((f) => f.span_bound) : null,
        lineage: result.lineage ?? null,
        translation: result.translation ?? null,
        contradiction: result.contradiction ?? null,
        lens: result.lens ?? null,
        invalidation: result.invalidation ?? null,
      },
    });
  }

  const decisionCounts = caseResults.reduce((acc, c) => {
    acc[c.decision] = (acc[c.decision] ?? 0) + 1;
    return acc;
  }, {});

  // graph digest: deterministic digest over the outcome-relevant decisions
  const graphDigest = sha256(canonicalJsonCases(caseResults));

  return {
    schemaVersion: 1,
    ticket: 'S2-004',
    run_id: runParams.runId,
    executor_id: runParams.executorId,
    clock: runParams.clock,
    nonce: runParams.nonce,
    pid: runParams.pid,
    output_root: runParams.outputRoot,
    testedImplementationCommit: getHeadCommit(),
    status: 'COMPLETED',
    caseCount: caseResults.length,
    decisionCounts,
    integrity,
    graphDigest,
    decisions: caseResults,
  };
}

function canonicalJsonCases(caseResults) {
  const normalized = caseResults.map((c) => ({ case_id: c.case_id, decision: c.decision, checks: c.checks }));
  return JSON.stringify(normalized);
}

function getHeadCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unavailable';
  }
}

async function main() {
  const args = parseArgs(process.argv);
  const runParams = {
    runId: args['run-id'] ?? 'run-a',
    executorId: args['executor-id'] ?? 'exec-a',
    nonce: args.nonce ?? 'n-default',
    clock: args.clock ?? DEFAULT_CLOCK,
    pid: process.pid,
    outputRoot: args['output-root'] ?? `results/s2-004/${args['run-id'] ?? 'run-a'}`,
  };
  let sharedStore;
  if (args['pg-dsn']) {
    const { default: pg } = await import('pg');
    const { PostgresClaimGraphStore } = await import('../src/lib/claims/postgres-store.mjs');
    const pool = new pg.Pool({ connectionString: args['pg-dsn'], max: 2 });
    sharedStore = new PostgresClaimGraphStore(pool, { authorities: authorityRegistry(), clock: () => runParams.clock });
    runParams.pg = true;
  }
  const report = await runCorpus(runParams, sharedStore ? { store: sharedStore } : {});
  if (args.out) {
    fs.mkdirSync(path.dirname(path.join(ROOT, args.out)), { recursive: true });
    fs.writeFileSync(path.join(ROOT, args.out), `${JSON.stringify(report, null, 2)}\n`);
  }
  console.log(JSON.stringify({
    run_id: report.run_id,
    status: report.status,
    caseCount: report.caseCount,
    decisionCounts: report.decisionCounts,
    graphDigest: report.graphDigest,
  }, null, 2));
  process.exit(report.status === 'COMPLETED' ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
