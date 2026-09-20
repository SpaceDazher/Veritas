// S2-006 offline evidence run (spec §3, §8, §9, §13).
//
// Architecture (blinding by construction):
//   * PARENT (this process, comparator/evaluator side) never executes the
//     candidate. It spawns TWO process-separated candidate children (distinct
//     executor id, PID, nonce, clock and output root) that run the SAME frozen
//     rubric implementation over the SAME frozen 45-case corpus.
//   * CHILD (--candidate) reads ONLY the frozen corpus manifest and case
//     files. The label sets, adjudications and thresholds are NEVER opened by
//     the child — the sealed prediction set is written before unseal.
//   * Only after BOTH prediction sets are sealed does the parent unseal the
//     labels/adjudication and run the preregistered exact comparator
//     (src/lib/verifier/comparator.mjs — never re-runs the candidate).
//   * Calibration metrics (fixture stratum), the lexicographic decision rule
//     and the A–S security probes are then computed and bound to evidence/.
//
// Honesty rules: no wall clock or randomness in decision-affecting output;
// no fabricated external metrics — the fixture stratum is labeled as such,
// the independence tier stays NOT_MEASURED (evaluator_not_independent) and
// every owner-owned threshold stays NEEDS_INPUT.
//
// Validated owner-inputs path (review finding 7, fix2-F): without
// --owner-inputs the run is byte-for-byte the honest fixture-only flow above.
// With --owner-inputs <dir> AND a separately stored --owner-trust <file>, the
// owner package (external manifest, independent
// signed annotation sets, adjudications, an authored thresholds
// preregistration, a canonical HumanDecision bound to its exact digest and a
// multi-axis independence profile) is loaded FAIL-CLOSED against the frozen
// contracts and driven through the real pipeline: sealed candidate children
// over the external corpus (labels never read before unseal), the fail-closed
// comparator, calibration with the owner independence profile and the
// lexicographic decision rule with the resolved threshold decision. Any
// loader miss refuses the run — never a silent fixture fallback.
//
//   node scripts/s2-006-run.mjs                 # full offline evidence run
//   node scripts/s2-006-run.mjs --candidate …   # internal child mode
//   node scripts/s2-006-run.mjs --owner-inputs <dir> --owner-trust <file> [--evidence-dir <dir>]
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { evaluateScenario, RUBRIC_ID, RUBRIC_VERSION } from '../src/lib/verifier/rubric.mjs';
import {
  compareRuns,
  adjudicationAttestationDigest,
  annotationSetBindingDigest,
  labelEntryDigest,
} from '../src/lib/verifier/comparator.mjs';
import { computeMetrics, decideLexicographic, resolveThresholdDecision } from '../src/lib/verifier/calibration.mjs';
import { registerKey, sign, verifyDetailed as verifySignatureDetailed } from '../src/lib/verifier/signature.mjs';
import { verifierValidators } from '../src/lib/verifier/api.mjs';
import { makeVerifierAuthorityRegistry, registerProviderGrant } from '../src/lib/verifier/commands.mjs';
import { runAllSecurityProbes } from '../src/lib/verifier/probes.mjs';

export { adjudicationAttestationDigest };

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS_DIR = path.join(ROOT, 'corpus/s2-006');
let EVIDENCE_DIR = path.join(ROOT, 'evidence');
const EXPECTED_CASE_COUNT = 45;
const THRESHOLDS_PATH = path.join(ROOT, 'contracts/s2-006-thresholds.json');
// Fixture-only HMAC key (tests/verifier/fixtures convention). Real annotator
// key custody with the label_custodian role is NOT_RUN — the fixture key
// proves the signature verification path, never real independence.
export const FIXTURE_ANNOTATION_HMAC_KEY = 's2-006-fixture-hmac-key';
const FIXTURE_KEYS_PATH = path.join(ROOT, 'tests', 'verifier', 'fixtures', 'keys.json');

function loadFixtureSignatureRegistry() {
  const registry = new Map();
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_KEYS_PATH, 'utf8'));
  for (const key of fixture.keys) registerKey({ ...key, registry });
  return registry;
}

function custodySignFixtureAdjudications(records, registry) {
  return records.map((record) => ({
    ...record,
    adjudicatorIdentity: sign(
      record.adjudicatorIdentity.principalId,
      'kms://test/s2-006/adjudicator-1',
      adjudicationAttestationDigest(record),
      { registry, form: 'adjudicator-identity' },
    ),
  }));
}

// Loader white-list for externalStratum.status on an OWNER external manifest
// (review finding 7). The frozen contracts/annotation-manifest.schema.json
// pins status to the const NEEDS_INPUT and is NOT modified: the extension
// lives only here, requires an explicit non-empty reason, and the manifest is
// additionally schema-validated with the status substituted back to
// NEEDS_INPUT so every other field still passes the frozen schema as-is.
export const OWNER_EXTERNAL_STATUS_WHITELIST = Object.freeze(['READY', 'MEASURED']);

// Candidate implementation identity: the exact modules the sealed predictions
// depend on. Any change to these bytes changes the implementation digest.
const CANDIDATE_MODULES = [
  'src/lib/verifier/rubric.mjs',
  'src/lib/verifier/canonical-json.mjs',
];

const RUN_A = {
  runId: 's2-006-run-a',
  executorId: 'exec-s2-006-a',
  nonce: 'n-a-7c1e4d90a2b8f3e6',
  clock: '2026-01-15T08:00:00.000Z',
  outputRoot: 'results/s2-006/run-a',
};
const RUN_B = {
  runId: 's2-006-run-b',
  executorId: 'exec-s2-006-b',
  nonce: 'n-b-3f9a62d1c5e80b74',
  clock: '2026-03-21T23:59:59.999Z',
  outputRoot: 'results/s2-006/run-b',
};

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) args[argv[i].slice(2)] = 'true';
      else { args[argv[i].slice(2)] = next; i += 1; }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

const sha256Bytes = (buf) => createHash('sha256').update(buf).digest('hex');

function getHeadCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unavailable';
  }
}

// ---- frozen corpus load (shared by child and parent) ------------------------

function loadFrozenCorpus() {
  const manifestBytes = fs.readFileSync(path.join(CORPUS_DIR, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const issues = [];
  if (manifest.contractVersion !== '1.0.0') issues.push('manifest:contract-version-unknown');
  if (!Array.isArray(manifest.cases) || manifest.cases.length !== EXPECTED_CASE_COUNT) {
    issues.push(`manifest:case-count-not-${EXPECTED_CASE_COUNT}`);
  }
  const rubricBytes = fs.readFileSync(path.join(CORPUS_DIR, 'rubric-v1.json'));
  if (sha256Bytes(rubricBytes) !== manifest.rubricDigest) issues.push('manifest:rubric-digest-drift');
  const splitByCase = new Map(manifest.splitAssignments.map((a) => [a.caseId, a.split]));
  if (splitByCase.size !== manifest.cases.length) issues.push('manifest:split-assignment-incomplete');
  const cases = [];
  for (const entry of manifest.cases) {
    let bytes;
    try {
      bytes = fs.readFileSync(path.join(CORPUS_DIR, 'cases', `${entry.caseId}.json`));
    } catch {
      issues.push(`${entry.caseId}:missing`);
      continue;
    }
    if (sha256Bytes(bytes) !== entry.caseSha256) issues.push(`${entry.caseId}:case-digest-drift`);
    const file = JSON.parse(bytes.toString('utf8'));
    if (file.case?.caseId !== entry.caseId) issues.push(`${entry.caseId}:record-id-mismatch`);
    if (canonicalDigest(file.scenario) !== file.case?.textDigest) issues.push(`${entry.caseId}:scenario-digest-drift`);
    cases.push({
      caseId: entry.caseId,
      bytes,
      record: file.case,
      scenario: file.scenario,
      split: splitByCase.get(entry.caseId) ?? null,
    });
  }
  for (const file of fs.readdirSync(path.join(CORPUS_DIR, 'cases'))) {
    if (file.endsWith('.json') && !manifest.cases.some((c) => c.caseId === file.replace(/\.json$/, ''))) {
      issues.push(`${file}:unmanifested`);
    }
  }
  if (manifest.externalStratum?.status !== 'NEEDS_INPUT') issues.push('manifest:external-stratum-must-be-needs-input');
  return { ok: issues.length === 0, issues, manifest, manifestBytes, rubricBytes, rubricDigest: manifest.rubricDigest, cases };
}

// ---- child mode: the candidate (labels never read) ---------------------------

export function runCandidate({ runId, executorId, nonce, clock, outputRoot, corpus }) {
  const predictions = {};
  const hardCounters = {
    unauthorizedLeakageEvents: 0,
    lockedLabelAccessEvents: 0, // the child never opens label/adjudication files
    producerSelfReviewEvents: 0,
    upstreamArtifactMutationEvents: 0,
    unauthorizedSideEffectEvents: 0,
  };
  const LEAK_VERDICTS = new Set(['SUPPORTED', 'CONTRADICTED', 'PARTIALLY_SUPPORTED']);
  const perCase = [];
  for (const c of corpus.cases) {
    const r = evaluateScenario(c.scenario);
    predictions[c.caseId] = {
      verdict: r.verdict,
      reasonCodes: [...r.reasonCodes],
      missingnessKind: r.missingness.kind,
    };
    // A content-asserting verdict on a private-category case could only be
    // produced by reading the private span: a hard leak, counted here.
    if (c.scenario.category === 'private' && LEAK_VERDICTS.has(r.verdict)) {
      hardCounters.unauthorizedLeakageEvents += 1;
    }
    perCase.push({ caseId: c.caseId, verdict: r.verdict });
  }
  const implementationModules = Object.fromEntries(CANDIDATE_MODULES.map((rel) => [
    rel,
    sha256Bytes(fs.readFileSync(path.join(ROOT, rel))),
  ]));
  const implementationDigest = canonicalDigest({
    modules: implementationModules,
    rubricId: RUBRIC_ID,
    rubricVersion: RUBRIC_VERSION,
  });
  const runManifestDigest = canonicalDigest({
    runId, executorId, pid: process.pid, nonce, outputRoot, implementationDigest,
  });
  return {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'candidate sealed prediction set (labels, adjudications and thresholds never read before unseal)',
    runId,
    executorId,
    pid: process.pid,
    nonce,
    clock,
    outputRoot,
    testedImplementationCommit: getHeadCommit(),
    corpus: {
      manifestId: corpus.manifest.manifestId,
      corpusVersion: corpus.manifest.corpusVersion,
      manifestSha256: sha256Bytes(corpus.manifestBytes),
      rubricDigest: corpus.rubricDigest,
      caseCount: corpus.cases.length,
      stratum: corpus.stratum ?? 'fixture',
    },
    implementationDigest,
    implementationModules,
    predictions,
    predictionSetDigest: canonicalDigest(predictions),
    runManifestDigest,
    hardCounters,
    perCase,
    sealedBeforeUnseal: true,
    status: 'COMPLETED',
  };
}

// ---- unseal: gold consensus from labels + adjudications ----------------------

function loadGold(corpusCases) {
  const annotators = { a: {}, b: {} };
  const labelSets = {};
  for (const annotator of ['a', 'b']) {
    const bytes = fs.readFileSync(path.join(CORPUS_DIR, 'labels', `annotator-${annotator}.json`));
    for (const set of JSON.parse(bytes.toString('utf8'))) {
      labelSets[set.annotationSetId] = set;
      for (const l of set.labels) annotators[annotator][l.caseId] = l.label;
    }
  }
  const adjudications = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, 'adjudication.json'), 'utf8'));
  const gold = {};
  for (const c of corpusCases) {
    const disagreement = adjudications.find((r) => r.caseId === c.caseId);
    gold[c.caseId] = disagreement ? disagreement.decision : annotators.a[c.caseId];
  }
  return { annotators, labelSets, adjudications, gold };
}

// ---- validated owner-inputs path (review finding 7, fix2-F) -----------------
// Fail-closed loading of an owner-supplied package. Every document is
// validated against the FROZEN contracts (never a copy, never a relaxed
// shape), every signature is verified over the exact binding digest and every
// cross-digest binding is recomputed. Any miss refuses the load — the run
// never falls back to fixture-only behavior silently.

const OWNER_REQUIRED_FILES = Object.freeze([
  'external-manifest.json', 'adjudication.json', 'threshold-decision.json', 'independence.json',
]);

// Lazy fail-closed validators compiled from the frozen contract files. The
// frozen schemas are the single source of truth — never copied, never edited.
let ownerSchemaValidators = null;
function ownerValidators() {
  if (ownerSchemaValidators) return ownerSchemaValidators;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const load = (name) => {
    const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', `${name}.schema.json`), 'utf8'));
    ajv.addSchema(schema, schema.$id);
    return schema;
  };
  load('needs-input'); // $ref target of human-decision
  load('annotation-manifest');
  load('semantic-provider-grant');
  load('owner-trust-bundle');
  load('corpus-case');
  const v2 = load('calibration-record-v2');
  // the frozen evaluator_independence subschema is compiled AS-IS (with the
  // frozen $defs); only its $id changes because ajv forbids fragment ids
  ajv.addSchema({ ...v2.properties.evaluator_independence, $defs: v2.$defs, $id: 'urn:veritas:s2-006:evaluator-independence' }, 'urn:veritas:s2-006:evaluator-independence');
  const byId = (id) => ajv.getSchema(id);
  ownerSchemaValidators = {
    annotationManifest: byId('https://veritas.local/contracts/annotation-manifest.schema.json'),
    ownerTrustBundle: byId('https://veritas.local/contracts/owner-trust-bundle.schema.json'),
    corpusCase: byId('https://veritas.local/contracts/corpus-case.schema.json'),
    evaluatorIndependence: byId('urn:veritas:s2-006:evaluator-independence'),
  };
  return ownerSchemaValidators;
}

function ajvErrors(validator) {
  return (validator.errors ?? []).map((e) => `${e.instancePath} ${e.message}`).join('; ');
}

// Validate the ORIGINAL owner manifest object against the versioned schema.
// Decision-bearing fields are never rewritten into a validator-only view.
function validateExternalManifest(manifest) {
  const issues = [];
  const status = manifest?.externalStratum?.status;
  if (!OWNER_EXTERNAL_STATUS_WHITELIST.includes(status)) {
    issues.push(`external-manifest: externalStratum.status ${JSON.stringify(status ?? null)} is outside [${OWNER_EXTERNAL_STATUS_WHITELIST.join(', ')}]`);
  }
  const reason = manifest?.externalStratum?.reason;
  if (typeof reason !== 'string' || reason.trim().length === 0) {
    issues.push('external-manifest: externalStratum.reason must be a non-empty explicit reason while the loader white-list applies');
  }
  const validate = ownerValidators().annotationManifest;
  if (validate(manifest) !== true) {
    issues.push(`external-manifest: annotation-manifest schema rejected the original document: ${ajvErrors(validate)}`);
  }
  return issues;
}

// Structural layout check of a thresholds document (canonical field layout;
// soft thresholds under thresholds.soft_thresholds — review P1-5b). Owner
// numerics may legitimately be null (the pipeline then honestly reports
// NEEDS_INPUT for the unauthored values), but the shape itself is mandatory.
function validateThresholdsShape(doc) {
  const issues = [];
  const bad = (msg) => issues.push(`thresholds: ${msg}`);
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    bad('document must be an object');
    return issues;
  }
  const soft = doc.thresholds?.soft_thresholds;
  if (!soft || typeof soft !== 'object' || Array.isArray(soft) || Object.keys(soft).length === 0) {
    bad('thresholds.soft_thresholds must be a non-empty object at the canonical nested path');
  } else {
    for (const [key, spec] of Object.entries(soft)) {
      if (!spec || typeof spec !== 'object' || typeof spec.metric !== 'string'
        || !['>=', '<='].includes(spec.operator) || !('value' in spec)
        || (spec.value !== null && typeof spec.value !== 'number')) {
        bad(`soft_thresholds.${key} must be {metric, operator '>='|'<=', value number|null}`);
      }
    }
  }
  for (const [field, key] of [['coverage_floor', 'value'], ['confidence_level', 'value'], ['non_inferiority_margin', 'delta']]) {
    const v = doc[field]?.[key];
    if (v !== null && v !== undefined && typeof v !== 'number') bad(`${field}.${key} must be a number or null`);
  }
  const rule = doc.tie_rule?.rule;
  if (rule !== null && rule !== undefined && typeof rule !== 'string') bad('tie_rule.rule must be a string or null');
  return issues;
}

// Candidate-side corpus loader for an owner external corpus. Reads ONLY the
// manifest and the case files — annotation sets, adjudications, thresholds
// and the decision are never opened before both prediction sets are sealed
// (blinding by construction, spec §3).
export function loadOwnerExternalCorpus(dir) {
  const issues = [];
  let manifestBytes;
  try {
    manifestBytes = fs.readFileSync(path.join(dir, 'external-manifest.json'));
  } catch {
    return { ok: false, issues: [`external-manifest.json is missing or unreadable in ${dir}`] };
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (e) {
    return { ok: false, issues: [`external-manifest.json is not valid JSON: ${e.message}`] };
  }
  issues.push(...validateExternalManifest(manifest));
  const rubricBytes = fs.readFileSync(path.join(CORPUS_DIR, 'rubric-v1.json'));
  if (sha256Bytes(rubricBytes) !== manifest.rubricDigest) {
    issues.push('external-manifest: rubricDigest does not bind the frozen in-repo rubric bytes');
  }
  const splitByCase = new Map(manifest.splitAssignments.map((a) => [a.caseId, a.split]));
  if (splitByCase.size !== manifest.cases.length) issues.push('external-manifest: split assignment incomplete');
  const cases = [];
  for (const entry of manifest.cases) {
    let bytes;
    try {
      bytes = fs.readFileSync(path.join(dir, 'cases', `${entry.caseId}.json`));
    } catch {
      issues.push(`case ${entry.caseId}: missing case file`);
      continue;
    }
    if (sha256Bytes(bytes) !== entry.caseSha256) issues.push(`case ${entry.caseId}: file bytes != manifest.caseSha256`);
    let file;
    try {
      file = JSON.parse(bytes.toString('utf8'));
    } catch (e) {
      issues.push(`case ${entry.caseId}: not valid JSON: ${e.message}`);
      continue;
    }
    if (file.case?.caseId !== entry.caseId) issues.push(`case ${entry.caseId}: record id mismatch`);
    if (canonicalDigest(file.scenario) !== file.case?.textDigest) issues.push(`case ${entry.caseId}: scenario digest != case.textDigest`);
    cases.push({ caseId: entry.caseId, bytes, record: file.case, scenario: file.scenario, split: splitByCase.get(entry.caseId) ?? null });
  }
  for (const file of fs.readdirSync(path.join(dir, 'cases'))) {
    if (file.endsWith('.json') && !manifest.cases.some((c) => c.caseId === file.replace(/\.json$/, ''))) {
      issues.push(`case file ${file}: unmanifested`);
    }
  }
  return { ok: issues.length === 0, issues, manifest, manifestBytes, rubricBytes, rubricDigest: manifest.rubricDigest, cases, stratum: 'external_owner_inputs' };
}

// Load operator-controlled trust anchors from a file supplied SEPARATELY from
// the untrusted owner package. This is the only CLI bridge from serialized
// custody material to runtime registries; owner package bytes can never add a
// key, principal or grant to these registries.
export function loadOwnerTrustBundle(file) {
  const issues = [];
  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    return { ok: false, issues: [`owner-trust: unreadable or invalid JSON (${error.message})`], context: null };
  }
  const validate = ownerValidators().ownerTrustBundle;
  if (validate(bundle) !== true) {
    return { ok: false, issues: [`owner-trust: schema rejected the original document: ${ajvErrors(validate)}`], context: null };
  }
  const keyRegistry = new Map();
  try {
    for (const key of bundle.keys) registerKey({ ...key, registry: keyRegistry });
  } catch (error) {
    issues.push(`owner-trust: custody key registration refused (${error.message})`);
  }
  const authorities = makeVerifierAuthorityRegistry(bundle.principals);
  if (issues.length === 0) {
    for (const entry of bundle.grants) {
      try {
        registerProviderGrant(authorities, { ...entry, registry: keyRegistry });
      } catch (error) {
        issues.push(`owner-trust: grant ${entry.grant?.grantId ?? '?'} refused (${error.message})`);
      }
    }
  }
  return issues.length > 0
    ? { ok: false, issues, context: null }
    : {
        ok: true,
        issues: [],
        context: {
          authorities,
          keyRegistry,
          bundleId: bundle.bundleId,
          fixtureGrade: bundle.fixtureGrade === true,
          source: path.resolve(file),
        },
      };
}

export function buildOwnerAuthorityContext(decision, trustedContext) {
  const binding = decision?.authority_binding;
  if (!binding || typeof binding.principalId !== 'string' || typeof binding.grantRef !== 'string') {
    return { error: 'authority_binding_missing_or_malformed' };
  }
  if (!(trustedContext?.keyRegistry instanceof Map)
    || !(trustedContext?.authorities instanceof Map)
    || !(trustedContext.authorities.issuedGrants instanceof Map)) {
    return { error: 'trusted_owner_context_missing' };
  }
  const registered = trustedContext.authorities.issuedGrants.get(binding.grantRef);
  if (!registered) return { error: 'authority_grant_not_trusted' };
  if (registered.grant.authenticatedPrincipal !== binding.principalId) {
    return { error: 'authority_grant_principal_mismatch' };
  }
  return trustedContext;
}

// Full fail-closed loader for the owner-inputs package. Returns
// { ok: false, issues, package: null } on ANY miss — schema violations, digest
// drift, signature or attestation failures, a decision that does not bind the
// exact thresholds digest, or an incomplete independence profile.
export function loadOwnerInputs(dir, { trustedContext = null } = {}) {
  const issues = [];
  const fail = () => ({ ok: false, issues, package: null });
  const trustProblem = !(trustedContext?.keyRegistry instanceof Map)
    || !(trustedContext?.authorities instanceof Map)
    || !(trustedContext.authorities.issuedGrants instanceof Map)
    ? 'owner-inputs: trusted owner context is required and must be supplied independently of the package'
    : trustedContext.fixtureGrade === true
      ? 'owner-inputs: trusted owner context is fixture-grade and cannot establish independent calibration'
      : null;

  for (const name of OWNER_REQUIRED_FILES) {
    if (!fs.existsSync(path.join(dir, name))) issues.push(`owner-inputs: required file ${name} is missing`);
  }
  if (!fs.existsSync(path.join(dir, 'cases')) || !fs.statSync(path.join(dir, 'cases')).isDirectory()) {
    issues.push('owner-inputs: cases/ directory is missing');
  }
  const setsDir = path.join(dir, 'annotation-sets');
  if (!fs.existsSync(setsDir) || !fs.statSync(setsDir).isDirectory()) {
    issues.push('owner-inputs: annotation-sets/ directory is missing');
  }
  if (issues.length > 0) return fail();

  // ---- external manifest (white-list + frozen schema) -----------------------
  let manifestBytes;
  try {
    manifestBytes = fs.readFileSync(path.join(dir, 'external-manifest.json'));
  } catch (e) {
    issues.push(`external-manifest.json is unreadable: ${e.message}`);
    return fail();
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (e) {
    issues.push(`external-manifest.json is not valid JSON: ${e.message}`);
    return fail();
  }
  issues.push(...validateExternalManifest(manifest));
  if (issues.length > 0) return fail();

  // ---- thresholds document (owner-authored version or the frozen repo doc) --
  let thresholdsDoc;
  let thresholdsSource;
  const thresholdsPath = path.join(dir, 'thresholds.json');
  if (fs.existsSync(thresholdsPath)) {
    try {
      thresholdsDoc = JSON.parse(fs.readFileSync(thresholdsPath, 'utf8'));
      thresholdsSource = 'owner-package';
    } catch (e) {
      issues.push(`thresholds.json is not valid JSON: ${e.message}`);
      return fail();
    }
  } else {
    try {
      thresholdsDoc = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts', 's2-006-thresholds.json'), 'utf8'));
      thresholdsSource = 'repo-contract';
    } catch (e) {
      issues.push(`contracts/s2-006-thresholds.json is unreadable: ${e.message}`);
      return fail();
    }
  }
  issues.push(...validateThresholdsShape(thresholdsDoc));
  const thresholdsDigest = canonicalDigest(thresholdsDoc);

  // ---- corpus composition (schema, digests, external stratum policy) --------
  const corpus = loadOwnerExternalCorpus(dir);
  if (!corpus.ok) issues.push(...corpus.issues);
  const validateCase = ownerValidators().corpusCase;
  for (const c of corpus.cases ?? []) {
    if (validateCase(c.record) !== true) {
      issues.push(`case ${c.caseId}: frozen corpus-case schema rejected the record: ${ajvErrors(validateCase)}`);
    }
    if (c.record?.stratum !== 'external') {
      issues.push(`case ${c.caseId}: owner-package cases must carry stratum "external" (found ${JSON.stringify(c.record?.stratum ?? null)})`);
    }
  }
  const eligibleLocked = (corpus.cases ?? []).filter((entry) => entry.split === 'locked_test' && entry.record?.stratum === 'external');
  const deduplicatedLocked = new Set(eligibleLocked.map((entry) => `${entry.record.sourceFamily}\u0000${entry.record.semanticTemplate}`));
  if (deduplicatedLocked.size < 20) {
    issues.push(`owner-inputs: locked_test external stratum has ${deduplicatedLocked.size} eligible cases after source-family/semantic-template dedup; at least 20 are required`);
  }
  const splitNames = ['dev', 'calibration', 'locked_test'];
  for (let i = 0; i < splitNames.length; i += 1) {
    for (let j = i + 1; j < splitNames.length; j += 1) {
      const left = (corpus.cases ?? []).filter((entry) => entry.split === splitNames[i]);
      const right = (corpus.cases ?? []).filter((entry) => entry.split === splitNames[j]);
      for (const field of ['sourceFamily', 'semanticTemplate']) {
        const leftValues = new Set(left.map((entry) => entry.record?.[field]));
        const overlap = [...new Set(right.map((entry) => entry.record?.[field]))].filter((value) => leftValues.has(value));
        if (overlap.length > 0) {
          issues.push(`owner-inputs: ${field} overlaps ${splitNames[i]}/${splitNames[j]} (${overlap.join(', ')})`);
        }
      }
    }
  }

  // ---- annotation sets (frozen schema + signature + coverage) ----------------
  const labelSets = {};
  const setIssues = [];
  for (const file of fs.readdirSync(setsDir).filter((f) => f.endsWith('.json')).sort()) {
    let set;
    try {
      set = JSON.parse(fs.readFileSync(path.join(setsDir, file), 'utf8'));
    } catch (e) {
      setIssues.push(`annotation set ${file}: not valid JSON: ${e.message}`);
      continue;
    }
    const verdict = verifierValidators().validate('annotation-set', set);
    if (verdict.ok !== true) {
      setIssues.push(`annotation set ${file}: frozen annotation-set schema rejected: ${verdict.errors}`);
      continue;
    }
    if (set.rubricDigest !== manifest.rubricDigest) setIssues.push(`annotation set ${set.annotationSetId}: rubric digest != manifest rubricDigest`);
    if (set.sourceDigest !== sha256Bytes(manifestBytes)) setIssues.push(`annotation set ${set.annotationSetId}: sourceDigest must bind the external-manifest bytes (sha256), found ${set.sourceDigest}`);
    const manifestIds = manifest.cases.map((c) => c.caseId).sort();
    if (JSON.stringify([...set.frozenCaseIds].sort()) !== JSON.stringify(manifestIds)) {
      setIssues.push(`annotation set ${set.annotationSetId}: frozenCaseIds must cover exactly the manifest cases`);
    }
    const expectedSplit = new Set(manifest.splitAssignments.filter((a) => set.frozenCaseIds.includes(a.caseId)).map((a) => a.split));
    if (expectedSplit.size !== 1 || !expectedSplit.has(set.split)) {
      setIssues.push(`annotation set ${set.annotationSetId}: split ${set.split} does not match the manifest split assignments`);
    }
    for (const l of set.labels) {
      if (l.annotatorId !== set.annotatorId) setIssues.push(`annotation set ${set.annotationSetId}: label for ${l.caseId} carries annotator ${l.annotatorId}`);
      if (l.labelDigest !== labelEntryDigest({ annotationSetId: set.annotationSetId, annotatorId: l.annotatorId, caseId: l.caseId, label: l.label, labeledAt: l.labeledAt })) {
        setIssues.push(`annotation set ${set.annotationSetId}: label digest binding broken for ${l.caseId}`);
      }
    }
    if (trustedContext?.keyRegistry instanceof Map) {
      const signature = verifySignatureDetailed(set.signature, set.annotatorId, annotationSetBindingDigest(set), { registry: trustedContext.keyRegistry });
      if (!signature.ok) setIssues.push(`annotation set ${set.annotationSetId}: signature rejected (${signature.reason})`);
    }
    if (labelSets[set.annotationSetId]) setIssues.push(`annotation set ${set.annotationSetId}: duplicate id`);
    labelSets[set.annotationSetId] = set;
  }
  issues.push(...setIssues);
  const annotatorIds = [...new Set(Object.values(labelSets).map((s) => s.annotatorId))].sort();
  if (annotatorIds.length < 2) issues.push(`owner-inputs: independent labeling requires at least two distinct annotator principals, found ${annotatorIds.length}`);

  // ---- adjudications (frozen schema + bindings + attestation) ----------------
  const adjudicators = new Set();
  let adjudications = [];
  try {
    adjudications = JSON.parse(fs.readFileSync(path.join(dir, 'adjudication.json'), 'utf8'));
  } catch (e) {
    issues.push(`adjudication.json is not valid JSON: ${e.message}`);
    return fail();
  }
  if (!Array.isArray(adjudications)) issues.push('adjudication.json must be an array of adjudication records');
  for (const rec of Array.isArray(adjudications) ? adjudications : []) {
    const verdict = verifierValidators().validate('adjudication-record', rec);
    if (verdict.ok !== true) {
      issues.push(`adjudication ${rec?.adjudicationId ?? '?'}: frozen adjudication-record schema rejected: ${verdict.errors}`);
      continue;
    }
    if (rec.versions.annotationManifestDigest !== sha256Bytes(manifestBytes)) issues.push(`adjudication ${rec.adjudicationId}: bound to a different annotation manifest`);
    if (rec.versions.rubricDigest !== manifest.rubricDigest) issues.push(`adjudication ${rec.adjudicationId}: bound to a different rubric`);
    if (rec.versions.thresholdsDigest !== thresholdsDigest) issues.push(`adjudication ${rec.adjudicationId}: bound to different thresholds`);
    if (!manifest.cases.some((c) => c.caseId === rec.caseId)) issues.push(`adjudication ${rec.adjudicationId}: unknown case ${rec.caseId}`);
    for (const ref of rec.annotationSetIds) {
      if (!labelSets[ref]) issues.push(`adjudication ${rec.adjudicationId}: references unknown annotation set ${ref}`);
    }
    const identity = rec.adjudicatorIdentity;
    if (annotatorIds.includes(identity.principalId)) issues.push(`adjudication ${rec.adjudicationId}: the adjudicator must never be an annotator of the package`);
    if (trustedContext?.keyRegistry instanceof Map) {
      const attestation = verifySignatureDetailed(identity, identity.principalId, adjudicationAttestationDigest(rec), { registry: trustedContext.keyRegistry });
      if (!attestation.ok) issues.push(`adjudication ${rec.adjudicationId}: adjudicator attestation rejected (${attestation.reason})`);
    }
    adjudicators.add(identity.principalId);
  }

  // ---- threshold decision (canonical HumanDecision via resolveThresholdDecision)
  let decision;
  try {
    decision = JSON.parse(fs.readFileSync(path.join(dir, 'threshold-decision.json'), 'utf8'));
  } catch (e) {
    issues.push(`threshold-decision.json is not valid JSON: ${e.message}`);
    return fail();
  }
  const authorityContext = buildOwnerAuthorityContext(decision, trustedContext);
  let thresholdResolution = { resolved: false, reason: authorityContext.error ?? 'authority_unavailable' };
  if (authorityContext.error) {
    issues.push(`threshold-decision.json refused: ${authorityContext.error}`);
  } else {
    thresholdResolution = resolveThresholdDecision(thresholdsDoc, decision, authorityContext.authorities, { keyRegistry: authorityContext.keyRegistry });
    if (!thresholdResolution.resolved) issues.push(`threshold-decision.json refused: ${thresholdResolution.reason}`);
  }

  // ---- independence profile (frozen evaluator_independence subschema) --------
  let profile;
  try {
    profile = JSON.parse(fs.readFileSync(path.join(dir, 'independence.json'), 'utf8'));
  } catch (e) {
    issues.push(`independence.json is not valid JSON: ${e.message}`);
    return fail();
  }
  const validateProfile = ownerValidators().evaluatorIndependence;
  if (validateProfile(profile) !== true) {
    issues.push(`independence.json: frozen evaluator_independence subschema (calibration-record-v2) rejected: ${ajvErrors(validateProfile)}`);
    return fail();
  }
  const profileAnnotators = profile.annotators.map((a) => a.principal_id).sort();
  if (JSON.stringify(profileAnnotators) !== JSON.stringify(annotatorIds)) {
    issues.push(`independence.json: profile annotators [${profileAnnotators.join(',')}] != annotation-set annotators [${annotatorIds.join(',')}]`);
  }
  if (!profile.annotators.every((a) => a.authenticated === true) || profile.annotators.length < 2) {
    issues.push('independence.json: at least two authenticated annotators are required');
  }
  if (Object.values(profile.blindness).some((v) => v !== true)) {
    issues.push('independence.json: every blindness axis must be explicit');
  }
  for (const axis of ['data_independence', 'model_independence', 'process_independence']) {
    if (profile[axis] !== true) issues.push(`independence.json: ${axis} must be explicit`);
  }
  if ((profile.locked_label_access ?? []).some((e) => e.access === 'granted')) {
    issues.push('independence.json: locked_label_access records a granted access before the one-time unseal HumanDecision (probe H)');
  }
  if (adjudicators.size > 0) {
    if (!profile.adjudicator || !adjudicators.has(profile.adjudicator.principal_id)) {
      issues.push(`independence.json: profile adjudicator must be the package adjudicator [${[...adjudicators].join(',')}]`);
    } else if (profile.adjudicator.authenticated !== true) {
      issues.push('independence.json: the package adjudicator must be authenticated');
    }
  }
  if (trustProblem) issues.push(trustProblem);
  if (issues.length > 0) return fail();

  return {
    ok: true,
    issues,
    package: {
      dir,
      manifest,
      manifestBytes,
      rubricBytes: corpus.rubricBytes,
      rubricDigest: manifest.rubricDigest,
      cases: corpus.cases,
      labelSets,
      adjudications,
      annotatorIds,
      adjudicators: [...adjudicators].sort(),
      thresholdsDoc,
      thresholdsSource,
      thresholdsDigest,
      decision,
      thresholdResolution,
      authorityContext,
      independence: {
        profile,
        resolved: true,
        tier: 'INDEPENDENTLY_CALIBRATED',
      },
    },
  };
}

// Runs the loaded owner package through the real pipeline: two sealed
// process-separated candidate children over the external corpus (labels never
// read before unseal), the fail-closed comparator, calibration metrics with
// the owner independence profile and the lexicographic decision rule fed with
// the resolved threshold decision. Deterministic: injected clocks, no wall clock.
const OWNER_RUN_PARAMS = {
  a: { runId: 's2-006-owner-run-a', executorId: 'exec-s2-006-owner-a', nonce: 'n-owner-a-51e7c2a4d9b803f6', clock: '2026-03-27T08:00:00.000Z', outputRoot: 'results/s2-006/owner-run-a' },
  b: { runId: 's2-006-owner-run-b', executorId: 'exec-s2-006-owner-b', nonce: 'n-owner-b-8d24a7c1e5f90b32', clock: '2026-04-01T23:59:59.999Z', outputRoot: 'results/s2-006/owner-run-b' },
};

export async function runOwnerInputsPipeline({ pkg, evidenceDir } = {}) {
  // review fix: direct callers (tests) must be able to redirect the evidence
  // output; the module default stays the canonical evidence/ directory.
  const outDir = evidenceDir ? path.resolve(ROOT, String(evidenceDir)) : EVIDENCE_DIR;
  const sealed = {};
  for (const [key, params] of Object.entries(OWNER_RUN_PARAMS)) {
    const out = path.join(outDir, `s2-006-owner-run-${key}.json`);
    const child = spawnSync(process.execPath, [
      path.join(ROOT, 'scripts/s2-006-run.mjs'),
      '--candidate',
      '--owner-corpus', pkg.dir,
      '--run-id', params.runId,
      '--executor-id', params.executorId,
      '--nonce', params.nonce,
      '--clock', params.clock,
      '--output-root', params.outputRoot,
      '--out', out,
      ...(evidenceDir ? ['--evidence-dir', String(evidenceDir)] : []),
    ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    if (child.status !== 0) {
      return { ok: false, stage: 'candidate', error: `owner candidate run ${params.runId} exited ${child.status}: ${String(child.stderr ?? '').slice(-800)}`, comparison: null, metrics: null, decision: null };
    }
    sealed[key] = JSON.parse(fs.readFileSync(out, 'utf8'));
    if (sealed[key].corpus.manifestSha256 !== sha256Bytes(pkg.manifestBytes)) {
      return { ok: false, stage: 'candidate', error: `owner candidate run ${params.runId} sealed a different manifest`, comparison: null, metrics: null, decision: null };
    }
  }

  const comparison = compareRuns({
    manifest: pkg.manifest,
    manifestBytes: pkg.manifestBytes,
    rubricBytes: pkg.rubricBytes,
    cases: pkg.cases,
    labelSets: pkg.labelSets,
    adjudications: pkg.adjudications,
    thresholdsDigest: pkg.thresholdsDigest,
    signatureKeyRegistry: pkg.authorityContext.keyRegistry,
    runA: {
      runId: sealed.a.runId,
      executorId: sealed.a.executorId,
      pid: sealed.a.pid,
      nonce: sealed.a.nonce,
      outputRoot: sealed.a.outputRoot,
      implementationDigest: sealed.a.implementationDigest,
      predictions: sealed.a.predictions,
      hardCounters: sealed.a.hardCounters,
    },
    runB: {
      runId: sealed.b.runId,
      executorId: sealed.b.executorId,
      pid: sealed.b.pid,
      nonce: sealed.b.nonce,
      outputRoot: sealed.b.outputRoot,
      implementationDigest: sealed.b.implementationDigest,
      predictions: sealed.b.predictions,
      hardCounters: sealed.b.hardCounters,
    },
  });
  if (!comparison.ok) {
    return { ok: false, stage: 'comparator', comparison, metrics: null, decision: null };
  }

  const [annotatorA, annotatorB] = pkg.annotatorIds;
  const collect = (annotatorId) => {
    const byCase = {};
    for (const set of Object.values(pkg.labelSets)) {
      if (set.annotatorId !== annotatorId) continue;
      for (const l of set.labels) byCase[l.caseId] = l.label;
    }
    return byCase;
  };
  const metrics = computeMetrics({
    cases: pkg.cases.map((c) => ({ caseId: c.caseId, category: c.scenario.category, stratum: 'external' })),
    gold: comparison.checks.consensusGold,
    goldReasons: Object.fromEntries(pkg.cases.map((c) => [c.caseId, c.scenario.expected?.reasonCodes ?? []])),
    predictions: sealed.a.predictions,
    annotators: { a: collect(annotatorA), b: collect(annotatorB) },
    independence: { independent: pkg.independence.resolved, reason: 'evaluator_not_independent' },
  });
  const decision = decideLexicographic({
    systems: [{ systemId: 'rubric-candidate', metrics, isCandidate: true, cost: null, latency: null }],
    thresholds: pkg.thresholdsDoc,
    ownerDecision: pkg.decision,
    authorities: pkg.authorityContext.authorities,
    keyRegistry: pkg.authorityContext.keyRegistry,
  });
  return { ok: true, stage: 'complete', comparison, metrics, decision, thresholdResolution: pkg.thresholdResolution };
}

function buildOwnerInputsRecord(pkg, run) {
  return {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'validated owner-inputs run (review finding 7): external corpus, independent signed annotations, authored thresholds, a canonical HumanDecision bound to their exact digest and a multi-axis independence profile, loaded fail-closed and driven through the real comparator, calibration and lexicographic decision rule',
    testedImplementationCommit: getHeadCommit(),
    ownerInputs: {
      dir: path.relative(ROOT, pkg.dir) || pkg.dir,
      manifest: {
        manifestId: pkg.manifest.manifestId,
        corpusVersion: pkg.manifest.corpusVersion,
        sha256: sha256Bytes(pkg.manifestBytes),
        rubricDigest: pkg.rubricDigest,
        caseCount: pkg.cases.length,
        externalStratum: { status: pkg.manifest.externalStratum.status, reason: pkg.manifest.externalStratum.reason },
      },
      annotationSets: Object.values(pkg.labelSets).map((s) => ({ annotationSetId: s.annotationSetId, annotatorId: s.annotatorId, split: s.split, labelCount: s.labels.length })),
      annotatorIds: pkg.annotatorIds,
      adjudicators: pkg.adjudicators,
      adjudicationCount: Array.isArray(pkg.adjudications) ? pkg.adjudications.length : 0,
      thresholds: { source: pkg.thresholdsSource, digest: pkg.thresholdsDigest },
      thresholdDecision: {
        resolved: pkg.thresholdResolution.resolved,
        reason: pkg.thresholdResolution.reason,
        decisionDigest: pkg.thresholdResolution.decisionDigest,
        ownerPrincipal: pkg.thresholdResolution.ownerPrincipal,
        grantRef: pkg.thresholdResolution.grantRef,
      },
      independence: {
        resolved: pkg.independence.resolved,
        tier: pkg.independence.tier,
        profile: pkg.independence.profile,
      },
    },
    pipeline: {
      stage: run.stage,
      ok: run.ok,
      error: run.error ?? null,
      predictionSetDigests: run.comparison?.checks?.predictionDigests ?? null,
      runManifestDigests: run.comparison?.checks?.runManifestDigests ?? null,
      comparatorOk: run.comparison?.ok ?? null,
      comparatorFailures: run.comparison?.failures ?? null,
      calibration: run.metrics ? {
        coverage: run.metrics.coverage,
        hardViolations: run.metrics.hardViolations,
        interAnnotatorAgreement: run.metrics.metricsByName.get('inter_annotator_agreement') ?? null,
        citationEntailmentF1: run.metrics.metricsByName.get('citation_entailment_f1') ?? null,
      } : null,
      decision: run.decision,
    },
    hardGates: { ok: run.ok === true && run.comparison?.ok === true, violations: run.ok ? [] : [`OWNER_INPUTS_${String(run.stage).toUpperCase()}`] },
    honesty: {
      signatureVerification: 'every annotation and adjudication is verified against the separately supplied operator trust registry; package bytes cannot register custody keys',
      authorityContext: `operator trust bundle ${pkg.authorityContext.bundleId ?? '<programmatic>'}; fixture-grade bundles are rejected before this record can be produced`,
      independenceProvenance: 'owner-declared profile cross-checked against authenticated principals in a separate non-fixture trust context plus the mandatory corpus/split constraints',
      noSilentFallback: 'loader misses refuse the run (OWNER_INPUTS_REJECTED, exit 1) instead of falling back to fixture-only behavior',
    },
  };
}

// ---- evidence writers ---------------------------------------------------------

function writeEvidence(name, value) {
  const target = path.join(EVIDENCE_DIR, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
  return `evidence/${name}`;
}

function buildCalibrationRecord({ corpus, metrics, goldState, thresholds, thresholdsDigest, decision }) {
  const metricRecords = metrics.metricRecords;
  const allMetricNames = [...new Set(metricRecords.map((r) => r.name))];
  const splitComposition = {};
  for (const c of corpus.cases) splitComposition[c.split] = (splitComposition[c.split] ?? 0) + 1;
  return {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'calibration metrics over the frozen fixture stratum (45 cases, dev/calibration/locked_test splits)',
    corpus: {
      manifestId: corpus.manifest.manifestId,
      corpusVersion: corpus.manifest.corpusVersion,
      manifestSha256: sha256Bytes(corpus.manifestBytes),
      rubricDigest: corpus.rubricDigest,
      caseCount: corpus.cases.length,
      stratum: 'fixture',
      splitComposition,
    },
    inputs: {
      thresholdsDigest,
      predictionSource: 'evidence/s2-006-run-a.json (verified identical to run B by the comparator)',
      goldSource: 'raw blind labels of prn-annotator-a/prn-annotator-b + adjudication records (corpus/s2-006)',
    },
    metricRecords,
    confusionMatrices: metrics.confusionMatrices,
    coverage: metrics.coverage,
    selectiveRisk: metrics.selectiveRisk,
    hardViolations: metrics.hardViolations,
    rawAnnotatorAgreement: metrics.rawAnnotatorAgreement,
    slices: [
      { name: 'fixture-all', stratum: 'fixture', caseCount: corpus.cases.length, metricNames: allMetricNames },
    ],
    thresholdDecision: {
      thresholdsDigest,
      status: 'NEEDS_INPUT',
      ownerDecisionRef: null,
      appliedAt: null,
    },
    independence: {
      tier: 'NOT_INDEPENDENT',
      status: 'NOT_MEASURED',
      reason: 'evaluator_not_independent',
      details: {
        annotatorsAreFixturePrincipals: true,
        producerAndVerifierShareProject: true,
        noRealIndependentAnnotatorsOrAdjudicator: true,
        noMethodOwnerHumanDecision: true,
        note: 'Synthetic principals prove policy mechanics only; they never create independence (spec §3).',
      },
    },
    decision,
    externalStratum: { status: 'NEEDS_INPUT', reason: 'evaluator_not_independent' },
    limitations: [
      'Fixture stratum only: no externally authored, independently labelled cases exist.',
      'Inter-annotator agreement is NOT_MEASURED on this stratum (evaluator_not_independent); raw agreement is kept for transparency.',
      'Every owner-owned threshold numeric is null: no method-owner HumanDecision exists.',
      'No EvidenceMap/HypothesisCard inputs in this offline harness: evidence_map_completeness is NOT_APPLICABLE here.',
      'No probabilities emitted: Brier/ECE stay NOT_APPLICABLE.',
    ],
  };
}

// ---- parent orchestration ------------------------------------------------------

async function parentMode() {
  const written = [];
  const violations = [];

  // 1. frozen corpus (parent-side check; children re-verify independently)
  const corpus = loadFrozenCorpus();
  if (!corpus.ok) {
    console.error(JSON.stringify({ ok: false, status: 'QUARANTINED', issues: corpus.issues }, null, 2));
    process.exit(1);
  }

  // 2. process-separated candidate runs BEFORE unseal
  const sealed = {};
  for (const [key, params] of [['a', RUN_A], ['b', RUN_B]]) {
    const out = path.join(EVIDENCE_DIR, `s2-006-run-${key}.json`);
    const child = spawnSync(process.execPath, [
      path.join(ROOT, 'scripts/s2-006-run.mjs'),
      '--candidate',
      '--run-id', params.runId,
      '--executor-id', params.executorId,
      '--nonce', params.nonce,
      '--clock', params.clock,
      '--output-root', params.outputRoot,
      '--out', out,
    ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    if (child.status !== 0) {
      console.error(`candidate run ${params.runId} exited ${child.status}: ${String(child.stderr ?? '').slice(-800)}`);
      process.exit(1);
    }
    sealed[key] = JSON.parse(fs.readFileSync(out, 'utf8'));
    written.push(`evidence/s2-006-run-${key}.json`);
  }

  // 3. UNSEAL: labels/adjudications/thresholds are opened only here
  const goldState = loadGold(corpus.cases);
  const fixtureSignatureRegistry = loadFixtureSignatureRegistry();
  goldState.adjudications = custodySignFixtureAdjudications(goldState.adjudications, fixtureSignatureRegistry);
  const thresholdsBytes = fs.readFileSync(THRESHOLDS_PATH);
  const thresholds = JSON.parse(thresholdsBytes.toString('utf8'));
  const thresholdsDigest = canonicalDigest(thresholds);

  // 4. preregistered exact comparator over the two sealed sets
  const comparison = compareRuns({
    manifest: corpus.manifest,
    manifestBytes: corpus.manifestBytes,
    rubricBytes: corpus.rubricBytes,
    cases: corpus.cases,
    labelSets: goldState.labelSets,
    adjudications: goldState.adjudications,
    thresholdsDigest,
    signatureKeyRegistry: fixtureSignatureRegistry,
    runA: {
      runId: sealed.a.runId,
      executorId: sealed.a.executorId,
      pid: sealed.a.pid,
      nonce: sealed.a.nonce,
      outputRoot: sealed.a.outputRoot,
      implementationDigest: sealed.a.implementationDigest,
      predictions: sealed.a.predictions,
      hardCounters: sealed.a.hardCounters,
    },
    runB: {
      runId: sealed.b.runId,
      executorId: sealed.b.executorId,
      pid: sealed.b.pid,
      nonce: sealed.b.nonce,
      outputRoot: sealed.b.outputRoot,
      implementationDigest: sealed.b.implementationDigest,
      predictions: sealed.b.predictions,
      hardCounters: sealed.b.hardCounters,
    },
  });
  if (!comparison.ok) {
    for (const f of comparison.failures) violations.push(`COMPARATOR_${f.code}`);
  }
  const comparisonRecord = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'fail-closed comparator over two pre-sealed process-separated prediction sets (spec §9); the candidate is never re-run after unseal',
    testedImplementationCommit: sealed.a.testedImplementationCommit,
    corpus: {
      manifestId: corpus.manifest.manifestId,
      manifestSha256: sha256Bytes(corpus.manifestBytes),
      rubricDigest: corpus.rubricDigest,
      caseCount: corpus.cases.length,
      stratum: 'fixture',
    },
    runParameters: {
      run_a: { executor: sealed.a.executorId, pid: sealed.a.pid, clock: sealed.a.clock, nonce: sealed.a.nonce, output_root: sealed.a.outputRoot },
      run_b: { executor: sealed.b.executorId, pid: sealed.b.pid, clock: sealed.b.clock, nonce: sealed.b.nonce, output_root: sealed.b.outputRoot },
    },
    predictionSetDigests: { run_a: sealed.a.predictionSetDigest, run_b: sealed.b.predictionSetDigest },
    runManifestDigests: { run_a: sealed.a.runManifestDigest, run_b: sealed.b.runManifestDigest },
    hardCounters: { run_a: sealed.a.hardCounters, run_b: sealed.b.hardCounters },
    comparison,
    hardGates: { ok: comparison.ok, violations },
    // no wall clock: the run identity is (executor, pid, nonce, output root)
    blinding: {
      candidateNeverReadLabels: true,
      comparatorNeverReRunsCandidate: true,
      annotationHmacKey: 'fixture-key (real label_custodian custody NOT_RUN)',
    },
  };
  written.push(writeEvidence('s2-006-comparison.json', comparisonRecord));

  // 5. calibration metrics on the fixture stratum (MEASURED counts, honest NOT_MEASURED independence)
  const cases = corpus.cases.map((c) => ({ caseId: c.caseId, category: c.scenario.category, stratum: 'fixture' }));
  const goldReasons = Object.fromEntries(corpus.cases.map((c) => [c.caseId, c.scenario.expected?.reasonCodes ?? []]));
  const metrics = computeMetrics({
    cases,
    gold: goldState.gold,
    goldReasons,
    predictions: sealed.a.predictions,
    annotators: goldState.annotators,
    independence: { independent: false, reason: 'evaluator_not_independent' },
  });
  const finalDecision = decideLexicographic({
    systems: [{ systemId: 'rubric-candidate', metrics, isCandidate: true, cost: null, latency: null }],
    thresholds,
  });
  const calibrationRecord = buildCalibrationRecord({
    corpus,
    metrics,
    goldState,
    thresholds,
    thresholdsDigest,
    decision: finalDecision,
  });
  if (metrics.hardViolations.total !== 0) {
    violations.push(`CALIBRATION_HARD_VIOLATIONS_${metrics.hardViolations.total}`);
  }
  written.push(writeEvidence('s2-006-calibration.json', calibrationRecord));

  // 6. validated owner-inputs path (review finding 7, fix2-F). Without
  // --owner-inputs this block is skipped entirely. With it, the owner package
  // is loaded FAIL-CLOSED (any schema, digest, signature or decision-binding
  // miss refuses the whole run with OWNER_INPUTS_REJECTED — no silent fixture
  // fallback) and driven through the real pipeline: sealed candidate children
  // over the external corpus, the fail-closed comparator, calibration with the
  // owner independence profile and the lexicographic decision rule with the
  // resolved threshold decision. The block runs BEFORE the probe suite so a
  // broken owner package is refused deterministically, independently of any
  // later probe outcome.
  let ownerInputsReport = null;
  if (args['owner-inputs']) {
    const ownerDir = path.resolve(ROOT, String(args['owner-inputs']));
    if (!args['owner-trust']) {
      console.error(JSON.stringify({ ok: false, status: 'OWNER_INPUTS_REJECTED', issues: ['owner-inputs: --owner-trust <file> is required'] }, null, 2));
      process.exit(1);
    }
    const trustPath = path.resolve(ROOT, String(args['owner-trust']));
    const trustRelative = path.relative(ownerDir, trustPath);
    if (trustRelative === '' || (!trustRelative.startsWith('..') && !path.isAbsolute(trustRelative))) {
      console.error(JSON.stringify({ ok: false, status: 'OWNER_INPUTS_REJECTED', issues: ['owner-trust: trust anchors must be stored outside the untrusted owner-inputs directory'] }, null, 2));
      process.exit(1);
    }
    const trusted = loadOwnerTrustBundle(trustPath);
    if (!trusted.ok) {
      console.error(JSON.stringify({ ok: false, status: 'OWNER_INPUTS_REJECTED', issues: trusted.issues }, null, 2));
      process.exit(1);
    }
    const loaded = loadOwnerInputs(ownerDir, { trustedContext: trusted.context });
    if (!loaded.ok) {
      console.error(JSON.stringify({ ok: false, status: 'OWNER_INPUTS_REJECTED', issues: loaded.issues }, null, 2));
      process.exit(1);
    }
    const ownerRun = await runOwnerInputsPipeline({ pkg: loaded.package });
    const ownerRecord = buildOwnerInputsRecord(loaded.package, ownerRun);
    written.push(writeEvidence('s2-006-owner-inputs.json', ownerRecord));
    if (!ownerRecord.hardGates.ok) violations.push('OWNER_INPUTS_PIPELINE');
    ownerInputsReport = {
      present: true,
      evidence: 'evidence/s2-006-owner-inputs.json',
      externalStratum: ownerRecord.ownerInputs.manifest.externalStratum.status,
      independenceTier: ownerRecord.ownerInputs.independence.tier,
      thresholdDecisionResolved: ownerRecord.ownerInputs.thresholdDecision.resolved,
      comparatorOk: ownerRecord.pipeline.comparatorOk,
      decisionStatus: ownerRecord.pipeline.decision?.status ?? null,
    };
  }

  // 7. adversarial probes A–S (offline; probe S is honestly NOT_RUN_DB here)
  // Review P2-6: every probe carries an honest status pass|failed|not_run and
  // NOT_RUN among the mandatory A–S set is NOT green. Probe S turns green
  // only through the PostgreSQL crash/restart phase of verify:s2-006-db-replay
  // (combined by the verify-s2-006 aggregator). A FAILED probe still violates
  // the run; a NOT_RUN probe leaves the run green but the probes gate
  // honestly incomplete.
  const probeSuite = await runAllSecurityProbes();
  const probeFailures = probeSuite.probes.filter((p) => p.status === 'failed');
  const probesGreen = probeFailures.length === 0 && probeSuite.hardCounters.total === 0 && probeSuite.totals.not_run === 0;
  if (probeFailures.length > 0 || probeSuite.hardCounters.total > 0) violations.push('PROBES_A_TO_S');
  const probesRecord = {
    schemaVersion: 1,
    ticket: 'S2-006',
    role: 'adversarial probes A–S over the verifier rubric/policy/signature/command surfaces (spec §12)',
    ok: probesGreen,
    status: probesGreen ? 'PASS' : (probeFailures.length > 0 ? 'FAIL' : 'INCOMPLETE_NOT_RUN_DB'),
    statusSemantics: 'each probe carries status pass|failed|not_run; not_run among the mandatory set is never green (review P2-6)',
    combine: 'probe S resolves to green ONLY via evidence/s2-006-db-comparison.json crashPhase (verify:s2-006-db-replay crash/restart phase)',
    totals: probeSuite.totals,
    hardCounters: probeSuite.hardCounters,
    notRun: probeSuite.notRun,
    probes: probeSuite.probes,
    testedImplementationCommit: sealed.a.testedImplementationCommit,
    executedAt: 'bound on the S2-006 branch',
  };
  written.push(writeEvidence('s2-006-security-probes.json', probesRecord));

  const ok = violations.length === 0;
  console.log(JSON.stringify({
    ok,
    violations,
    written,
    caseCount: corpus.cases.length,
    comparison: { ok: comparison.ok, failures: comparison.failures.length },
    predictionSetDigests: comparisonRecord.predictionSetDigests,
    calibration: {
      coverage: metrics.coverage,
      hardViolations: metrics.hardViolations.total,
      decision: finalDecision.status,
      independence: calibrationRecord.independence.status,
    },
    probes: {
      green: probesGreen,
      total: probeSuite.totals.probes,
      pass: probeSuite.totals.pass,
      failed: probeSuite.totals.failed,
      not_run: probeSuite.totals.not_run,
      probeS: probeSuite.probes.find((p) => p.id === 'S')?.status ?? null,
      combine: 'probe S green ONLY via verify:s2-006-db-replay crash phase',
    },
    ...(ownerInputsReport ? { ownerInputs: ownerInputsReport } : {}),
  }, null, 2));
  process.exit(ok ? 0 : 1);
}

// ---- entry ----------------------------------------------------------------------

const args = parseArgs(process.argv);
if (args['evidence-dir']) {
  EVIDENCE_DIR = path.resolve(ROOT, String(args['evidence-dir']));
}
if (args.candidate === 'true') {
  // the candidate reads the frozen fixture corpus (default) or, with
  // --owner-corpus, the owner external corpus — manifest and case files only;
  // label material is never opened before unseal (spec §3)
  const corpus = args['owner-corpus']
    ? loadOwnerExternalCorpus(path.resolve(ROOT, String(args['owner-corpus'])))
    : loadFrozenCorpus();
  if (!corpus.ok) {
    console.error(JSON.stringify({ status: 'QUARANTINED', issues: corpus.issues }, null, 2));
    process.exit(2);
  }
  const sealed = runCandidate({
    runId: args['run-id'] ?? 'run-x',
    executorId: args['executor-id'] ?? 'exec-x',
    nonce: args.nonce ?? 'n-default',
    clock: args.clock ?? '1970-01-01T00:00:00.000Z',
    outputRoot: args['output-root'] ?? 'results/s2-006/run-x',
    corpus,
  });
  const outPath = path.isAbsolute(args.out ?? '') ? args.out : path.join(ROOT, args.out ?? 'results/s2-006/sealed.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(sealed, null, 2)}\n`);
  console.log(JSON.stringify({
    run_id: sealed.runId,
    status: sealed.status,
    caseCount: corpus.cases.length,
    predictionSetDigest: sealed.predictionSetDigest,
    runManifestDigest: sealed.runManifestDigest,
    hardCounters: sealed.hardCounters,
  }, null, 2));
  process.exit(sealed.status === 'COMPLETED' ? 0 : 1);
} else if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await parentMode();
}
