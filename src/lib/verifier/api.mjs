// S2-006 provider-neutral pure compute/query API (spec §5).
// Everything here is read-only over exact artifact revisions/digests and
// never mutates tracked files, upstream artifacts or a store. The semantic
// rubric checker is INJECTED (options.checker with check(item) -> verdict);
// this module deliberately does not import any producer semantics
// (src/lib/synthesis/*, src/lib/claims/* entailment/relation functions) —
// the module whitelist of spec §3 allows only identity/ACL, persistence
// primitives, contracts and their validation, canonical JSON and hashing.
//
// Failure semantics: a checker exception/timeout/unavailable source is
// translated by errors.mjs#missingnessForError into a typed missingness
// record with an INSUFFICIENT_EVIDENCE abstention — never into a semantic
// pass/fail (probe P). Deterministic staleness rules of spec §7 (stale,
// future, revoked evidence invalidate the dependent verdict) are applied
// after the checker verdict, deterministically.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { canonicalize, canonicalDigest } from './canonical-json.mjs';
import {
  AclDenied,
  ContractVersionUnknown,
  NeedsInput,
  StaleInput,
  VerifierError,
  VerifierPolicyBlock,
  missingnessForError,
  reasonCodeForMissingness,
} from './errors.mjs';
import { check as policyCheck } from './policy.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');

// Contracts validated/produced by this module. calibration-record (+v2) and
// semantic-verification-item are included because calibration-report and
// semantic-verification-result $ref them.
export const VERIFIER_CONTRACTS = Object.freeze([
  'semantic-verification-request',
  'semantic-verification-item',
  'semantic-verification-result',
  'calibration-record',
  'calibration-record-v2',
  'calibration-report',
  'adjudication-record',
  'verifier-run',
  'verifier-invalidation-event',
  'semantic-provider-grant',
  'annotation-set',
]);

export const CONTRACT_VERSION = '1.0.0';

export const VERDICT_LABELS = Object.freeze([
  'SUPPORTED', 'CONTRADICTED', 'PARTIALLY_SUPPORTED', 'INSUFFICIENT_EVIDENCE',
  'OUT_OF_SCOPE', 'STALE_INPUT', 'BLOCKED_POLICY',
]);

export const REASON_CODES = Object.freeze([
  'topic_overlap', 'number_unit_drift', 'negation_drift', 'modality_drift',
  'scope_difference', 'missing_citation', 'stale_source', 'future_source',
  'revoked_source', 'family_collapse', 'causal_overclaim', 'out_of_scope',
  'policy_block', 'evaluator_missing', 'other',
]);

const CITATION_CHECKS = Object.freeze(new Set(['citation_entailment', 'citation_coverage']));
const HEX64 = /^[0-9a-f]{64}$/;

// fix2-C finding 2: an upstream artifact whose payload passes the digest
// gate but violates the FROZEN producer schema for its kind is a contract
// violation in the BLOCKED_POLICY family — a typed rejection before any
// statement extraction, never a semantic verdict and never silence.
export class ArtifactContractViolation extends VerifierPolicyBlock {
  constructor(message, detail = undefined) {
    super(message, detail);
    this.name = 'ArtifactContractViolation';
    this.reasonCode = 'artifact_contract_violation';
  }
}

// Frozen producer contracts by artifact kind (contracts/*.schema.json are
// the single source of truth; additionalProperties:false rejects unknown
// version extras, and required[] rejects missing members such as
// contractVersion).
const PRODUCER_CONTRACT_BY_KIND = Object.freeze({
  claim: 'claim',
  evidence_map: 'evidence-map',
  hypothesis_card: 'hypothesis-card',
  synthesis_result: 'synthesis-result',
});

let producerValidator = null;

// Fail-closed Ajv (draft 2020-12) validation of upstream artifact payloads
// against the frozen producer schemas, compiled once at first use (module
// initialization of the validation closure; the schema FILES stay the
// source of truth and are read at compilation time).
export function producerArtifactValidators(io = {}) {
  if (producerValidator && !io.reload) return producerValidator;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  for (const name of Object.values(PRODUCER_CONTRACT_BY_KIND)) {
    const schema = JSON.parse(fs.readFileSync(path.join(CONTRACTS_DIR, `${name}.schema.json`), 'utf8'));
    ajv.addSchema(schema, schema.$id);
  }
  const compiled = new Map();
  for (const [kind, name] of Object.entries(PRODUCER_CONTRACT_BY_KIND)) {
    compiled.set(kind, ajv.getSchema(`https://veritas.local/contracts/${name}.schema.json`));
  }
  producerValidator = {
    validate(kind, payload) {
      const fn = compiled.get(kind);
      if (!fn) return { ok: false, errors: `no frozen producer contract for artifact kind ${kind}` };
      const ok = fn(payload);
      return {
        ok,
        errors: ok ? '' : fn.errors.map((e) => `${e.instancePath} ${e.message}`).join('; '),
      };
    },
  };
  return producerValidator;
}

function requireValidArtifactPayload(kind, payload) {
  const outcome = producerArtifactValidators().validate(kind, payload);
  if (!outcome.ok) {
    const error = new ArtifactContractViolation(
      `upstream ${kind} payload violates the frozen producer contract: ${outcome.errors}`,
    );
    error.issues = outcome.errors;
    throw error;
  }
}

let validator = null;

// Fail-closed ajv (draft 2020-12) validation over the verifier contract
// closure; the JSON Schemas in contracts/ remain the single source of truth.
export function verifierValidators(io = {}) {
  if (validator && !io.reload) return validator;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const schemas = {};
  for (const name of VERIFIER_CONTRACTS) {
    const schemaPath = path.join(CONTRACTS_DIR, `${name}.schema.json`);
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    ajv.addSchema(schema, schema.$id);
    schemas[name] = schema;
  }
  const compiled = new Map();
  for (const name of VERIFIER_CONTRACTS) {
    compiled.set(name, ajv.getSchema(`https://veritas.local/contracts/${name}.schema.json`));
  }
  validator = {
    schemas,
    validate(name, object) {
      const fn = compiled.get(name);
      if (!fn) throw new VerifierError('CONTRACT_UNKNOWN', `unknown contract: ${name}`);
      const ok = fn(object);
      return {
        ok,
        errors: ok ? [] : fn.errors.map((e) => `${e.instancePath} ${e.message}`).join('; '),
      };
    },
    requireValid(name, object) {
      const result = this.validate(name, object);
      if (!result.ok) {
        const error = new VerifierError('CONTRACT_REJECTED', `contract ${name} rejected payload: ${result.errors}`);
        error.contract = name;
        error.issues = result.errors;
        throw error;
      }
      return object;
    },
  };
  return validator;
}

function sha256HexText(text) {
  return createHash('sha256').update(String(text), 'utf8').digest('hex');
}

// canonical_args_digest: SHA-256 over the canonical-json-v1 form of the
// request payload excluding the field itself (spec §4). Idempotency keys and
// digests are computed exclusively over the canonical-json-v1 form.
export function computeCanonicalArgsDigest(request) {
  const { canonicalArgsDigest, ...rest } = request ?? {};
  void canonicalArgsDigest;
  return canonicalDigest(rest);
}

// ---- pure statement extraction (no producer semantics) ----------------------

function firstString(source, keys) {
  for (const key of keys) {
    const value = source?.[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return null;
}

function readSpan(span, statement) {
  if (
    span && Number.isInteger(span.start) && Number.isInteger(span.end) &&
    span.start >= 0 && span.end >= span.start && span.end <= statement.length
  ) {
    return { start: span.start, end: span.end };
  }
  return { start: 0, end: statement.length };
}

function normalizeEvidenceLink(raw) {
  if (!raw || typeof raw !== 'object') throw new NeedsInput('evidence citation must be an object');
  if (typeof raw.claimId !== 'string' || !/^clm-[a-z0-9][a-z0-9-]{0,62}$/.test(raw.claimId)) {
    throw new NeedsInput('citation without a well-formed claim identity');
  }
  const link = {
    claimId: raw.claimId,
    claimRevision: Number.isInteger(raw.claimRevision) && raw.claimRevision >= 1 ? raw.claimRevision : 1,
  };
  if (typeof raw.segmentId === 'string' && raw.segmentId.length > 0) link.segmentId = raw.segmentId;
  if (raw.span && Number.isInteger(raw.span.start) && Number.isInteger(raw.span.end)) {
    link.span = { start: raw.span.start, end: raw.span.end };
  }
  if (typeof raw.quoteDigest === 'string' && raw.quoteDigest.length > 0) link.quoteDigest = raw.quoteDigest;
  if (raw.evidenceMapId !== undefined) link.evidenceMapId = raw.evidenceMapId ?? null;
  if (raw.entryIndex !== undefined) link.entryIndex = raw.entryIndex ?? null;
  return link;
}

// Canonical evidence-link adapter for the FROZEN S2-005 evidence-map schema
// (contracts/evidence-map.schema.json): entries carry snake_case
// claim_id/claim_revision plus optional segment_id/span/quote_digest. They
// are projected onto the semantic-verification-item evidence-link contract.
const CLAIM_ID = /^clm-[a-z0-9][a-z0-9-]{0,62}$/;

function canonicalEntryLink(entry, index) {
  if (!entry || typeof entry !== 'object') throw new NeedsInput(`evidence_map entry ${index} is not an object`);
  if (typeof entry.claim_id !== 'string' || !CLAIM_ID.test(entry.claim_id)) {
    throw new NeedsInput(`evidence_map entry ${index} exposes no well-formed canonical claim_id`);
  }
  const link = {
    claimId: entry.claim_id,
    claimRevision: Number.isInteger(entry.claim_revision) && entry.claim_revision >= 1 ? entry.claim_revision : 1,
  };
  if (typeof entry.segment_id === 'string' && entry.segment_id.length > 0) link.segmentId = entry.segment_id;
  if (entry.span && Number.isInteger(entry.span.start) && Number.isInteger(entry.span.end)) {
    link.span = { start: entry.span.start, end: entry.span.end };
  }
  if (typeof entry.quote_digest === 'string' && entry.quote_digest.length > 0) link.quoteDigest = entry.quote_digest;
  return link;
}

function canonicalCardStatement(card) {
  // Frozen hypothesis-card.schema.json: the atomic checkable proposition is
  // the proposed_relation triple; nodes[]/counterevidence[] are citations.
  const relation = card?.proposed_relation;
  if (
    !relation || typeof relation !== 'object' ||
    typeof relation.subject !== 'string' || relation.subject.length === 0 ||
    typeof relation.predicate !== 'string' || relation.predicate.length === 0 ||
    typeof relation.object !== 'string' || relation.object.length === 0
  ) {
    throw new NeedsInput('hypothesis_card exposes no proposed_relation (subject/predicate/object) triple');
  }
  const statement = `${relation.subject} ${relation.predicate} ${relation.object}`;
  const evidenceLinks = [];
  for (const node of Array.isArray(card.nodes) ? card.nodes : []) {
    if (typeof node?.claim_id !== 'string' || !CLAIM_ID.test(node.claim_id)) {
      throw new NeedsInput(`hypothesis_card node exposes no well-formed canonical claim_id`);
    }
    evidenceLinks.push({
      claimId: node.claim_id,
      claimRevision: Number.isInteger(node.revision) && node.revision >= 1 ? node.revision : 1,
    });
  }
  for (const counterevidence of Array.isArray(card.counterevidence) ? card.counterevidence : []) {
    if (typeof counterevidence?.claim_id !== 'string' || !CLAIM_ID.test(counterevidence.claim_id)) {
      throw new NeedsInput('hypothesis_card counterevidence exposes no well-formed canonical claim_id');
    }
    evidenceLinks.push({ claimId: counterevidence.claim_id, claimRevision: 1 });
  }
  return { statement, span: readSpan(undefined, statement), evidenceLinks };
}

// Atomic checkable statements per artifact kind. Pure projection of the
// CANONICAL producer form defined by the frozen contracts (the single source
// of truth — there is no second internal format, review P1-1):
//   claim            (S2-004) -> normalized_text/original_text statement
//   evidence_map     (S2-005) -> the map-level statement + entries[] links
//   hypothesis_card  (S2-005) -> the proposed_relation triple + node links
//   synthesis_result (S2-005) -> the embedded evidence_maps[] + hypothesis_cards[]
function extractStatements(kind, payload) {
  switch (kind) {
    case 'claim': {
      // Canonical claims carry normalized_text/original_text and NO citations
      // field; citation checks therefore abstain deterministically (probe E).
      const statement = firstString(payload, ['statement', 'normalized_text', 'original_text']);
      if (statement === null) throw new NeedsInput('claim payload exposes no statement text');
      const citations = Array.isArray(payload.citations)
        ? payload.citations
        : Array.isArray(payload.evidence) ? payload.evidence : [];
      return [{ statement, span: readSpan(payload.span, statement), evidenceLinks: citations.map(normalizeEvidenceLink) }];
    }
    case 'evidence_map': {
      // entries[].statement was never canonical: the map-level statement is
      // the single checkable unit and entries[] are its citations.
      const statement = firstString(payload, ['statement']);
      if (statement === null) throw new NeedsInput('evidence_map payload exposes no map-level statement text');
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      if (entries.length === 0) throw new NeedsInput('evidence_map payload exposes no entries');
      return [{
        statement,
        span: readSpan(payload.span, statement),
        evidenceLinks: entries.map(canonicalEntryLink),
      }];
    }
    case 'hypothesis_card': {
      return [canonicalCardStatement(payload)];
    }
    case 'synthesis_result': {
      const statements = [];
      for (const map of Array.isArray(payload.evidence_maps) ? payload.evidence_maps : []) {
        statements.push(...extractStatements('evidence_map', map));
      }
      for (const card of Array.isArray(payload.hypothesis_cards) ? payload.hypothesis_cards : []) {
        statements.push(canonicalCardStatement(card));
      }
      if (statements.length === 0) {
        throw new NeedsInput('synthesis_result payload exposes no embedded evidence_maps or hypothesis_cards');
      }
      return statements;
    }
    default:
      throw new ContractVersionUnknown(`unsupported artifact kind: ${kind}`);
  }
}

// ---- verification (pure compute) --------------------------------------------

function requireRequestGate(request) {
  if (!request || typeof request !== 'object') throw new NeedsInput('verification request missing');
  if (request.contractVersion !== CONTRACT_VERSION) {
    throw new ContractVersionUnknown(`unsupported contractVersion ${String(request.contractVersion)}; expected ${CONTRACT_VERSION}`);
  }
  verifierValidators().requireValid('semantic-verification-request', request);
  if (computeCanonicalArgsDigest(request) !== request.canonicalArgsDigest) {
    throw new VerifierPolicyBlock('exact-args gate: canonicalArgsDigest does not match the canonical-json-v1 request payload');
  }
}

async function evaluateItem({ request, checkName, statement, statementIndex, span, evidenceLinks, options }) {
  const validators = verifierValidators();
  const itemId = `svi-${sha256HexText([request.requestId, statementIndex, checkName].join('\u0000')).slice(0, 24)}`;
  const item = {
    contractVersion: CONTRACT_VERSION,
    itemId,
    statement,
    spanRef: { quoteDigest: sha256HexText(statement), start: span.start, end: span.end },
    criterion: checkName,
    goldLabel: options.goldLabels?.[statementIndex] ?? null,
    predictedLabel: 'INSUFFICIENT_EVIDENCE',
    verdict: 'INSUFFICIENT_EVIDENCE',
    reasonCodes: [],
    evidenceLinks,
    missingness: { kind: 'none' },
    provenance: {
      runId: options.provenance?.runId ?? `run-sv-${request.requestId.slice(4)}`,
      implementationDigest: options.provenance?.implementationDigest,
      corpusVersion: request.corpusVersion,
      rubricVersion: request.rubricVersion,
      asOf: request.asOf,
    },
  };
  if (item.provenance.implementationDigest === undefined) delete item.provenance.implementationDigest;

  const finalizeMissingness = (missingness) => {
    item.missingness = missingness;
    item.verdict = 'INSUFFICIENT_EVIDENCE';
    item.predictedLabel = item.verdict;
    const reason = reasonCodeForMissingness(missingness.kind);
    if (!item.reasonCodes.includes(reason)) item.reasonCodes.push(reason);
  };

  // Deterministic abstention: a citation check without any cited span can
  // never be entailed by persuasive output (probe E); skip the checker.
  if (CITATION_CHECKS.has(checkName) && evidenceLinks.length === 0) {
    item.verdict = 'INSUFFICIENT_EVIDENCE';
    item.predictedLabel = item.verdict;
    if (!item.reasonCodes.includes('missing_citation')) item.reasonCodes.push('missing_citation');
    validators.requireValid('semantic-verification-item', item);
    return { item, citationAbstention: true };
  }

  try {
    const outcome = await options.checker.check({
      criterion: checkName,
      statement,
      spanRef: item.spanRef,
      evidenceLinks,
      asOf: request.asOf,
      artifactKind: request.artifact.kind,
    });
    const verdict = typeof outcome === 'string' ? outcome : outcome?.verdict;
    if (typeof verdict !== 'string' || !VERDICT_LABELS.includes(verdict)) {
      finalizeMissingness({ kind: 'evaluator_missing', detail: 'checker returned a verdict outside the bounded enum' });
      validators.requireValid('semantic-verification-item', item);
      return { item, citationAbstention: false };
    }
    item.verdict = verdict;
    item.predictedLabel = verdict;
    if (typeof outcome === 'object' && outcome !== null) {
      if (Array.isArray(outcome.reasonCodes)) {
        for (const code of outcome.reasonCodes) {
          if (!REASON_CODES.includes(code)) {
            finalizeMissingness({ kind: 'evaluator_missing', detail: `checker returned unknown reason code ${String(code)}` });
            validators.requireValid('semantic-verification-item', item);
            return { item, citationAbstention: false };
          }
          if (!item.reasonCodes.includes(code)) item.reasonCodes.push(code);
        }
      }
      if (outcome.uncertainty !== undefined && outcome.uncertainty !== null) {
        const u = outcome.uncertainty;
        if (
          (u.kind === 'aleatoric' || u.kind === 'epistemic') &&
          typeof u.value === 'number' && u.value >= 0 && u.value <= 1
        ) {
          item.uncertainty = { kind: u.kind, value: u.value };
        } else {
          finalizeMissingness({ kind: 'evaluator_missing', detail: 'checker returned malformed uncertainty' });
          validators.requireValid('semantic-verification-item', item);
          return { item, citationAbstention: false };
        }
      }
    }
  } catch (error) {
    // Spec §5 / probe P: an exception, timeout or unavailable source never
    // becomes a semantic pass/fail — typed missingness instead.
    finalizeMissingness(missingnessForError(error));
    validators.requireValid('semantic-verification-item', item);
    return { item, citationAbstention: false };
  }

  // Deterministic staleness rules (spec §7): stale/future/revoked evidence
  // invalidates the dependent verdict even when the text looks similar.
  const asOfMs = Date.parse(request.asOf);
  for (const link of evidenceLinks) {
    const source = options.sourceIndex?.[link.segmentId ?? link.claimId];
    if (!source) continue;
    let reason = null;
    if (source.publishedAt !== undefined && Number.isFinite(asOfMs) && Date.parse(source.publishedAt) > asOfMs) reason = 'future_source';
    else if (source.accessState === 'tombstoned' || source.accessState === 'revoked') reason = 'revoked_source';
    else if (source.stale === true) reason = 'stale_source';
    if (reason) {
      item.verdict = 'STALE_INPUT';
      item.predictedLabel = item.verdict;
      if (!item.reasonCodes.includes(reason)) item.reasonCodes.push(reason);
      break;
    }
  }

  validators.requireValid('semantic-verification-item', item);
  return { item, citationAbstention: false };
}

async function verifyArtifact(request, options = {}) {
  requireRequestGate(request);

  // ACL before any text/span read (spec §10): no ACL provider configured is
  // a default deny, not an implicit allow.
  const acl = options.acl;
  if (!acl || typeof acl.can !== 'function') {
    throw new AclDenied('ACL provider not configured; verifier default-denies');
  }
  const allowed = acl.can(
    request.actor,
    'verify',
    {
      kind: request.artifact.kind,
      artifactId: request.artifact.artifactId,
      revision: request.artifact.revision,
      workspaceId: request.workspaceId,
      grantRef: request.aclGrantRef,
    },
  );
  if (!allowed) {
    throw new AclDenied(`actor ${request.actor} has no verify capability over ${request.artifact.kind} ${request.artifact.artifactId}@${request.artifact.revision}`);
  }

  if (!options.checker || typeof options.checker.check !== 'function') {
    throw new NeedsInput('no semantic checker injected (options.checker.check)');
  }
  const digests = options.digests ?? {};
  for (const key of ['rubricDigest', 'corpusManifestDigest', 'thresholdsDigest']) {
    if (typeof digests[key] !== 'string' || !HEX64.test(digests[key])) {
      throw new NeedsInput(`missing exact ${key}; verifier refuses implicit defaults`);
    }
  }

  // Exact upstream revision binding (spec §5): read the exact digest the
  // request named, never "latest".
  const artifact = options.artifact;
  if (!artifact || typeof artifact !== 'object' || !artifact.payload) {
    throw new NeedsInput('exact artifact payload not provided (options.artifact.payload)');
  }
  if (
    artifact.kind !== request.artifact.kind ||
    artifact.artifactId !== request.artifact.artifactId ||
    (artifact.revision ?? 1) !== request.artifact.revision
  ) {
    throw new StaleInput('artifact identity differs from the exact revision named by the request');
  }
  const payloadDigest = canonicalDigest(artifact.payload);
  if (payloadDigest !== request.artifact.digest) {
    throw new StaleInput(`artifact digest mismatch: request bound ${request.artifact.digest}, payload hashes to ${payloadDigest}`);
  }
  // fix2-C finding 2: fail-closed frozen-schema validation BEFORE any
  // statement extraction — a payload without contractVersion, with extra
  // fields or missing required members never reaches READY_FOR_HUMAN_REVIEW.
  requireValidArtifactPayload(request.artifact.kind, artifact.payload);

  const statements = extractStatements(request.artifact.kind, artifact.payload);
  const validators = verifierValidators();
  const items = [];
  const abstentions = [];
  for (const [statementIndex, s] of statements.entries()) {
    for (const checkName of request.requestedChecks) {
      const { item, citationAbstention } = await evaluateItem({
        request, checkName, statement: s.statement, statementIndex, span: s.span, evidenceLinks: s.evidenceLinks, options,
      });
      items.push(item);
      if (citationAbstention) {
        abstentions.push({
          itemId: item.itemId,
          scope: 'item',
          reason: 'NO_CITATION',
          detail: 'statement carries no cited spans; deterministic abstention',
        });
      } else if (item.missingness.kind !== 'none') {
        const reasonByKind = {
          source_unavailable: 'SOURCE_UNAVAILABLE',
          evaluator_missing: 'EVALUATOR_MISSING',
          timeout: 'TIMEOUT',
          policy_refusal: 'POLICY_BLOCK',
          budget_exhausted: 'BUDGET_EXHAUSTED',
        };
        abstentions.push({
          itemId: item.itemId,
          scope: 'item',
          reason: reasonByKind[item.missingness.kind],
          detail: String(item.missingness.detail ?? 'typed missingness').slice(0, 1024),
        });
      }
    }
  }

  const disagreements = [];
  for (const item of items) {
    if (item.goldLabel !== null && item.goldLabel !== item.verdict) {
      disagreements.push({
        itemId: item.itemId,
        goldLabel: item.goldLabel,
        predictedLabel: item.verdict,
        annotationSetIds: options.annotationSetIds ?? [],
        adjudicationRequired: true,
      });
    }
  }

  const evaluated = items.filter((item) => item.missingness.kind === 'none').length;
  const result = {
    contractVersion: CONTRACT_VERSION,
    resultId: options.resultId ?? `sres-${request.canonicalArgsDigest.slice(0, 24)}`,
    requestRef: request.requestId,
    inputDigests: {
      artifactDigest: request.artifact.digest,
      rubricDigest: digests.rubricDigest,
      corpusManifestDigest: digests.corpusManifestDigest,
      thresholdsDigest: digests.thresholdsDigest,
      canonicalArgsDigest: request.canonicalArgsDigest,
    },
    outputDigest: null,
    items,
    disagreements,
    criticalFindings: [],
    abstentions,
    coverage: { denominator: items.length, evaluated, missing: items.length - evaluated },
    independenceProfileRef: options.independenceProfileRef ?? 'ind-unverified',
    humanDecisionRequired: true,
    status: items.length - evaluated > 0 ? 'INCOMPLETE' : 'READY_FOR_HUMAN_REVIEW',
  };
  // Self-excluding output digest (contract §4): digest over the canonical
  // form with outputDigest set to null.
  result.outputDigest = canonicalDigest(result);
  validators.requireValid('semantic-verification-result', result);
  return { result };
}

export function verifyClaim(request, options) {
  return verifyArtifact(request, options);
}

export function verifyEvidenceMap(request, options) {
  return verifyArtifact(request, options);
}

export function verifyHypothesisCard(request, options) {
  return verifyArtifact(request, options);
}

export function verifySynthesisResult(request, options) {
  return verifyArtifact(request, options);
}

// ---- query API (read-only, ACL-enforced — spec §10, review P1-3) -----------

// Read authorization over the SAME server-enforced policy matrix as every
// other surface. `authorities` is the makeVerifierAuthorityRegistry product
// (Map: principal -> { roles: Set, workspaces: Set }). Missing actor/workspace
// or missing enforcement is a LOUD typed denial — legacy un-attributed reads
// must fail, never silently return records (review P1-3).
function authorizeRead({ actor, workspaceId, authorities, resourceType, resourceRef }) {
  if (
    typeof actor !== 'string' || actor.length === 0 ||
    typeof workspaceId !== 'string' || workspaceId.length === 0
  ) {
    throw new AclDenied('read API requires the reading actor and workspace; un-attributed reads are refused loudly, never answered with a global projection');
  }
  const entry = authorities instanceof Map ? authorities.get(actor) : null;
  if (!entry) {
    throw new AclDenied(`actor ${actor} has no authority registry entry; read denied by default`);
  }
  const roles = [...entry.roles];
  const workspaces = [...entry.workspaces];
  const allowed = roles.some((role) => policyCheck(
    actor,
    role,
    'read',
    { type: resourceType, workspaceId, recordId: resourceRef },
    { workspaces },
  ).allowed);
  if (!allowed) {
    throw new AclDenied(`actor ${actor} holds no read capability over ${resourceType} in workspace ${workspaceId}`);
  }
}

export async function getVerificationResult(store, { actor, workspaceId, resultId, authorities } = {}) {
  if (!store || typeof store.getRecord !== 'function') {
    throw new NeedsInput('getVerificationResult requires a verifier store with getRecord()');
  }
  if (typeof resultId !== 'string' || resultId.length === 0) throw new NeedsInput('resultId required');
  authorizeRead({ actor, workspaceId, authorities, resourceType: 'verification_result', resourceRef: resultId });
  // fix2-C finding 1: the query API is ASYNC over BOTH stores — every store
  // access is awaited (the old synchronous call tested a Promise, skipped
  // the ACL check and handed the caller a Promise of the private record).
  // Workspace-scoped selection: a record that exists but lives in another
  // workspace is an ACL denial, never an empty miss (review P1-3).
  const record = await store.getRecord('result', resultId, { workspaceId });
  if (record === null) return null;
  // ACL is enforced over the RESULT before anything is returned: derived
  // results inherit the strictest-of-inputs ACL as store-level metadata
  // (never inside the contract payload); a private inherited ACL is
  // readable only by the named principals.
  const recordAcl = typeof store.getRecordAcl === 'function' ? await store.getRecordAcl('result', resultId) : null;
  if (recordAcl && recordAcl.visibility === 'private') {
    const allowed = Array.isArray(recordAcl.allowedPrincipalIds) ? recordAcl.allowedPrincipalIds : [];
    if (!allowed.includes(actor)) {
      throw new AclDenied(`result ${resultId} inherited a private ACL (strictest of its inputs); actor ${actor} is not among the allowed principals`);
    }
  }
  return record;
}

export async function listCalibrationReports(store, filter = {}) {
  if (!store || typeof store.listCalibrationReports !== 'function') {
    throw new NeedsInput('listCalibrationReports requires a verifier store with listCalibrationReports()');
  }
  const { actor, workspaceId, authorities, corpusVersion } = filter ?? {};
  authorizeRead({ actor, workspaceId, authorities, resourceType: 'calibration_report', resourceRef: null });
  // Strictly workspace-scoped listing (async, fix2-C finding 1); the store
  // also fails loudly when the workspace binding is missing.
  const reports = await store.listCalibrationReports({
    workspaceId,
    ...(corpusVersion !== undefined ? { corpusVersion } : {}),
  });
  // fix2-C finding 1: a privately-inherited report never appears in a
  // listing for an actor outside its allow-list (same rule as direct reads).
  const visible = [];
  for (const report of reports) {
    const recordAcl = typeof store.getRecordAcl === 'function' && typeof report?.reportId === 'string'
      ? await store.getRecordAcl('calibration_report', report.reportId)
      : null;
    if (recordAcl && recordAcl.visibility === 'private') {
      const allowed = Array.isArray(recordAcl.allowedPrincipalIds) ? recordAcl.allowedPrincipalIds : [];
      if (!allowed.includes(actor)) continue;
    }
    visible.push(report);
  }
  return visible;
}

// ---- static leak audit (read-only, probe G/H/Q) ------------------------------

// Static, read-only audit of a verifier run record for the hard-fail leak
// classes of spec §3/§10: locked-label access before unseal (or by a
// candidate at any time), candidate/producer access to adjudication,
// private span/count content leaked into the shared projection, and
// post-as_of sources. Zero mutations; findings never echo the private
// marker content itself.
export function auditVerifierRunForLeaks(runRecord, context = {}) {
  const findings = [];
  const run = runRecord ?? {};
  const unsealAt = context.unsealAt ?? run.unsealAt ?? null;
  const roleOf = (entry) => entry.role ?? context.roleByPrincipal?.[entry.principalId] ?? null;
  const isProducerSide = (entry) => {
    const role = roleOf(entry);
    return role === 'candidate' || role === 'producer' ||
      (Array.isArray(context.producerPrincipals) && context.producerPrincipals.includes(entry.principalId));
  };

  for (const access of run.lockedLabelAccess ?? []) {
    if (isProducerSide(access)) {
      findings.push({
        code: 'locked_label_access',
        hardFail: true,
        detail: `principal ${access.principalId} holds candidate/producer role and accessed locked labels`,
      });
      continue;
    }
    if (!unsealAt || String(access.at) < String(unsealAt)) {
      findings.push({
        code: 'locked_label_access',
        hardFail: true,
        detail: `locked labels accessed at ${access.at} before unseal (${unsealAt ?? 'never unsealed'})`,
      });
    }
  }

  for (const access of run.adjudicationAccess ?? []) {
    if (isProducerSide(access)) {
      findings.push({
        code: 'producer_self_review',
        hardFail: true,
        detail: `principal ${access.principalId} with role ${roleOf(access) ?? 'unknown'} read adjudication records`,
      });
    }
  }

  if (run.shared !== undefined && run.shared !== null) {
    const serialized = canonicalize(run.shared);
    const markers = context.privateMarkers ?? run.privateMarkers ?? [];
    markers.forEach((marker, index) => {
      if (typeof marker === 'string' && marker.length > 0 && serialized.includes(marker)) {
        findings.push({
          code: 'private_leak',
          hardFail: true,
          detail: `shared projection contains private marker #${index} (content withheld from this report)`,
        });
      }
    });
  }

  const asOf = run.asOf ?? context.asOf ?? null;
  if (typeof asOf === 'string' && asOf.length > 0) {
    for (const source of run.inputSources ?? []) {
      if (typeof source.publishedAt === 'string' && String(source.publishedAt) > String(asOf)) {
        findings.push({
          code: 'post_as_of_source',
          hardFail: true,
          detail: `source ${source.sourceId} published ${source.publishedAt} after asOf ${asOf}`,
        });
      }
    }
  }

  return { ok: findings.length === 0, findings };
}
