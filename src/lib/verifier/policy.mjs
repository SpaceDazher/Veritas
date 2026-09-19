// S2-006 server-enforced role/access matrix (spec §3, §10).
//
// Trust model in one file: roles, resource types and the capability matrix
// are declared here, closed, and enforced fail-closed. The engine decides
// ONLY over structural fields (principal ids, role sets, resource ids,
// digests, sealed/unsealed flags, workspace ids). Source text, labels and
// model output are untrusted data (spec §10): a resource may carry an
// `untrusted` blob (prompt-injection probe J) and the engine is specified to
// never read it — decisions are byte-identical with and without it.
//
// Conflict-of-interest is identity-based (spec §3): a principal that also
// holds a producer-side role (candidate/producer/verifier_operator) can never
// exercise annotator or adjudicator capabilities, and one actor can never
// adjudicate a case it annotated (or annotate a case it adjudicated).
//
// Private-node invisibility (spec §10): for an unauthorized actor the
// private projection drops content AND counts — a private node never appears
// in a count, metric, prompt, trace, error, snippet or report (probe G).
//
// Determinism: enforce() has no clock and no randomness. Unseal gating is by
// explicit structural flags (resource.unsealed, context.unsealDecisionRef),
// never by wall-clock comparison. Denials throw the typed AclDenied error.

import { AclDenied } from './errors.mjs';

export const ROLES = Object.freeze([
  'candidate',
  'label_custodian',
  'annotator',
  'adjudicator',
  'evaluation_harness',
  'reviewer',
]);

// Core S2-006 resource types (spec §4 grant/capability surface).
export const RESOURCE_TYPES = Object.freeze([
  'annotation_set',
  'adjudication_record',
  'locked_label',
  'verification_result',
  'calibration_report',
  'verifier_run',
  'corpus_case',
]);

// Producer artifact kinds guarded by the compute/query API (api.mjs calls
// its ACL provider with the artifact kind). They are part of the same
// matrix so probes can route every real call through policy.enforce; any
// resource type outside these lists is denied.
export const ARTIFACT_RESOURCE_TYPES = Object.freeze([
  'claim',
  'evidence_map',
  'hypothesis_card',
  'synthesis_result',
]);

export const ACTIONS = Object.freeze([
  'read', 'write', 'submit', 'annotate', 'adjudicate', 'compare',
  'unseal', 'publish', 'verify', 'invalidate',
]);

// role -> resourceType -> allowed actions. The matrix is the ONLY allow
// source; everything not listed is denied (fail-closed).
const MATRIX = Object.freeze({
  candidate: {
    // spec §3: candidate submits predictions and reads its OWN runs; it can
    // never read locked labels (not even after unseal), annotations or
    // adjudications.
    verifier_run: ['read', 'submit'],
    corpus_case: ['read'],
    claim: ['read', 'submit'],
    evidence_map: ['read', 'submit'],
    hypothesis_card: ['read', 'submit'],
    synthesis_result: ['read', 'submit'],
  },
  label_custodian: {
    // custody of split secrets; unseal requires an immutable HumanDecision
    // reference (spec §8) supplied in the context.
    locked_label: ['read', 'write', 'unseal'],
    corpus_case: ['read'],
    annotation_set: ['read'],
    calibration_report: ['invalidate'],
  },
  annotator: {
    // reads the blind case, writes its own label set; never locked labels,
    // never adjudication (same case) — enforced as conflict-of-interest.
    corpus_case: ['read'],
    annotation_set: ['read', 'annotate'],
  },
  adjudicator: {
    // reads conflicting label sets, writes adjudication records.
    corpus_case: ['read'],
    annotation_set: ['read'],
    adjudication_record: ['read', 'adjudicate'],
  },
  evaluation_harness: {
    // isolated comparator/calibration process: reads sealed runs, and locked
    // labels ONLY after unseal (resource.unsealed === true).
    locked_label: ['read'],
    verifier_run: ['read', 'compare'],
    annotation_set: ['read'],
    adjudication_record: ['read'],
    verification_result: ['read', 'write', 'publish'],
    calibration_report: ['read', 'write', 'publish'],
    corpus_case: ['read'],
    claim: ['read', 'verify'],
    evidence_map: ['read', 'verify'],
    hypothesis_card: ['read', 'verify'],
    synthesis_result: ['read', 'verify'],
  },
  reviewer: {
    // read everything for human review; locked labels only after unseal.
    verification_result: ['read'],
    calibration_report: ['read', 'invalidate'],
    verifier_run: ['read'],
    adjudication_record: ['read'],
    annotation_set: ['read'],
    corpus_case: ['read'],
    locked_label: ['read'],
  },
});

// Producer-side roles: holding any of these while exercising annotator or
// adjudicator capabilities is a conflict of interest (spec §3, probes I/R).
export const PRODUCER_SIDE_ROLES = Object.freeze(['candidate', 'producer', 'verifier_operator']);
const LABELING_ROLES = Object.freeze(['annotator', 'adjudicator']);

const KNOWS = (role, type, action) => Boolean(MATRIX[role]?.[type]?.includes(action));

function deny(code, reason) {
  return { allowed: false, code, reason };
}

function denyThrow(failure) {
  const error = new AclDenied(`${failure.code}: ${failure.reason}`);
  error.policyCode = failure.code;
  throw error;
}

function structuralIdentity(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

// Pure, structural decision. Returns { allowed: true } or a typed denial —
// never throws, never reads resource.untrusted / context.untrusted.
export function check(actor, role, action, resource, context = {}) {
  if (!structuralIdentity(actor)) return deny('unknown_actor', 'actor must be a non-empty principal id');
  if (!ROLES.includes(role)) return deny('unknown_role', `role ${String(role)} is outside the S2-006 role set`);
  if (!ACTIONS.includes(action)) return deny('unknown_action', `action ${String(action)} is outside the action vocabulary`);
  const type = structuralIdentity(resource?.type);
  if (!type) return deny('unknown_resource_type', 'resource.type is required');
  const known = RESOURCE_TYPES.includes(type) || ARTIFACT_RESOURCE_TYPES.includes(type);
  if (!known) return deny('unknown_resource_type', `resource type ${type} is outside the S2-006 resource set`);
  if (!KNOWS(role, type, action)) {
    return deny('capability_absent', `role ${role} has no ${action} capability over ${type}`);
  }

  // Workspace binding (S2-002 authenticated subjects carry workspaces).
  const workspaces = Array.isArray(context.workspaces) ? context.workspaces : null;
  if (workspaces !== null && typeof resource.workspaceId === 'string') {
    if (!workspaces.includes(resource.workspaceId)) {
      return deny('workspace_mismatch', `actor ${actor} holds no authority in workspace ${resource.workspaceId}`);
    }
  }

  // Ownership: candidate touches only its own runs/predictions/artifacts;
  // annotators read back only their own annotation sets.
  const requiresOwn =
    (role === 'candidate' && (type === 'verifier_run' || ARTIFACT_RESOURCE_TYPES.includes(type))) ||
    (role === 'annotator' && type === 'annotation_set');
  if (requiresOwn && resource.ownerId !== actor) {
    return deny('not_owner', `role ${role} may only access its own ${type}`);
  }

  // Sealing gate for locked labels (spec §3/§8): read before unseal is
  // denied for everyone except the custodian holding split custody.
  if (type === 'locked_label' && action === 'read' && role !== 'label_custodian') {
    if (resource.unsealed !== true) {
      return deny('locked_label_sealed', 'locked labels are sealed before the unseal HumanDecision');
    }
  }
  // Unseal is a custody operation bound to an immutable HumanDecision
  // reference over the exact study+thresholds digest (spec §8).
  if (type === 'locked_label' && action === 'unseal') {
    if (typeof context.unsealDecisionRef !== 'string' || context.unsealDecisionRef.length === 0) {
      return deny('unseal_decision_missing', 'unseal requires an immutable HumanDecision reference');
    }
  }

  // Conflict of interest (identity-based, structural): producer-side
  // principals can never label or adjudicate (probes I/R).
  if (LABELING_ROLES.includes(role)) {
    const roles = Array.isArray(context.roles) ? context.roles : [role];
    const clash = roles.find((r) => PRODUCER_SIDE_ROLES.includes(r));
    if (clash) {
      return deny('conflict_of_interest', `actor also holds producer-side role ${clash}; labeling/adjudication refused`);
    }
    // One actor, one side of the same case (probe R).
    const caseId = structuralIdentity(resource.caseId);
    if (role === 'adjudicator' && caseId && Array.isArray(context.annotatedCases) && context.annotatedCases.includes(caseId)) {
      return deny('annotator_cannot_adjudicate_same_case', `actor annotated ${caseId} and can never adjudicate it`);
    }
    if (role === 'annotator' && caseId && Array.isArray(context.adjudicatedCases) && context.adjudicatedCases.includes(caseId)) {
      return deny('adjudicator_cannot_annotate_same_case', `actor adjudicated ${caseId} and can never annotate it`);
    }
  }

  return { allowed: true, code: 'capability_granted' };
}

// Throwing form: returns the resource reference on allow, throws the typed
// AclDenied on any denial. The `untrusted` fields are ignored by contract
// (probe J): they are accepted as input so callers can pass hostile payloads
// verbatim, and decisions are identical to the sanitized call.
export function enforce(actor, role, action, resource, context = {}) {
  const decision = check(actor, role, action, resource, context);
  if (!decision.allowed) denyThrow(decision);
  return { allowed: true, code: decision.code, resourceType: resource?.type ?? null, action };
}

// Matrix projection for introspection/tests; frozen copy, no live reference.
export function capabilitiesFor(role) {
  if (!ROLES.includes(role)) {
    throw new AclDenied(`unknown role: ${String(role)}`);
  }
  const row = MATRIX[role] ?? {};
  return Object.freeze(Object.fromEntries(
    Object.entries(row).map(([type, actions]) => [type, Object.freeze([...actions])]),
  ));
}

function clone(value) {
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = clone(v);
    return out;
  }
  return value;
}

function redactClone(value) {
  if (Array.isArray(value)) return value.map(redactClone);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (/private/i.test(k)) {
        // a private node must not appear in a count either: no number, no
        // zero, only the typed absence marker
        out[k] = null;
        continue;
      }
      out[k] = redactClone(v);
    }
    return out;
  }
  return value;
}

// Private-node invisibility (spec §10, probe G). The projection for an
// unauthorized actor carries the public part only; private nodes contribute
// neither content nor counts. Redaction markers never echo the withheld
// content. The authorized projection is a frozen deep copy of both parts.
export function projectForActor(record, { authorized } = {}) {
  const shared = redactClone(record?.shared ?? {});
  if (authorized === true) {
    return Object.freeze({ aclScope: 'full', shared, private: clone(record?.private ?? {}) });
  }
  return Object.freeze({
    aclScope: 'public',
    shared,
    private: Object.freeze({ redacted: true, nodeCount: null, reason: 'acl_denied' }),
  });
}
