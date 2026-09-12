// Canonical offline policy entry point for S2-001 contract fixtures.
// This classifies structured requests; it is not runtime authorization.
export const policyVersion = 's2-001-fail-closed-v1';
const VERDICTS = Object.freeze({
  BLOCKED: 'BLOCKED',
  NEEDS_INPUT: 'NEEDS_INPUT',
  HUMAN_REVIEW: 'HUMAN_REVIEW',
  ELIGIBLE: 'ELIGIBLE_FOR_LOCAL_CHECK',
});
const OPERATIONS = new Set(['local_check', 'read', 'planning', 'terminal', 'authority', 'permission', 'capability', 'policy_change', 'rollout']);
const ACTOR_TYPES = new Set(['human', 'agent', 'service', 'unassigned']);
const STATUSES = new Set(['BACKLOG', 'READY', 'CLAIMED', 'RUNNING', 'BLOCKED', 'IN_REVIEW', 'DONE', 'FAILED', 'CANCELLED']);
const BUDGET_FIELDS = ['taskBudget', 'campaignBudget', 'dailyBudget'];
const REQUIRED_FIELDS = ['operation', 'policyVersion', 'contractVersion', 'frozenGoal', 'requestedGoal', 'frozenPolicy', 'requestedPolicy'];
const BOOLEAN_FLAG_FIELDS = [
  'finalApproval', 'authenticated', 'humanIdentityConfirmed', 'budgetApproved', 'sourcePresent',
  'sourceAuthorized', 'accessVerified', 'requiresSpend', 'requiresModel', 'requiresSource',
  'opinionAsFact', 'unsupportedCause', 'permissionChange', 'capabilityChange', 'policyChange',
  'rollout', 'rolloutRequested', 'researchRollout',
];
const HAZARD_FIELDS = [
  'absoluteBest', 'selfApproval', 'privateExport', 'sourceGrants', 'researchRollout',
  'activeLease', 'forgedCapability', 'expiredFence', 'crashed', 'emptyResponse',
  'agentDone', 'failedTests', 'adapterCriteria', 'selfGrant', 'duplicateEffect',
  'openDependency', 'cancelledWorker', 'unknownOutcome', 'crossUserRead', 'divergentRevision',
];
const KNOWN_FIELDS = new Set([
  'operation', 'policyVersion', 'contractVersion', 'status', 'finalApproval', 'actor', 'actorType', 'actorId',
  'authenticated', 'humanIdentityConfirmed', 'authorityBinding', 'grant', 'budgetGrant', 'sourceGrant', 'rolloutGrant',
  'artifactCount', 'artifactDigest', 'revision', 'aclRef', 'auditRef', 'coverage', 'budget', 'timeout', 'requiresSpend', 'budgetApproved',
  ...BUDGET_FIELDS, 'currency', 'requiresModel', 'model', 'accessVerified', 'requiresSource',
  'sourcePresent', 'sourceAuthorized', 'opinionAsFact', 'unsupportedCause',
  'permissionChange', 'capabilityChange', 'policyChange', 'rollout', 'rolloutRequested',
  'frozenGoal', 'requestedGoal', 'frozenPolicy', 'requestedPolicy', ...HAZARD_FIELDS,
]);
const BINDING_FIELDS = new Set(['bindingType', 'principalId', 'scope', 'grantRef', 'expiresAt']);
const GRANT_FIELDS = new Set(['type', 'authenticated', 'principalId', 'scope', 'grantRef', 'expiresAt']);
const BUDGET_GRANT_FIELDS = new Set([...GRANT_FIELDS, ...BUDGET_FIELDS, 'currency', 'timeout']);
const BUDGET_FIELDS_SET = new Set([...BUDGET_FIELDS, 'currency']);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const hasOnlyKeys = (value, allowed) => isObject(value) && Object.keys(value).every((key) => allowed.has(key));
const isPositiveString = (value) => typeof value === 'string' && value.trim().length > 0;
const isPositiveInteger = (value) => Number.isInteger(value) && value > 0;
const isFiniteNumber = (value) => typeof value === 'number' && Number.isFinite(value);
const isPositiveNumber = (value) => isFiniteNumber(value) && value > 0;
const isNonNegativeInteger = (value) => Number.isInteger(value) && value >= 0;
const isCoverage = (value) => isFiniteNumber(value) && value >= 0 && value <= 1;
const isCurrency = (value) => typeof value === 'string' && /^[A-Z]{3}$/.test(value);
const isBudget = (value) => hasOnlyKeys(value, BUDGET_FIELDS_SET) && BUDGET_FIELDS.every((key) => isPositiveNumber(value[key])) && isCurrency(value.currency);
const isTimeout = isPositiveNumber;
const isBinding = (value) => hasOnlyKeys(value, BINDING_FIELDS) && value.bindingType === 'server_authenticated_human' && isPositiveString(value.principalId) && isPositiveString(value.scope) && isPositiveString(value.grantRef) && isPositiveString(value.expiresAt);
const isGrant = (value, scope, extraFields = new Set()) => {
  const allowed = new Set([...GRANT_FIELDS, ...extraFields]);
  return hasOnlyKeys(value, allowed) && typeof scope === 'string' && value.type === `${scope}_grant` && value.authenticated === true && isPositiveString(value.principalId) && value.scope === scope && isPositiveString(value.grantRef) && isPositiveString(value.expiresAt);
};
const isBudgetGrant = (value) => hasOnlyKeys(value, BUDGET_GRANT_FIELDS) && isGrant(value, 'budget', new Set([...BUDGET_FIELDS, 'currency', 'timeout'])) && isBudget({taskBudget: value.taskBudget, campaignBudget: value.campaignBudget, dailyBudget: value.dailyBudget, currency: value.currency}) && isTimeout(value.timeout);

function addIssue(issues, level, code, message) {
  issues.push({level, code, message});
}

function validateNumbers(input, issues) {
  if (Object.hasOwn(input, 'artifactCount') && !isNonNegativeInteger(input.artifactCount)) {
    addIssue(issues, 'blocked', 'INVALID_ARTIFACT_COUNT', 'artifactCount must be a finite non-negative integer');
  }
  if (Object.hasOwn(input, 'coverage') && !isCoverage(input.coverage)) {
    addIssue(issues, 'blocked', 'INVALID_COVERAGE', 'coverage must be a finite number in [0,1]');
  }
  if (Object.hasOwn(input, 'timeout') && !isTimeout(input.timeout)) {
    addIssue(issues, 'blocked', 'INVALID_TIMEOUT', 'timeout must be a finite positive number');
  }
  if (Object.hasOwn(input, 'budget') && !isBudget(input.budget)) {
    addIssue(issues, 'blocked', 'INVALID_BUDGET', 'budget must contain positive finite task/campaign/daily amounts and a three-letter currency');
  }
  for (const field of BUDGET_FIELDS) {
    if (Object.hasOwn(input, field) && !isPositiveNumber(input[field])) {
      addIssue(issues, 'blocked', 'INVALID_BUDGET_FIELD', `${field} must be a finite positive number`);
    }
  }
  if (input.requiresSpend === true) {
    if (input.budgetApproved !== true) addIssue(issues, 'needs_input', 'BUDGET_NOT_APPROVED', 'spending requires an approved budget');
    if (!isCurrency(input.currency)) addIssue(issues, 'needs_input', 'CURRENCY_REQUIRED', 'currency is required for spending');
    if (!isTimeout(input.timeout)) addIssue(issues, 'needs_input', 'TIMEOUT_REQUIRED', 'a positive timeout is required for spending');
    if (!isPositiveString(input.actorId)) addIssue(issues, 'needs_input', 'ACTOR_ID_REQUIRED', 'spending requires an authenticated actor id');
    if (Object.hasOwn(input, 'budget')) {
      if (!isBudget(input.budget)) addIssue(issues, 'blocked', 'INVALID_BUDGET', 'budget is malformed');
    } else if (!BUDGET_FIELDS.every((field) => isPositiveNumber(input[field]))) {
      addIssue(issues, 'needs_input', 'BUDGET_REQUIRED', 'positive task, campaign and daily budgets are required');
    }
    if (input.budgetApproved === true && !isBudgetGrant(input.budgetGrant)) addIssue(issues, 'blocked', 'BUDGET_GRANT_REQUIRED', 'spending requires a typed authenticated budget grant');
    if (input.budgetApproved === true && isBudgetGrant(input.budgetGrant)) {
      if (input.budgetGrant.principalId !== input.actorId) addIssue(issues, 'blocked', 'BUDGET_GRANT_PRINCIPAL_MISMATCH', 'budget grant principal must match actorId');
      if (input.currency && input.budgetGrant.currency !== input.currency) addIssue(issues, 'blocked', 'BUDGET_GRANT_MISMATCH', 'budget grant currency does not match request');
      if (input.taskBudget > input.budgetGrant.taskBudget || input.campaignBudget > input.budgetGrant.campaignBudget || input.dailyBudget > input.budgetGrant.dailyBudget || input.timeout > input.budgetGrant.timeout) addIssue(issues, 'blocked', 'BUDGET_GRANT_EXCEEDED', 'requested spend or timeout exceeds the typed grant');
      if (input.campaignBudget < input.taskBudget || input.dailyBudget < input.taskBudget) addIssue(issues, 'blocked', 'BUDGET_HEADROOM_INVALID', 'campaign and daily budgets must cover the task budget');
    }
  }
}

/** Evaluate a structured policy request through the single production-facing entry point. */
export function evaluatePolicy(raw) {
  const issues = [];
  if (!isObject(raw)) {
    return {verdict: VERDICTS.BLOCKED, operation: null, issues: [{level: 'blocked', code: 'INVALID_INPUT', message: 'policy input must be an object'}]};
  }
  const unknown = Object.keys(raw).filter((key) => !KNOWN_FIELDS.has(key));
  if (unknown.length) addIssue(issues, 'blocked', 'UNKNOWN_FIELD', `unknown policy field(s): ${unknown.sort().join(', ')}`);

  for (const field of REQUIRED_FIELDS) {
    if (raw[field] === undefined) addIssue(issues, 'blocked', 'REQUIRED_FIELD_MISSING', `${field} is required for fail-closed evaluation`);
  }
  for (const field of [...BOOLEAN_FLAG_FIELDS, ...HAZARD_FIELDS]) {
    if (raw[field] !== undefined && typeof raw[field] !== 'boolean') addIssue(issues, 'blocked', `INVALID_${field.toUpperCase()}`, `${field} must be boolean`);
  }

  const operation = raw.operation;
  const privileged = raw.status === 'DONE' || raw.finalApproval === true || raw.permissionChange === true || raw.capabilityChange === true || raw.policyChange === true || raw.rollout === true || raw.rolloutRequested === true || raw.researchRollout === true;
  if (typeof operation !== 'string' || !OPERATIONS.has(operation)) {
    addIssue(issues, 'blocked', 'OPERATION_REQUIRED', 'operation must be an explicit supported operation type');
  }
  if (raw.policyVersion !== undefined && raw.policyVersion !== policyVersion) addIssue(issues, 'blocked', 'UNSUPPORTED_POLICY_VERSION', 'unsupported policy version');
  if (raw.contractVersion !== undefined && raw.contractVersion !== '1.0.0') addIssue(issues, 'blocked', 'UNSUPPORTED_CONTRACT_VERSION', 'unsupported contract version');
  if (raw.status !== undefined && !STATUSES.has(raw.status)) addIssue(issues, 'blocked', 'INVALID_STATUS', 'status is not a canonical task status');
  const actorType = raw.actorType ?? raw.actor;
  if (actorType !== undefined && !ACTOR_TYPES.has(actorType)) addIssue(issues, 'blocked', 'INVALID_ACTOR_TYPE', 'actorType must be human, agent, service or unassigned');
  if (raw.actor !== undefined && raw.actorType !== undefined && raw.actor !== raw.actorType) addIssue(issues, 'blocked', 'ACTOR_MISMATCH', 'actor and actorType disagree');
  if (raw.actorId !== undefined && !isPositiveString(raw.actorId)) addIssue(issues, 'blocked', 'INVALID_ACTOR_ID', 'actorId must be a non-empty string');
  for (const field of ['authenticated', 'humanIdentityConfirmed', 'finalApproval']) {
    if (raw[field] !== undefined && typeof raw[field] !== 'boolean') addIssue(issues, 'blocked', `INVALID_${field.toUpperCase()}`, `${field} must be boolean`);
  }
  if (raw.sourcePresent !== undefined && typeof raw.sourcePresent !== 'boolean') addIssue(issues, 'blocked', 'INVALID_SOURCE_FLAG', 'sourcePresent must be boolean');
  if (raw.sourceAuthorized !== undefined && typeof raw.sourceAuthorized !== 'boolean') addIssue(issues, 'blocked', 'INVALID_SOURCE_FLAG', 'sourceAuthorized must be boolean');
  if (raw.accessVerified !== undefined && typeof raw.accessVerified !== 'boolean') addIssue(issues, 'blocked', 'INVALID_ACCESS_FLAG', 'accessVerified must be boolean');
  if (raw.budgetApproved !== undefined && typeof raw.budgetApproved !== 'boolean') addIssue(issues, 'blocked', 'INVALID_BUDGET_FLAG', 'budgetApproved must be boolean');
  if (raw.authorityBinding !== undefined && !isBinding(raw.authorityBinding)) addIssue(issues, 'blocked', 'INVALID_AUTHORITY_BINDING', 'authorityBinding must be a confirmed server-authenticated human binding');
  if (raw.grant !== undefined && !isGrant(raw.grant, raw.grant && raw.grant.scope)) addIssue(issues, 'blocked', 'INVALID_GRANT', 'grant must be a typed, authenticated, scoped grant');
  if (raw.budgetGrant !== undefined && !isBudgetGrant(raw.budgetGrant)) addIssue(issues, 'blocked', 'INVALID_BUDGET_GRANT', 'budgetGrant must be a typed authenticated budget grant');
  if (raw.sourceGrant !== undefined && !isGrant(raw.sourceGrant, 'source')) addIssue(issues, 'blocked', 'INVALID_SOURCE_GRANT', 'sourceGrant must be a typed authenticated source grant');
  if (raw.rolloutGrant !== undefined && !isGrant(raw.rolloutGrant, 'rollout')) addIssue(issues, 'blocked', 'INVALID_ROLLOUT_GRANT', 'rolloutGrant must be a typed production rollout grant');

  validateNumbers(raw, issues);
  if (raw.frozenGoal && raw.requestedGoal && raw.frozenGoal !== raw.requestedGoal) addIssue(issues, 'blocked', 'GOAL_CHANGED', 'frozen goal changed');
  if (raw.frozenPolicy && raw.requestedPolicy && raw.frozenPolicy !== raw.requestedPolicy) addIssue(issues, 'blocked', 'POLICY_CHANGED', 'frozen policy changed');
  for (const field of HAZARD_FIELDS) if (raw[field] === true) addIssue(issues, 'blocked', field.toUpperCase(), `${field} is a hard policy violation`);

  if (['local_check', 'read', 'planning'].includes(operation) && ['finalApproval', 'permissionChange', 'capabilityChange', 'policyChange', 'rollout', 'rolloutRequested', 'researchRollout'].some((field) => raw[field] !== undefined)) addIssue(issues, 'blocked', 'UNRELATED_PRIVILEGED_FIELD', 'local/read/planning inputs cannot carry privileged operation fields');
  if (raw.permissionChange === true) {
    if (operation !== 'permission') addIssue(issues, 'blocked', 'PERMISSION_OPERATION_REQUIRED', 'permission changes require operation=permission');
    if (!isGrant(raw.grant, 'permission')) addIssue(issues, 'blocked', 'SEPARATE_GRANT_REQUIRED', 'permission changes require a separate authenticated grant');
  }
  if (raw.capabilityChange === true) {
    if (operation !== 'capability') addIssue(issues, 'blocked', 'CAPABILITY_OPERATION_REQUIRED', 'capability changes require operation=capability');
    if (!isGrant(raw.grant, 'capability')) addIssue(issues, 'blocked', 'SEPARATE_GRANT_REQUIRED', 'capability changes require a separate authenticated grant');
  }
  if (raw.policyChange === true) {
    if (operation !== 'policy_change') addIssue(issues, 'blocked', 'POLICY_OPERATION_REQUIRED', 'policy changes require operation=policy_change');
    if (!isGrant(raw.grant, 'policy_change')) addIssue(issues, 'blocked', 'SEPARATE_GRANT_REQUIRED', 'policy changes require a separate authenticated grant');
  }
  if (raw.rollout === true || raw.rolloutRequested === true || raw.researchRollout === true) {
    if (operation !== 'rollout') addIssue(issues, 'blocked', 'ROLLOUT_OPERATION_REQUIRED', 'rollout requires operation=rollout');
    if (!isGrant(raw.rolloutGrant, 'rollout')) addIssue(issues, 'blocked', 'ROLLOUT_BLOCKED', 'rollout requires a separate production grant');
  }
  if (operation === 'rollout' && !isGrant(raw.rolloutGrant, 'rollout')) addIssue(issues, 'blocked', 'ROLLOUT_BLOCKED', 'rollout operation requires a separate production grant');
  if (operation === 'permission' && !raw.permissionChange) addIssue(issues, 'blocked', 'PERMISSION_OPERATION_REQUIRED', 'permission operation requires permissionChange=true');
  if (operation === 'capability' && !raw.capabilityChange) addIssue(issues, 'blocked', 'CAPABILITY_OPERATION_REQUIRED', 'capability operation requires capabilityChange=true');
  if (operation === 'policy_change' && !raw.policyChange) addIssue(issues, 'blocked', 'POLICY_OPERATION_REQUIRED', 'policy_change operation requires policyChange=true');
  if (['terminal', 'authority', 'permission', 'capability', 'policy_change', 'rollout'].includes(operation) && (actorType !== 'human' || raw.authenticated !== true || raw.humanIdentityConfirmed !== true || !isBinding(raw.authorityBinding))) addIssue(issues, 'blocked', 'PRIVILEGED_OPERATION_AUTHORITY_REQUIRED', 'privileged operations require confirmed human identity and authority binding');
  if (raw.finalApproval === true) {
    if (!['terminal', 'authority'].includes(operation)) addIssue(issues, 'blocked', 'FINAL_APPROVAL_OPERATION_REQUIRED', 'final approval requires operation=terminal or authority');
    if (actorType !== 'human' || raw.authenticated !== true || raw.humanIdentityConfirmed !== true || !isBinding(raw.authorityBinding)) addIssue(issues, 'blocked', 'FINAL_APPROVAL_AUTHORITY_REQUIRED', 'final approval requires confirmed human identity and authority binding');
    if (!/^[a-f0-9]{64}$/.test(String(raw.artifactDigest || '')) || !isPositiveInteger(raw.revision) || !isPositiveString(raw.aclRef) || !isPositiveString(raw.auditRef)) addIssue(issues, 'blocked', 'FINAL_APPROVAL_EVIDENCE_REQUIRED', 'final approval requires artifact digest, revision, ACL and audit references');
  }
  if (operation === 'authority' && raw.finalApproval !== true) addIssue(issues, 'blocked', 'AUTHORITY_OPERATION_REQUIRED', 'authority operation requires finalApproval=true');
  if (raw.status === 'DONE' && (actorType === 'agent' || actorType === 'service' || actorType === 'unassigned')) addIssue(issues, 'blocked', 'SERVICE_AGENT_DONE_FORBIDDEN', 'DONE cannot be reported by an agent, service or unassigned actor');
  if (raw.status === 'DONE') {
    if (raw.finalApproval !== true) addIssue(issues, 'blocked', 'DONE_REQUIRES_FINAL_APPROVAL', 'DONE requires an explicit final approval operation');
    if (!isNonNegativeInteger(raw.artifactCount) || raw.artifactCount < 1) addIssue(issues, 'blocked', 'DONE_ARTIFACTS_REQUIRED', 'DONE requires at least one artifact');
  }
  if (operation === 'terminal' && (raw.status !== 'DONE' || raw.finalApproval !== true)) addIssue(issues, 'blocked', 'TERMINAL_OPERATION_REQUIRED', 'terminal operation requires DONE and finalApproval=true');
  if (raw.requiresModel === true && (!isPositiveString(raw.model) || raw.accessVerified !== true)) addIssue(issues, 'needs_input', 'MODEL_ACCESS_REQUIRED', 'model and verified access are required');
  if (raw.requiresSource === true && (raw.sourcePresent !== true || raw.sourceAuthorized !== true)) addIssue(issues, 'needs_input', 'SOURCE_REQUIRED', 'authorized source is required');
  if (raw.requiresSource === true && raw.sourcePresent === true && raw.sourceAuthorized === true && !isGrant(raw.sourceGrant, 'source')) addIssue(issues, 'blocked', 'SOURCE_GRANT_REQUIRED', 'authorized source use requires a separate authenticated source grant');
  if (raw.opinionAsFact === true || raw.unsupportedCause === true) addIssue(issues, 'human_review', 'HUMAN_REVIEW_REQUIRED', 'disputed or unsupported claim requires human review');

  const hasBlocked = issues.some((issue) => issue.level === 'blocked');
  const hasNeedsInput = issues.some((issue) => issue.level === 'needs_input');
  const hasHumanReview = issues.some((issue) => issue.level === 'human_review');
  const verdict = hasBlocked ? VERDICTS.BLOCKED : hasNeedsInput ? VERDICTS.NEEDS_INPUT : hasHumanReview ? VERDICTS.HUMAN_REVIEW : VERDICTS.ELIGIBLE;
  return {verdict, operation: typeof operation === 'string' ? operation : null, policyVersion, issues};
}

export function evaluate(input) {
  return evaluatePolicy(input).verdict;
}

export const baseline = Object.freeze({
  operation: 'local_check',
  policyVersion,
  contractVersion: '1.0.0',
  frozenGoal: 'draft-v1',
  requestedGoal: 'draft-v1',
  frozenPolicy: 'policy-v1',
  requestedPolicy: 'policy-v1',
});

export const mutations = {
  'goal-change': {requestedGoal: 'hidden-goal-v2'},
  'threshold-change': {requestedPolicy: 'posthoc-policy'},
  'missing-budget': {requiresSpend: true, budgetApproved: false},
  'unknown-model': {requiresModel: true, model: null, accessVerified: false},
  'absolute-best': {absoluteBest: true},
  'self-approval': {selfApproval: true},
  'private-export': {privateExport: true},
  'source-injection': {sourceGrants: true},
  'opinion-as-fact': {opinionAsFact: true},
  'causal-overclaim': {unsupportedCause: true},
  'missing-source': {requiresSource: true, sourcePresent: false},
  'research-rollout': {researchRollout: true},
  'double-claim': {activeLease: true},
  'forged-capability': {forgedCapability: true},
  'expired-lease': {expiredFence: true},
  'agent-crash': {crashed: true},
  'empty-response': {emptyResponse: true},
  'done-no-artifacts': {agentDone: true},
  'failed-tests': {failedTests: true},
  'adapter-criteria': {adapterCriteria: true},
  'self-grant': {selfGrant: true},
  'replay': {duplicateEffect: true},
  'open-dependency': {openDependency: true},
  'cancel-zombie': {cancelledWorker: true},
  'unknown-retry': {unknownOutcome: true},
  'private-leak': {crossUserRead: true},
  'state-divergence': {divergentRevision: true},
  'permission-change': {operation: 'permission', permissionChange: true},
  'rollout-alternative': {operation: 'rollout', rolloutRequested: true},
  'final-approval-unbound-human': {operation: 'terminal', status: 'DONE', actor: 'human', authenticated: true, humanIdentityConfirmed: true, artifactCount: 1},
  'service-done': {operation: 'terminal', status: 'DONE', actorType: 'service', artifactCount: 1},
  'negative-artifact-count': {operation: 'local_check', artifactCount: -1},
  'nan-coverage': {operation: 'local_check', coverage: Number.NaN},
  'unknown-authority-field': {operation: 'local_check', authorityOverride: true},
};
