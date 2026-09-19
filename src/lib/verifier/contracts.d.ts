// S2-006 verifier contract TypeScript types.
// GENERATED from contracts/*.schema.json by scripts/generate-verifier-types.mjs
// (including the transitive $ref closure over upstream contract schemas).
// Do not edit by hand: the JSON Schemas are the single source of truth and
// tests/verifier/contracts.test.mjs fails if this file drifts.

// semantic-verification-request.schema.json (contractVersion 1.0.0)
export interface SemanticVerificationRequest {
  contractVersion: "1.0.0";
  requestId: string;
  actor: SemanticVerificationRequestPrincipalId;
  workspaceId: SemanticVerificationRequestWorkspaceId;
  artifact: {
    kind: "claim" | "evidence_map" | "hypothesis_card" | "synthesis_result";
    artifactId: string;
    revision: number;
    digest: SemanticVerificationRequestSha256Hex;
  };
  requestedChecks: Array<SemanticVerificationRequestCheckName>;
  asOf: SemanticVerificationRequestUtcTimestamp;
  aclGrantRef: SemanticVerificationRequestCapabilityId;
  rubricVersion: SemanticVerificationRequestSemVer;
  corpusVersion: SemanticVerificationRequestSemVer;
  thresholdVersion: SemanticVerificationRequestSemVer;
  modelRef?: {
    modelId: string;
    modelVersion: SemanticVerificationRequestSemVer;
    modelDigest?: SemanticVerificationRequestSha256Hex | null;
  };
  budget?: {
    task: number;
    campaign: number;
    day: number;
  };
  idempotencyKey: string;
  canonicalArgsDigest: SemanticVerificationRequestSha256Hex;
}
export type SemanticVerificationRequestSha256Hex = string;
export type SemanticVerificationRequestUtcTimestamp = string;
export type SemanticVerificationRequestPrincipalId = string;
export type SemanticVerificationRequestWorkspaceId = string;
export type SemanticVerificationRequestCapabilityId = string;
export type SemanticVerificationRequestSemVer = string;
export type SemanticVerificationRequestCheckName = "citation_entailment" | "citation_coverage" | "qualifier_scope_binding" | "number_unit_preservation" | "negation_preservation" | "modality_preservation" | "contradiction_detection" | "scope_difference_discrimination" | "epistemic_type" | "causal_overclaim" | "temporal_ordering" | "evidence_family_independence" | "near_duplicate_collapse" | "stale_evidence_invalidation" | "future_evidence_invalidation" | "revoked_evidence_invalidation" | "as_of_leakage" | "completeness_and_abstention" | "bounded_novelty";

// semantic-verification-item.schema.json (contractVersion 1.0.0)
export interface SemanticVerificationItem {
  contractVersion: "1.0.0";
  itemId: string;
  statement: string;
  spanRef: {
    quoteDigest: SemanticVerificationItemSha256Hex;
    start: number;
    end: number;
  };
  criterion: SemanticVerificationItemCheckName;
  goldLabel: SemanticVerificationItemVerdictLabel | null;
  predictedLabel: SemanticVerificationItemVerdictLabel;
  verdict: SemanticVerificationItemVerdictLabel;
  reasonCodes: Array<SemanticVerificationItemReasonCode>;
  evidenceLinks: Array<{
    claimId: string;
    claimRevision: number;
    segmentId?: string;
    span?: {
      start: number;
      end: number;
    };
    quoteDigest?: SemanticVerificationItemSha256Hex;
    evidenceMapId?: string | null;
    entryIndex?: number | null;
  }>;
  missingness: {
    kind: "none" | "source_unavailable" | "evaluator_missing" | "timeout" | "policy_refusal" | "budget_exhausted";
    detail?: string;
  };
  uncertainty?: {
    kind: "aleatoric" | "epistemic";
    value: number;
  };
  provenance: {
    runId: string;
    implementationDigest?: SemanticVerificationItemSha256Hex;
    corpusVersion?: SemanticVerificationItemSemVer;
    rubricVersion?: SemanticVerificationItemSemVer;
    asOf?: SemanticVerificationItemUtcTimestamp;
  };
}
export type SemanticVerificationItemSha256Hex = string;
export type SemanticVerificationItemUtcTimestamp = string;
export type SemanticVerificationItemSemVer = string;
export type SemanticVerificationItemVerdictLabel = "SUPPORTED" | "CONTRADICTED" | "PARTIALLY_SUPPORTED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "STALE_INPUT" | "BLOCKED_POLICY";
export type SemanticVerificationItemReasonCode = "topic_overlap" | "number_unit_drift" | "negation_drift" | "modality_drift" | "scope_difference" | "missing_citation" | "stale_source" | "future_source" | "revoked_source" | "family_collapse" | "causal_overclaim" | "out_of_scope" | "policy_block" | "evaluator_missing" | "other";
export type SemanticVerificationItemCheckName = "citation_entailment" | "citation_coverage" | "qualifier_scope_binding" | "number_unit_preservation" | "negation_preservation" | "modality_preservation" | "contradiction_detection" | "scope_difference_discrimination" | "epistemic_type" | "causal_overclaim" | "temporal_ordering" | "evidence_family_independence" | "near_duplicate_collapse" | "stale_evidence_invalidation" | "future_evidence_invalidation" | "revoked_evidence_invalidation" | "as_of_leakage" | "completeness_and_abstention" | "bounded_novelty";

// semantic-verification-result.schema.json (contractVersion 1.0.0)
export interface SemanticVerificationResult {
  contractVersion: "1.0.0";
  resultId: string;
  requestRef: string;
  inputDigests: {
    artifactDigest: SemanticVerificationResultSha256Hex;
    rubricDigest: SemanticVerificationResultSha256Hex;
    corpusManifestDigest: SemanticVerificationResultSha256Hex;
    thresholdsDigest: SemanticVerificationResultSha256Hex;
    canonicalArgsDigest?: SemanticVerificationResultSha256Hex;
  };
  outputDigest: SemanticVerificationResultSha256Hex;
  items: Array<SemanticVerificationItem>;
  disagreements: Array<{
    itemId: string;
    goldLabel: SemanticVerificationResultVerdictLabel | null;
    predictedLabel: SemanticVerificationResultVerdictLabel;
    annotationSetIds: Array<string>;
    adjudicationRequired: boolean;
  }>;
  criticalFindings: Array<{
    findingId: string;
    code: "private_leak" | "locked_label_access" | "producer_self_review" | "fabricated_citation" | "upstream_mutation" | "unauthorized_side_effect" | "prompt_injection_override";
    detail: string;
    hardFail: boolean;
  }>;
  abstentions: Array<{
    itemId: string | null;
    scope: "item" | "artifact" | "corpus" | "provider";
    reason: "NO_CITATION" | "SOURCE_UNAVAILABLE" | "OUT_OF_SCOPE" | "POLICY_BLOCK" | "BUDGET_EXHAUSTED" | "EVALUATOR_MISSING" | "TIMEOUT";
    detail: string;
  }>;
  coverage: {
    denominator: number;
    evaluated: number;
    missing: number;
  };
  independenceProfileRef: string;
  humanDecisionRequired: true;
  status: "READY_FOR_HUMAN_REVIEW" | "INCOMPLETE" | "BLOCKED";
}
export type SemanticVerificationResultSha256Hex = string;
export type SemanticVerificationResultVerdictLabel = "SUPPORTED" | "CONTRADICTED" | "PARTIALLY_SUPPORTED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "STALE_INPUT" | "BLOCKED_POLICY";

// annotation-set.schema.json (contractVersion 1.0.0)
export interface AnnotationSet {
  contractVersion: "1.0.0";
  annotationSetId: string;
  corpusVersion: AnnotationSetSemVer;
  frozenCaseIds: Array<string>;
  split: "dev" | "calibration" | "locked_test";
  blindAssignment: {
    producerIdentityHidden: boolean;
    producerVerdictHidden: boolean;
    predictionsHidden: boolean;
    thresholdsHidden: boolean;
    splitAssignmentHidden: boolean;
  };
  annotatorId: AnnotationSetPrincipalId;
  annotatorRole: "annotator" | "adjudicator" | "label_custodian" | "reviewer";
  labels: Array<{
    caseId: string;
    label: "SUPPORTED" | "CONTRADICTED" | "PARTIALLY_SUPPORTED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "STALE_INPUT" | "BLOCKED_POLICY";
    labelDigest: AnnotationSetSha256Hex;
    annotatorId: AnnotationSetPrincipalId;
    labeledAt: AnnotationSetUtcTimestamp;
  }>;
  timestamps: {
    frozenAt: AnnotationSetUtcTimestamp;
    createdAt: AnnotationSetUtcTimestamp;
  };
  sourceDigest: AnnotationSetSha256Hex;
  rubricDigest: AnnotationSetSha256Hex;
  signature: {
    scheme: "hmac-sha256" | "ed25519";
    keyRef: string;
    digest: AnnotationSetSha256Hex;
    verified: boolean;
    attestedBy: AnnotationSetPrincipalId;
  };
}
export type AnnotationSetSha256Hex = string;
export type AnnotationSetUtcTimestamp = string;
export type AnnotationSetPrincipalId = string;
export type AnnotationSetSemVer = string;

// adjudication-record.schema.json (contractVersion 1.0.0)
export interface AdjudicationRecord {
  contractVersion: "1.0.0";
  adjudicationId: string;
  caseId: string;
  annotationSetIds: Array<string>;
  conflictingLabels: Array<AdjudicationRecordRawLabel>;
  retainedRawLabels: Array<AdjudicationRecordRawLabel>;
  decision: "SUPPORTED" | "CONTRADICTED" | "PARTIALLY_SUPPORTED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "STALE_INPUT" | "BLOCKED_POLICY";
  rationale: string;
  adjudicatorIdentity: {
    principalId: AdjudicationRecordPrincipalId;
    role: "adjudicator";
    authenticated: boolean;
    attestationDigest: AdjudicationRecordSha256Hex;
  };
  versions: {
    corpusVersion: AdjudicationRecordSemVer;
    rubricDigest: AdjudicationRecordSha256Hex;
    annotationManifestDigest: AdjudicationRecordSha256Hex;
    thresholdsDigest: AdjudicationRecordSha256Hex;
  };
  auditRef: {
    auditEntryId: string;
    auditDigest: AdjudicationRecordSha256Hex;
  };
  createdAt: AdjudicationRecordUtcTimestamp;
}
export type AdjudicationRecordSha256Hex = string;
export type AdjudicationRecordUtcTimestamp = string;
export type AdjudicationRecordPrincipalId = string;
export type AdjudicationRecordSemVer = string;
export type AdjudicationRecordRawLabel = {
    annotationSetId: string;
    annotatorId: AdjudicationRecordPrincipalId;
    label: "SUPPORTED" | "CONTRADICTED" | "PARTIALLY_SUPPORTED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "STALE_INPUT" | "BLOCKED_POLICY";
    labelDigest: AdjudicationRecordSha256Hex;
  };

// verifier-run.schema.json (contractVersion 1.0.0)
export interface VerifierRun {
  contractVersion: "1.0.0";
  runId: string;
  runKind: "candidate" | "deterministic_baseline" | "heuristic_baseline" | "comparator" | "evaluation_harness";
  implementationDigest: VerifierRunSha256Hex;
  modelRef?: {
    modelId: string;
    modelVersion: VerifierRunSemVer;
    modelDigest?: VerifierRunSha256Hex | null;
  };
  promptDigest?: VerifierRunSha256Hex | null;
  toolDigests: Array<{
    tool: string;
    digest: VerifierRunSha256Hex;
  }>;
  configHash: VerifierRunSha256Hex;
  seed: number | null;
  environment: {
    node: string;
    platform: string;
    arch: string;
  };
  inputRoots: Array<{
    name: string;
    digest: VerifierRunSha256Hex;
  }>;
  outputRoots: Array<{
    name: string;
    digest: VerifierRunSha256Hex;
  }>;
  predictionSetDigest: VerifierRunSha256Hex;
  runManifestDigest: VerifierRunSha256Hex;
  failures: Array<{
    code: string;
    detail: string;
  }>;
  cost: {
    operations: number;
    retries: number;
    providerCost: number | null;
  };
  latencyMs?: number;
  execution: {
    executorId: string;
    pid: number;
    nonce: string;
    outputRootDigest: VerifierRunSha256Hex;
    clock: VerifierRunUtcTimestamp;
  };
}
export type VerifierRunSha256Hex = string;
export type VerifierRunUtcTimestamp = string;
export type VerifierRunSemVer = string;

// calibration-report.schema.json (contractVersion 1.0.0)
export interface CalibrationReport {
  contractVersion: "1.0.0";
  reportId: string;
  corpusVersion: CalibrationReportSemVer;
  rubricDigest: CalibrationReportSha256Hex;
  thresholdsDigest: CalibrationReportSha256Hex;
  metricRecords: Array<unknown & unknown>;
  confusionMatrices: Array<{
    name: string;
    truePositive: number;
    falsePositive: number;
    falseNegative: number;
    trueNegative: number;
    missing: number;
  }>;
  slices: Array<{
    name: string;
    stratum: "external" | "fixture" | "reannotation" | "global" | "local";
    caseCount: number;
    metricNames: Array<string>;
  }>;
  selectiveRisk: {
    risk: number | null;
    coverage: number | null;
    curve: Array<{
    coverage: number;
    risk: number;
  }>;
  };
  coverage: {
    denominator: number;
    evaluated: number;
    missing: number;
    floor: number;
  };
  thresholdDecision: {
    thresholdsDigest: CalibrationReportSha256Hex;
    status: "APPLIED" | "NEEDS_INPUT" | "NOT_APPLICABLE";
    ownerDecisionRef: CalibrationReportSha256Hex | null;
    appliedAt: CalibrationReportUtcTimestamp | null;
  };
  independenceTier: "INDEPENDENTLY_CALIBRATED" | "PARTIALLY_INDEPENDENT" | "NOT_INDEPENDENT" | "UNVERIFIED";
  limitations: Array<string>;
  expiry: {
    at: CalibrationReportUtcTimestamp;
    cause: "model_drift" | "prompt_drift" | "rubric_drift" | "corpus_drift" | "contract_drift" | "source_revision_changed" | "label_revoked" | "threshold_changed";
  };
  driftScope: Array<string>;
  calibrationRecords?: Array<CalibrationRecord>;
  calibrationRecordsV2?: Array<CalibrationRecordV2>;
}
export type CalibrationReportSha256Hex = string;
export type CalibrationReportUtcTimestamp = string;
export type CalibrationReportSemVer = string;
export type CalibrationReportNotMeasuredReason = "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | "missing_thresholds" | "missing_human_decision" | "dependency_blocked" | null;
export type CalibrationReportNotMeasuredReasonNonEmpty = "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | "missing_thresholds" | "missing_human_decision" | "dependency_blocked";

// verifier-invalidation-event.schema.json (contractVersion 1.0.0)
export interface VerifierInvalidationEvent {
  contractVersion: "1.0.0";
  eventId: string;
  cause: "model_drift" | "prompt_drift" | "rubric_drift" | "corpus_drift" | "contract_drift" | "source_revision_changed" | "label_revoked" | "threshold_changed";
  causeDetail: string;
  affectedRecords: Array<{
    recordKind: "calibration_record" | "calibration_record_v2" | "calibration_report" | "verification_result" | "verifier_run" | "annotation_set" | "adjudication_record";
    recordId: string;
    recordDigest: VerifierInvalidationEventSha256Hex;
    resultingState: "STALE" | "OUT_OF_SCOPE" | "INVALID";
  }>;
  supersedeLink: {
    supersededByKind: "calibration_record" | "calibration_record_v2" | "calibration_report" | "verification_result" | "verifier_run" | "annotation_set" | "adjudication_record";
    supersededById: string;
    supersededByDigest: VerifierInvalidationEventSha256Hex;
  };
  createdBy: VerifierInvalidationEventPrincipalId;
  createdAt: VerifierInvalidationEventUtcTimestamp;
}
export type VerifierInvalidationEventSha256Hex = string;
export type VerifierInvalidationEventUtcTimestamp = string;
export type VerifierInvalidationEventPrincipalId = string;

// semantic-provider-grant.schema.json (contractVersion 1.0.0)
export interface SemanticProviderGrant {
  contractVersion: "1.0.0";
  grantId: SemanticProviderGrantGrantId;
  authenticatedPrincipal: SemanticProviderGrantPrincipalId;
  tool: string;
  workspaceId: SemanticProviderGrantWorkspaceId;
  modelAccess: {
    modelId: string;
    modelVersion: SemanticProviderGrantSemVer;
    access: "inference_only";
  };
  currency: "USD" | "EUR" | "GBP" | "none";
  timeoutMs: number;
  budget: {
    task: number | null;
    campaign: number | null;
    day: number | null;
  };
  noTraining: boolean;
  noRetention: boolean;
  issuedAt: SemanticProviderGrantUtcTimestamp;
  expiresAt: SemanticProviderGrantUtcTimestamp;
}
export type SemanticProviderGrantUtcTimestamp = string;
export type SemanticProviderGrantPrincipalId = string;
export type SemanticProviderGrantWorkspaceId = string;
export type SemanticProviderGrantGrantId = string;
export type SemanticProviderGrantSemVer = string;

// corpus-case.schema.json (contractVersion 1.0.0)
export interface CorpusCase {
  contractVersion: "1.0.0";
  caseId: string;
  corpusVersion: CorpusCaseSemVer;
  sourceFamily: string;
  semanticTemplate: string;
  stratum: "external" | "fixture" | "reannotation";
  license: "public_domain" | "cc0" | "cc_by_4_0" | "licensed_local_only" | "synthetic";
  locator: {
    type: "url" | "doi" | "file_path";
    ref: string;
  } | null;
  provenance: {
    snapshotId: string;
    sourceDigest: CorpusCaseSha256Hex | null;
    retrievedAt: CorpusCaseUtcTimestamp | null;
    lineage: "UPSTREAM_AUTHORED" | "DERIVED" | "SYNTHETIC";
  };
  asOf: CorpusCaseUtcTimestamp;
  expectedLabelsRef: {
    labelsDigest: CorpusCaseSha256Hex;
    annotationSetIds: Array<string>;
  };
  textDigest: CorpusCaseSha256Hex;
}
export type CorpusCaseSha256Hex = string;
export type CorpusCaseUtcTimestamp = string;
export type CorpusCaseSemVer = string;

// annotation-manifest.schema.json (contractVersion 1.0.0)
export interface AnnotationManifest {
  contractVersion: "1.0.0";
  manifestId: string;
  corpusVersion: AnnotationManifestSemVer;
  rubricDigest: AnnotationManifestSha256Hex;
  splitAssignments: Array<{
    caseId: string;
    split: "dev" | "calibration" | "locked_test";
  }>;
  cases: Array<{
    caseId: string;
    caseSha256: AnnotationManifestSha256Hex;
    labelsSha256: AnnotationManifestSha256Hex;
  }>;
  frozenAt: AnnotationManifestUtcTimestamp;
  externalStratum?: {
    status: "NEEDS_INPUT";
    reason: string;
  };
}
export type AnnotationManifestSha256Hex = string;
export type AnnotationManifestUtcTimestamp = string;
export type AnnotationManifestSemVer = string;

// rubric.schema.json (contractVersion 1.0.0)
export interface Rubric {
  contractVersion: "1.0.0";
  rubricId: string;
  rubricVersion: RubricSemVer;
  classes: Array<{
    name: string;
    definition: string;
    examples: Array<string>;
    counterexamples: Array<string>;
    ambiguityRule: string;
    abstentionRule: string;
  }>;
}
export type RubricSemVer = string;

// calibration-record-v2.schema.json (contractVersion 2.0.0)
export interface CalibrationRecordV2 {
  contractVersion: "2.0.0";
  calibration_id: CalibrationRecordV2CalibrationId;
  corpus_version: string;
  corpus_sha256: CalibrationRecordV2Sha256Hex;
  outcome_definition: {
    metric: "extraction_accuracy" | "span_binding_accuracy" | "epistemic_type_accuracy" | "qualifier_preservation" | "contradiction_precision" | "contradiction_recall" | "upstream_collapse_accuracy" | "stale_invalidation_recall" | "citation_entailment_precision" | "citation_entailment_recall" | "citation_entailment_f1" | "citation_coverage" | "exact_span_preservation" | "number_unit_preservation" | "negation_preservation" | "modality_preservation" | "scope_difference_confusion_rate" | "epistemic_type_macro_f1" | "causal_overclaim_rate" | "family_collapse_precision" | "family_collapse_recall" | "future_invalidation_recall" | "unauthorized_leakage_rate" | "evidence_map_completeness" | "critical_contradiction_miss_rate" | "hypothesis_falsifiability" | "hypothesis_completeness" | "bounded_novelty_assessment" | "false_advisory_acceptance_rate" | "false_advisory_rejection_rate" | "abstention_rate" | "selective_risk" | "inter_annotator_agreement" | "adjudication_rate" | "calibration_curve" | "brier_score" | "expected_calibration_error" | "human_intervention_rate" | "regression_rate" | "safety_incident_rate" | "latency_p95" | "actual_cost" | "reproducibility";
    threshold: number;
    description: string;
  };
  numerator: number;
  denominator: number;
  missing_count: number;
  uncertainty: {
    method: "wilson" | "clopper_pearson" | "bootstrap" | "paired_bootstrap";
    confidence_interval: {
      lower: number;
      upper: number;
      confidence_level: number;
    };
  };
  evaluator_independence: {
    artifact_producer: string;
    implementation_owner: string;
    implementation_digest: CalibrationRecordV2Sha256Hex;
    annotators: Array<{
    principal_id: CalibrationRecordV2PrincipalId;
    authenticated: boolean;
    domain_competence: string;
  }>;
    adjudicator: {
    principal_id: CalibrationRecordV2PrincipalId;
    authenticated: boolean;
  } | null;
    blindness: {
      producer_identity_hidden: boolean;
      producer_verdict_hidden: boolean;
      predictions_hidden: boolean;
      thresholds_hidden: boolean;
      split_assignment_hidden: boolean;
    };
    data_independence: boolean;
    model_independence: boolean;
    process_independence: boolean;
    locked_label_access: Array<{
    principal_id: CalibrationRecordV2PrincipalId;
    access: "granted" | "denied" | "not_attempted";
    recorded_at: CalibrationRecordV2UtcTimestamp;
  }>;
  };
  status: "MEASURED" | "NOT_MEASURED" | "NEEDS_INPUT" | "NOT_APPLICABLE";
  not_measured_reason: "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | "missing_thresholds" | "missing_human_decision" | "dependency_blocked" | null;
  measured_at: CalibrationRecordV2UtcTimestamp;
  measured_by: CalibrationRecordV2PrincipalId;
}
export type CalibrationRecordV2Sha256Hex = string;
export type CalibrationRecordV2UtcTimestamp = string;
export type CalibrationRecordV2PrincipalId = string;
export type CalibrationRecordV2CalibrationId = string;
export type CalibrationRecordV2NotMeasuredReason = "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | "missing_thresholds" | "missing_human_decision" | "dependency_blocked" | null;
export type CalibrationRecordV2NotMeasuredReasonNonEmpty = "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | "missing_thresholds" | "missing_human_decision" | "dependency_blocked";

// calibration-record.schema.json (contractVersion 1.0.0)
export interface CalibrationRecord {
  contractVersion: "1.0.0";
  calibration_id: CalibrationRecordCalibrationId;
  corpus_version: string;
  corpus_sha256: CalibrationRecordSha256Hex;
  outcome_definition: {
    metric: "extraction_accuracy" | "span_binding_accuracy" | "epistemic_type_accuracy" | "qualifier_preservation" | "contradiction_precision" | "contradiction_recall" | "upstream_collapse_accuracy" | "stale_invalidation_recall";
    threshold: number;
    description: string;
  };
  numerator: number;
  denominator: number;
  missing_count: number;
  uncertainty: {
    method: "wilson" | "clopper_pearson" | "bootstrap";
    confidence_interval: {
      lower: number;
      upper: number;
      confidence_level: number;
    };
  };
  evaluator_independence: {
    independent_evaluators: number;
    blind_to_producer: boolean;
    separate_processes?: boolean;
  };
  status: "MEASURED" | "NOT_MEASURED";
  not_measured_reason?: "no_valid_corpus" | "insufficient_samples" | "evaluator_not_independent" | "outcome_not_defined" | null;
  measured_at: CalibrationRecordUtcTimestamp;
  measured_by: CalibrationRecordPrincipalId;
}
export type CalibrationRecordUtcTimestamp = string;
export type CalibrationRecordSha256Hex = string;
export type CalibrationRecordCalibrationId = string;
export type CalibrationRecordPrincipalId = string;
