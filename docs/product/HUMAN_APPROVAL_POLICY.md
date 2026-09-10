# Human approval policy v1.0.0

Human remains final SolutionPack owner. Input owner=user; authenticated decision/budget identities NEEDS_INPUT. AgentOS verdict, JSON actor_type, UI click without identity, or a model's self-reported approval is not authorization.

Review package contains frozen brief/policy/source digests, producer and independent verifier identities, test results, evidence, actual costs, coverage/uncertainty, alternatives, unresolved contradictions, rollback and requested decision scope.

Actions: approve, reject, challenge, retry, reassign, cancel. Server checks authenticated subject, role, current revision, resource ACL, conflicts (producer cannot self-approve), requested scope and hard gates. Store immutable HumanDecision: subject identity, scope, exact artifact digest, reason, timestamp and audit reference. A pending example is not a signed grant. A new artifact digest invalidates prior approval. Rejected/challenged output cannot silently return to approved; retries create linked attempts and preserve history.

Critical actions (budget increase, permission change, secrets access, declassification, production rollout) require separate explicit confirmation showing exact scope and consequence; final research/solution approval grants none of these automatically. Budget authority and final result authority are separate roles even if one human later holds both. Human cannot waive data safety or falsify test evidence.

The included local workspace has no authenticated approval or execution endpoint. Moving a planning card to review or archiving it is not final solution approval. Human approval must be implemented and identity provisioned before the actual pilot.
