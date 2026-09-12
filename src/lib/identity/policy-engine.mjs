// S2-002 server-side policy engine.
// Single deterministic authorization point for Web, API and CLI adapters.
// Default deny; every decision returns one of ALLOW | DENY |
// BLOCKED_SANDBOX | NEEDS_APPROVAL with reason codes and a contract-valid
// AuthorizationDecision document. Nothing here trusts prompts, environment
// variables, model output or content hashes as proof of identity.
//
// Deterministic and offline: the clock is injected, never read from the
// system, so decisions are reproducible byte-for-byte for the same input.
import { createHash } from 'node:crypto';
import {
  PRINCIPALS,
  WORKSPACES,
  ROLES,
  CAPABILITIES,
  GRANTS,
  LEASES,
  SANDBOX_PROFILES,
} from './principals.mjs';
import { assertValidContract } from './contract-registry.mjs';

export const POLICY_VERSION = 's2-002-policy-v1';

const ADAPTERS = new Set(['web', 'api', 'cli']);
const ID_PATTERNS = {
  principalId: /^prn-[a-z0-9][a-z0-9-]{0,62}$/,
  workspaceId: /^ws-[a-z0-9][a-z0-9-]{0,62}$/,
};
const OWNER_ROLE = 'rol-workspace-owner';

const principalIndex = new Map(PRINCIPALS.map((p) => [p.principal_id, p]));
const workspaceIndex = new Map(WORKSPACES.map((w) => [w.workspace_id, w]));
const capabilityIndex = new Map(CAPABILITIES.map((c) => [c.action, c]));
const roleIndex = new Map(ROLES.map((r) => [r.role_id, r]));
const grantIndex = new Map(GRANTS.map((g) => [g.grant_id, g]));
const leaseIndex = new Map(LEASES.map((l) => [l.lease_id, l]));

// Sandbox tier satisfying each exec_tier. Tiers without a profile that
// carries OS-control evidence stay blocked: BLOCKED_SANDBOX, not best effort.
const TIER_FOR_EXEC = Object.freeze({
  none: null,
  no_exec: 'NO_EXEC',
  local_restricted: 'LOCAL_RESTRICTED',
  untrusted_code: 'UNTRUSTED_CODE',
});

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function digestOf(request) {
  return createHash('sha256').update(JSON.stringify(canonicalize(request)), 'utf8').digest('hex');
}

function sandboxProfileFor(tier) {
  return SANDBOX_PROFILES.find((profile) => profile.tier === tier && (
    tier === 'NO_EXEC' || typeof profile.os_controls_evidence === 'string'
  ));
}

export function createPolicyEngine({ now } = {}) {
  const decidedAt = now ?? '2026-09-12T12:00:00.000Z';
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(decidedAt)) {
    throw new Error(`POLICY_CLOCK_INVALID: ${decidedAt}`);
  }

  // Mutable, in-memory enforcement state. Tests seed a fresh engine per case.
  const consumedNonces = new Set();
  const revokedGrants = new Set();
  const revokedLeases = new Set();
  const frozenPrincipals = new Set();
  const fencingMax = new Map();

  const deny = (reasonCodes, meta = {}) => ({
    decision: 'DENY',
    reasonCodes,
    document: buildDocument('DENY', reasonCodes, meta),
  });

  function buildDocument(decision, reasonCodes, meta) {
    if (!meta.wellFormed) return null;
    const inputDigest = digestOf(meta.request);
    const document = {
      contractVersion: '1.0.0',
      decision,
      reason_codes: reasonCodes,
      policy_version: POLICY_VERSION,
      input_digest: `sha256:${inputDigest}`,
      audit_ref: `aud:${inputDigest.slice(0, 16)}`,
      principal_id: meta.request.principalId,
      capability_id: meta.capabilityId,
      workspace_id: meta.request.workspaceId,
      decided_at: decidedAt,
      context: {},
    };
    if (meta.grantId) document.context.grant_id = meta.grantId;
    if (meta.leaseId) document.context.lease_id = meta.leaseId;
    if (meta.fencingToken) document.context.fencing_token = meta.fencingToken;
    assertValidContract('authorization-decision', document);
    return document;
  }

  function resolveAccess(request, capability) {
    const ws = workspaceIndex.get(request.workspaceId);
    const reasons = [];
    // Path 1: workspace ACL role entry.
    const entries = ws.acl.filter((entry) => entry.principal_id === request.principalId);
    let ownerMaintenance = false;
    for (const entry of entries) {
      const role = roleIndex.get(entry.role_id);
      if (!role?.capabilities.includes(capability.capability_id)) continue;
      if (entry.role_id === OWNER_ROLE) ownerMaintenance = true;
      return { via: 'ACL', roleId: entry.role_id, ownerMaintenance };
    }
    // Path 2: explicit grant from a human.
    let sawExpired = false;
    let sawRevoked = false;
    let sawConsumed = false;
    for (const g of GRANTS) {
      if (g.principal_id !== request.principalId) continue;
      if (g.capability_id !== capability.capability_id) continue;
      if (g.resource_scope.workspace_id !== request.workspaceId) continue;
      if (revokedGrants.has(g.grant_id)) {
        sawRevoked = true;
        continue;
      }
      if (g.status === 'expired' || Date.parse(g.expires_at) <= Date.parse(decidedAt)) {
        sawExpired = true;
        continue;
      }
      if (g.nonce && consumedNonces.has(g.grant_id)) {
        sawConsumed = true;
        continue;
      }
      if (!g.resource_scope.resource_ids.includes(request.resource.id)) {
        continue;
      }
      return { via: 'GRANT', grant: g };
    }
    if (sawRevoked) reasons.push('GRANT_REVOKED');
    if (sawExpired) reasons.push('GRANT_EXPIRED');
    if (sawConsumed) reasons.push('GRANT_NONCE_CONSUMED');
    if (reasons.length === 0) reasons.push('NO_ACCESS');
    return { via: 'DENIED', reasons };
  }

  function checkLease(request, capability, access) {
    if (!capability.constraints.requires_lease) return { ok: true };
    if (access.via === 'ACL' && access.ownerMaintenance) {
      return { ok: true, waived: true };
    }
    const presented = request.lease;
    if (!presented || typeof presented !== 'object') {
      return { ok: false, reasonCodes: ['LEASE_REQUIRED'] };
    }
    const lease = leaseIndex.get(presented.leaseId);
    if (!lease) return { ok: false, reasonCodes: ['UNKNOWN_LEASE'] };
    if (lease.owner !== request.principalId) return { ok: false, reasonCodes: ['LEASE_OWNER_MISMATCH'] };
    if (lease.workspace_id !== request.workspaceId) return { ok: false, reasonCodes: ['LEASE_WORKSPACE_MISMATCH'] };
    if (revokedLeases.has(lease.lease_id)) return { ok: false, reasonCodes: ['LEASE_REVOKED'] };
    if (lease.state !== 'active') return { ok: false, reasonCodes: ['LEASE_NOT_ACTIVE'] };
    if (Date.parse(lease.expires_at) <= Date.parse(decidedAt)) {
      return { ok: false, reasonCodes: ['LEASE_EXPIRED'] };
    }
    const knownGrant = grantIndex.get(lease.grant_id);
    if (!knownGrant) return { ok: false, reasonCodes: ['LEASE_GRANT_UNKNOWN'] };
    const taskKey = `${request.workspaceId}/${lease.task_ref.task_id}`;
    const max = fencingMax.get(taskKey) ?? 0;
    if (presented.fencingToken < max) {
      return { ok: false, reasonCodes: ['STALE_FENCING_TOKEN'] };
    }
    fencingMax.set(taskKey, Math.max(max, presented.fencingToken));
    return { ok: true, lease, fencingToken: presented.fencingToken };
  }

  function checkApprovalRules(request, principalRecord) {
    if (request.action !== 'approval.decide') return { ok: true };
    if (principalRecord.kind !== 'human') {
      return { ok: false, reasonCodes: ['APPROVAL_NOT_HUMAN'] };
    }
    if (request.resource?.producerPrincipalId === request.principalId) {
      return { ok: false, reasonCodes: ['SELF_APPROVAL'] };
    }
    return { ok: true };
  }

  function checkDerivedInputs(request, capability) {
    if (!['summary.generate', 'cache.write'].includes(request.action)) return { ok: true };
    const inputs = request.args?.inputs;
    if (!Array.isArray(inputs)) return { ok: false, reasonCodes: ['DERIVED_INPUTS_REQUIRED'] };
    for (const input of inputs) {
      if (input?.workspaceId !== request.workspaceId) {
        // Derived artifacts inherit the strictest ACL of all inputs; a
        // cross-tenant input can never be laundered into this workspace.
        return { ok: false, reasonCodes: ['CROSS_TENANT_INPUT'] };
      }
    }
    return { ok: true };
  }

  function checkSandbox(request, capability) {
    const tier = TIER_FOR_EXEC[capability.constraints.exec_tier] ?? null;
    if (tier === null) return { ok: true };
    const profile = sandboxProfileFor(tier);
    if (!profile) {
      return { ok: false, decision: 'BLOCKED_SANDBOX', reasonCodes: ['SBX_NO_OS_EVIDENCE'] };
    }
    return { ok: true, profile };
  }

  function authorize(request) {
    const meta = { request, wellFormed: false };
    const fail = (decision, reasonCodes) => ({
      decision,
      reasonCodes,
      document: buildDocument(decision, reasonCodes, meta),
    });

    if (typeof request?.adapter !== 'string' || !ADAPTERS.has(request.adapter)) {
      return fail('DENY', ['UNKNOWN_ADAPTER']);
    }
    const shapeOk = (
      typeof request.principalId === 'string' && ID_PATTERNS.principalId.test(request.principalId)
      && typeof request.workspaceId === 'string' && ID_PATTERNS.workspaceId.test(request.workspaceId)
      && typeof request.action === 'string'
      && request.resource !== null && typeof request.resource === 'object'
    );
    if (!shapeOk) {
      return { decision: 'DENY', reasonCodes: ['MALFORMED_REQUEST'], document: null };
    }
    const capability = capabilityIndex.get(request.action);
    if (!capability) return fail('DENY', ['UNKNOWN_ACTION']);
    meta.capabilityId = capability.capability_id;

    const principalRecord = principalIndex.get(request.principalId);
    if (!principalRecord) return fail('DENY', ['UNKNOWN_PRINCIPAL']);
    if (frozenPrincipals.has(request.principalId) || principalRecord.lifecycle_state !== 'active') {
      return fail('DENY', ['PRINCIPAL_NOT_ACTIVE']);
    }
    if (!workspaceIndex.has(request.workspaceId)) return fail('DENY', ['UNKNOWN_WORKSPACE']);

    meta.wellFormed = true;

    const approval = checkApprovalRules(request, principalRecord);
    if (!approval.ok) return fail('DENY', approval.reasonCodes);

    const sandbox = checkSandbox(request, capability);
    if (!sandbox.ok) return fail(sandbox.decision, sandbox.reasonCodes);

    const access = resolveAccess(request, capability);
    if (access.via === 'DENIED') return fail('DENY', access.reasons);
    if (access.via === 'GRANT') meta.grantId = access.grant.grant_id;

    const lease = checkLease(request, capability, access);
    if (!lease.ok) return fail('DENY', lease.reasonCodes);
    if (lease.lease) {
      meta.leaseId = lease.lease.lease_id;
      meta.fencingToken = lease.fencingToken;
    }

    const derived = checkDerivedInputs(request, capability);
    if (!derived.ok) return fail('DENY', derived.reasonCodes);

    const reasonCodes = [];
    if (access.via === 'ACL') reasonCodes.push('ACL_ROLE_MATCH');
    if (access.via === 'GRANT') reasonCodes.push('GRANT_VALID');
    if (lease.lease) reasonCodes.push('LEASE_FRESH');
    if (lease.waived) reasonCodes.push('LEASE_WAIVED_OWNER');
    if (reasonCodes.length === 0) reasonCodes.push('ALLOWED');

    if (access.via === 'GRANT' && access.grant.nonce) {
      consumedNonces.add(access.grant.grant_id);
    }

    return fail('ALLOW', reasonCodes);
  }

  function revokeGrant(grantId) {
    if (!grantIndex.has(grantId)) throw new Error(`UNKNOWN_GRANT: ${grantId}`);
    revokedGrants.add(grantId);
    return true;
  }

  function revokeLease(leaseId) {
    if (!leaseIndex.has(leaseId)) throw new Error(`UNKNOWN_LEASE: ${leaseId}`);
    revokedLeases.add(leaseId);
    return true;
  }

  function freezePrincipal(principalId) {
    if (!principalIndex.has(principalId)) throw new Error(`UNKNOWN_PRINCIPAL: ${principalId}`);
    frozenPrincipals.add(principalId);
    return true;
  }

  return Object.freeze({ authorize, revokeGrant, revokeLease, freezePrincipal });
}
