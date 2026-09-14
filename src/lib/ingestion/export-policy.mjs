// S2-003 export policy.
// Server-side ACL enforcement for every read/export of snapshots and
// segments. Private bytes can never reach public output: exports are built
// from the stored contract documents and filtered by the viewer's principal
// and workspace scope. Content-claimed visibility is ignored by construction
// — only the descriptor-inherited ACL on the snapshot is consulted.
export class ExportDeniedError extends Error {
  constructor(reason) {
    super(`EXPORT_DENIED: ${reason}`);
    this.name = 'ExportDeniedError';
    this.reason = reason;
  }
}

// Server-side ACL check used by every read/export path, including dedup
// scoping: a snapshot outside the viewer's tenant/ACL does not exist for the
// decision.
export function viewerCanRead(snapshot, viewer) {
  return principalAllowed(snapshot, viewer);
}

function principalAllowed(snapshot, viewer) {
  const acl = snapshot.acl;
  if (viewer.workspace_id !== acl.workspace_id && viewer.tenant_id !== acl.tenant_id) {
    if (!(acl.allowed_workspace_ids ?? []).includes(viewer.workspace_id)) return false;
  }
  if (acl.visibility === 'private') {
    return (acl.allowed_principal_ids ?? []).includes(viewer.principal_id)
      || (acl.allowed_workspace_ids ?? []).includes(viewer.workspace_id) && viewer.workspace_id === acl.workspace_id;
  }
  if (acl.visibility === 'project') {
    return viewer.workspace_id === acl.workspace_id
      || viewer.tenant_id === acl.tenant_id
      || (acl.allowed_workspace_ids ?? []).includes(viewer.workspace_id);
  }
  return true; // public
}

// Export a snapshot for a viewer. Denied for out-of-scope viewers.
export function exportSnapshot({ store, snapshotId, viewer }) {
  const snapshot = store.getSnapshot(snapshotId);
  if (!snapshot) throw new ExportDeniedError('NOT_FOUND');
  if (!principalAllowed(snapshot, viewer)) {
    throw new ExportDeniedError(snapshot.acl.visibility === 'private' ? 'PRIVATE_SCOPE' : 'OUT_OF_WORKSPACE');
  }
  const segments = store.segmentsFor(snapshotId).map((segment) => ({
    segment_id: segment.segment_id,
    ordinal: segment.ordinal,
    coordinates: segment.coordinates,
    text: segment.text,
    text_sha256: segment.text_sha256,
    status: segment.status,
    extraction: segment.extraction,
  }));
  return {
    snapshot_id: snapshot.snapshot_id,
    source_id: snapshot.source_id,
    canonical_locator: snapshot.canonical_locator,
    version: snapshot.version,
    snapshot_kind: snapshot.snapshot_kind,
    tombstone_reason: snapshot.tombstone_reason,
    raw_sha256: snapshot.raw_sha256,
    normalized_sha256: snapshot.normalized_sha256,
    published_at: snapshot.published_at,
    event_time: snapshot.event_time,
    observed_at: snapshot.observed_at,
    fetched_at: snapshot.fetched_at,
    license: snapshot.license,
    attribution_required: snapshot.license.attribution_required,
    acl: { visibility: snapshot.acl.visibility, workspace_id: snapshot.acl.workspace_id },
    segments,
  };
}

// Public evidence view: a snapshot may enter public evidence only if its ACL
// is public; otherwise the export contains existence metadata only, never
// content bytes. Private content can never leak through this path.
// A pre-fetched snapshot may be passed for async stores.
export function publicEvidenceView({ store, snapshot, snapshotId }) {
  // sync path (in-memory stores): resolve via the store directly
  const resolvedSnapshot = snapshot ?? store.getSnapshot(snapshotId);
  if (!resolvedSnapshot) throw new ExportDeniedError('NOT_FOUND');
  return publicEvidenceFromSnapshot({ store, snapshot: resolvedSnapshot, snapshotId });
}

// Async variant for PostgreSQL-backed stores: resolves the snapshot and its
// segments through awaited store calls. Semantics are identical to
// publicEvidenceView.
export async function publicEvidenceViewAsync({ store, snapshotId }) {
  const snapshot = await store.getSnapshot(snapshotId);
  if (!snapshot) throw new ExportDeniedError('NOT_FOUND');
  if (snapshot.acl.visibility !== 'public') {
    return {
      snapshot_id: snapshot.snapshot_id,
      exists: true,
      visibility: snapshot.acl.visibility,
      content_included: false,
      raw_sha256: snapshot.raw_sha256,
      normalized_sha256: snapshot.normalized_sha256,
      segments: [],
    };
  }
  const segments = (await store.segmentsFor(snapshotId)).map((segment) => ({
    segment_id: segment.segment_id,
    ordinal: segment.ordinal,
    coordinates: segment.coordinates,
    text: segment.text,
    text_sha256: segment.text_sha256,
    status: segment.status,
    extraction: segment.extraction,
  }));
  return {
    snapshot_id: snapshot.snapshot_id,
    source_id: snapshot.source_id,
    canonical_locator: snapshot.canonical_locator,
    version: snapshot.version,
    snapshot_kind: snapshot.snapshot_kind,
    tombstone_reason: snapshot.tombstone_reason,
    raw_sha256: snapshot.raw_sha256,
    normalized_sha256: snapshot.normalized_sha256,
    published_at: snapshot.published_at,
    event_time: snapshot.event_time,
    observed_at: snapshot.observed_at,
    fetched_at: snapshot.fetched_at,
    license: snapshot.license,
    attribution_required: snapshot.license.attribution_required,
    acl: { visibility: snapshot.acl.visibility, workspace_id: snapshot.acl.workspace_id },
    segments,
    content_included: true,
  };
}

function publicEvidenceFromSnapshot({ store, snapshot, snapshotId }) {
  if (!snapshot) throw new ExportDeniedError('NOT_FOUND');
  if (snapshot.acl.visibility !== 'public') {
    return {
      snapshot_id: snapshot.snapshot_id,
      exists: true,
      visibility: snapshot.acl.visibility,
      content_included: false,
      raw_sha256: snapshot.raw_sha256, // digest is not content
      normalized_sha256: snapshot.normalized_sha256,
      segments: [],
    };
  }
  return {
    ...exportSnapshot({ store, snapshotId, viewer: { principal_id: 'prn-public-evidence', workspace_id: snapshot.acl.workspace_id, tenant_id: snapshot.acl.tenant_id } }),
    content_included: true,
  };
}
