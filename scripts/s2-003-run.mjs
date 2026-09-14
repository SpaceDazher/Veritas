// S2-003 corpus run executor.
// Executes the frozen corpus through the production ingestion path
// (src/lib/ingestion — the exact pipeline the tests and the probes use).
// Before executing anything, the frozen manifest is verified fail-closed:
// any drift in case digests, contract digests or the evaluator hash stops
// the run as QUARANTINED (probe L / §11).
//
// Usage:
//   node scripts/s2-003-run.mjs --run-id run-a --executor-id exec-a \
//        --nonce n-abc12345 --output-root results/s2-003/run-a \
//        --out evidence/s2-003-run-a.json [--clock 2026-01-15T20:00:00.000Z]
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { IngestionStore } from '../src/lib/ingestion/store.mjs';
import { IngestionPipeline } from '../src/lib/ingestion/pipeline.mjs';
import { ManualExportConnector } from '../src/lib/ingestion/connectors/manual-export.mjs';
import { MarkdownObsidianConnector } from '../src/lib/ingestion/connectors/markdown-obsidian.mjs';
import { HttpSnapshotConnector } from '../src/lib/ingestion/connectors/http-snapshot.mjs';
import {
  createGithubConnector,
  createTelegramConnector,
  createYoutubeConnector,
  createArxivHuggingfaceConnector,
} from '../src/lib/ingestion/connectors/blocked-connectors.mjs';
import { connectorError, UnknownOutcomeError } from '../src/lib/ingestion/connectors/base.mjs';
import { createDecisionClock } from '../src/lib/ingestion/time-model.mjs';
import { contractDigests } from '../src/lib/ingestion/contract-registry.mjs';
import { publicEvidenceView, publicEvidenceViewAsync } from '../src/lib/ingestion/export-policy.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const { algorithm } = { algorithm: 'corpus-v1' };

export const DEFAULT_CLOCK = '2026-01-15T08:00:00.000Z';

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key.startsWith('--')) args[key.slice(2)] = argv[i + 1];
  }
  return args;
}

export function verifyFrozenManifest({ manifest, casesDir, contractsDir, runnerPath }) {
  const issues = [];
  if (manifest.schemaVersion !== 1) issues.push('manifest:schema-version-unknown');
  if (!manifest.caseCount || manifest.caseCount < 72) issues.push('manifest:case-count-below-minimum');
  for (const [caseId, digest] of Object.entries(manifest.caseSha256 ?? {})) {
    const file = path.join(casesDir, `${caseId}.json`);
    let bytes;
    try {
      bytes = fs.readFileSync(file);
    } catch {
      issues.push(`${caseId}:missing`);
      continue;
    }
    if (sha256Hex(bytes) !== digest) issues.push(`${caseId}:digest-drift`);
  }
  for (const [name, digest] of Object.entries(manifest.contracts ?? {})) {
    let bytes;
    try {
      bytes = fs.readFileSync(path.join(contractsDir, name));
    } catch {
      issues.push(`contract:${name}:missing`);
      continue;
    }
    if (sha256Hex(bytes) !== digest) issues.push(`contract:${name}:digest-drift`);
  }
  const runnerDigest = sha256Hex(fs.readFileSync(runnerPath));
  if (manifest.evaluator?.sha256 !== runnerDigest) issues.push('evaluator:digest-drift');
  return { ok: issues.length === 0, issues };
}

// A connector wrapper that can be forced to fail per locator — the corpus
// uses this to model unavailable/rate-limited/timeout connectors, simulated
// crashes (unknown outcome) and cancellations.
function withForcedErrors(underlying, forced) {
  return {
    id: underlying.id,
    version: underlying.version,
    discoverCapabilities: () => underlying.discoverCapabilities(),
    resolveDescriptor: (request) => underlying.resolveDescriptor(request),
    fetchVersion: async (request) => {
      const code = forced.get(request.locator);
      if (code) {
        return connectorError(code, {
          operationId: request.operation_id,
          connectorId: underlying.id ?? 'conn-corpus',
          retryable: ['RATE_LIMITED', 'TIMEOUT', 'BLOCKED_CONNECTOR'].includes(code),
          reconciliationAction: 'retry_with_backoff',
          detail: `corpus forced error ${code}`,
        });
      }
      if (forced.has(`__unknown__${request.locator}`)) {
        throw new UnknownOutcomeError(request.operation_id, 'corpus-simulated connection cut');
      }
      if (forced.has(`__cancel__${request.locator}`)) {
        return { ok: false, code: 'CANCELLED', cancelled: true };
      }
      return underlying.fetchVersion(request);
    },
    extract: (snapshot, fetched) => underlying.extract(snapshot, fetched),
    reconcile: (operationId) => underlying.reconcile(operationId),
    observeDeletion: (sourceId, locator) => underlying.observeDeletion(sourceId, locator),
  };
}

function gitHead() {
  try {
    return {
      commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim(),
      tree: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: ROOT, encoding: 'utf8' }).trim(),
    };
  } catch {
    return { commit: '0'.repeat(40), tree: '0'.repeat(40) };
  }
}

export async function runCorpus({ runId, executorId, nonce, outputRoot, clockNow = DEFAULT_CLOCK, manifestPath = 'corpus/s2-003/manifest.json', store: injectedStore = null } = {}) {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, manifestPath), 'utf8'));
  const frozen = verifyFrozenManifest({
    manifest,
    casesDir: path.join(ROOT, 'corpus/s2-003/cases'),
    contractsDir: path.join(ROOT, 'contracts'),
    runnerPath: path.join(ROOT, 'scripts/s2-003-run.mjs'),
  });
  if (!frozen.ok) {
    return {
      quarantined: true,
      issues: frozen.issues,
      run_id: runId,
      counts: { total: 0, QUARANTINED: 1 },
      outcomes: [],
      observations: [],
      decisions: [],
    };
  }

  const store = injectedStore ?? new IngestionStore();
  const clock = createDecisionClock(clockNow);
  let privateLeakCounter = 0;
  let authorityExpansionCounter = 0;
  let tick = 0;
  const now = () => {
    // Telemetry-only clock: distinct audit timestamps per operation, while
    // every decision stays on the injected decision clock.
    tick += 1;
    return new Date(Date.parse(clockNow) + tick * 1000).toISOString();
  };

  // One connector instance per source kind, created once per run; cases feed
  // shared fixture stores so per-case state can never leak into another
  // case's connector decisions.
  const markdownRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-corpus-vault-'));
  const manualExports = new Map();
  const httpFixtures = new Map();
  const fixtureByKind = new Map(); // fixture-backed connectors (github/telegram/youtube/arxiv)
  const forcedByKind = new Map();

  const makeForced = () => {
    const map = new Map();
    forcedByKind.set(map, true);
    return map;
  };
  const forcedManual = new Map();
  const forcedMarkdown = new Map();
  const forcedWeb = new Map();

  const underlying = new Map([
    ['manual_export', new ManualExportConnector({ clock, exports: manualExports })],
    ['markdown_obsidian', new MarkdownObsidianConnector({ vaultRoot: markdownRoot, clock })],
    ['web_url', new HttpSnapshotConnector({
      clock,
      fetchFn: async (locator) => {
        const body = httpFixtures.get(locator);
        if (body === undefined) throw new Error('ECONNREFUSED corpus fixture missing');
        return {
          ok: true,
          status: 200,
          headers: { get: (k) => (k.toLowerCase() === 'content-type' ? 'text/html' : null) },
          url: locator,
          arrayBuffer: async () => { const buf = Buffer.from(body); return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength); },
        };
      },
    })],
    ['github', createGithubConnector({ fixtureFetch: () => fixtureByKind.get('github') ?? null })],
    ['telegram', createTelegramConnector({ fixtureFetch: () => fixtureByKind.get('telegram') ?? null })],
    ['youtube', createYoutubeConnector({ fixtureFetch: () => fixtureByKind.get('youtube') ?? null })],
    ['arxiv_huggingface', createArxivHuggingfaceConnector({ fixtureFetch: () => fixtureByKind.get('arxiv_huggingface') ?? null })],
    ['pdf', new ManualExportConnector({ clock, exports: manualExports })],
  ]);

  const connectors = new Map();
  const forcedByKey = new Map([
    ['manual_export', forcedManual],
    ['markdown_obsidian', forcedMarkdown],
    ['web_url', forcedWeb],
  ]);
  for (const [kind, connector] of underlying) {
    const forced = forcedByKey.get(kind) ?? new Map();
    if (!forcedByKey.has(kind)) forcedByKey.set(kind, forced);
    connectors.set(kind, withForcedErrors(connector, forced));
  }
  const pipelineByKind = new Map();
  for (const kind of underlying.keys()) {
    pipelineByKind.set(kind, new IngestionPipeline({ store, connectors: new Map([[kind, connectors.get(kind)]]), clock, now, classifier: null }));
  }

  const caseIds = Object.keys(manifest.caseSha256).sort();
  const outcomes = [];
  const observations = [];

  for (const caseId of caseIds) {
    const testCase = JSON.parse(fs.readFileSync(path.join(ROOT, 'corpus/s2-003/cases', `${caseId}.json`), 'utf8'));
    const kind = testCase.descriptor.source_kind;
    const forced = forcedByKey.get(kind);
    const pipeline = pipelineByKind.get(kind);

    await store.registerDescriptor(testCase.descriptor);
    if (testCase.second_descriptor) await store.registerDescriptor(testCase.second_descriptor);

    // Register fixtures for this case.
    for (const [fixtureId, payload] of Object.entries(testCase.fixtures ?? {})) {
      if (kind === 'web_url') {
        httpFixtures.set(fixtureId, payload);
        httpFixtures.set(`case-fixture/${caseId}`, payload);
      } else if (kind === 'markdown_obsidian') {
        const absolute = path.join(markdownRoot, fixtureId);
        fs.mkdirSync(path.dirname(absolute), { recursive: true });
        fs.writeFileSync(absolute, payload);
      } else {
        manualExports.set(fixtureId, { bytes: Buffer.from(payload, 'utf8'), text: payload, mime_type: 'text/plain' });
      }
    }
    if (['github', 'telegram', 'youtube', 'arxiv_huggingface'].includes(kind)) {
      const entries = Object.entries(testCase.fixtures ?? {});
      fixtureByKind.set(kind, entries.length > 0 ? { bytes: Buffer.from(entries[0][1], 'utf8'), mime_type: 'text/plain', text: entries[0][1] } : null);
    }

    const sequenceByOp = new Map((testCase.sequence_fixtures ?? []).map((entry) => [entry.op, entry]));
    const replayKeyByOp = new Map();
    for (const operation of testCase.operations ?? []) {
      if (operation.replay_of) replayKeyByOp.set(operation.operation_id, operation.replay_of);
    }

    const lineageEventsBefore = store.events.filter((e) => e.type === 'LINEAGE_APPENDED').length;
    const lineageAutomatedBefore = store.events.filter((e) => e.type === 'LINEAGE_APPENDED' && e.automated).length;
    const terminals = [];
    let lastSnapshotId = null;
    const caseSnapshotIds = new Set();

    for (const operation of testCase.operations ?? []) {
      if (operation.simulate === 'unknown_outcome') forced.set(`__unknown__${operation.locator}`, '1');
      if (operation.simulate === 'cancel') forced.set(`__cancel__${operation.locator}`, '1');
      if (operation.force_error) forced.set(operation.locator, operation.force_error);

      const seq = sequenceByOp.get(operation.operation_id);
      if (seq) {
        if (kind === 'markdown_obsidian') {
          fs.writeFileSync(path.join(markdownRoot, seq.exportId), seq.text);
        } else {
          manualExports.set(seq.exportId, { bytes: Buffer.from(seq.text, 'utf8'), text: seq.text, mime_type: 'text/plain' });
        }
      }

      if (operation.type === 'record_deletion') {
        const outcome = await pipeline.recordDeletion({
          request: {
            contractVersion: '1.0.0',
            operation_id: operation.operation_id,
            source_id: testCase.descriptor.source_id,
            connector_id: testCase.descriptor.connector_id,
            actor: 'prn-corpus-reviewer',
            locator: operation.locator,
            workspace_id: operation.workspace_id ?? 'ws-corpus',
            budget: { max_bytes: 1000000, time_limit_ms: 30000 },
            requested_at: clockNow,
          },
          descriptor: await store.getDescriptor(testCase.descriptor.source_id),
          reason: operation.reason,
          caseId,
        });
      terminals.push(outcome.terminal);
        if (outcome.snapshot_id) caseSnapshotIds.add(outcome.snapshot_id);
        lastSnapshotId = outcome.snapshot_id ?? lastSnapshotId;
        continue;
      }

      if (operation.type === 'public_evidence_check') {
        try {
          const view = await publicEvidenceViewAsync({ store, snapshotId: lastSnapshotId });
          const contentFree = view.content_included === false && view.segments.length === 0;
          if (!contentFree) privateLeakCounter += 1;
          terminals.push(contentFree ? 'COMMITTED' : 'FAILED');
        } catch (error) {
          terminals.push('FAILED');
        }
        continue;
      }

      const effectiveOperationId = replayKeyByOp.get(operation.operation_id) ?? operation.operation_id;
      const descriptorForOp = (await store.getDescriptor(operation.source_id ?? testCase.descriptor.source_id)) ?? testCase.descriptor;
      const outcome = await pipeline.ingest({
        request: {
          contractVersion: '1.0.0',
          operation_id: effectiveOperationId,
          source_id: descriptorForOp.source_id,
          connector_id: descriptorForOp.connector_id,
          actor: 'prn-corpus-reviewer',
          locator: operation.locator,
          workspace_id: operation.workspace_id ?? 'ws-corpus',
          version_selector: { latest: true },
          budget: operation.budget ?? { max_bytes: 1000000, max_segments: 500, time_limit_ms: 30000 },
          grant_id: null,
          requested_at: clockNow,
          claimed: operation.claimed ?? null,
        },
        caseId,
      });
      if (process.env.VERITAS_DEBUG_DUMP && caseId === 'gold-web') { const snp2 = outcome.snapshot_id ? store.getSnapshot(outcome.snapshot_id) : null; console.error('DUMP ' + JSON.stringify({ outcome, snap: snp2 && { id: snp2.snapshot_id, raw: String(snp2.raw_sha256).slice(0, 16), v: snp2.version } })); }
      terminals.push(outcome.terminal);
      if (outcome.snapshot_id) caseSnapshotIds.add(outcome.snapshot_id);
      lastSnapshotId = outcome.snapshot_id ?? lastSnapshotId;
    }

    const lineageForCase = store.events.filter((e) => e.type === 'LINEAGE_APPENDED').length - lineageEventsBefore;
    outcomes.push({
      operation_id: (testCase.operations ?? [])[0]?.operation_id ?? caseId,
      case_id: caseId,
      terminal: terminals[terminals.length - 1] ?? 'FAILED',
      snapshot_id: lastSnapshotId,
      error_code: null,
      raw_observation_ref: null,
    });
    observations.push({
      case_id: caseId,
      decision: terminals[terminals.length - 1] ?? 'FAILED',
      terminals,
      snapshot_ids: [...caseSnapshotIds].sort(),
      lineage_created: lineageForCase,
      lineage_automated: store.events.filter((e) => e.type === 'LINEAGE_APPENDED' && e.automated).length - lineageAutomatedBefore,
      public_view_checked: (testCase.operations ?? []).some((o) => o.type === 'public_evidence_check'),
    });
  }

  fs.rmSync(markdownRoot, { recursive: true, force: true });

  // Hard integrity counters (§13), computed by the store itself — in-memory
  // or PostgreSQL-backed — never from narrative claims.
  const integrity = await store.integritySummary({ outcomes, privateLeakCounter, authorityExpansionCounter });

  const counts = {
    total: outcomes.length,
    COMMITTED: outcomes.filter((o) => o.terminal === 'COMMITTED').length,
    BLOCKED_CONNECTOR: outcomes.filter((o) => o.terminal === 'BLOCKED_CONNECTOR').length,
    ACCESS_DENIED: outcomes.filter((o) => o.terminal === 'ACCESS_DENIED').length,
    TOMBSTONED: outcomes.filter((o) => o.terminal === 'TOMBSTONED').length,
    QUARANTINED: outcomes.filter((o) => o.terminal === 'QUARANTINED').length,
    FAILED: outcomes.filter((o) => o.terminal === 'FAILED').length,
    CANCELLED: outcomes.filter((o) => o.terminal === 'CANCELLED').length,
    RECONCILIATION_REQUIRED: outcomes.filter((o) => o.terminal === 'RECONCILIATION_REQUIRED').length,
  };

  const head = gitHead();
  const run = {
    contractVersion: '1.0.0',
    run_id: runId,
    executor_id: executorId,
    pid: process.pid,
    nonce,
    output_root: outputRoot,
    frozen_inputs: {
      connector_contracts_sha256: sha256Hex(JSON.stringify(contractDigests())),
      corpus_sha256: sha256Hex(fs.readFileSync(path.join(ROOT, manifestPath))),
      policy_sha256: sha256Hex(fs.readFileSync(path.join(ROOT, 'src/lib/ingestion/contract-registry.mjs'))),
    },
    started_at: clockNow,
    finished_at: null,
    environment: {
      commit: head.commit,
      tree: head.tree,
      node_version: process.versions.node ?? null,
      platform: `${process.platform}-${process.arch}`,
    },
    counts,
    outcomes,
  };
  return { ...run, quarantined: false, integrity, observations, decisions: observations.map((o) => ({ case_id: o.case_id, decision: o.decision, terminals: o.terminals, snapshot_ids: o.snapshot_ids })) };
}

async function main() {
  const args = parseArgs(process.argv);
  const result = await runCorpus({
    runId: args['run-id'] ?? 'run-solo',
    executorId: args['executor-id'] ?? `exec-${process.pid}`,
    nonce: args.nonce ?? `n-${createHash('sha256').update(String(process.pid + Math.random())).digest('hex').slice(0, 16)}`,
    outputRoot: args['output-root'] ?? 'results/s2-003/run-solo',
    clockNow: args.clock ?? DEFAULT_CLOCK,
  });
  const output = args.out ?? 'results/s2-003/run-solo.json';
  fs.mkdirSync(path.dirname(path.join(ROOT, output)), { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(ROOT, output), bytes);
  console.log(JSON.stringify({
    run_id: result.run_id,
    quarantined: result.quarantined ?? false,
    counts: result.counts,
    observations: result.observations?.length ?? 0,
    written: output,
    output_sha256: sha256Hex(bytes),
  }, null, 2));
  process.exit(result.quarantined ? 2 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
