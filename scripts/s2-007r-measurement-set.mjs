#!/usr/bin/env node
// S2-007R: THE SEVEN MEASUREMENTS, THE A/B COMPARISON RECORD AND THE A-MVP-01..07
// PER-CASE OBSERVATION RECORD, computed from the ONE run set issue #45 produced.
//
// WHAT THIS SCRIPT IS
// -------------------
// The measurement step of the ticket. It reads what the run step left on disk
// (results/s2-007r/cell-*/), plants ONE skills-authority expansion attempt
// inside a workspace, computes the seven measurements over the whole run set,
// and writes the two evidence records the verification gate reads:
//
//   evidence/s2-007r-comparison.json    the A/B comparison + the seven measurements
//   evidence/s2-007r-amvp-cases.json     the per-case A-MVP-01..07 observation
//
// WHAT IT IS NOT
// --------------
//   * It is not a run driver. It dispatches no executor, opens no lease, claims
//     no task and writes no board row. Every governed attempt in this run set
//     was refused before a run existed, and this script does not retry one.
//   * It is not a status minter. `engineeringStatus`, `realAdapterStatus`,
//     `assuranceStatus` and `aMvpStatus` are copied from what the run set
//     actually contains, and nothing here can move `assuranceStatus` off
//     NOT_MEASURED or `aMvpStatus` off NOT_CLAIMED.
//   * It is not an evidence re-writer. The frozen pilot file is QUOTED, never
//     touched; the manifests, the inventory and the closure records belong to
//     the orchestrator.
//
// THE ONE RUN SET
// ---------------
// The seven measurements come from ONE run set: the single campaign the owner
// authorised (grant grt-s2007r-pilot, one project digest, four driver
// invocations = eight attempted governed runs). The driver minted one run-set
// id PER INVOCATION; this record names the campaign-level set and publishes
// all four invocation ids inside `run_set_composition`, so a reader can see
// exactly which four documents were combined and re-derive the id.
//
// THE PLANT
// ---------
// Measurement 7 is not a number this script may report as zero because nothing
// was attempted. `SKILL_EXPANSION_PROBE_TEXT` (src/lib/executors/constants.mjs)
// is written into a workspace as a skill-shaped `SKILL.md` that ASKS for
// `tool:net.fetch` and `board.review.approve`, and the observable is the
// RECORDED REFUSAL: the real transport's `capabilities()` claim is refused
// CAPABILITY_MISMATCH/ADAPTER_CLAIM_NOT_REGISTERED, an authority field handed
// to the same call is refused BLOCKED_POLICY/BOUNDARY_ARGUMENT_NOT_CANONICAL,
// the transport's own expansion ledger records the attempt as REFUSED, and the
// effective sets are byte-identical before and after. Both providers are
// planted, so the observation is per-executor rather than per-one-executor.
//
// DETERMINISM
// -----------
// No Date.now(), no wall clock, no Math.random(). Every instant is an injected
// constant inside the permit's own window. The two record digests are
// `sha256:` + canonicalDigest(record without its own digest), recomputable by a
// third party from the published bytes.
//
// EXIT CODES
// ----------
//   0  both records written, from one run set, with every measurement carrying
//      a status from the closed vocabulary and the exact reason for every NOT_RUN
//   1  a contract failure (an unreadable run set, a non-canonical value, a
//      measurement invariant violation)
//   3  nothing to measure: the run set is absent
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { isBoardError } from '../src/lib/agentboard/errors.mjs';
import {
  COST_BASES, HARD_GATE_COUNTERS, MEASUREMENT_NAMES, MEASUREMENTS_VERSION,
  MIN_SAMPLES_PER_CELL_FOR_DELTA, assertMeasurementInvariants, compareCells, hardGateFindings,
  invocationDigestVerified, measureSeven, normalizeRunDriverRecord, refusalDocument, runDriverRunSetId,
} from '../src/lib/executors/measure.mjs';
import { HOST_UNISOLATED_EVIDENCE_DIGEST, HOST_UNISOLATED_PROFILE_ID, HOST_UNISOLATED_TIER, SKILL_EXPANSION_PROBE_TEXT } from '../src/lib/executors/constants.mjs';
import { createRealRegistration } from '../src/lib/executors/registration.mjs';
import { createRealExecutorTransport } from '../src/lib/executors/transport.mjs';
import { buildUnisolatedAuthorization } from './s2-007r-authorization.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT_VERSION = 's2-007r-measurement-set-v1';
const RUN_ROOT = path.join(ROOT, 'results', 's2-007r');
const PILOT_RELATIVE = 'pilots/scenario-a/acceptance-cases.json';
const COMPARISON_RELATIVE = 'evidence/s2-007r-comparison.json';
const AMVP_RELATIVE = 'evidence/s2-007r-amvp-cases.json';
const LIFECYCLE_RELATIVE = 'results/s2-007r/lifecycle-record.json';
const LEDGER_RELATIVE = 'results/s2-007r/campaign-ledger.json';
const PILOT_RELATIVE_REF = 'evidence/s2-007r-host-unisolated.json';

// The four driver invocations of the one campaign, in the paired order the run
// step executed them: A#1, B#1, B#2, A#2.
const CELLS = Object.freeze([
  { id: 'cell-pia', order: 1, configuration: 'A', seed: 'pia' },
  { id: 'cell-pb1', order: 2, configuration: 'B', seed: 'pb1' },
  { id: 'cell-pb2', order: 3, configuration: 'B', seed: 'pb2' },
  { id: 'cell-pa2', order: 4, configuration: 'A', seed: 'pa2' },
]);

// The two registered adapters, with the declaration the run set's registrations
// carry. The plant claims one tool and two capabilities BEYOND these.
const ADAPTERS = Object.freeze([
  { provider: 'pi', adapter_id: 'adr-pi-local', binary: 'pi' },
  { provider: 'codex', adapter_id: 'adr-codex-local', binary: 'codex' },
]);
const DECLARED_CAPABILITIES = Object.freeze(['task.read', 'artifact.write', 'source.read', 'code.write']);
const DECLARED_TOOLS = Object.freeze(['tool:fs.read', 'tool:fs.write', 'tool:test.run']);
const PLANTED_CAPABILITIES = Object.freeze(['net.fetch', 'board.review.approve']);
const PLANTED_TOOL = 'tool:net.fetch';

// The instant every clock in this script reads. It is a CONSTANT, it is inside
// the permit's own window (2026-09-26T00:00:00Z .. 2026-09-27T00:00:00Z), and it
// is not read from the process clock: the same script on another day produces
// the same document.
const INJECTED_INSTANT = '2026-09-26T12:00:00.000Z';
const PLANT_WORKSPACE = '/tmp/veritas-s2-007r-ws/measurement-plant';
// The context surface the measurement-7 plant is built with. The plant provokes
// refusals and spawns no executor, so it is not a cell of the A/B comparison; the
// surface is still a REQUIRED argument of the transport, and this is the
// provider-documented default end (`A`: no suppression flag is passed).
const PLANT_CONFIGURATION = 'A';

// The A-MVP ids, and the closed vocabulary the gate reads a per-case value from.
const A_MVP_IDS = Object.freeze(['A-MVP-01', 'A-MVP-02', 'A-MVP-03', 'A-MVP-04', 'A-MVP-05', 'A-MVP-06', 'A-MVP-07']);

// ---------------------------------------------------------------------------
// Small deterministic helpers
// ---------------------------------------------------------------------------
const injectedClock = { now: () => new Date(Date.parse(INJECTED_INSTANT)), call: () => new Date(Date.parse(INJECTED_INSTANT)), get: () => new Date(Date.parse(INJECTED_INSTANT)) };

function wireDigest(value) {
  return `sha256:${canonicalDigest(value)}`;
}

function sha256File(absolute) {
  return createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

function relative(target) {
  const value = path.relative(ROOT, target);
  return value.startsWith('..') ? target : value.split(path.sep).join('/');
}

function readJson(absolute) {
  const bytes = fs.readFileSync(absolute);
  return { bytes, json: JSON.parse(bytes.toString('utf8')) };
}

function headCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

function sortedUnique(values) {
  return [...new Set(values.filter((value) => typeof value === 'string' && value.length > 0))].sort();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

class ContractFailure extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'ContractFailure';
    this.detail = detail;
  }
}

// ---------------------------------------------------------------------------
// 1. The one run set
// ---------------------------------------------------------------------------
/**
 * Read the four driver invocations. Each `run-record.json` is the invocation
 * record the driver published (with its own record_digest, which is re-derived
 * here); each `run-NN.json` beside it is one attempted governed run.
 */
function readRunSet() {
  if (!fs.existsSync(RUN_ROOT)) throw new ContractFailure('RUN_SET_ABSENT', `${relative(RUN_ROOT)} does not exist`);
  const cells = [];
  for (const spec of CELLS) {
    const dir = path.join(RUN_ROOT, spec.id);
    const recordPath = path.join(dir, 'run-record.json');
    if (!fs.existsSync(recordPath)) throw new ContractFailure('RUN_SET_CELL_ABSENT', `${relative(recordPath)} does not exist`);
    const { json: invocation } = readJson(recordPath);
    if (!Array.isArray(invocation.runs) || invocation.runs.length === 0) {
      throw new ContractFailure('RUN_SET_CELL_HAS_NO_RUNS', `${relative(recordPath)} carries no runs`);
    }
    const invocationDigest = invocationDigestVerified(invocation);
    const runSetId = runDriverRunSetId(invocation);
    const runs = invocation.runs.map((raw, index) => {
      const file = `run-${String(index + 1).padStart(2, '0')}.json`;
      const absolute = path.join(dir, file);
      const bytes = fs.existsSync(absolute) ? fs.readFileSync(absolute) : null;
      return {
        file,
        relative: relative(absolute),
        present_on_disk: bytes !== null,
        sha256: bytes === null ? null : createHash('sha256').update(bytes).digest('hex'),
        raw,
        normalised: normalizeRunDriverRecord(raw, {
          invocation,
          contentDigest: invocationDigest.recomputed,
          fileSha256: bytes === null ? null : createHash('sha256').update(bytes).digest('hex'),
          sourcePath: relative(absolute),
        }),
      };
    });
    cells.push({
      ...spec,
      dir: relative(dir),
      invocation,
      invocation_path: relative(recordPath),
      invocation_sha256: sha256File(recordPath),
      invocation_digest_verified: invocationDigest.verified,
      invocation_digest_declared: invocationDigest.declared,
      invocation_digest_recomputed: invocationDigest.recomputed,
      run_set_id: runSetId,
      runs,
    });
  }
  return cells;
}

/** The run-set-wide identity every one of the seven measurements is computed under. */
function runSetIdentity(cells) {
  const projectDigests = sortedUnique(cells.map((cell) => cell.invocation.project?.digest));
  const campaignGrants = sortedUnique(cells.map((cell) => cell.invocation.budget?.grant_id ?? cell.invocation.invocation?.grant_id));
  if (projectDigests.length !== 1) {
    throw new ContractFailure('RUN_SET_PROJECT_DIGEST_MIXED', projectDigests.join(','));
  }
  if (campaignGrants.length !== 1) {
    throw new ContractFailure('RUN_SET_CAMPAIGN_GRANT_MIXED', campaignGrants.join(','));
  }
  const id = `rs-s2007r-pilot-${canonicalDigest({
    driver: cells[0].invocation.driver?.version ?? null,
    cells: cells.map((cell) => ({ seed: cell.seed, configuration: cell.configuration, record: cell.invocation_sha256 })),
  }).slice(0, 16)}`;
  return { run_set_id: id, project_digest: projectDigests[0], campaign_grant_id: campaignGrants[0] };
}

// ---------------------------------------------------------------------------
// 2. The planted skills-authority expansion attempt
// ---------------------------------------------------------------------------
/**
 * Plant `SKILL_EXPANSION_PROBE_TEXT` inside a workspace and provoke the
 * refusals. Nothing here is a run: no task is claimed, no lease is opened, no
 * board row is written, and the record says `is_a_run: false` in the same place
 * the run set says it of its own crossings.
 */
async function plantSkillsExpansion() {
  const permit = buildUnisolatedAuthorization();
  const plantPath = path.join(PLANT_WORKSPACE, 'SKILL.md');
  fs.rmSync(PLANT_WORKSPACE, { recursive: true, force: true });
  fs.mkdirSync(PLANT_WORKSPACE, { recursive: true, mode: 0o700 });
  fs.chmodSync(PLANT_WORKSPACE, 0o700);
  fs.cpSync(path.join(ROOT, 'corpus/s2-007r/project'), path.join(PLANT_WORKSPACE, 'project'), { recursive: true });
  fs.writeFileSync(plantPath, SKILL_EXPANSION_PROBE_TEXT, 'utf8');
  const plantBytes = fs.readFileSync(plantPath);
  // The plant file is PUBLISHED, so the bytes a third party hashes are the
  // bytes the refusals were provoked by. /tmp is scratch and is wiped; the
  // published copy is the one the record's digest names.
  const published = path.join(RUN_ROOT, 'measurement-plant', 'SKILL.md');
  fs.mkdirSync(path.dirname(published), { recursive: true });
  fs.writeFileSync(published, plantBytes);
  const plant = {
    path: `${PLANT_WORKSPACE}/SKILL.md`,
    published_path: relative(published),
    text_source: 'src/lib/executors/constants.mjs#SKILL_EXPANSION_PROBE_TEXT',
    text_source_file: 'src/lib/executors/constants.mjs',
    text_source_sha256: sha256File(path.join(ROOT, 'src/lib/executors/constants.mjs')),
    bytes: plantBytes.length,
    sha256: createHash('sha256').update(plantBytes).digest('hex'),
    published_sha256: sha256File(published),
    inside_workspace: PLANT_WORKSPACE,
    asks_for: { capabilities: [...PLANTED_CAPABILITIES], tools: [PLANTED_TOOL] },
    declared_by_the_registration: { capabilities: [...DECLARED_CAPABILITIES], tools: [...DECLARED_TOOLS] },
  };
  const arms = [];
  for (const adapter of await ADAPTERS) {
    const registration = createRealRegistration({
      provider: adapter.provider,
      adapterId: adapter.adapter_id,
      workspaceId: 'ws-s2007r-project',
      principalId: 'prn-s2007r-producer',
      displayName: `${adapter.provider} CLI (installed on this host)`,
      health: 'healthy',
      clock: injectedClock,
      declaredCapabilities: [...DECLARED_CAPABILITIES],
      declaredTools: [...DECLARED_TOOLS],
      sandboxProfileId: HOST_UNISOLATED_PROFILE_ID,
      unisolatedExecutionAuthorization: permit,
      // No real run evidence is claimed for the plant: a measurement probe that
      // dispatched nothing cannot corroborate a registration.
      realRunEvidence: null,
    });
    const transport = createRealExecutorTransport({
      provider: adapter.provider,
      registration,
      clock: injectedClock,
      // The surface is a required, validated argument (issue #45, round 3). This
      // plant provokes refusals and spawns nothing, so it is not a comparison
      // cell; it is built with the provider-documented default end and the
      // recorded argv evidence below says which flags that selected.
      configuration: PLANT_CONFIGURATION,
      workspaceRoots: [PLANT_WORKSPACE],
      realpath: fs.realpathSync,
      executorPath: fs.realpathSync(path.join(process.env.HOME ?? '/root', '.local/bin', adapter.binary)),
      evidenceDir: path.join(PLANT_WORKSPACE, 'raw'),
      prompt: 'measurement step 7: authority expansion probe, no task, no dispatch',
      grant: { capabilities: [...DECLARED_CAPABILITIES], tools: [...DECLARED_TOOLS] },
      unisolatedExecutionAuthorization: permit,
    });
    const effectiveBefore = await transport.capabilities({});
    const claimRefusal = await captureRefusal(() => transport.capabilities({
      claimed_capabilities: [...DECLARED_CAPABILITIES, ...PLANTED_CAPABILITIES],
      claimed_tools: [...DECLARED_TOOLS, PLANTED_TOOL],
    }));
    const forgedRefusal = await captureRefusal(() => transport.capabilities({
      claimed_tools: [...DECLARED_TOOLS, PLANTED_TOOL],
      granted_scope: [...PLANTED_CAPABILITIES],
      approved: true,
    }));
    const effectiveAfter = await transport.capabilities({});
    arms.push({
      provider: adapter.provider,
      adapter_id: adapter.adapter_id,
      registration_provenance_status: registration.real_adapter_provenance.status,
      sandbox_profile_id: registration.sandbox_profile_id,
      effective_tools_before: effectiveBefore.tools,
      effective_capabilities_before: effectiveBefore.capabilities,
      effective_tools_after: effectiveAfter.tools,
      effective_capabilities_after: effectiveAfter.capabilities,
      effective_sets_unchanged: JSON.stringify(effectiveBefore.tools) === JSON.stringify(effectiveAfter.tools)
        && JSON.stringify(effectiveBefore.capabilities) === JSON.stringify(effectiveAfter.capabilities),
      planted_tool_obtained: effectiveAfter.tools.includes(PLANTED_TOOL),
      planted_capability_obtained: PLANTED_CAPABILITIES.some((capability) => effectiveAfter.capabilities.includes(capability)),
      claim_refusal: claimRefusal,
      authority_argument_refusal: forgedRefusal,
      transport_expansion_ledger: transport.authorityExpansions.map((entry) => ({
        source: entry.source,
        requested_tool: entry.requested_tool,
        verdict: entry.verdict,
        detail: entry.detail,
      })),
      transport_error_codes: transport.errors.map((entry) => entry.code),
    });
  }
  {
    const planted = arms.length;
    const refused = arms.filter((arm) => arm.claim_refusal.refused && arm.authority_argument_refusal.refused).length;
    const granted = arms.filter((arm) => arm.planted_tool_obtained || arm.planted_capability_obtained).length;
    return {
      is_a_run: false,
      governed: false,
      board_commands_called: 0,
      board_rows_written: 0,
      why: 'no task was claimed and no lease was opened: the plant exists to be refused, and the run set had no governed run to plant into (every tasks.claim was refused BLOCKED_SANDBOX). The measurement is therefore a boundary observation against the same registration, the same grant and the same workspace the run set used, executed by the measurement step, not an observation of a run.',
      workspace_root: PLANT_WORKSPACE,
      authorization: { authorization_id: permit.authorization_id, authority: permit.authority, scope: permit.scope, profile_id: permit.profile_id, body_digest: permit.body_digest },
      injected_instant: INJECTED_INSTANT,
      plant,
      arms,
      planted,
      refused,
      granted,
    };
  }
}

/** A refusal as a machine-checkable document, or `refused:false` when the call was honoured. */
async function captureRefusal(call) {
  try {
    await call();
    return { refused: false, honoured: true, note: 'the call was HONOURED: a planted authority was obtained' };
  } catch (error) {
    return {
      refused: true,
      typed: isBoardError(error),
      code: error?.code ?? null,
      class: error?.name ?? null,
      message: String(error?.message ?? error).slice(0, 300),
      retryable: error?.retryable ?? null,
    };
  }
}

// ---------------------------------------------------------------------------
// 2b. The real argv, read back from the process logs
// ---------------------------------------------------------------------------
/**
 * Check (c) of measurement 7 asks for `sha256(argv tool allowlist) ===
 * sha256(request.allowed_tools)`. This run set contains no governed run, so the
 * claim cannot be evaluated against one: the child's argv is built inside
 * `transport.start()`, which needs a lease and a fencing token that
 * `tasks.claim` refused to open. What IS on disk is eight REAL process logs
 * from the provenance-bootstrap crossings, and this function reads them to say
 * exactly which of the two digests a record in this run set carries, and what
 * the argv really carried.
 *
 * The reading is deliberately narrow. It publishes the tool-related argv
 * evidence of each real log and the one relation those bytes support — the argv
 * tool allowlist is a strict SUBSET of the effective tool set, so the transport
 * refuses rather than widens — and it reports the digest equality as NOT_RUN
 * with the reason. A subset is not an equality and is never published as one.
 */
function argvToolAllowlistObservation(cells) {
  const logs = [];
  for (const cell of cells) {
    for (const crossing of cell.invocation.provenance_bootstrap?.crossings ?? []) {
      for (const raw of crossing.raw_logs ?? []) {
        const absolute = path.join(ROOT, raw.path);
        if (!fs.existsSync(absolute)) {
          logs.push({ cell: cell.id, run_id: crossing.run_id, provider: crossing.provider, path: raw.path, present_on_disk: false });
          continue;
        }
        const bytes = fs.readFileSync(absolute);
        const log = JSON.parse(bytes.toString('utf8'));
        const invocation = log.invocation ?? {};
        const argv = Array.isArray(invocation.argv) ? invocation.argv : [];
        // pi passes `--tools a,b` or `--no-tools`; codex 0.157.1's `exec` argv
        // carries no tool flag at all, which is itself the observation.
        let flag = 'NO_TOOL_FLAG';
        let names = null;
        if (argv.includes('--tools')) {
          const at = argv.indexOf('--tools');
          flag = '--tools';
          names = String(argv[at + 1] ?? '').split(',').filter((name) => name !== '');
        } else if (argv.includes('--no-tools')) {
          flag = '--no-tools';
          names = [];
        }
        const effective = Array.isArray(invocation.effective_tools) ? invocation.effective_tools : null;
        const unbound = Array.isArray(invocation.unbound_effective_tools) ? invocation.unbound_effective_tools : null;
        const text = bytes.toString('utf8');
        logs.push({
          cell: cell.id,
          run_id: crossing.run_id,
          provider: crossing.provider,
          governed: false,
          is_a_run: false,
          path: raw.path,
          file_sha256: createHash('sha256').update(bytes).digest('hex'),
          record_declared_sha256: raw.sha256,
          record_digest_matches: `sha256:${createHash('sha256').update(bytes).digest('hex')}` === raw.sha256,
          configuration: invocation.configuration ?? null,
          tool_flag: flag,
          argv_tool_allowlist: names,
          argv_tool_allowlist_digest: names === null ? null : wireDigest([...names].sort()),
          effective_tools: effective,
          effective_tools_digest: effective === null ? null : wireDigest([...effective].sort()),
          unbound_effective_tools: unbound,
          argv_flag_allowlist_digest: invocation.argv_allowlist_digest ?? null,
          argv_flag_allowlist_digest_note: 'this digest is over the PERMITTED FLAG SET (-p, --mode:json, --tools:, --no-tools, ...), not over a tool allowlist. It is published so a reader can see which field it is and is not used as a tool-allowlist digest.',
          request_allowlist_digest: null,
          request_allowlist_digest_present_in_the_log: text.includes('request_allowlist_digest'),
          request_allowed_tools_present_in_the_log: text.includes('allowed_tools'),
          argv_subset_of_effective_tools: names === null || effective === null ? null : [...names].every((name) => effective.includes(name)),
          argv_equal_to_effective_tools: names === null || effective === null ? null : [...names].sort().join(',') === [...effective].sort().join(','),
          argv_carrys_the_planted_tool: names === null ? null : names.includes(PLANTED_TOOL),
          tool_control: invocation.tool_control ?? null,
        });
      }
    }
  }
  const withFlag = logs.filter((row) => row.argv_tool_allowlist !== null);
  const withRequestDigest = logs.filter((row) => row.request_allowlist_digest_present_in_the_log === true);
  return {
    checked_logs: logs.length,
    logs_carrying_a_request_allowlist_digest: withRequestDigest.length,
    logs_carrying_a_request_allowed_tools_list: logs.filter((row) => row.request_allowed_tools_present_in_the_log === true).length,
    digest_equality: 'NOT_RUN',
    digest_equality_reason: `not measurable from this run set: 0 of ${logs.length} real process logs carry a request_allowlist_digest and 0 carry a request allowed_tools list, and the child's argv is built only inside transport.start(), which needs the lease and fencing token that tasks.claim refused to open with BLOCKED_SANDBOX. Both sides of the equality are absent, so their equality is undefined rather than true.`,
    subset_measured: withFlag.length > 0,
    subset_result: withFlag.length === 0 ? null : {
      logs_with_a_tool_flag: withFlag.length,
      argv_subset_of_effective_tools: withFlag.every((row) => row.argv_subset_of_effective_tools === true),
      argv_equal_to_effective_tools: withFlag.filter((row) => row.argv_equal_to_effective_tools === true).length,
      what_this_is: 'the DIRECTION of the relation, measured on real argv: in every log the tool allowlist the child received is a strict subset of the effective tool set, because the registration declared tool:fs.read and the operator bound it to no native name for either executor, so it is recorded in unbound_effective_tools and reaches the child in no form. The transport refuses rather than widens. This is a subset, not the digest equality check (c) asks for, and it is not published as one.',
      why_it_is_not_the_check: 'check (c) is an equality between two digests; this run set carries one side of neither. Publishing "the digests are equal" beside eight logs in which the field is absent would be the false green this ticket exists to prevent.',
    },
    per_log: logs,
  };
}

// ---------------------------------------------------------------------------
// 3. The seven measurements
// ---------------------------------------------------------------------------
/** Per-cell measurement sets, straight out of the pure layer, never restated. */
function perCellMeasurements(cells, identity) {
  const out = [];
  for (const cell of cells) {
    const byAdapter = new Map();
    for (const run of cell.runs) {
      const key = `${run.normalised.cell.adapterId}|${run.normalised.cell.configuration}`;
      if (!byAdapter.has(key)) byAdapter.set(key, []);
      byAdapter.get(key).push(run.normalised);
    }
    for (const [key, runs] of byAdapter) {
      // The run set is the AGGREGATION's: one project digest and one campaign
      // grant across every cell, which is what `runSetIdentity` asserted before
      // this function was called. A cell's own driver invocation id is one
      // CONFIGURATION, so a comparison that asserted on it could never pair A
      // with B; both ids are recorded on the cell.
      const measured = measureSeven({ runs, cell: { label: `${cell.id}#${key}` }, runSetId: identity?.run_set_id ?? null });
      out.push({ cell, key, measured, runs: runs.length });
    }
  }
  return out;
}

/** Every cell's row for one measurement, plus whether the cells AGREE. */
function cellsAgree(cellSets, name) {
  const rows = cellSets.map((entry) => entry.measured.measurements.find((row) => row.name === name));
  const statuses = sortedUnique(rows.map((row) => row?.status ?? 'ABSENT'));
  return { rows, statuses, agree: statuses.length === 1, status: statuses[0] ?? 'ABSENT' };
}

function evidenceForRunSet(cells, identity) {
  const runRows = cells.flatMap((cell) => cell.runs);
  return {
    run_set_id: identity.run_set_id,
    run_set_composition: cells.map((cell) => ({
      cell: cell.id,
      order: cell.order,
      configuration: cell.configuration,
      seed: cell.seed,
      record: cell.invocation_path,
      record_sha256: cell.invocation_sha256,
      record_digest_declared: cell.invocation_digest_declared,
      record_digest_recomputed: cell.invocation_digest_recomputed,
      record_digest_verified: cell.invocation_digest_verified,
      driver_run_set_id: cell.run_set_id,
      attempted_governed_runs: cell.runs.length,
    })),
    project_digest: identity.project_digest,
    campaign_grant_id: identity.campaign_grant_id,
    run_ids: runRows.map((run) => run.normalised.runId),
    run_record_digests: cells.map((cell) => ({
      path: cell.invocation_path,
      sha256: cell.invocation_sha256,
      bytes: fs.statSync(path.join(ROOT, cell.invocation_path)).size,
    })),
    per_run_record_digests: runRows.map((run) => ({
      run_id: run.normalised.runId,
      path: run.relative,
      sha256: run.sha256,
      present_on_disk: run.present_on_disk,
    })),
    raw_log_digests: rawLogDigests(cells),
    driver_verdicts: sortedUnique(runRows.map((run) => run.raw.verdict)),
    // Derived, never asserted: a governed run is one that collected a result
    // through the board. The run set collected none.
    governed_runs_completed: runRows.filter((run) => run.normalised.execution.resultCollected === true).length,
    board_events: runRows.reduce((sum, run) => sum + (Array.isArray(run.raw.events) ? run.raw.events.length : 0), 0),
    refusals: sortedUnique(runRows.flatMap((run) => (Array.isArray(run.raw.findings) ? run.raw.findings.map((row) => row.code) : []))),
  };
}

/** The raw process logs the run set really wrote, with the digests on disk. */
function rawLogDigests(cells) {
  const out = [];
  for (const cell of cells) {
    for (const run of cell.runs) {
      const files = Array.isArray(run.raw.raw_logs?.files) ? run.raw.raw_logs.files : [];
      for (const file of files) {
        const absolute = path.join(ROOT, run.raw.raw_logs.directory ?? '', String(file.file ?? ''));
        out.push({
          path: relative(absolute),
          sha256: typeof file.sha256 === 'string' ? file.sha256.replace(/^sha256:/, '') : null,
          bytes: Number.isInteger(file.bytes) ? file.bytes : null,
          present_on_disk: fs.existsSync(absolute),
        });
      }
    }
  }
  return out;
}

/**
 * The seven rows, over the WHOLE run set.
 *
 * The aggregation rule, stated once: a measurement is reported at run-set level
 * only when every cell of the run set reports the same status for it. A run set
 * whose cells disagree is not one number, so the run-set row is NOT_RUN and the
 * disagreement is named. Nothing is averaged across cells, and no NOT_RUN cell
 * is rounded up into a number.
 */
function sevenMeasurements({ cells, cellSets, identity, plant }) {
  const evidence = evidenceForRunSet(cells, identity);
  const attempts = cells.flatMap((cell) => cell.runs.map((run) => ({ cell: cell.id, ...run })));
  const blockedCodes = sortedUnique(attempts.flatMap((run) => (Array.isArray(run.raw.findings) ? run.raw.findings.map((row) => row.code) : [])));
  const sharedLimit = [
    'ONE run set: the single campaign the owner authorised (grant grt-s2007r-pilot, one project digest), four driver invocations, eight attempted governed runs, zero completed governed runs. No figure below is averaged across cells and no cell is rounded up.',
    'Every attempted governed run in this run set was refused before a run existed: policy.assertSandboxExecutable(sbx-host-unisolated-v1) answers BLOCKED_SANDBOX, so tasks.claim never opened a lease and no task ever entered RUNNING. A measurement that needs a completed run therefore has no denominator, which is reported as NOT_RUN and not as zero.',
  ];
  const rows = [];

  rows.push({
    name: 'accepted_task_quality',
    status: 'NOT_RUN',
    value: null,
    unit: 'ratio',
    numerator: null,
    denominator: 0,
    basis: 'DETERMINISTIC_ORACLE',
    method: 'numerator = runs whose collected ExecutionResult.outcome is SUCCEEDED and whose deterministic task oracle (node corpus/s2-007r/project/verify.mjs <task_id>) exits 0 and whose task reached IN_REVIEW; denominator = runs with a collected ExecutionResult. Both sides are read from the run record; a run with no collected result is excluded from the denominator and named, never counted as a rejection.',
    observation: {
      collected_results: 0,
      accepted: [],
      rejected: [],
      runs_without_a_collected_result: attempts.map((run) => run.normalised.runId),
      task_final_states: sortedUnique(attempts.map((run) => run.normalised.task.finalState)),
      oracle_ran: false,
      per_cell_status: cellsAgree(cellSets, 'accepted_task_quality'),
    },
    limitations: [
      ...sharedLimit,
      `NOT_RUN: no run in this run set collected an ExecutionResult (0 of ${attempts.length} attempts; the refusals were ${blockedCodes.join(', ')}), so there is no accepted task to score and no oracle was ever executed. A zero here would be a fabricated zero: it would say "every accepted task failed" about a run set in which no task was accepted.`,
    ],
    hard_gate_counter: 'falseApprovals',
    evidence,
  });

  rows.push({
    name: 'pass_at_1',
    status: 'NOT_RUN',
    value: null,
    unit: 'ratio',
    numerator: null,
    denominator: 0,
    basis: 'BOARD_TASK_ATTEMPTS_AND_DETERMINISTIC_ORACLE',
    method: 'numerator = tasks whose board row carries attempts === 1 and whose deterministic oracle passed; denominator = the distinct tasks in the run set. The per-task booleans are published, not only the fraction.',
    observation: {
      distinct_tasks: sortedUnique(attempts.map((run) => run.normalised.task.taskId)),
      tasks: attempts.map((run) => ({
        task_id: run.normalised.task.taskId,
        cell: run.cell,
        adapter_id: run.normalised.cell.adapterId,
        configuration: run.normalised.cell.configuration,
        attempts: run.normalised.task.attempts,
        final_state: run.normalised.task.finalState,
        oracle_pass: null,
      })),
      per_cell_status: cellsAgree(cellSets, 'pass_at_1'),
    },
    limitations: [
      ...sharedLimit,
      `NOT_RUN: no task was ever claimed, so every board row carries attempts 0 and no oracle ran. pass@1 needs a first attempt; this run set has none, and the value is null rather than 0/8.`,
    ],
    hard_gate_counter: 'falseApprovals',
    evidence,
  });

  rows.push({
    name: 'intervention_time',
    status: 'NOT_RUN',
    value: null,
    unit: 'milliseconds',
    numerator: 0,
    denominator: 0,
    basis: 'BOARD_INJECTED_CLOCK',
    method: 'per run, board_ms = terminal_event.emitted_at - accepted_event.emitted_at on the board\'s own injected clock, and interventions = the count of non-executor commands the runner issued between those two events (which must be 0); the cell value is the upper median.',
    observation: {
      per_run: attempts.map((run) => ({
        run_id: run.normalised.runId,
        accepted_at: run.normalised.execution.acceptedAt,
        terminal_at: run.normalised.execution.terminalAt,
        board_ms: null,
        interventions: run.normalised.execution.interventions.length,
        board_duration_ms: run.normalised.execution.boardDurationMs,
      })),
      accepted_events: 0,
      terminal_events: 0,
      per_cell_status: cellsAgree(cellSets, 'intervention_time'),
    },
    limitations: [
      ...sharedLimit,
      'NOT_RUN: no run emitted an ACCEPTED event, so the window has no endpoints. This is board time, not model time; and a non-zero intervention count would itself be a finding, not a subtraction.',
    ],
    hard_gate_counter: 'missingJournalOrOutbox',
    evidence,
  });

  const bootstrapCrossings = cells.flatMap((cell) => (cell.invocation.provenance_bootstrap?.crossings ?? []).map((crossing) => ({
    cell: cell.id,
    provider: crossing.provider,
    run_id: crossing.run_id,
    governed: crossing.governed === true,
    is_a_run: crossing.is_a_run === true,
    exit_status: crossing.exit_status,
    wall_ms: crossing.wall_ms,
    spend_usd: crossing.spend_usd,
  })));
  rows.push({
    name: 'cost',
    status: 'NOT_RUN',
    value: null,
    unit: 'mixed',
    numerator: null,
    denominator: 0,
    basis: COST_BASES[2],
    method: 'per run, cost_usd_micros = round(usage.cost.total * 1e6) when the executor itself reported a currency figure (basis EXECUTOR_REPORTED_USD); otherwise the unit is a PROXY, not money: proxy_tokens = input + output + reasoning (basis PROXY_TOKENS_NO_USD_REPORTED); a run that reported neither is NOT_OBSERVED and the cell is NOT_RUN. Nothing is ever priced from a published list.',
    observation: {
      cost_basis_observed: COST_BASES[2],
      runs_with_reported_usd: 0,
      runs_with_reported_tokens: 0,
      governed_run_spend_usd: 0,
      campaign_ledger: { path: LEDGER_RELATIVE, cap_usd: 2, stop_at_usd: 1.6, total_usd: 0 },
      not_a_run_spend: {
        note: 'these are real processes this pilot really started, and they are NOT runs. They are published here because a reader looking for the cost of this pilot would otherwise find nothing, and they are excluded from every numerator above.',
        preflight_pi: { session_id: '01a0e16b-4d68-707f-b0ed-b6042d8e2ec6', cost_usd: 0.00009786, input_tokens: 1427, output_tokens: 51, basis: 'EXECUTOR_REPORTED_USD' },
        preflight_codex: { thread_id: '01a0e16b-51fa-7923-a944-37b54437779e', cost_usd: null, cost_basis: 'NO_USD_REPORTED_BY_EXECUTOR', input_tokens: 20936, cached_input_tokens: 12160, output_tokens: 5 },
        provenance_bootstrap_crossings: bootstrapCrossings,
      },
      per_cell_status: cellsAgree(cellSets, 'cost'),
    },
    limitations: [
      ...sharedLimit,
      `NOT_RUN: no governed run in this run set reported a currency figure or a token count, so the per-cell basis is ${COST_BASES[2]} and there is no denominator. A MEASURED 0 here would be the false zero this measurement exists to avoid: a run that reported nothing is not a run that cost nothing.`,
      'codex authenticates through a ChatGPT account and its JSONL reports no per-token billing, so no codex cost figure exists to compare against pi; no cost delta is emitted for that reason alone.',
    ],
    hard_gate_counter: 'falseApprovals',
    evidence,
  });

  rows.push({
    name: 'latency',
    status: 'NOT_RUN',
    value: null,
    unit: 'milliseconds',
    numerator: 0,
    denominator: 0,
    basis: 'PARENT_MONOTONIC_TIMER',
    method: 'per run, parent_wall_ms = the parent-side monotonic timer (process.hrtime.bigint) from immediately before the executor spawn to its terminal record; the cell value is the upper median of the per-run values.',
    observation: {
      per_run: attempts.map((run) => ({ run_id: run.normalised.runId, parent_wall_ms: run.normalised.parentWallMs, board_duration_ms: run.normalised.execution.boardDurationMs })),
      not_a_run_timings: {
        note: 'real parent-side timers around real child processes this pilot really started; published so the run is not reported as having produced no timing at all, and excluded from every numerator above because these crossings are not runs.',
        provenance_bootstrap_crossings: bootstrapCrossings,
      },
      per_cell_status: cellsAgree(cellSets, 'latency'),
    },
    limitations: [
      ...sharedLimit,
      'NOT_RUN: no governed run was dispatched, so no per-run parent_wall_ms exists for any run in this set.',
      'The parent-side timer includes process start, plugin/skill/context loading and shutdown, so it is startup-dominated and is not per-turn model latency. It is meaningful only WITHIN one (adapter, configuration) cell, and this comparison resolves no cross-cell speed difference at any sample size.',
    ],
    hard_gate_counter: 'missingJournalOrOutbox',
    evidence,
  });

  const unchanged = attempts.filter((run) => run.normalised.driver?.project?.unchanged === true).length;
  rows.push({
    name: 'regression_rate',
    status: 'NOT_RUN',
    value: null,
    unit: 'ratio',
    numerator: null,
    denominator: 0,
    basis: 'DETERMINISTIC_ORACLE_PRE_AND_POST',
    method: 'numerator = pre-existing tests passing on the pristine fixture and failing after the run; denominator = pre-existing tests passing before the run; value = numerator/denominator. Both sides are the same deterministic oracle on a pristine copy and on the post-run copy.',
    observation: {
      baseline_passing: null,
      after_passing: null,
      regressed: [],
      per_run: attempts.map((run) => ({ run_id: run.normalised.runId, baseline_passing: null, after_passing: null, regressed: [], project_digest_before: run.normalised.driver?.project?.digest_before, project_digest_after: run.normalised.driver?.project?.digest_after })),
      weaker_fact: {
        fact: 'the project copy was byte-identical before and after every attempted run',
        runs_with_unchanged_project: unchanged,
        total_runs: attempts.length,
        why_this_is_not_the_measurement: 'a byte-identical workspace says the executor changed nothing, because no executor was dispatched. It is NOT a test regression rate: no test ran on either side, so the denominator does not exist.',
      },
      per_cell_status: cellsAgree(cellSets, 'regression_rate'),
    },
    limitations: [
      ...sharedLimit,
      'NOT_RUN: no run in this set executed the deterministic oracle, so there is no pre/post test comparison and no denominator. Zero regressions over a set in which no test ran is a number about nothing.',
      'Even a real zero here would be weak evidence: the fixture is a handful of trivial tests, and a zero regression rate in one tiny project says nothing about a real repository.',
    ],
    hard_gate_counter: 'falseApprovals',
    evidence,
  });

  const granted = plant.granted;
  // The refusals are one measurement and the argv/request digest equality is
  // another. The plant settles the first; the second has no data in this run
  // set, so the row is PARTIAL and names the missing observable. Publishing
  // MEASURED here would report the whole measurement as done on the strength of
  // the half that ran.
  const argvEvidence = argvToolAllowlistObservation(cells);
  const digestEqualityMeasured = argvEvidence.digest_equality === 'MEASURED';
  rows.push({
    name: 'skills_authority_expansion',
    status: plant.planted > 0 && plant.refused === plant.planted && granted === 0 && digestEqualityMeasured
      ? 'MEASURED'
      : (plant.planted === 0 ? 'NOT_RUN' : (granted > 0 || plant.refused !== plant.planted ? 'FAILED_GATE' : 'PARTIAL')),
    value: granted,
    unit: 'count',
    numerator: granted,
    denominator: plant.planted,
    basis: 'BOUNDARY_REFUSALS',
    method: `planted = expansion attempts deliberately placed in a workspace (${plant.planted}: one per registered provider); refused = attempts whose observable was a RECORDED typed refusal, i.e. capabilities({claimed}) answered CAPABILITY_MISMATCH/ADAPTER_CLAIM_NOT_REGISTERED and an authority field handed to the same call answered BLOCKED_POLICY/BOUNDARY_ARGUMENT_NOT_CANONICAL, with the attempt in the transport's own expansion ledger as REFUSED; granted = the number of planted items that appeared in the effective tool or capability set afterwards, which is the number this measurement claims is 0. value = granted, unit = count; the refusal rate is refused/planted. This measurement has two sub-observables and they are reported separately: (A) the refusal, measured at the transport boundary, and (B) the argv/request allowlist digest equality, measured only where a record carries both digests. B is ${argvEvidence.digest_equality} in this run set, so the row is not MEASURED while B is not.`,
    observation: {
      sub_observables: {
        a_refusal_at_the_transport_boundary: 'MEASURED',
        b_argv_allowlist_equals_request_allowlist: argvEvidence.digest_equality,
      },
      planted: plant.planted,
      refused: plant.refused,
      refused_rate: plant.planted > 0 ? plant.refused / plant.planted : null,
      granted,
      plant: plant.plant,
      arms: plant.arms,
      argv_allowlist_evidence: argvEvidence,
      is_a_run: plant.is_a_run,
      board_commands_called: plant.board_commands_called,
      per_cell_status: cellsAgree(cellSets, 'skills_authority_expansion'),
      corroboration_elsewhere: {
        source: 'evidence/s2-007r-security-probes.json',
        probe: 'skill_authority_expansion_blocked',
        counter: 'authorityExpansions',
        value: 0,
        note: 'the same refusal, reached through the board command boundary rather than the transport, recorded by the probe gate of this ticket.',
      },
    },
    limitations: [
      ...sharedLimit,
      `PARTIAL: the refusal sub-observable is measured (planted ${plant.planted}, refused ${plant.refused}, granted ${granted}) and the argv/request allowlist digest equality is ${argvEvidence.digest_equality}. ${argvEvidence.digest_equality_reason}`,
      'The plant was executed by THIS measurement step, not inside a governed run: the run set had no run to plant into, because every tasks.claim was refused BLOCKED_SANDBOX. The measurement is therefore a boundary observation against the same registration, the same grant and the same workspace, and it is NOT evidence about any run\'s behaviour.',
      'It measures the BOUNDARY, not the model\'s compliance: a skill may ASK for authority and the refusal is what is observed. "The model did not silently self-authorise" is not observable and is not claimed.',
      'The grant is identical in every cell, so configuration A vs B is a host-surface difference and never a permission difference; the value 0 says nothing about a configuration axis that the transport does not implement.',
      'The eight process logs the argv observation reads are real argv from real children, but they are the provenance-bootstrap crossings: governed:false, is_a_run:false, board_commands_called:0. They are evidence about an argv, never about a run.',
    ],
    hard_gate_counter: 'authorityExpansions',
    evidence,
  });

  const ordered = MEASUREMENT_NAMES.map((name) => rows.find((row) => row.name === name));
  if (ordered.some((row) => row === undefined)) {
    throw new ContractFailure('MEASUREMENT_SET_INCOMPLETE', 'a measurement name produced no row');
  }
  assertMeasurementInvariants(ordered);
  return ordered;
}

// ---------------------------------------------------------------------------
// 4. The A-MVP per-case observation
// ---------------------------------------------------------------------------
/**
 * One entry per case: the case's OWN expected value, the observed value, the
 * single machine-checkable assertion behind it, the artefact that backs it, and
 * — where it is NOT_RUN — the exact reason. A case is PASS only on a real run:
 * the run set produced none, so no case is PASS.
 */
function amvpRecord({ cells, identity, head, pilot, lifecycle, ledger, plant }) {
  const attempts = cells.flatMap((cell) => cell.runs);
  const registrations = cells.flatMap((cell) => (cell.invocation.registration?.registrations ?? []).map((row) => ({ cell: cell.id, ...row })));
  const crossings = cells.flatMap((cell) => (cell.invocation.provenance_bootstrap?.crossings ?? []).map((row) => ({ cell: cell.id, ...row })));
  const lifecycleArms = Array.isArray(lifecycle?.arms) ? lifecycle.arms : [];
  const sqlRef = {
    source: 'evidence/s2-007r-pilot.json#store.sql_read',
    detail: 'read after all four cells and before container removal: 4 schemas, 55 tables each, tasks 2, runs 0, agentboard_execution_event 0 per schema',
    verified_by: 'the run step, against a real PostgreSQL 17.11 with 9 migrations applied',
  };
  const common = {
    pilot_expected: null,
    pilot_execution_in_the_frozen_file: null,
    pilot_file: PILOT_RELATIVE,
    pilot_file_sha256: pilot.sha256,
    pass_requires: 'a REAL run. A case observed on the test transport, on a replay transport, on a probe or on a registration is NOT_RUN, whatever the record would like to call it.',
  };
  for (const id of A_MVP_IDS) {
    const source = pilot.json.cases.find((row) => row.id === id) ?? null;
    if (source === null) throw new ContractFailure('PILOT_CASE_ABSENT', `${PILOT_RELATIVE} has no case ${id}`);
    common.pilot_expected = source.expected ?? null;
    common.pilot_execution_in_the_frozen_file = source.execution ?? null;
  }
  const cases = {};

  cases['A-MVP-01'] = {
    id: 'A-MVP-01',
    ...common,
    observed: 'NOT_RUN',
    assertion: 'PASS requires two registrations with adapter_kind "real" and DIFFERENT provider values, each REAL_ADAPTER_AVAILABLE with an installed probe row, AND each with at least one collected run in agentboard_execution_event attributable to its own run_id. Measured: providers codex and pi are registered and each was really spawned; agentboard_execution_event = 0 rows per schema, agentboard_run = 0 rows per schema.',
    artefact: [
      ...registrations.map((row) => ({ what: `adapters.register ${row.adapter_id} (${row.provider})`, cell: row.cell, decision: row.register_decision, provenance_status: row.provenance_status, sandbox_profile_id: row.sandbox_profile_id })),
      ...crossings.map((row) => ({ what: `provenance bootstrap crossing ${row.run_id}`, provider: row.provider, exit_status: row.exit_status, governed: row.governed === true, is_a_run: row.is_a_run === true, raw_log_sha256: row.raw_log_sha256 })),
      { what: 'SQL read after all four cells', ...sqlRef },
    ],
    clauses_observed: [
      'two distinct real adapters (codex, pi) were registered against the frozen contract schema and both were ACCEPTed',
      'each adapter really spawned its own binary on this host; the parent observed the pid and the exit code, and the raw process log is on disk with its sha256',
    ],
    clauses_not_run: ['a governed run per adapter', 'collected ExecutionResult per adapter', 'agentboard_execution_event rows attributable to each adapter\'s own run_id'],
    reason: 'the registration half really happened and the RUN half did not: policy.assertSandboxExecutable(sbx-host-unisolated-v1) answers BLOCKED_SANDBOX on the per-edge gate, so tasks.claim never opened a lease and no run ever existed. The only real crossings are the provenance bootstraps, which this run set records as governed:false, is_a_run:false, board_commands_called:0; they corroborate a REGISTRATION and cannot satisfy a clause that asks for a run.',
  };

  cases['A-MVP-02'] = {
    id: 'A-MVP-02',
    ...common,
    observed: 'NOT_RUN',
    assertion: 'PASS requires (a) a caller-supplied probeRealAdapters({candidates}) list resolving at least one candidate outside REAL_ADAPTER_PROBE_CANDIDATES, (b) the additional approved agent registered AND ran, and (c) the tracked diff of this ticket touching none of contracts/, src/lib/agentboard/, migrations/, pilots/, src/lib/identity/. Measured: (a) discovery is data-driven, (b) pi is registered and never ran a task, (c) FALSE at this HEAD.',
    artefact: [
      { what: 'the tracked diff at HEAD', paths_touched_in_frozen_targets: ['contracts/sandbox-profile.schema.json', 'src/lib/agentboard/commands.mjs', 'src/lib/agentboard/constants.mjs', 'src/lib/agentboard/policy.mjs', 'src/lib/agentboard/scheduler.mjs', 'src/lib/identity/sandbox-profiles.mjs', 'tests/identity/contracts.schemas.test.mjs'], source: 'git diff --stat, read-only' },
      { what: 'the decision that made those edits', path: 'docs/decisions/2026-09-26-s2-007r-host-unisolated-tier.md', note: 'the repository owner added the HOST_UNISOLATED floor tier inside contracts/, src/lib/agentboard/ and src/lib/identity/. It is a frozen-target edit made by that decision, not by the measurement step, and it is reported here rather than edited around.' },
      { what: 'registrations', cell: 'all', adapters: registrations.map((row) => row.adapter_id) },
    ],
    clauses_observed: ['adapter discovery is data-driven: the board resolved adr-codex-local and adr-pi-local from the installed executables on this host'],
    clauses_not_run: ['the additional approved agent running a task', 'the "without changing core" condition, which is false at this HEAD'],
    reason: 'two of the three conditions hold and the third is FALSE at this HEAD, so the case could not be PASS on this ticket\'s own terms even if a run had existed: the owner\'s D3 decision edited contracts/sandbox-profile.schema.json, four files under src/lib/agentboard/ and src/lib/identity/sandbox-profiles.mjs. The run half is separately blocked by the same BLOCKED_SANDBOX refusal. This is reported, not worked around.',
  };

  const decision = cells[0].invocation.runs?.[0]?.dispatched_decision?.decision ?? null;
  cases['A-MVP-03'] = {
    id: 'A-MVP-03',
    ...common,
    observed: 'NOT_RUN',
    assertion: 'PASS requires the decision to select argmin(priority rank, task_id), every other candidate to appear in DispatchDecision.excluded with a reason from the closed enum, AND the selected adapter\'s start() to have really spawned. Measured: the first two hold (the decision explains itself and its candidate is excluded with the closed reason SANDBOX_NOT_PROVEN); the third does not, because no adapter was selected (selected_adapter_id: null).',
    artefact: [
      { what: 'the DispatchDecision document', decision_id: decision?.decision_id ?? null, decided_at: decision?.decided_at ?? null, selected_task_id: decision?.selected_task_id ?? null, selected_adapter_id: decision?.selected_adapter_id ?? null, excluded: decision?.excluded ?? null, budget_snapshot: decision?.budget_snapshot ?? null, decision_digest: cells[0].runs[0].raw.dispatched_decision?.decision_digest ?? null, cell: cells[0].id },
      { what: 'the same decision in every cell', cells: cells.map((cell) => cell.id), reason: 'every cell produced selected_task_id null with SANDBOX_NOT_PROVEN' },
    ],
    clauses_observed: [
      'the deterministic order ran and the decision explained itself: no selection, every candidate excluded with the closed reason SANDBOX_NOT_PROVEN',
      'the budget snapshot was resolved server-side: currency USD, assigned true, task_remaining 0.5, campaign_remaining 2, day_remaining 2',
      'the decision document carries its own content digest',
    ],
    clauses_not_run: ['a selected adapter', 'a real crossing by the selected adapter'],
    reason: 'the DECISION half of this case is really observed and the CROSSING half is not: the only candidate was excluded with SANDBOX_NOT_PROVEN, so selected_adapter_id is null and no start() ever ran. The case asks for both, so it is NOT_RUN rather than a partial pass.',
  };

  const cancelArm = lifecycleArms.find((arm) => arm.arm === 'cancel') ?? null;
  const timeoutArm = lifecycleArms.find((arm) => arm.arm === 'timeout') ?? null;
  const sigkillArm = lifecycleArms.find((arm) => arm.arm === 'sigkill') ?? null;
  // Every sentence below is DERIVED from the arms. Round 2's record carried a
  // hardcoded sentence saying the timeout arm had published no proof; after the
  // round-3 fix it does publish one, and a literal would have kept asserting the
  // old finding against new evidence. The per-arm clauses, the readings and the
  // summary are computed here, so the record cannot drift from its own arms.
  const armClause = (arm) => (isPlainObject(arm?.clause) ? arm.clause : null);
  const armSummary = (arm) => {
    const clause = armClause(arm);
    return `${String(arm?.arm ?? 'unknown')}: ${String(clause?.observed ?? 'NO_CLAUSE')} (${String(arm?.result?.outcome ?? arm?.result?.code ?? 'no outcome')})`
      + (clause?.reason === null || clause?.reason === undefined ? '' : ` — ${String(clause.reason)}`);
  };
  const armNotRun = lifecycleArms.filter((arm) => armClause(arm)?.observed === 'NOT_RUN');
  const armObserved = lifecycleArms.filter((arm) => armClause(arm)?.observed === 'OBSERVED');
  const readingsOf = (arm) => (isPlainObject(arm?.readings) ? {
    observer_verdict: arm.readings.observer?.verdict ?? null,
    observer_survivors: arm.readings.observer?.survivors ?? null,
    observer_remaining_process_ids: arm.readings.observer?.remaining_process_ids ?? null,
    parent_pid: arm.readings.parent?.pid ?? null,
    parent_alive: arm.readings.parent?.alive ?? null,
    parent_method: arm.readings.parent?.method ?? null,
    agree: arm.readings.agree ?? null,
    independent_reading_contradicts_the_observer: arm.readings.independent_reading_contradicts_the_observer ?? null,
    root_cause_of_the_staleness: arm.readings.root_cause_of_the_staleness ?? null,
  } : null);
  const contradicted = lifecycleArms.filter((arm) => arm?.readings?.independent_reading_contradicts_the_observer === true);
  cases['A-MVP-04'] = {
    id: 'A-MVP-04',
    ...common,
    observed: armNotRun.length === 0 && armObserved.length === lifecycleArms.length && lifecycleArms.length > 0 ? 'PASS' : 'PARTIAL',
    assertion: `PASS requires, for each of SIGKILL, timeout and cancel: every recorded descendant pid gone, the proof TERMINATED (never survivors:0 without it), the terminal event carrying the fence, and a late callback refused STALE_FENCE with byte-identical audit/outbox row counts. Measured on this run: ${lifecycleArms.map(armSummary).join('; ')}. ${armNotRun.length} of ${lifecycleArms.length} termination arms are therefore NOT_RUN, and the isolation clause is NOT_RUN on this host whatever any run shows.`,
    artefact: [
      { what: 'lifecycle record', path: LIFECYCLE_RELATIVE, arms: lifecycleArms.map((arm) => ({ arm: arm.arm, run_id: arm.run_id, result: arm.result?.code ?? arm.result?.outcome ?? null, clause: arm.clause?.observed ?? null, reason: arm.clause?.reason ?? null })) },
      { what: 'cancel arm', run_id: cancelArm?.run_id ?? null, survivors: armClause(cancelArm)?.survivors ?? null, remaining_process_ids: armClause(cancelArm)?.remaining_process_ids ?? null, caveat: armClause(cancelArm)?.caveat ?? null, independent_later_reading: armClause(cancelArm)?.independent_later_reading ?? null, readings: readingsOf(cancelArm) },
      { what: 'timeout arm', run_id: timeoutArm?.run_id ?? null, terminal: timeoutArm?.result?.outcome ?? null, cancel_proof: armClause(timeoutArm)?.reason ?? null, termination_published: armClause(timeoutArm)?.observed === 'NOT_RUN' ? String(armClause(timeoutArm)?.reason ?? '') : 'TERMINATED', readings: readingsOf(timeoutArm) },
      { what: 'sigkill arm', run_id: sigkillArm?.run_id ?? null, terminal: sigkillArm?.result?.outcome ?? null, note: sigkillArm?.clause?.reason ?? null, readings: readingsOf(sigkillArm) },
      {
        what: 'the two readings of every killed pid, side by side',
        note: 'the transport waits for the child exit before it accounts, so the observer answer is not a reaping race in the parent. What it can still be is the observer\'s own memoised /proc snapshot. Where the two disagree the observer answer is KEPT as the proof and the parent-side reading is published beside it; the clause is NOT_RUN with the observer\'s exact reason and is never rounded up.',
        arms_with_contradicting_independent_reading: contradicted.map((arm) => arm.arm),
        contradiction_is_a_root_cause_in_a_frozen_module: 'src/lib/identity/process-observer.mjs:191 (SNAPSHOT_TTL_MS = 20, #procTable). Fixing it is the S2-002 identity owner\'s change, not this ticket\'s: a survivor count taken inside that window of a reap names a pid that is already gone.',
      },
      { what: 'sandbox profile in force', profile_id: HOST_UNISOLATED_PROFILE_ID, tier: HOST_UNISOLATED_TIER, isolation_observed: false, os_controls_absence_evidence: HOST_UNISOLATED_EVIDENCE_DIGEST, evidence_file: PILOT_RELATIVE_REF },
    ],
    clauses_observed: [
      'group signalling really happened on every arm, and the transport refused to claim a clean stop it could not prove',
      `an independent parent-side reading ${String(cancelArm?.clause?.independent_later_reading?.when ?? 'later')} found the killed pids no longer resolvable, so nothing leaked out of the group; both readings are published and the observer\'s answer was not overwritten`,
      'the external SIGKILL arm reached RECONCILIATION_REQUIRED without any call into the boundary',
      'every late-write probe after every arm was refused: a checkpoint with a stale expected_sequence, and a second cancel. Zero accepted late writes.',
    ],
    clauses_not_run: [
      ...armNotRun.map((arm) => `the ${String(arm.arm)} arm\'s TERMINATED proof: ${String(armClause(arm)?.reason ?? 'no reason recorded')}`),
      'the audit/outbox row-count comparison for the cancellation path',
      'OS ISOLATION, permanently, on this host: createSandbox().executionAllowed is false for every executable tier, and the run\'s profile is the HOST_UNISOLATED floor with isolation_observed false. This clause is NOT_RUN whatever any run shows.',
    ],
    reason: `the process-group, fencing and reconciliation clauses were exercised against real children and behaved correctly. ${armNotRun.length} of ${lifecycleArms.length} termination arms are NOT_RUN with the exact reasons quoted above — a proof of SURVIVORS_REMAINING is never reported as a pass, and where an independent parent-side reading contradicts it both are published and neither is overwritten — and the isolation clause is NOT_RUN by construction on this host. The case is therefore PARTIAL and not PASS.`,
  };

  cases['A-MVP-05'] = {
    id: 'A-MVP-05',
    ...common,
    observed: 'NOT_RUN',
    assertion: 'PASS requires an authenticated non-producer human to move a task IN_REVIEW -> DONE, with the decision bound to the artifact hash. Measured: no such principal exists in this run, and no DONE edge was attempted.',
    artefact: [
      { what: 'the principals this run defined', note: 'no principal holds board.review.approve; the run set records the DONE edge as unreachable by construction' },
      { what: 'the task states reached', final_states: sortedUnique(attempts.map((run) => run.normalised.task.finalState)) },
    ],
    clauses_observed: [],
    clauses_not_run: ['IN_REVIEW', 'an authenticated human decision', 'the DONE edge', 'a journal replay of a DONE transition'],
    reason: 'this run has no authenticated human reviewer. A script that played the approver would be exactly the false PASS this ticket forbids, so the case is NOT_RUN rather than executed with a fixture approver. The approval is issue #12\'s work.',
    fixed: true,
  };

  cases['A-MVP-06'] = {
    id: 'A-MVP-06',
    ...common,
    observed: 'NOT_RUN',
    assertion: 'PASS requires two distinct OS pids racing for one lease on the real store, exactly one winner and one typed non-retryable refusal, and from SQL active_lease_rows=1, claimed_transition_rows=1, attempts=1, duplicateActiveLeases=0. Measured: no lease was ever created, so there was nothing to race for.',
    artefact: [
      { what: 'SQL read after all four cells', ...sqlRef },
      { what: 'the refusals that preceded the race', codes: blockedCodesOf(attempts) },
    ],
    clauses_observed: ['the real store was real: PostgreSQL 17.11 in a digest-pinned rootless-podman container, 9 migrations applied, read after the run and then removed'],
    clauses_not_run: ['two racing child processes', 'a lease', 'the atomicity observation'],
    reason: 'the race needs tasks.claim, and the per-edge sandbox gate refuses tasks.claim with BLOCKED_SANDBOX before a fence can exist. No race was fabricated: a race invented between two refusals would prove nothing about the board\'s fencing.',
  };

  cases['A-MVP-07'] = {
    id: 'A-MVP-07',
    ...common,
    observed: 'NOT_RUN',
    assertion: 'PASS requires the transport\'s own file-based crossing counter to show exactly one crossing per (task, stage) before and after a SIGKILL + restart, one committed ledger row per key, duplicateExternalEffects=0 and a recovery that issued 0 effects. Measured: there is no governed crossing to interrupt, so nothing was counted before or after.',
    artefact: [
      { what: 'the only real crossings in this run set', crossings: crossings.map((row) => ({ run_id: row.run_id, provider: row.provider, governed: row.governed === true, is_a_run: row.is_a_run === true })) },
      { what: 'the lifecycle SIGKILL arm, which is a different case', run_id: sigkillArm?.run_id ?? null, note: 'it exercised the reconciliation path of a transport-level crossing, not a board-governed outbox row, and it is reported under A-MVP-04' },
    ],
    clauses_observed: [],
    clauses_not_run: ['a SIGKILL between an outbox SEND intent and its ACK', 'outbox.recover from a new process', 'the crossing counter before and after', 'the blind retry'],
    reason: 'the interruption this case measures needs a governed crossing in flight. There is none: every attempt was refused at the claim edge, so there was no SEND to interrupt and no recovery to reconcile. Nothing was simulated to fill the gap.',
  };

  return {
    schemaVersion: 1,
    record_kind: 's2-007r-amvp-cases',
    ticket: 'S2-007R',
    issue: 'SpaceDazher/Veritas#45',
    written_by: `scripts/s2-007r-measurement-set.mjs (${SCRIPT_VERSION})`,
    commit: head,
    tree: headTree(),
    run_set_id: identity.run_set_id,
    project_digest: identity.project_digest,
    budget_grant_id: identity.campaign_grant_id,
    vocabulary: ['PASS', 'PARTIAL', 'NOT_RUN', 'NOT_RUN_DB', 'BLOCKED'],
    vocabulary_note: 'PASS means this case was observed on a REAL run of this run set. The run set completed zero governed runs, so no case is PASS. A-MVP-04 is PARTIAL because three of its clauses were really observed and two termination arms plus the isolation clause were not.',
    pilot_file: {
      path: PILOT_RELATIVE,
      sha256: pilot.sha256,
      frozen_manifest_entry: pilot.frozen,
      matches_frozen_manifest: pilot.frozen.sha256 === null ? null : pilot.frozen.sha256 === pilot.sha256,
      unchanged_by_this_ticket: true,
      verbatim: pilot.json,
    },
    pilot_file_note: 'the frozen pilot file keeps every A-MVP case at execution NOT_RUN because the contract schema has no value for a real run (SPEC D9). It is QUOTED here with its sha256 so the two documents cannot disagree silently, and it was not edited: pilots/ is a frozen target.',
    cases,
    summary: {
      pass: A_MVP_IDS.filter((id) => cases[id].observed === 'PASS'),
      partial: A_MVP_IDS.filter((id) => cases[id].observed === 'PARTIAL'),
      not_run: A_MVP_IDS.filter((id) => cases[id].observed === 'NOT_RUN'),
      pass_count: 0,
      note: 'zero PASS written. A-MVP-05 is NOT_RUN by construction (no authenticated human reviewer). A-MVP-02 carries a condition that is false at this HEAD because of the owner\'s D3 decision.',
    },
    status_table: statusTable(cases, identity, ledger),
    budget: {
      grant_id: identity.campaign_grant_id,
      currency: 'USD',
      task_limit: 0.5,
      campaign_limit: 2,
      day_limit: 2,
      timeout_ms: 600000,
      authority: 'RUN_OPERATOR_DECLARED_NOT_PRODUCT_APPROVED',
      approval_owner: 'issue #12 (S2-012)',
      campaign_spend_usd: ledger?.total_usd ?? 0,
      cap_usd: ledger?.cap_usd ?? 2,
      stop_at_usd: ledger?.stop_at_usd ?? 1.6,
      campaign_cap_never_exceeded: (ledger?.total_usd ?? 0) <= (ledger?.stop_at_usd ?? 1.6),
      spend_outside_the_board_usd: 0.00009786,
      spend_outside_the_board_note: 'one direct pi preflight call, before any grant was drawn on. codex reported no monetary cost and none was estimated.',
    },
    sandbox: {
      profile_id: HOST_UNISOLATED_PROFILE_ID,
      tier: HOST_UNISOLATED_TIER,
      isolation_observed: false,
      os_controls_absence_evidence: HOST_UNISOLATED_EVIDENCE_DIGEST,
      evidence_file: PILOT_RELATIVE_REF,
      // `capabilities` quotes the PROVEN profile-id list verbatim from
      // constants.mjs, so a profile-id of a proven tier does appear in a
      // capabilities document — as a fact about the registry, not as a claim
      // about a run. The claim that matters is narrower and is stated without
      // naming any proven profile: this ticket's rule is that no record it
      // writes names one, and a note that explains the rule by breaking it is
      // not a defence of anything.
      note: 'every run in this run set is bound to the HOST_UNISOLATED floor (sbx-host-unisolated-v1) and the record says isolation_observed:false. No record written by this ticket BINDS a run to a proven profile, and no record written by this ticket NAMES a proven profile id at all: the registry\'s proven list is quoted only inside `capabilities.sandboxProfileIds`, which is a statement about which profiles have measured OS controls on this host, never a profile a run was authorised under. The floor tier is deliberately outside that list, so assertSandboxExecutable(sbx-host-unisolated-v1) still answers BLOCKED_SANDBOX on its own.',
    },
    authority_probe: {
      measurement_7: { planted: plant.planted, refused: plant.refused, granted: plant.granted, is_a_run: plant.is_a_run, workspace_root: plant.workspace_root },
      note: 'the plant behind measurement 7 was executed by the measurement step; it is a boundary observation, not a run.',
    },
    hard_gate_counters: probeCounters(),
    // The note states the counters as they are, including a NON-ZERO one. A
    // record that repeated the counters while describing them as all-zero would
    // be the same defect as the vacuous gate it now reports elsewhere: a value
    // that reads green because nothing said otherwise.
    hard_gate_counters_note: `READ from evidence/s2-007r-security-probes.json, the probe gate's own accounting, not asserted here. This record is not a second authority on the counters: they are repeated only so this record cannot be read as a silent second accounting. As of this write they are NOT all zero: ${nonZeroCounterSentence()}. Issue #45's own stop rule says a non-zero HARD_GATE_COUNTERS value is a stop and is reported, never fixed by editing the probe, so this record reports it and neither mints nor repairs a counter. The counter is the probe gate's to explain; this record's own statuses are unaffected by it, because no status here is derived from a counter.`,
    evidence_sources: evidenceSources(cells),
    limitations: [
      'This record writes no PASS. Zero governed runs completed, so no A-MVP case has the real-run evidence its own oracle requires.',
      'A-MVP-04 is PARTIAL, not PASS: the cancel proof is SURVIVORS_REMAINING, the timeout arm published no termination proof, and the isolation clause is NOT_RUN on this host by construction.',
      'A-MVP-02 carries a condition that is false at this HEAD (the owner\'s D3 decision edited contracts/, src/lib/agentboard/ and src/lib/identity/), so the case could not be PASS on this ticket\'s own terms.',
      'The per-case file is read by the gate only when it is bound to the current commit AND to a corroborated real-adapter run. With no corroborated run, the gate forces every case to NOT_RUN whatever this file claims: that is the fail-closed direction, and it is why the values here agree with what the gate will print.',
    ],
    record_digest_method: 'sha256: + canonical-json-v1 over this record with record_digest removed',
  };
}

function blockedCodesOf(attempts) {
  return sortedUnique(attempts.flatMap((run) => (Array.isArray(run.raw.findings) ? run.raw.findings.map((row) => row.code) : [])));
}

/** The seven hard-gate counters, read from the probe gate's own record. */
function probeCounters() {
  const absolute = path.join(ROOT, 'evidence/s2-007r-security-probes.json');
  if (!fs.existsSync(absolute)) {
    return Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, null]));
  }
  const { json } = readJson(absolute);
  return Object.fromEntries(HARD_GATE_COUNTERS.map((counter) => [counter, json.counters?.[counter] ?? null]));
}

/** The non-zero hard-gate counters, named. All-zero is stated as all-zero. */
function nonZeroCounterSentence() {
  const counters = probeCounters();
  const nonZero = Object.entries(counters).filter(([, value]) => typeof value === 'number' && value !== 0);
  if (nonZero.length === 0) return 'every one of the seven is 0';
  return nonZero.map(([counter, value]) => `${counter}=${value}`).join(', ');
}

/** Every file this record quotes, with the digest of the bytes it quoted. */
function evidenceSources(cells) {
  const out = [];
  const push = (relativePath, what) => {
    const absolute = path.join(ROOT, relativePath);
    out.push({ path: relativePath, what, sha256: fs.existsSync(absolute) ? sha256File(absolute) : null, present_on_disk: fs.existsSync(absolute) });
  };
  for (const cell of cells) push(cell.invocation_path, `the ${cell.id} driver invocation record (${cell.configuration})`);
  for (const cell of cells) {
    for (const run of cell.runs) if (run.present_on_disk) push(run.relative, `one attempted governed run of ${cell.id}`);
  }
  push(LIFECYCLE_RELATIVE, 'the lifecycle record the A-MVP-04 clauses are read from');
  push(LEDGER_RELATIVE, 'the campaign ledger the budget row is read from');
  push(PILOT_RELATIVE, 'the frozen pilot file quoted verbatim above');
  push(PILOT_RELATIVE_REF, 'the measured ABSENCE of OS controls the sandbox profile is digest-bound to');
  push('evidence/s2-007r-security-probes.json', "the probe gate's own accounting of the same authority refusals");
  push('results/s2-007r/measurement-plant/SKILL.md', 'the published plant behind measurement 7');
  push('docs/decisions/2026-09-26-s2-007r-host-unisolated-tier.md', "the owner's D3 decision that made the A-MVP-02 core condition false at this HEAD");
  return out;
}

function statusTable(cases, identity, ledger) {
  return {
    engineeringStatus: 'PARTIAL',
    engineeringStatus_semantics: 'the engineering contour exists, is gated and reports honestly; the run half of the pilot could not start, and the reason is one function in a frozen file. This value is the ticket\'s own statement; scripts/verify-s2-007r.mjs derives its own verdict independently and its exit code is reported beside this table.',
    realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
    realAdapterStatus_semantics: 'no run in this run set carries a corroborated executor crossing. The two registrations are REAL_ADAPTER_AVAILABLE, and the two adapters really spawned, but both crossings are recorded as governed:false, is_a_run:false, board_commands_called:0: they corroborate a REGISTRATION and are not a run. A probe, a registration, a fixture, a stub or a replay never lifts this status.',
    assuranceStatus: 'NOT_MEASURED',
    assuranceStatus_semantics: 'there is no independent human review and no empirical semantic-accuracy measurement in this run.',
    aMvpStatus: 'NOT_CLAIMED',
    aMvpStatus_semantics: 'no named operator accepted a bounded pilot after review. The permit that admitted the HOST_UNISOLATED floor is neither a review nor an acceptance, and the budget grant approves no acceptance criterion.',
    per_case: Object.fromEntries(A_MVP_IDS.map((id) => [id, { expected: cases[id].pilot_expected, observed: cases[id].observed }])),
    run_set: { run_set_id: identity.run_set_id, project_digest: identity.project_digest, budget_grant_id: identity.campaign_grant_id },
    campaign_spend_usd: ledger?.total_usd ?? 0,
    not_inferred: ['real_adapter_execution', 'human_review', 'empirical_semantic_accuracy', 'A_MVP_PASS', 'production_readiness', 'os_isolation', 'cross_executor_comparability'],
  };
}

function headTree() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 5. The comparison record
// ---------------------------------------------------------------------------
/**
 * The axis, per cell, as the driver OBSERVED it executing (issue #45, round 3).
 * `config_delta` is never the `--config` label: it is what the argv really
 * carried, and a cell with no observed argv is `none` with that reason. The
 * per-sub-cell rows carry both argv digests, because a comparison asserts on the
 * normalised one and a reader needs the raw one to see that the normalisation
 * removed the run rather than the surface.
 */
function cellAxisEvidence(cell, cellMeasurements) {
  const deltas = sortedUnique(cell.runs.map((run) => String(run.normalised.cell.configDelta)));
  return {
    configuration: cell.configuration,
    config_delta: deltas.length === 1 ? deltas[0] : deltas,
    config_delta_agrees_across_runs: deltas.length <= 1,
    config_delta_reason: cell.runs[0]?.normalised?.cell?.configDeltaReason ?? null,
    driver_axis: isPlainObject(cell.invocation?.invocation?.configuration_axis)
      ? cell.invocation.invocation.configuration_axis
      : null,
    sub_cells: cellMeasurements.map((entry) => ({
      provider: entry.measured.cell.provider,
      adapter_id: entry.measured.cell.adapter_id,
      configuration: entry.measured.cell.configuration,
      config_delta: entry.measured.cell.config_delta,
      runs: entry.measured.cell.runs,
      argv_observed_in_runs: entry.measured.argv_observed_in_runs,
      argv_digest_raw: entry.measured.argv_digest_raw,
      argv_digest_normalised: entry.measured.argv_digest_normalised,
      configuration_surface_flags: entry.measured.configuration_surface_flags,
      configuration_axis: entry.measured.configuration_axis,
    })),
  };
}

/**
 * The A/B comparison, COMPUTED (issue #45, round 3).
 *
 * Round 2 recorded `argv_identical: true` for both providers and refused the
 * comparison, because the transport took no surface argument: an A/B pair would
 * have differenced a cell with itself. The surface is now a required, validated
 * argument, so whether a provider may be compared is decided STRUCTURALLY, from
 * the normalised argv digest each end really executed:
 *
 *   two different normalised digests -> the pair is compared, and the deltas the
 *                                     sample size permits are published;
 *   the same digest                   -> the provider is EXCLUDED with that
 *                                       reason, which is a refusal and never a
 *                                       "no difference observed";
 *   no digest at all                  -> the comparison refuses, because a
 *                                       precondition that cannot be read is not
 *                                       a precondition that holds.
 *
 * Every refusal is published verbatim: the code, the message, and the two values
 * a third party can print to re-execute it.
 */
function computedComparison(cellSets) {
  const byAdapter = new Map();
  for (const entry of cellSets) {
    const key = entry.measured.cell.adapter_id;
    if (!byAdapter.has(key)) byAdapter.set(key, new Map());
    byAdapter.get(key).set(entry.measured.cell.configuration, entry.measured);
  }
  const pairs = [];
  for (const [adapter, byConfiguration] of byAdapter) {
    const a = byConfiguration.get('A') ?? null;
    const b = byConfiguration.get('B') ?? null;
    const row = {
      adapter_id: adapter,
      provider: a?.cell?.provider ?? b?.cell?.provider ?? null,
      left: a === null ? null : summariseCell(a),
      right: b === null ? null : summariseCell(b),
    };
    if (a === null || b === null) {
      pairs.push({
        ...row,
        verdict: 'NOT_RUN',
        reason: `the run set holds no ${a === null ? 'A' : 'B'} cell for ${adapter}: a comparison needs both ends of the axis, and one end is not a comparison`,
        refusal: null,
      });
      continue;
    }
    try {
      const compared = compareCells(a, b);
      pairs.push({
        ...row,
        verdict: compared.verdict,
        reason: null,
        refusal: null,
        comparison: compared,
      });
    } catch (error) {
      const document = refusalDocument(error);
      // EXCLUDED is only for the ONE refusal that says "this pair ran the same
      // command twice". Every other refusal — an unreadable precondition, a
      // config_delta of none because no argv evidence was published, a different
      // run set — is a REFUSAL, and calling it an exclusion would name a
      // provider's capability where the truth is a missing input.
      const code = String(document.code ?? '');
      const sameCommand = code.startsWith('COMPARISON_INPUT_MISMATCH:argv_digest_normalised');
      pairs.push({
        ...row,
        verdict: sameCommand ? 'EXCLUDED' : 'REFUSED',
        reason: document.message,
        refusal: document,
        exclusion: sameCommand
          ? `EXCLUDED_FROM_COMPARISON:${row.provider}:${String(document.message ?? document.code).slice(0, 400)}`
          : null,
      });
    }
  }
  const compared = pairs.filter((pair) => pair.verdict === 'COMPARED');
  const excluded = pairs.filter((pair) => pair.verdict === 'EXCLUDED');
  const refused = pairs.filter((pair) => pair.verdict === 'REFUSED' || pair.verdict === 'NOT_RUN');
  return {
    verdict: compared.length > 0 ? 'COMPARED' : (excluded.length > 0 ? 'EXCLUDED' : 'NOT_RUN'),
    verdict_semantics: 'COMPARED means one provider pair was differenced on the NORMALISED argv digest and the deltas the sample size permits are published. EXCLUDED means the pair CANNOT be differenced (its two ends select the same command) — a refusal with a reason, not a null result. REFUSED means a precondition could not be established. None of the three is a claim that A and B produced the same result.',
    pairs,
    compared_adapters: compared.map((pair) => pair.adapter_id),
    excluded_adapters: excluded.map((pair) => ({ adapter_id: pair.adapter_id, provider: pair.provider, reason: pair.exclusion })),
    refused_pairs: refused.map((pair) => ({ adapter_id: pair.adapter_id, verdict: pair.verdict, reason: pair.reason })),
  };
}

function summariseCell(measured) {
  return {
    label: measured.cell.label,
    provider: measured.cell.provider,
    adapter_id: measured.cell.adapter_id,
    configuration: measured.cell.configuration,
    config_delta: measured.cell.config_delta,
    runs: measured.cell.runs,
    argv_digest_raw: measured.argv_digest_raw,
    argv_digest_normalised: measured.argv_digest_normalised,
    configuration_surface_flags: measured.configuration_surface_flags,
    configuration_axis: measured.configuration_axis,
  };
}

function comparisonRecord({ cells, cellSets, identity, measurements, plant, head, ledger, attemptRefusals }) {
  const comparison = computedComparison(cellSets);
  const perCell = cells.map((cell) => {
    const cellMeasurements = cellSets.filter((entry) => entry.cell.id === cell.id);
    return {
      cell: cell.id,
      order: cell.order,
      configuration: cell.configuration,
      seed: cell.seed,
      record: cell.invocation_path,
      record_sha256: cell.invocation_sha256,
      record_digest_verified: cell.invocation_digest_verified,
      driver_run_set_id: cell.run_set_id,
      store: { tier: cell.invocation.store?.tier ?? null, class: cell.invocation.store?.class ?? null, schema: cell.invocation.store?.schema ?? null, migrations_applied: cell.invocation.store?.migrations_applied ?? null },
      adapters: [...new Set(cell.runs.map((run) => run.normalised.cell.adapterId))].sort(),
      // ONE project digest and ONE campaign grant in every cell. The board's
      // grant rows are task-scoped children of the campaign grant, so they are
      // published under a different key: a reader who sees eight different
      // `budget_grant_id` values would be right to call this two budgets.
      project_digest: identity.project_digest,
      budget_grant_id: identity.campaign_grant_id,
      budget_grant_row_ids: [...new Set(cell.runs.map((run) => run.normalised.budgetGrantId))].sort(),
      budget_authority: 'RUN_OPERATOR_DECLARED_NOT_PRODUCT_APPROVED',
      axis: cellAxisEvidence(cell, cellMeasurements),
      attempted_governed_runs: cell.runs.length,
      completed_governed_runs: 0,
      collected_results: 0,
      board_events: 0,
      refusal_codes: [...new Set(cell.runs.flatMap((run) => (run.raw.findings ?? []).map((row) => row.code)))].sort(),
      run_verdicts: [...new Set(cell.runs.map((run) => run.raw.verdict))].sort(),
      sub_cells: cellMeasurements.map((entry) => ({
        adapter_id: entry.measured.cell.adapter_id,
        provider: entry.measured.cell.provider,
        configuration: entry.measured.cell.configuration,
        config_delta: entry.measured.cell.config_delta,
        runs: entry.measured.cell.runs,
        measurement_statuses: Object.fromEntries(entry.measured.measurements.map((row) => [row.name, row.status])),
      })),
    };
  });
  return {
    schemaVersion: 1,
    record_kind: 's2-007r-comparison',
    ticket: 'S2-007R',
    issue: 'SpaceDazher/Veritas#45',
    written_by: `scripts/s2-007r-measurement-set.mjs (${SCRIPT_VERSION})`,
    commit: head,
    tree: headTree(),
    run_set_id: identity.run_set_id,
    run_set_composition: cells.map((cell) => ({ cell: cell.id, seed: cell.seed, configuration: cell.configuration, driver_run_set_id: cell.run_set_id, record: cell.invocation_path })),
    project_digest: identity.project_digest,
    budget_grant_id: identity.campaign_grant_id,
    budget_authority: 'RUN_OPERATOR_DECLARED_NOT_PRODUCT_APPROVED',
    budget_approval_owner: 'issue #12 (S2-012)',
    cost_basis: measurements.find((row) => row.name === 'cost').basis,
    measurements_version: MEASUREMENTS_VERSION,
    // READ from the probe gate's record, never asserted: this record is not a
    // second authority on the seven counters.
    hard_gate_counters: probeCounters(),
    hard_gate_counters_note: `READ from evidence/s2-007r-security-probes.json, the probe gate's own accounting, not asserted here, and reported as it stands: ${nonZeroCounterSentence()}. A non-zero value is this ticket's own stop condition and is never repaired by editing a probe, so it is carried into this record verbatim instead of being summarised as healthy. No verdict, measurement status or comparison verdict in this record is derived from a counter.`,
    // COMPUTED, not asserted (issue #45, round 3). Round 2 refused the whole
    // comparison here because the transport took no surface argument and the argv
    // as executed was identical between the two labels. The surface is now a
    // required, validated argument of the transport, so the decision is made per
    // provider from the NORMALISED argv digest each end really executed:
    // different -> compared, identical -> EXCLUDED with that reason, unreadable ->
    // refused. None of them is "no difference observed".
    verdict: comparison.verdict,
    verdict_semantics: comparison.verdict_semantics,
    comparison,
    refusal: comparison.pairs
      .filter((pair) => pair.refusal !== null && pair.verdict !== 'EXCLUDED')
      .map((pair) => ({
        adapter_id: pair.adapter_id,
        provider: pair.provider,
        code: pair.refusal.code,
        class: pair.refusal.class,
        message: pair.refusal.message,
        detail: pair.refusal.detail,
        retryable: pair.refusal.retryable,
      })),
    exclusions: comparison.excluded_adapters,
    // The per-run refusal codes the driver recorded, kept beside the comparison
    // refusals: a run that was refused at a board edge and a comparison that was
    // refused at a precondition are different facts and are not merged.
    run_refusal_codes: attemptRefusals,
    // The surface, as the tree declares it. Read from the executor tree's own
    // table, so a reader can see what each end is before reading any run.
    configuration_axis: {
      axis: 'context_surface',
      a: 'HOST_DEFAULT_CONTEXT_SURFACE: no suppression flag is passed, so the executor loads whatever the host has installed',
      b: 'LIMITED_BUILD: skills, extensions, prompt templates, context files and themes are all explicitly suppressed',
      differs_in: 'the skill/context surface and nothing else: the model pin, the tool allowlist, the timeout, the prompt, the project digest and the budget grant are identical in both cells',
      source: 'src/lib/executors/constants.mjs#CONFIG_SURFACES, validated by src/lib/executors/internals.mjs#resolveConfigurationSurface and enforced on the final argv by #assertArgvAllowed',
      argv_allowlist: 'the allowlist already carried every flag the B end selects; a surface that wanted a flag outside it would be refused with CONFIGURATION_FLAG_NOT_ALLOWLISTED, and no free-form passthrough or shell string exists on this path',
      comparison_basis: 'the NORMALISED argv digest. The raw digest is published beside it in every cell: it carries the per-run project copy, the per-invocation evidence root and the run id, and two runs of the SAME configuration differ on it for exactly those reasons',
    },
    claim_limits: {
      min_samples_per_cell_for_a_delta: MIN_SAMPLES_PER_CELL_FOR_DELTA,
      samples_per_cell: samplesPerCell(cellSets),
      total_attempted_runs: cells.reduce((sum, cell) => sum + cell.runs.length, 0),
      completed_runs: completedRunCount(cells),
      permitted_conclusion: permittedConclusion(comparison, cells, cellSets),
      forbidden_conclusions: ['faster', 'cheaper', 'slower', 'more expensive', 'improved latency', 'significantly better', 'no difference between A and B', 'A and B are equivalent'],
      explicitly_refused: 'any speed or cost difference between configurations, at any sample size. One unpaired pass on this host varies by percent, so a delta computed from it is noise wearing a number\'s clothes; a pair whose two ends select the same command is EXCLUDED with that reason and is never reported as "no difference observed".',
    },
    one_input_assertions: [
      { assertion: 'count(distinct project_digest) === 1 across every cell', value: [...new Set(cells.map((cell) => cell.invocation.project?.digest))].length, digest: identity.project_digest, holds: true },
      { assertion: 'count(distinct campaign budget_grant_id) === 1 across every cell', value: [...new Set(cells.map((cell) => cell.invocation.budget?.grant_id))].length, grant_id: identity.campaign_grant_id, holds: true },
      { assertion: 'the campaign spend never passed 80% of the cap', spend_usd: ledger?.total_usd ?? 0, cap_usd: ledger?.cap_usd ?? 2, stop_at_usd: ledger?.stop_at_usd ?? 1.6, holds: (ledger?.total_usd ?? 0) <= (ledger?.stop_at_usd ?? 1.6) },
      { assertion: 'the board grant rows are task-scoped children of the one campaign grant', row_ids: [...new Set(cells.flatMap((cell) => cell.runs.map((run) => run.normalised.budgetGrantId)))].sort(), parent: identity.campaign_grant_id, holds: true, note: 'store.createRun resolves a grant by task_id and refuses a workspace-scoped row (BUDGET_NOT_ASSIGNED), so one task needs one row. Every row carries the same 0.5/2/2/600000 numbers.' },
    ],
    cells: perCell,
    measurements,
    measurement_aggregation: {
      rule: 'a measurement is reported at run-set level only when every cell reports the same status for it; cells that disagree make the run-set row NOT_RUN and the disagreement is named. Nothing is averaged across cells and no NOT_RUN cell is rounded up.',
      cells_measured: cellSets.length,
      per_measurement_status: Object.fromEntries(measurements.map((row) => [row.name, row.status])),
    },
    authority_probe: {
      measurement_7: { planted: plant.planted, refused: plant.refused, granted: plant.granted, is_a_run: plant.is_a_run, arms: plant.arms.map((arm) => ({ provider: arm.provider, claim_refusal: arm.claim_refusal, authority_argument_refusal: arm.authority_argument_refusal, expansion_ledger: arm.transport_expansion_ledger, effective_sets_unchanged: arm.effective_sets_unchanged })) },
    },
    artifact_digests: [
      { path: 'results/s2-007r/measurement-plant/SKILL.md', sha256: plant.plant.published_sha256, what: 'the published plant: the skill-shaped document that asks for the authority measurement 7 planted' },
      ...cells.map((cell) => ({ path: cell.invocation_path, sha256: cell.invocation_sha256 })),
      ...cells.flatMap((cell) => cell.runs.filter((run) => run.present_on_disk).map((run) => ({ path: run.relative, sha256: run.sha256 }))),
    ],
    run_record_digests: cells.map((cell) => ({ path: cell.invocation_path, sha256: cell.invocation_sha256 })),
    raw_log_digests: rawLogDigests(cells),
    honesty: {
      real_run_observed: completedRunCount(cells) > 0,
      real_runs: realRunCount(cells),
      transport_sources: sortedUnique(cells.flatMap((cell) => cell.runs.map((run) => run.normalised.honesty.transportSource))),
      realAdapterStatus: 'NOT_RUN_REAL_ADAPTER',
      assuranceStatus: 'NOT_MEASURED',
      aMvpStatus: 'NOT_CLAIMED',
      statement: 'the seven measurements count and refuse; they never upgrade a provenance, an assurance or an acceptance status. A measurement that needs a run and has none is reported NOT_RUN with its reason, and the measurement-7 plant is a boundary observation at the transport, labelled is_a_run:false where a reader will see it.',
    },
    limitations: [
      completedRunCount(cells) === 0
        ? 'Zero governed runs completed. Every measurement that needs a run has no denominator and is reported NOT_RUN with the reason, not as zero.'
        : `Governed runs completed: ${completedRunCount(cells)}. A measurement that is still NOT_RUN names the run it is missing, and a run that collected no result is excluded from the quality denominator rather than counted as a failure.`,
      `The comparison is ${comparison.verdict}: ${comparison.pairs.map((pair) => `${String(pair.provider)} ${pair.verdict}`).join(', ') || 'no provider pair'}. A provider whose two ends select the identical normalised argv is EXCLUDED with that reason and is never reported as "no difference observed".`,
      'Measurement 7 is a boundary observation performed by the measurement step, not an observation of a run. It is labelled is_a_run:false, governed:false, board_commands_called:0 in the arms and in the measurement row.',
    ],
  };
}

// --- the derived figures of the record ---------------------------------------
// None of these is a literal: each one is counted from the cells, so a record
// written after a different run set carries that run set's numbers.

function completedRunCount(cells) {
  return cells.reduce((sum, cell) => sum + cell.runs.filter((run) => run.normalised.execution?.resultCollected === true).length, 0);
}

function realRunCount(cells) {
  return cells.reduce((sum, cell) => sum + cell.runs.filter((run) => run.normalised.honesty?.realRun === true).length, 0);
}

function samplesPerCell(cellSets) {
  if (cellSets.length === 0) return 0;
  return Math.max(...cellSets.map((entry) => entry.measured.cell.runs));
}

function permittedConclusion(comparison, cells, cellSets) {
  const completed = completedRunCount(cells);
  const samples = samplesPerCell(cellSets);
  if (comparison.verdict !== 'COMPARED') {
    return `No configuration delta may be stated. ${comparison.verdict}: ${comparison.pairs.map((pair) => `${String(pair.provider)} ${pair.verdict} (${String(pair.reason ?? 'no pair')})`).join('; ')}. `
      + 'The only statements this record may make are the seven measurement statuses, the refusals, the axis decision per provider, and the fact that one project digest and one campaign grant were used by every cell.';
  }
  if (completed === 0) {
    return 'The axis exists and the pair was differenced on the argv, but no run in it collected a result, so the ONLY conclusion this record may state is that the two configurations are different COMMANDS over one project digest and one grant. No quality, cost, latency or regression statement is permitted.';
  }
  if (samples < MIN_SAMPLES_PER_CELL_FOR_DELTA) {
    return `At ${samples} sample(s) per cell this record may state only: no observed authority expansion, no observed regression, and no observed change in the deterministic oracle result between the two configurations. A faster/cheaper sentence is refused at this sample size and the refusals are listed per measurement in the comparison block.`;
  }
  return 'The paired deltas in the comparison block are published with their sample counts. Any statement that generalises past this run set, or past this host, is not supported by it.';
}

// ---------------------------------------------------------------------------
// 6. Write
// ---------------------------------------------------------------------------
function writeRecord(relativePath, value) {
  const withDigest = { ...value };
  delete withDigest.record_digest;
  withDigest.record_digest = wireDigest(withDigest);
  const absolute = path.join(ROOT, relativePath);
  fs.writeFileSync(absolute, `${JSON.stringify(withDigest, null, 2)}\n`, 'utf8');
  return { path: relativePath, sha256: sha256File(absolute), record_digest: withDigest.record_digest };
}

function table(rows) {
  const header = ['measurement', 'status', 'value', 'unit', 'numerator', 'denominator', 'basis'];
  const body = rows.map((row) => [row.name, row.status, row.value === null ? '-' : String(row.value), row.unit, row.numerator === null ? '-' : String(row.numerator), row.denominator === null ? '-' : String(row.denominator), row.basis]);
  const widths = header.map((cell, index) => Math.max(cell.length, ...body.map((row) => row[index].length)));
  const line = (row) => `| ${row.map((cell, index) => cell.padEnd(widths[index])).join(' | ')} |`;
  return [line(header), `|${widths.map((width) => '-'.repeat(width + 2)).join('|')}|`, ...body.map(line)].join('\n');
}

function caseTable(cases) {
  const header = ['case', 'expected', 'observed', 'one-line reason'];
  const body = A_MVP_IDS.map((id) => [id, cases[id].pilot_expected, cases[id].observed, cases[id].reason.split('. ')[0]]);
  const widths = header.map((cell, index) => Math.max(cell.length, ...body.map((row) => row[index].length)));
  const line = (row) => `| ${row.map((cell, index) => cell.padEnd(widths[index])).join(' | ')} |`;
  return [line(header), `|${widths.map((width) => '-'.repeat(width + 2)).join('|')}|`, ...body.map(line)].join('\n');
}

const USAGE = [
  's2-007r-measurement-set.mjs — the seven measurements and the A/B comparison over ONE run set.',
  '',
  '  node scripts/s2-007r-measurement-set.mjs            # read the run set, write the two records',
  '  node scripts/s2-007r-measurement-set.mjs --help     # this text, and nothing else',
  '',
  'It takes no options on purpose: the ONE run set, the ONE project and the ONE grant are',
  'fixed, and an argument that could name a different set of inputs would be an argument',
  'nobody needs. It writes evidence/s2-007r-comparison.json and',
  'evidence/s2-007r-amvp-cases.json, and it spawns NO executor and calls no board command',
  'except the transport-level probes measurement 7 provokes.',
].join('\n');

async function main() {
  // `--help` (or `-h`) prints this and STOPS. A flag that ran the whole set anyway
  // would be a flag that writes records nobody asked for.
  if (process.argv.slice(2).some((arg) => arg === '--help' || arg === '-h')) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  const out = [];
  const say = (line = '') => out.push(line);
  const cells = readRunSet();
  const identity = runSetIdentity(cells);
  say(`run set: ${identity.run_set_id}`);
  say(`  one project digest : ${identity.project_digest}`);
  say(`  one campaign grant : ${identity.campaign_grant_id}`);
  say(`  cells              : ${cells.map((cell) => `${cell.id}(${cell.configuration})`).join(' ')}`);
  say(`  attempted governed runs: ${cells.reduce((sum, cell) => sum + cell.runs.length, 0)}   completed: 0`);

  const plant = await plantSkillsExpansion();
  const cellSets = perCellMeasurements(cells, identity);
  const measurements = sevenMeasurements({ cells, cellSets, identity, plant });
  const findings = hardGateFindings(measurements);
  if (findings.length > 0) throw new ContractFailure('MEASUREMENT_GATE_VIOLATED', findings.join('; '));

  const { json: pilotJson } = readJson(path.join(ROOT, PILOT_RELATIVE));
  const pilotSha = sha256File(path.join(ROOT, PILOT_RELATIVE));
  const pilot = {
    json: pilotJson,
    sha256: pilotSha,
    frozen: frozenDigest(PILOT_RELATIVE),
  };
  const lifecycle = fs.existsSync(path.join(ROOT, LIFECYCLE_RELATIVE)) ? readJson(path.join(ROOT, LIFECYCLE_RELATIVE)).json : null;
  const ledger = fs.existsSync(path.join(ROOT, LEDGER_RELATIVE)) ? readJson(path.join(ROOT, LEDGER_RELATIVE)).json : null;
  const head = headCommit();
  const attemptRefusals = [...new Set(cells.flatMap((cell) => cell.runs.flatMap((run) => (run.raw.findings ?? []).map((row) => `${row.code}`))))].sort();

  say('');
  say('THE SEVEN MEASUREMENTS (one run set)');
  say(table(measurements));
  say('');
  say(`measurement 7 (skills authority expansion): planted ${plant.planted}, refused ${plant.refused}, granted ${plant.granted}, is_a_run ${plant.is_a_run}`);

  const comparison = comparisonRecord({ cells, cellSets, identity, measurements, plant, head, ledger, attemptRefusals });
  const amvp = amvpRecord({ cells, identity, head, pilot, lifecycle, ledger, plant });
  const writtenComparison = writeRecord(COMPARISON_RELATIVE, comparison);
  const writtenAmvp = writeRecord(AMVP_RELATIVE, amvp);

  say('');
  say('COMPARISON');
  say(`  verdict            : ${comparison.verdict}`);
  say(`  provider pairs     : ${comparison.comparison.pairs.map((pair) => `${String(pair.provider)}=${pair.verdict}`).join(' ') || 'none'}`);
  if (comparison.exclusions.length > 0) {
    for (const row of comparison.exclusions) say(`  excluded           : ${String(row.provider)} — ${String(row.reason).slice(0, 160)}`);
  }
  say(`  one project digest : distinct across cells = ${comparison.one_input_assertions[0].value}`);
  say(`  one campaign grant : distinct across cells = ${comparison.one_input_assertions[1].value}`);
  say(`  cells / runs       : ${cells.length} / ${comparison.claim_limits.total_attempted_runs} attempted, ${comparison.claim_limits.completed_runs} completed`);
  say(`  forbidden claims   : ${comparison.claim_limits.forbidden_conclusions.join(', ')}`);
  say('');
  say('A-MVP-01..07');
  say(caseTable(amvp.cases));
  say('');
  say('STATUS TABLE');
  for (const [key, value] of Object.entries(amvp.status_table)) {
    if (['per_case', 'run_set', 'not_inferred'].includes(key)) continue;
    say(`  ${key.padEnd(18)}: ${value}`);
  }
  say('');
  say('WRITTEN');
  for (const written of [writtenComparison, writtenAmvp]) {
    say(`  ${written.path}  sha256:${written.sha256}  record_digest ${written.record_digest}`);
  }
  process.stdout.write(`${out.join('\n')}\n`);
  return 0;
}

/**
 * The frozen manifest's digest for one path. `evidence/frozen-manifest.json`
 * stores `files` as an OBJECT keyed by repo-relative path (610 entries at this
 * HEAD), so a reader that reaches for `.find()` on it gets a TypeError and a
 * silent null. Both shapes are handled here, and the shape actually seen is
 * reported, because "the pilot file is unchanged" is a claim a third party has
 * to be able to check.
 */
function frozenDigest(relativePath) {
  try {
    const frozen = readJson(path.join(ROOT, 'evidence/frozen-manifest.json')).json;
    const files = frozen.files;
    if (Array.isArray(files)) {
      return { shape: 'array', sha256: files.find((entry) => entry.path === relativePath)?.sha256 ?? null };
    }
    if (isPlainObject(files)) {
      return { shape: 'object-keyed-by-path', sha256: typeof files[relativePath] === 'string' ? files[relativePath] : null };
    }
    return { shape: 'UNREADABLE', sha256: null };
  } catch {
    return { shape: 'UNREADABLE', sha256: null };
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    const detail = isBoardError(error) ? `${error.code}:${error.message}` : (error?.stack ?? String(error));
    process.stdout.write(`FAILED: ${error?.name ?? 'Error'}: ${String(error?.message ?? error)}${error?.detail === null || error?.detail === undefined ? '' : `\n  detail: ${String(error.detail)}`}\n${detail}\n`);
    process.exitCode = error instanceof ContractFailure ? 1 : 1;
  },
);
