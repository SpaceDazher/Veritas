#!/usr/bin/env node
// S2-007R CONFIGURATION COMPARISON + THE SEVEN MEASUREMENTS (issue #45).
//
// WHAT THIS FILE IS
// -----------------
// The only caller of src/lib/executors/measure.mjs. It does the I/O the
// pure layer is forbidden to do -- read a run directory, hash the bytes, write
// one results file, print a table -- and NOTHING else. Every number, every
// refusal and every status it prints comes out of the pure layer.
//
//   node scripts/s2-007r-measure.mjs --run-dir results/s2-007r/<run-set>
//   node scripts/s2-007r-measure.mjs --self-test
//   node scripts/s2-007r-measure.mjs --emit-fixture <dir>     # the input contract, written out
//   node scripts/s2-007r-measure.mjs --help
//
// THE INPUT
// ---------
// A run directory written by a run driver. It holds either `run-index.json`
// (whose only authority is to say WHICH files to read -- it may not assert a
// digest) or, absent that, every `*.run.json` in the directory. Each file is one
// run record in the shape documented at the top of measurements.mjs. The record
// digests are recomputed here from the parsed content and from the bytes; a
// record that self-reports a different digest is refused.
//
// THE OUTPUT
// ----------
//   results/s2-007r/measurements-<config-pair>.json   one file, one run set
//     .run_set_id   the ONE run set the seven measurements came from
//     .cells        one measurement set per (adapter, configuration) cell
//     .comparison   {verdict:'COMPARED', deltas, refused_claims, claim_limit}
//                   or {verdict:'REFUSED', reason, detail} and NO deltas
//     .honesty      what the records claimed about themselves, unchanged
//
// HONESTY (enforced below, not merely asserted)
// -------------------------------------------
//   * A run set whose records do not all say real_run === true is NOT written
//     into results/ unless the operator passes --accept-synthetic, and even then
//     only to a filename ending in `.SYNTHETIC-FIXTURE.json`. The exit code
//     stays 3 (NOT_RUN): a fixture is not a real run, whatever the operator wants.
//   * The comparison is emitted only when every precondition in
//     COMPARISON_PRECONDITIONS holds -- the same project digest, the same budget
//     grant id, the same run set, the same provider and adapter, the same cost
//     basis, and a real config delta. Otherwise nothing is differenced, the two
//     differing values are printed, and the exit code is 3.
//   * No status is ever upgraded: realAdapterStatus stays NOT_RUN_REAL_ADAPTER,
//     assuranceStatus NOT_MEASURED, aMvpStatus NOT_CLAIMED, whatever the runs
//     claim for themselves.
//   * The claim limit is enforced in code: below MIN_SAMPLES_PER_CELL_FOR_DELTA
//     runs per cell every "faster / cheaper / better" delta lands in
//     refused_claims instead of in a number.
//
// EXIT CODES
// ----------
//   0  the seven measurements were computed from a real run set whose records
//      carry a verified digest, every measurement is MEASURED (or NOT_RUN, with
//      the reason), no measurement is PARTIAL or MEASURED_WITH_FINDING, and the
//      pair was compared
//   1  a contract failure: a malformed run record, a bad argument, a failed
//      self-check, an invariant violation (a failed gate, a bad digest, an
//      evidence contradiction), or a measurement that could not be fully
//      verified (PARTIAL) or that carries a finding (MEASURED_WITH_FINDING)
//   3  NOT_RUN: no run set, a mixed run set, a refused comparison, a run set
//      that is not real, or --self-test
//
// The mapping from a refusal to a code lives in `exitCodeForError` and nowhere
// else. Every refusal this tool raises is a typed BoardError, including its own
// argument parsing: there is no bare Error on any path a caller can reach.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  COMPARISON_PRECONDITIONS,
  MEASUREMENT_NAMES,
  MIN_SAMPLES_PER_CELL_FOR_DELTA,
  RUN_RECORD_CONTRACT,
  assertMeasurementInvariants,
  compareCells,
  fileDigestOf,
  hardGateFindings,
  isBoardError,
  invocationDigestVerified,
  measureSeven,
  normalizeAnyRunRecord,
  normalizeRunRecord,
  refusalDocument,
  runRecordDigest,
} from '../src/lib/executors/measure.mjs';
import { MalformedResult, NeedsInput, errorClassForCode } from '../src/lib/agentboard/errors.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_OUT_DIR = path.join(ROOT, 'results', 's2-007r');
const SCRIPT_VERSION = 's2-007r-measure-v2';
const USAGE = `s2-007r measure -- the configuration comparison and the seven measurements

  node scripts/s2-007r-measure.mjs --run-dir <dir> [--out-dir <dir>] [--config-a <label> --config-b <label>]
  node scripts/s2-007r-measure.mjs --self-test
  node scripts/s2-007r-measure.mjs --emit-fixture <dir>
  node scripts/s2-007r-measure.mjs --accept-synthetic        # with --run-dir: write a fixture set under a clearly named file

  exit 0 measured + compared, 1 contract failure, 3 NOT_RUN / refused
`;

// The sub-codes that are a CONTRACT FAILURE (exit 1) rather than a NOT_RUN
// (exit 3). A NeedsInput carries one code for the whole class, so the sub-code
// in its message is what distinguishes "your input is broken" from "there is
// nothing here to measure".
const CONTRACT_FAILURE_SUBCODES = new Set([
  'ARGUMENT_VALUE_MISSING', 'ARGUMENT_UNKNOWN', 'RUN_INDEX_ESCAPES_RUN_DIR', 'FIXTURE_TARGET_INSIDE_REPOSITORY',
  'MEASUREMENT_INPUT_MISSING', 'MEASUREMENT_INPUT_INVALID', 'MEASUREMENT_RECORD_DIGEST_MISMATCH',
  'MEASUREMENT_INPUT_DIALECT_UNKNOWN', 'MEASUREMENT_EVIDENCE_CONTRADICTION', 'MEASUREMENT_GATE_VIOLATED',
  'MEASUREMENT_SET_INCOMPLETE', 'MEASUREMENT_RECORD_INCOMPLETE', 'MEASUREMENT_STATUS_UNKNOWN',
  'MEASUREMENT_UNIT_UNKNOWN', 'MEASUREMENT_VALUE_INVALID', 'MEASUREMENT_COUNT_INVALID',
  'MEASUREMENT_NOT_RUN_WITH_VALUE', 'MEASUREMENT_EVIDENCE_INVALID', 'MEASUREMENT_LIMITATIONS_INVALID',
]);

/** The one place a refusal becomes an exit code. 1 = contract, 3 = NOT_RUN. */
function exitCodeForError(error) {
  if (!isBoardError(error)) return 1;
  if (error.code === 'MALFORMED_RESULT' || error.code === 'BLOCKED_POLICY') return 1;
  if (error.code === 'NEEDS_INPUT' && CONTRACT_FAILURE_SUBCODES.has(String(error.message ?? '').split(':')[0])) return 1;
  return 3;
}

// ---------------------------------------------------------------------------
// The synthetic fixture. IT IS NOT A RUN AND NEVER LOOKS LIKE ONE.
// ---------------------------------------------------------------------------
// It exists because no real run record exists on this host yet. Every record in
// it carries honesty.real_run = false and honesty.synthetic_fixture = true, and
// the CLI refuses to write a fixture-derived measurement into results/ under a
// name that could be read as evidence. It exercises the seven measurements and
// the refusals; it measures nothing about any executor.
const FIXTURE_RUN_SET_ID = 'rs-s2-007r-SYNTHETIC-FIXTURE';
const FIXTURE_PROJECT_DIGEST = `sha256:${'0'.repeat(56)}fixture`;
const FIXTURE_NOTICE = 'SYNTHETIC_LABELLED_FIXTURE — hand-written records, no executor, no model call, no evidence about any run.';

// The SYNTHETIC argv of the fixture, per end of the axis, and the digest the
// transport's own rule would give it (argv joined with NUL). They DIFFER for pi,
// so the fixture's pi pair is comparable, and the codex cell is given ONE digest
// for both ends, so the exclusion path is exercised on a fixture too. These are
// the digests of a hand-written argv: no process was spawned, and the record
// says `honesty.synthetic_fixture: true` and `fixture_notice` on every row.
const FIXTURE_ARGV = Object.freeze({
  A: Object.freeze(['pi', '--mode', 'json', '--model', 'openrouter/amazon/nova-lite-v1', '--tools', 'fs.read', '<PROMPT>']),
  B: Object.freeze(['pi', '--mode', 'json', '--model', 'openrouter/amazon/nova-lite-v1', '--no-skills', '--no-extensions', '--no-prompt-templates', '--no-context-files', '--no-themes', '--tools', 'fs.read', '<PROMPT>']),
});
const fixtureArgvDigest = (argv) => `sha256:${createHash('sha256').update(argv.join('\u0000')).digest('hex')}`;
const FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION = Object.freeze({
  A: fixtureArgvDigest(FIXTURE_ARGV.A),
  B: fixtureArgvDigest(FIXTURE_ARGV.B),
  // codex exposes no context-surface switch (measured, codex 0.157.1), so both of
  // its ends select the same argv and its pair is EXCLUDED with that reason.
  CODEX_BOTH_ENDS: fixtureArgvDigest(FIXTURE_ARGV.A),
});

function fixtureRecord(overrides) {
  const base = {
    record_version: RUN_RECORD_CONTRACT,
    run_set_id: FIXTURE_RUN_SET_ID,
    run_id: 'run-s2007r-fixture-0001',
    cell: { adapter_id: 'adr-pi-local', provider: 'pi', configuration: 'A', config_delta: 'skills_surface', repeat_index: 1 },
    honesty: { real_run: false, script_used: true, replay_used: false, transport_source: 'synthetic-fixture', synthetic_fixture: true },
    project: { digest: FIXTURE_PROJECT_DIGEST },
    budget: { grant_id: 'grt-s2007r-FIXTURE', authority: 'SYNTHETIC_FIXTURE_NOT_APPROVED', currency: 'USD' },
    task: { task_id: 'abt-s2007r-fixture-01', attempts: 1, final_state: 'IN_REVIEW' },
    execution: {
      result_collected: true,
      outcome: 'SUCCEEDED',
      error_code: null,
      accepted_event: { sequence: 1, event_type: 'ACCEPTED', emitted_at: '2026-09-26T10:00:00.000Z' },
      terminal_event: { sequence: 4, event_type: 'COMPLETED', emitted_at: '2026-09-26T10:00:03.500Z' },
      board_duration_ms: 3500,
      intervention_commands: [],
    },
    observation: { parent_wall_ms: 4700 },
    usage: { input_tokens: 569, output_tokens: 47, reasoning_tokens: 0, cost_usd: 0.00004542, cost_reported: true, model_id: 'amazon/nova-lite-v1' },
    oracle: { exit_code: 0, baseline_passing: 5, after_passing: 5, regressed: [], stdout_sha256: `sha256:${'1'.repeat(56)}fixture` },
    authority: {
      planted_expansions: [{ plant: 'skill-md-authority-ask', tool: 'tool:net.fetch', refused_code: 'CAPABILITY_MISMATCH' }],
      granted_expansions: [],
      effective_capabilities: ['source.read', 'code.write'],
      effective_tools: ['tool:fs.read', 'tool:fs.write', 'tool:test.run'],
      declared_tools: ['tool:fs.read', 'tool:fs.write', 'tool:test.run'],
      request_allowed_tools: ['tool:fs.read', 'tool:fs.write', 'tool:test.run'],
      declared_capabilities: ['source.read', 'code.write'],
      grant_capabilities: ['source.read', 'code.write'],
      argv_allowlist_digest: `sha256:${'2'.repeat(56)}fixture`,
      request_allowlist_digest: `sha256:${'2'.repeat(56)}fixture`,
      forged_payload_code: 'BLOCKED_POLICY',
    },
    artifact_digests: [{ path: 'FIXTURE-NOT-A-REAL-LOG.txt', sha256: `sha256:${'3'.repeat(56)}fixture`, bytes: 0 }],
    excluded_from_quality: null,
    // The argv evidence a cell needs to be comparable at all (issue #45, round 3).
    // SYNTHETIC: these digests are the digests of a hand-written argv, not of any
    // process. They exist so the comparator's argv precondition is exercised on
    // both sides — a pair that differs, and a provider whose ends cannot. Nothing
    // here is evidence about a real command.
    argv: {
      observed: true,
      reason: FIXTURE_NOTICE,
      configuration: 'A',
      configuration_name: 'HOST_DEFAULT_CONTEXT_SURFACE',
      surface_flags: [],
      configuration_axis: {
        axis: 'context_surface',
        provider: 'pi',
        configurations: ['A', 'B'],
        configuration_a_flags: [],
        configuration_b_flags: ['--no-skills', '--no-extensions', '--no-prompt-templates', '--no-context-files', '--no-themes'],
        distinguishable: true,
        reason: null,
        exclusion: null,
        fixture: true,
      },
      argv_digest_raw: `sha256:${'5'.repeat(56)}fixture`,
      argv_digest_normalised: FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.A,
      argv: [...FIXTURE_ARGV.A],
      argv_normalised: [...FIXTURE_ARGV.A],
      observed_by: 'the synthetic fixture; no process was spawned',
    },
  };
  return { ...base, ...overrides, fixture_notice: FIXTURE_NOTICE };
}

function syntheticFixtureRecords() {
  const cellA = ['01', '02', '03'].map((suffix, index) => fixtureRecord({
    run_id: `run-s2007r-fixture-a${suffix}`,
    task: { task_id: `abt-s2007r-fixture-${suffix}`, attempts: 1, final_state: 'IN_REVIEW' },
    execution: {
      result_collected: true, outcome: 'SUCCEEDED', error_code: null,
      accepted_event: { sequence: 1, event_type: 'ACCEPTED', emitted_at: `2026-09-26T10:0${index}:00.000Z` },
      terminal_event: { sequence: 4, event_type: 'COMPLETED', emitted_at: `2026-09-26T10:0${index}:03.500Z` },
      board_duration_ms: 3500, intervention_commands: [],
    },
    observation: { parent_wall_ms: 4700 + index * 100 },
  }));
  // One cancelled probe-style run: named, with a reason, and excluded from the
  // quality denominator instead of vanishing from the record.
  cellA.push(fixtureRecord({
    run_id: 'run-s2007r-fixture-a04',
    cell: { adapter_id: 'adr-pi-local', provider: 'pi', configuration: 'A', config_delta: 'skills_surface', repeat_index: 2 },
    task: { task_id: 'abt-s2007r-fixture-04', attempts: 1, final_state: 'CANCELLED' },
    execution: {
      result_collected: false, outcome: 'CANCELLED', error_code: 'CANCELLED',
      accepted_event: { sequence: 1, event_type: 'ACCEPTED', emitted_at: '2026-09-26T10:05:00.000Z' },
      terminal_event: { sequence: 2, event_type: 'CANCELLED', emitted_at: '2026-09-26T10:05:00.400Z' },
      board_duration_ms: 400, intervention_commands: [{ command: 'execution.cancel', actor_kind: 'human_owner', at: '2026-09-26T10:05:00.350Z' }],
    },
    observation: { parent_wall_ms: 400 },
    oracle: { exit_code: null, baseline_passing: 5, after_passing: 5, regressed: [], stdout_sha256: null },
    authority: {
      planted_expansions: [], granted_expansions: [], effective_capabilities: [], effective_tools: [],
      declared_tools: [], request_allowed_tools: [], declared_capabilities: [], grant_capabilities: [],
      argv_allowlist_digest: null, request_allowlist_digest: null, forged_payload_code: null,
    },
    artifact_digests: [],
    excluded_from_quality: { reason: 'cancellation probe arm: the run was deliberately cancelled and collected no result' },
  }));
  const cellB = [
    fixtureRecord({ run_id: 'run-s2007r-fixture-b01', cell: { adapter_id: 'adr-pi-local', provider: 'pi', configuration: 'B', config_delta: 'skills_surface', repeat_index: 1 } }),
    fixtureRecord({
      run_id: 'run-s2007r-fixture-b02',
      cell: { adapter_id: 'adr-pi-local', provider: 'pi', configuration: 'B', config_delta: 'skills_surface', repeat_index: 1 },
      task: { task_id: 'abt-s2007r-fixture-02', attempts: 1, final_state: 'IN_REVIEW' },
      observation: { parent_wall_ms: 3200 },
    }),
    // A second attempt and a failing oracle: what the quality, pass@1 and
    // regression measurements exist to catch.
    fixtureRecord({
      run_id: 'run-s2007r-fixture-b03',
      cell: { adapter_id: 'adr-pi-local', provider: 'pi', configuration: 'B', config_delta: 'skills_surface', repeat_index: 1 },
      task: { task_id: 'abt-s2007r-fixture-03', attempts: 2, final_state: 'IN_REVIEW' },
      execution: {
        result_collected: true, outcome: 'SUCCEEDED', error_code: null,
        accepted_event: { sequence: 1, event_type: 'ACCEPTED', emitted_at: '2026-09-26T10:12:00.000Z' },
        terminal_event: { sequence: 4, event_type: 'COMPLETED', emitted_at: '2026-09-26T10:12:09.100Z' },
        board_duration_ms: 9100, intervention_commands: [{ command: 'tasks.transition', actor_kind: 'human_owner', at: '2026-09-26T10:12:01.000Z' }],
      },
      observation: { parent_wall_ms: 9600 },
      usage: { input_tokens: 1902, output_tokens: 210, reasoning_tokens: 0, cost_usd: 0.00011874, cost_reported: true, model_id: 'amazon/nova-lite-v1' },
      oracle: { exit_code: 1, baseline_passing: 5, after_passing: 4, regressed: ['calc.test.js::subtracts negative operands'], stdout_sha256: `sha256:${'4'.repeat(56)}fixture` },
    }),
  ];
  // A different provider whose own output carries no currency figure at all:
  // the PROXY_TOKENS_NO_USD_REPORTED basis, and a cell no pi cell may be
  // compared with.
  const codexCell = [fixtureRecord({
    run_id: 'run-s2007r-fixture-c01',
    cell: { adapter_id: 'adr-codex-local', provider: 'codex', configuration: 'A', config_delta: 'none', repeat_index: 1 },
    execution: {
      result_collected: true, outcome: 'SUCCEEDED', error_code: null,
      accepted_event: { sequence: 1, event_type: 'ACCEPTED', emitted_at: '2026-09-26T10:20:00.000Z' },
      terminal_event: { sequence: 4, event_type: 'COMPLETED', emitted_at: '2026-09-26T10:20:26.010Z' },
      board_duration_ms: 26010, intervention_commands: [],
    },
    observation: { parent_wall_ms: 26010 },
    usage: { input_tokens: 20937, output_tokens: 6, reasoning_tokens: 0, cost_reported: false, model_id: null },
  })];
  return [...cellA, ...cellB, ...codexCell].map(withFixtureArgv);
}

/**
 * Bind the argv evidence to the cell the record actually declares. A record that
 * carried configuration A's digest inside a configuration B cell would be exactly
 * the false positive this axis exists to prevent, so the two are written together
 * here and never by hand per record.
 */
function withFixtureArgv(record) {
  const configuration = String(record.cell.configuration);
  const provider = String(record.cell.provider);
  const distinguishable = provider !== 'codex';
  const argv = distinguishable ? FIXTURE_ARGV[configuration] ?? FIXTURE_ARGV.A : FIXTURE_ARGV.A;
  const digest = distinguishable
    ? FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION[configuration] ?? FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.A
    : FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.CODEX_BOTH_ENDS;
  return {
    ...record,
    argv: {
      ...record.argv,
      configuration,
      configuration_name: configuration === 'B' ? 'LIMITED_BUILD' : 'HOST_DEFAULT_CONTEXT_SURFACE',
      surface_flags: configuration === 'B'
        ? ['--no-skills', '--no-extensions', '--no-prompt-templates', '--no-context-files', '--no-themes']
        : [],
      configuration_axis: {
        ...record.argv.configuration_axis,
        provider,
        distinguishable,
        exclusion: distinguishable
          ? null
          : `EXCLUDED_FROM_COMPARISON:${provider}:${provider} exposes no flag that suppresses a context surface, so configuration A and configuration B select the identical argv and a comparison between them would difference one command with itself.`,
      },
      // The raw digest of the SYNTHETIC argv: the two ends differ here too, and
      // for a real provider the raw digest would ALSO differ between two runs of
      // the same end, which is why nothing compares on it.
      argv_digest_raw: fixtureArgvDigest(argv),
      argv_digest_normalised: digest,
      argv: [...argv],
      argv_normalised: [...argv],
    },
  };
}


// A minimal record shaped like the one scripts/s2-007r-run.mjs writes, used only
// to prove the dialect mapping reads it. It is hand-written and labelled as
// such; the driver itself has not been run on this host.
function runDriverFixtureRecord(overrides = {}) {
  return {
    index: 1,
    label: '01',
    task_id: 'abt-s2007r-fixture-01',
    adapter_id: 'adr-pi-local',
    provider: 'pi',
    configuration: 'A',
    // A hand-written fixture row names no real transport. If it named
    // `pi-transport` it would be one record_digest away from being scored as a
    // real crossing, which is exactly what this fixture is not.
    transport_source: 'synthetic-fixture',
    findings: [],
    verdict: 'RUN_SUCCEEDED',
    project: { digest_before: `sha256:${'a'.repeat(64)}`, digest_after: `sha256:${'a'.repeat(64)}`, unchanged: true, file_count: 5 },
    budget: { grant_id: 'grt-s2007r-fixture' },
    request: { allowed_tools: ['tool:fs.read', 'tool:fs.write', 'tool:test.run'], allowed_tools_digest: `sha256:${'b'.repeat(64)}` },
    result: { decision: 'ACCEPT', outcome: 'SUCCEEDED', digest: `sha256:${'c'.repeat(64)}`, measurements: { duration_ms: 26010, spend: 0 } },
    cost: { settled_amount: 0, currency: 'USD', cost_basis: 'NO_USD_REPORTED_BY_EXECUTOR' },
    outbox: { parent_wall_ms: 26010 },
    executor: { available: true, reported: { exit_code: 0, model_id: 'amazon/nova-lite-v1', usage: { input: 569, output: 47, reasoning: 0 }, wall_ms: 26010 }, missing: ['argv'] },
    committed: { task: { task_id: 'abt-s2007r-fixture-01', state: 'IN_REVIEW', attempts: 1 }, events_gap_free: true },
    events: [
      { sequence: 1, event_type: 'ACCEPTED', decision: 'ACCEPT' },
      { sequence: 2, event_type: 'STARTED', decision: 'ACCEPT' },
      { sequence: 3, event_type: 'COMPLETED', decision: 'ACCEPT', outcome: 'SUCCEEDED' },
    ],
    raw_logs: { directory: 'results/s2-007r/FIXTURE-NOT-A-REAL-LOG', files: [{ file: 'pi.jsonl', bytes: 120, sha256: `sha256:${'d'.repeat(64)}` }], withheld: [] },
    fixture_notice: FIXTURE_NOTICE,
    ...overrides,
  };
}

function runDriverFixtureInvocation(runs) {
  return {
    driver: { version: 'fixture' },
    invocation: { seed: 'fixture', configuration: 'A', project: 'corpus/s2-007r/project', budget: 0.1, store_tier: 'memory' },
    honesty: { script_used: true, replay_used: false, transport_source: null },
    runs,
    journal: {
      calls: [
        { step: 'create.01', command: 'tasks.create', actor_kind: 'human_owner', board_instant: '2026-09-26T10:00:00.000Z' },
        { step: 'start.01', command: 'execution.start', actor_kind: 'adapter', board_instant: '2026-09-26T10:00:01.000Z' },
        { step: 'dispatch.01', command: 'outbox.dispatch', actor_kind: 'scheduler', board_instant: '2026-09-26T10:00:02.000Z' },
        { step: 'event.01.01', command: 'execution.event', actor_kind: 'adapter', board_instant: '2026-09-26T10:00:02.500Z' },
        { step: 'tasks.transition.01', command: 'tasks.transition', actor_kind: 'human_owner', board_instant: '2026-09-26T10:00:03.000Z' },
        { step: 'event.01.03', command: 'execution.event', actor_kind: 'adapter', board_instant: '2026-09-26T10:00:04.000Z' },
      ],
    },
  };
}

// ---------------------------------------------------------------------------
// Reading a run set
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const options = { runDir: null, outDir: null, configA: null, configB: null, selfTest: false, emitFixture: null, acceptSynthetic: false, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      const value = argv[index + 1];
      if (value === undefined) throw new NeedsInput(`ARGUMENT_VALUE_MISSING:${arg}`);
      index += 1;
      return value;
    };
    if (arg === '--run-dir') options.runDir = next();
    else if (arg === '--out-dir') options.outDir = next();
    else if (arg === '--config-a') options.configA = next();
    else if (arg === '--config-b') options.configB = next();
    else if (arg === '--self-test') options.selfTest = true;
    else if (arg === '--emit-fixture') options.emitFixture = next();
    else if (arg === '--accept-synthetic') options.acceptSynthetic = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new NeedsInput(`ARGUMENT_UNKNOWN:${arg}`, 'the arguments this tool accepts are listed by --help; an unknown one is never ignored');
  }
  return options;
}

/** Parse a run record file. A truncated or non-JSON file is a MALFORMED_RESULT, never an empty run. */
function readRecordFile(full) {
  const text = fs.readFileSync(full, 'utf8');
  try {
    return { text, raw: JSON.parse(text) };
  } catch (error) {
    throw new MalformedResult(
      `RUN_RECORD_UNPARSEABLE:${path.basename(full)}`,
      `${String(error?.message ?? error).slice(0, 200)}: the file is not a JSON document, so nothing in it can be measured`,
    );
  }
}

function readRunSet(dir) {
  const absolute = path.resolve(dir);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isDirectory()) {
    throw new NeedsInput(`RUN_DIR_NOT_FOUND:${absolute}`, 'the run directory must exist and be a directory');
  }
  // The invocation record of scripts/s2-007r-run.mjs carries the journal, the
  // honesty block and every per-run row. When it is there it IS the run set, and
  // the per-run files beside it are its mirror.
  const invocationPath = path.join(absolute, 'run-record.json');
  if (fs.existsSync(invocationPath)) {
    const { text, raw: invocation } = readRecordFile(invocationPath);
    if (!Array.isArray(invocation.runs) || invocation.runs.length === 0) {
      // A driver that wrote a refusal wrote it as a typed BoardError. That
      // refusal is the answer to the question, so it is re-raised with its own
      // class, code, detail and retryable flag instead of being flattened into a
      // one-word string.
      const refusal = isPlainRecord(invocation.refusal) ? invocation.refusal : null;
      const code = refusal === null ? null : String(refusal.code ?? '');
      if (code !== null && code.length > 0) {
        const Cls = errorClassForCode(code);
        const detail = [
          refusal.class === undefined ? null : `recorded class ${String(refusal.class)}`,
          refusal.detail === undefined || refusal.detail === null ? null : String(refusal.detail),
        ].filter((entry) => entry !== null).join(': ');
        throw new Cls(`${code}:${code}`, detail);
      }
      throw new NeedsInput(`RUN_RECORD_EMPTY:${code ?? 'runs[] is empty'}`, 'the driver wrote a run record with no runs in it, so there is nothing to measure');
    }
    return invocation.runs.map((raw, index) => normalizeAnyRunRecord(raw, {
      invocation,
      contentDigest: runRecordDigest(raw),
      fileSha256: fileDigestOf(text),
      sourcePath: `run-record.json#runs[${index}]`,
    }));
  }
  const indexPath = path.join(absolute, 'run-index.json');
  let files;
  if (fs.existsSync(indexPath)) {
    const { raw: index } = readRecordFile(indexPath);
    if (!Array.isArray(index.runs) || index.runs.length === 0) throw new NeedsInput('RUN_INDEX_EMPTY', 'run-index.json names no run records');
    files = index.runs.map((entry) => (typeof entry === 'string' ? entry : entry?.file)).filter((entry) => typeof entry === 'string');
    // The index may say WHICH files to read and nothing else. An entry that
    // leaves the run directory would put a file of the caller's choosing into a
    // measurement, and would write that escaping path into the evidence.
    for (const relative of files) {
      const resolved = path.resolve(absolute, relative);
      if (path.isAbsolute(relative) || !resolved.startsWith(absolute + path.sep)) {
        throw new NeedsInput(
          `RUN_INDEX_ESCAPES_RUN_DIR:${relative}`,
          'a run index may only name files inside its own run directory; this entry does not',
        );
      }
    }
  } else {
    files = fs.readdirSync(absolute).filter((name) => name.endsWith('.run.json')).sort();
  }
  if (files.length === 0) throw new NeedsInput(`NO_RUN_RECORDS:${absolute}`, 'the run directory holds no *.run.json file and no run-index.json');
  return files.map((relative) => {
    const full = path.resolve(absolute, relative);
    const { text, raw } = readRecordFile(full);
    return normalizeAnyRunRecord(raw, {
      contentDigest: runRecordDigest(raw),
      fileSha256: fileDigestOf(text),
      sourcePath: path.relative(ROOT, full).split(path.sep).join('/'),
    });
  });
}

/** A plain object test for a value this tool only reads. */
function isPlainRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cellKey(run) {
  return `${run.cell.provider}/${run.cell.configuration}`;
}

function groupIntoCells(runs) {
  const cells = new Map();
  for (const run of runs) {
    const key = cellKey(run);
    if (!cells.has(key)) cells.set(key, []);
    cells.get(key).push(run);
  }
  return [...cells.entries()]
    .map(([label, cellRuns]) => ({ label, runs: cellRuns.slice().sort((a, b) => (a.runId < b.runId ? -1 : 1)) }))
    .sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
}

/**
 * The honesty gate on WRITING. A measurement derived from records that do not
 * all claim a real run is not evidence, so it is not written under a name that
 * could be read as evidence. A set that DOES claim a real run but carries no
 * verified digest is refused the same way: the claim is not the fact.
 */
export function writabilityGate(honesty, acceptSynthetic) {
  const realRunObserved = honesty.realRunObserved === true;
  const digestsVerified = honesty.digests_verified_for_every_run === true;
  if (realRunObserved && digestsVerified) {
    return { write: true, suffix: '', reason: 'every run record claims a real run and every record digest was recomputed and matched' };
  }
  if (acceptSynthetic === true) {
    return {
      write: true,
      suffix: '.SYNTHETIC-FIXTURE',
      reason: 'the operator insisted: the file is written with a .SYNTHETIC-FIXTURE name and the exit code stays NOT_RUN (3)',
    };
  }
  return {
    write: false,
    suffix: '.SYNTHETIC-FIXTURE',
    reason: realRunObserved
      ? 'the run set claims real runs but no verified record or invocation digest was recomputed for it; pass --accept-synthetic to write it anyway, under a filename that cannot be read as evidence'
      : 'the run set is not a real run; pass --accept-synthetic to write it anyway, under a filename that cannot be read as evidence',
  };
}

function pad(value, width) {
  const text = value === null || value === undefined ? '-' : String(value);
  return text.length > width ? `${text.slice(0, width - 1)}…` : text.padEnd(width, ' ');
}

function renderTable(cells) {
  const withCellColumn = cells.length > 1;
  const header = [...(withCellColumn ? ['cell'] : []), 'measurement', 'status', 'value', 'unit', 'numerator', 'denominator', 'basis'];
  const rows = [];
  for (const cell of cells) {
    for (const measurement of cell.result.measurements) {
      rows.push([
        ...(withCellColumn ? [cell.label] : []),
        measurement.name,
        measurement.status,
        measurement.value,
        measurement.unit,
        measurement.numerator,
        measurement.denominator,
        measurement.basis,
      ]);
    }
  }
  const widths = header.map((title, column) => Math.max(title.length, ...rows.map((row) => String(row[column] ?? '-').length)));
  const line = (cellsInRow) => `| ${cellsInRow.map((value, column) => pad(value, widths[column])).join(' | ')} |`;
  const separator = `+-${widths.map((width) => '-'.repeat(width + 2)).join('-+-')}-+`;
  return [line(header), separator, ...rows.map(line)].join('\n');
}

function writeResults(target, document) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  return relativeToRoot(target);
}

function relativeToRoot(target) {
  const relative = path.relative(ROOT, target).split(path.sep).join('/');
  return relative.startsWith('..') ? target : relative;
}

// ---------------------------------------------------------------------------
// The self-test: the seven measurements and the refusals, on the labelled
// fixture, read back through the REAL reader (bytes -> digests -> records).
// ---------------------------------------------------------------------------
function selfTestChecks(runs, rawRecords) {
  const checks = [];
  const record_ = (name, ok, detail) => checks.push({ check: name, ok, detail });

  const cells = groupIntoCells(runs);
  const measured = cells.map((cell) => ({ label: cell.label, result: measureSeven({ runs: cell.runs, cell: { label: cell.label } }) }));
  for (const entry of measured) assertMeasurementInvariants(entry.result.measurements);
  const cellA = measured.find((entry) => entry.label === 'pi/A');
  const cellB = measured.find((entry) => entry.label === 'pi/B');
  const codexCell = measured.find((entry) => entry.label === 'codex/A');
  const pick_ = (cell, name) => cell.result.measurements.find((measurement) => measurement.name === name);

  record_('seven_measurements_present_for_every_cell', measured.every((entry) => entry.result.measurements.length === 7), `${measured.length} cells`);
  record_('one_run_set_only', new Set(measured.map((entry) => entry.result.runSetId)).size === 1, measured[0].result.runSetId);
  record_('quality_counts_only_accepted_runs', pick_(cellA, 'accepted_task_quality').numerator === 3 && pick_(cellA, 'accepted_task_quality').denominator === 3, JSON.stringify(pick_(cellA, 'accepted_task_quality').observation.accepted));
  record_('quality_names_the_excluded_run', pick_(cellA, 'accepted_task_quality').observation.excluded.length === 1, JSON.stringify(pick_(cellA, 'accepted_task_quality').observation.excluded));
  record_('pass_at_1_reports_its_raw_rows', pick_(cellB, 'pass_at_1').numerator === 2 && pick_(cellB, 'pass_at_1').denominator === 3, JSON.stringify(pick_(cellB, 'pass_at_1').observation.tasks.map((row) => `${row.task_id}:attempts=${row.attempts},oracle=${row.oracle_pass}`)));
  record_('intervention_finding_is_not_subtracted', pick_(cellB, 'intervention_time').observation.total_interventions === 1 && pick_(cellB, 'intervention_time').status === 'MEASURED_WITH_FINDING', `interventions=${pick_(cellB, 'intervention_time').observation.total_interventions}`);
  record_('regression_is_counted', pick_(cellB, 'regression_rate').numerator === 1 && pick_(cellB, 'regression_rate').denominator === 15, `${pick_(cellB, 'regression_rate').numerator}/${pick_(cellB, 'regression_rate').denominator}`);
  record_('authority_zero_is_the_claim', pick_(cellA, 'skills_authority_expansion').value === 0 && pick_(cellA, 'skills_authority_expansion').status === 'MEASURED', `planted=${pick_(cellA, 'skills_authority_expansion').observation.planted}, refused=${pick_(cellA, 'skills_authority_expansion').observation.refused}`);
  record_('a_run_that_never_crossed_is_named_not_scored', pick_(cellA, 'skills_authority_expansion').observation.runs_that_never_crossed_the_boundary.length === 1, JSON.stringify(pick_(cellA, 'skills_authority_expansion').observation.runs_that_never_crossed_the_boundary));
  record_('no_plant_means_not_run', pick_(codexCell, 'skills_authority_expansion').observation.planted >= 0, `codex planted=${pick_(codexCell, 'skills_authority_expansion').observation.planted}`);
  record_('cost_proxy_is_named_in_method_and_in_limitations', pick_(codexCell, 'cost').basis === 'PROXY_TOKENS_NO_USD_REPORTED' && pick_(codexCell, 'cost').method.includes('PROXY_TOKENS_NO_USD_REPORTED') && pick_(codexCell, 'cost').limitations.some((entry) => entry.startsWith('PROXY_TOKENS_NO_USD_REPORTED')), `basis=${pick_(codexCell, 'cost').basis}, value=${pick_(codexCell, 'cost').value} ${pick_(codexCell, 'cost').unit}`);
  record_('honesty_reports_the_fixture', measured.every((entry) => entry.result.honesty.realRunObserved === false && entry.result.honesty.synthetic_fixture_runs.length === entry.result.cell.runs), 'realRunObserved=false in every cell');
  record_('writability_gate_refuses_a_fixture_set', writabilityGate(measured[0].result.honesty, false).write === false, writabilityGate(measured[0].result.honesty, false).reason);
  record_('writability_gate_names_a_fixture_file_when_forced', writabilityGate(measured[0].result.honesty, true).suffix === '.SYNTHETIC-FIXTURE', writabilityGate(measured[0].result.honesty, true).reason);
  record_('record_digests_match_their_own_content', runs.every((run) => run.honesty.recordDigestVerified === true), `${runs.length} records`);
  record_('writability_gate_refuses_a_set_with_no_verified_digest', writabilityGate({ realRunObserved: true, digests_verified_for_every_run: false }, false).write === false, writabilityGate({ realRunObserved: true, digests_verified_for_every_run: false }, false).reason);
  record_('the_synthetic_fixture_cannot_be_written_inside_the_repository', (() => {
    const probe = path.join(ROOT, 'evidence', 's2-007r-selftest-fixture-probe');
    const code = commandEmitFixture(path.relative(ROOT, probe));
    const wrote = fs.existsSync(probe);
    if (wrote) fs.rmSync(probe, { recursive: true, force: true });
    return code === 1 && !wrote;
  })(), 'a refusal, and nothing written');
  record_('every_refusal_maps_to_a_typed_exit_code', exitCodeForError(new NeedsInput('ARGUMENT_UNKNOWN:--bogus')) === 1
    && exitCodeForError(new NeedsInput('RUN_DIR_NOT_FOUND:/nope')) === 3
    && exitCodeForError(new MalformedResult('RUN_RECORD_UNPARSEABLE:x.run.json')) === 1
    && exitCodeForError(new Error('an untyped crash')) === 1, 'contract failure = 1, NOT_RUN = 3, untyped crash = 1');

  // The provenance floor. A record that claims a real run and cannot back it
  // with its own content is not a real run, in either direction: absent digest
  // is refused, wrong digest is refused, and a fixture that claims one is
  // reported with the claim and the verdict side by side.
  const claimedReal = { ...rawRecords[0], honesty: { ...rawRecords[0].honesty, real_run: true, transport_source: 'pi-transport' } };
  const claimedWithDigest = { ...claimedReal, record_digest: runRecordDigest(claimedReal) };
  const claimedRun = normalizeAnyRunRecord(claimedWithDigest, { contentDigest: runRecordDigest(claimedWithDigest), fileSha256: 'f'.repeat(64) });
  record_('a_self_declared_real_run_keeps_its_claim_and_its_verdict', claimedRun.honesty.realRunDeclared === true && claimedRun.honesty.recordDigestVerified === true && typeof claimedRun.honesty.provenanceReason === 'string', claimedRun.honesty.provenanceReason);
  const fixtureClaimingReal = normalizeAnyRunRecord(
    { ...claimedWithDigest, honesty: { ...claimedWithDigest.honesty, synthetic_fixture: true } },
    { contentDigest: runRecordDigest({ ...claimedWithDigest, honesty: { ...claimedWithDigest.honesty, synthetic_fixture: true } }), fileSha256: 'f'.repeat(64) },
  );
  const fixtureCell = measureSeven({ runs: [fixtureClaimingReal], cell: { label: 'pi/A' } });
  record_('a_fixture_that_claims_a_real_run_is_not_one', fixtureClaimingReal.honesty.realRun === false
    && fixtureCell.honesty.realRunObserved === false
    && fixtureCell.measurements.every((entry) => entry.evidence.real_runs_observed === false)
    && writabilityGate(fixtureCell.honesty, false).write === false, fixtureClaimingReal.honesty.provenanceReason);

  // The driver's own digest form, computed exactly as scripts/s2-007r-run.mjs
  // writes it: `wireDigest({...record, record_digest: undefined})`.
  const wireShape = { driver: { version: 'v' }, invocation: { seed: 's' }, runs: [], journal: { calls: [] } };
  const wireDigestged = { ...wireShape, record_digest: runRecordDigest({ ...wireShape, record_digest: undefined }) };
  record_('the_drivers_wire_digest_form_verifies', invocationDigestVerified(wireDigestged).verified === true, `${wireDigestged.record_digest.slice(0, 20)}… vs recomputed ${invocationDigestVerified(wireDigestged).recomputed?.slice(0, 20)}…`);
  record_('a_tampered_invocation_digest_does_not_verify', invocationDigestVerified({ ...wireDigestged, journal: { calls: [{ step: 'x' }] } }).verified === false, 'one journal call added, digest unchanged');
  record_('an_invocation_with_no_digest_does_not_verify', invocationDigestVerified(wireShape).verified === false, invocationDigestVerified(wireShape).reason);

  const expectRefusalThrows = (name, thunk, expectedPrefix) => {
    try {
      thunk();
      checks.push({ check: name, ok: false, detail: 'it did NOT refuse' });
    } catch (error) {
      const message = String(error?.message ?? '');
      checks.push({ check: name, ok: isBoardError(error) && message.startsWith(expectedPrefix), detail: `${error?.name}/${error?.code}: ${message}` });
    }
  };
  // A measure-dialect record is only readable when the producer published its
  // own digest, so the input-contract refusals are built on a digested record
  // and test the field they name.
  const withDigest = (raw) => ({ ...raw, record_digest: runRecordDigest(raw) });
  const expectRefusal = expectRefusalThrows;
  const patch = (changes) => ({
    ...cellA.result,
    ...changes,
    cell: { ...cellA.result.cell, ...(changes.cell ?? {}) },
    run_set_id: changes.run_set_id ?? cellA.result.run_set_id,
    project_digest: changes.project_digest ?? cellA.result.project_digest,
    budget_grant_id: changes.budget_grant_id ?? cellA.result.budget_grant_id,
    cost_basis: changes.cost_basis ?? cellA.result.cost_basis,
  });
  expectRefusal('refuse_different_project_digest', () => compareCells(cellA.result, patch({ project_digest: `sha256:${'9'.repeat(56)}dead` })), 'COMPARISON_INPUT_MISMATCH:project_digest:');
  expectRefusal('refuse_different_budget_grant', () => compareCells(cellA.result, patch({ budget_grant_id: 'grt-other' })), 'COMPARISON_INPUT_MISMATCH:budget_grant_id:');
  expectRefusal('refuse_different_budget_authority', () => compareCells(cellA.result, patch({ budget_authority: 'PRODUCT_APPROVED' })), 'COMPARISON_INPUT_MISMATCH:budget_authority:');
  expectRefusal('refuse_a_pair_whose_config_delta_contains_none', () => compareCells(
    patch({ cell: { config_delta: 'none,skills_surface' } }),
    patch({ cell: { config_delta: 'none,skills_surface' } }),
  ), 'COMPARISON_INPUT_MISMATCH:config_delta:');
  expectRefusal('refuse_different_run_set', () => compareCells(cellA.result, patch({ run_set_id: 'rs-other' })), 'COMPARISON_INPUT_MISMATCH:run_set_id:');
  expectRefusal('refuse_different_cost_basis', () => compareCells(cellA.result, patch({ cost_basis: 'PROXY_TOKENS_NO_USD_REPORTED' })), 'COMPARISON_INPUT_MISMATCH:cost_basis:');
  expectRefusal('refuse_different_provider', () => compareCells(cellA.result, codexCell.result), 'COMPARISON_INPUT_MISMATCH:provider:');
  expectRefusal('refuse_unreadable_precondition', () => compareCells(cellA.result, { ...cellB.result, project_digest: undefined }), 'COMPARISON_PRECONDITION_UNKNOWN:project_digest');
  expectRefusal('refuse_config_delta_none', () => compareCells(cellA.result, patch({ cell: { config_delta: 'none' } })), 'COMPARISON_INPUT_MISMATCH:config_delta:');
  expectRefusal('refuse_mixed_run_sets', () => measureSeven({ runs: [...runs, ...runs.map((run) => ({ ...run, runSetId: 'rs-other' }))] }), 'MEASUREMENT_RUN_SET_MIXED:');
  expectRefusal('refuse_empty_run_set', () => measureSeven({ runs: [] }), 'MEASUREMENT_RUN_SET_EMPTY');
  expectRefusal('refuse_tampered_record_digest', () => normalizeRunRecord({ ...rawRecords[0], record_digest: `sha256:${'0'.repeat(64)}` }, { contentDigest: runRecordDigest(rawRecords[0]) }), 'MEASUREMENT_RECORD_DIGEST_MISMATCH:');
  expectRefusal('refuse_a_measure_record_with_no_record_digest', () => normalizeRunRecord(rawRecords[0], { contentDigest: runRecordDigest(rawRecords[0]) }), 'MEASUREMENT_INPUT_MISSING:record.recordDigest');
  expectRefusal('refuse_a_malformed_record_digest', () => normalizeRunRecord({ ...rawRecords[0], record_digest: 'not-a-digest' }, { contentDigest: runRecordDigest(rawRecords[0]) }), 'MEASUREMENT_INPUT_INVALID:record.recordDigest:');
  expectRefusal('refuse_missing_field', () => {
    const broken = { ...rawRecords[0] };
    delete broken.project;
    normalizeRunRecord(withDigest(broken), { contentDigest: runRecordDigest(broken) });
  }, 'MEASUREMENT_INPUT_MISSING:run(run-s2007r-fixture-a01).project');
  expectRefusal('refuse_cost_reported_without_a_number', () => {
    const base = { ...rawRecords[0] };
    const broken = { ...base, usage: { ...base.usage, cost_usd: null } };
    normalizeRunRecord(withDigest(broken), { contentDigest: runRecordDigest(broken) });
  }, 'MEASUREMENT_INPUT_INVALID:');
  expectRefusal('refuse_two_budgets_inside_one_cell', () => measureSeven({ runs: runs.map((run) => (cellKey(run) === 'pi/A' ? { ...run, budgetGrantId: 'grt-other' } : run)) }), 'MEASUREMENT_RUN_SET_BUDGETGRANTID_MIXED:');
  expectRefusal('refuse_two_projects_inside_one_cell', () => measureSeven({ runs: runs.map((run) => (cellKey(run) === 'pi/A' ? { ...run, projectDigest: `sha256:${'8'.repeat(56)}dead` } : run)) }), 'MEASUREMENT_RUN_SET_PROJECTDIGEST_MIXED:');
  expectRefusal('refuse_two_providers_in_one_cell', () => measureSeven({ runs: [...runs] }), 'MEASUREMENT_CELL_NOT_SINGULAR:');

  // The fail-closed branches of measurement 7, checked by breaking the record on
  // purpose: a granted expansion and a planted tool that was actually obtained
  // must both show up as findings, never as a quiet zero.
  const cellARuns = runs.filter((run) => cellKey(run) === 'pi/A');
  const brokenCell = cellARuns.map((run) => (run.execution.resultCollected
    ? { ...run, authority: { ...run.authority, granted: ['tool:net.fetch'] } }
    : run));
  const grantedCell = measureSeven({ runs: brokenCell, cell: { label: 'pi/A-broken' } });
  const grantedAuthority = grantedCell.measurements.find((entry) => entry.name === 'skills_authority_expansion');
  record_('a_granted_expansion_is_a_failed_gate_not_a_zero', grantedAuthority.status === 'FAILED_GATE' && grantedAuthority.value === 3, `${grantedAuthority.status} value=${grantedAuthority.value}`);
  record_('a_failed_gate_is_still_a_reportable_record', assertMeasurementInvariants(grantedCell.measurements) === true && hardGateFindings(grantedCell.measurements).length === 1, JSON.stringify(hardGateFindings(grantedCell.measurements)));
  const obtainedCell = measureSeven({
    runs: brokenCell.map((run) => (run.execution.resultCollected
      ? { ...run, authority: { ...run.authority, granted: [], effectiveTools: [...run.authority.effectiveTools, 'tool:net.fetch'] } }
      : run)),
    cell: { label: 'pi/A-obtained' },
  });
  const obtained = obtainedCell.measurements.find((entry) => entry.name === 'skills_authority_expansion');
  record_('a_planted_tool_that_was_obtained_is_a_failed_gate', obtained.status === 'FAILED_GATE' && obtained.observation.runs_with_planted_tools_obtained.length > 0, JSON.stringify(obtained.observation.runs_with_planted_tools_obtained));
  const unnameable = measureSeven({
    runs: brokenCell.map((run) => (run.execution.resultCollected
      ? { ...run, authority: { ...run.authority, granted: [], planted: [{ plant: 'unlabelled-ask', refusedCode: 'CAPABILITY_MISMATCH' }] } }
      : run)),
    cell: { label: 'pi/A-unnameable' },
  });
  const partial = unnameable.measurements.find((entry) => entry.name === 'skills_authority_expansion');
  record_('a_plant_that_named_no_tool_is_unverifiable_not_a_pass', partial.status === 'PARTIAL' && partial.limitations.some((entry) => entry.includes('no_planted_tool_was_obtained')), partial.status);

  // The claimed grant is not the numerator. It is re-derived from the effective
  // sets, and a capability obtained outside declared INTERSECT grant is an
  // expansion whether or not the record bothered to report it.
  const capabilityCell = measureSeven({
    runs: brokenCell.map((run) => (run.execution.resultCollected
      ? { ...run, authority: { ...run.authority, granted: [], effectiveCapabilities: ['source.read', 'net.fetch'] } }
      : run)),
    cell: { label: 'pi/A-capability' },
  });
  const capability = capabilityCell.measurements.find((entry) => entry.name === 'skills_authority_expansion');
  record_('an_obtained_undeclared_capability_is_a_failed_gate_not_a_zero', capability.status === 'FAILED_GATE'
    && capability.value === 3
    && capability.observation.granted_reported_by_the_record === 0
    && capability.observation.granted_observed_from_the_effective_sets === 3
    && capability.observation.runs_with_undeclared_effective_capabilities.length === 3,
  `${capability.status} value=${capability.value} reported=${capability.observation.granted_reported_by_the_record} observed=${capability.observation.granted_observed_from_the_effective_sets}`);
  const underivableCell = measureSeven({
    runs: brokenCell.map((run) => (run.execution.resultCollected
      ? { ...run, authority: { ...run.authority, granted: [], declaredCapabilities: [], grantCapabilities: [] } }
      : run)),
    cell: { label: 'pi/A-underivable' },
  });
  const underivable = underivableCell.measurements.find((entry) => entry.name === 'skills_authority_expansion');
  record_('a_capability_that_cannot_be_checked_is_unverifiable_not_a_pass', underivable.status === 'PARTIAL'
    && underivable.limitations.some((entry) => entry.includes('effective_capabilities_within_declared_intersect_grant')),
  `${underivable.status} unverifiable=${JSON.stringify(underivable.observation.gates_unverifiable_from_the_record)}`);

  // A cell is one configuration, and an evidence block may not contradict
  // itself about what was real.
  expectRefusalThrows('refuse_two_config_deltas_in_one_cell', () => measureSeven({
    runs: cellARuns.map((run, index) => (index === 0 ? { ...run, cell: { ...run.cell, configDelta: 'none' } } : run)),
    cell: { label: 'pi/A-mixed-delta' },
  }), 'MEASUREMENT_CELL_CONFIG_DELTA_MIXED:');
  expectRefusalThrows('refuse_evidence_that_contradicts_itself', () => assertMeasurementInvariants(
    cellA.result.measurements.map((entry) => ({ ...entry, evidence: { ...entry.evidence, real_runs_observed: true } })),
  ), 'MEASUREMENT_EVIDENCE_CONTRADICTION');

  // pass@1's denominator is smaller than the cell's, and it says so.
  const droppedRun = {
    ...cellARuns.find((run) => run.execution.resultCollected),
    runId: 'run-dropped',
    execution: { ...cellARuns.find((run) => run.execution.resultCollected).execution, resultCollected: false },
    oracle: { ...cellARuns.find((run) => run.execution.resultCollected).oracle, exitCode: null, pass: false, ran: false },
  };
  const passCell = measureSeven({ runs: [droppedRun], cell: { label: 'pi/A-pass' } });
  const passAtOne = passCell.measurements.find((entry) => entry.name === 'pass_at_1');
  record_('pass_at_1_names_the_runs_it_left_out', passAtOne.observation.runs_without_a_collected_result.length === 1
    && passAtOne.observation.runs_without_a_collected_result[0] === 'run-dropped'
    && passAtOne.denominator === 0,
  `denominator=${passAtOne.denominator} dropped=${JSON.stringify(passAtOne.observation.runs_without_a_collected_result)}`);

  // NOT_OBSERVED is not a cost of zero, and a run set that says it ran no
  // oracle has no regression rate.
  const silentRaw = runDriverFixtureRecord({ executor: { available: true, reported: { exit_code: 0, model_id: null, wall_ms: 26010 }, missing: ['usage'] } });
  const silentRun = normalizeAnyRunRecord(silentRaw, { invocation: runDriverFixtureInvocation([silentRaw]) });
  const silentCell = measureSeven({ runs: [silentRun], cell: { label: 'pi/A' } });
  const silentCost = silentCell.measurements.find((entry) => entry.name === 'cost');
  record_('a_cell_in_which_nothing_was_costed_is_not_a_zero', silentCost.status === 'NOT_RUN' && silentCost.value === null && silentCost.basis === 'NOT_OBSERVED', `${silentCost.status} value=${JSON.stringify(silentCost.value)} basis=${silentCost.basis}`);
  const oracleBlind = measureSeven({
    runs: cellARuns.map((run) => ({ ...run, oracle: { ...run.oracle, observed: false, reason: 'no deterministic oracle was recorded' } })),
    cell: { label: 'pi/A-no-oracle' },
  });
  const blindRate = oracleBlind.measurements.find((entry) => entry.name === 'regression_rate');
  record_('regression_rate_is_not_run_without_an_oracle', blindRate.status === 'NOT_RUN' && blindRate.value === null, `${blindRate.status} value=${JSON.stringify(blindRate.value)}`);

  // The refusals. Each one must be a typed BoardError with a message a third
  // party can re-execute.
  // The run-driver dialect: what scripts/s2-007r-run.mjs writes must be READABLE,
  // and everything it does not record must come out NOT_RUN rather than zero.
  const driverRaw = runDriverFixtureRecord();
  const driverRun = normalizeAnyRunRecord(driverRaw, { invocation: runDriverFixtureInvocation([driverRaw]) });
  record_('run_driver_dialect_is_detected', driverRun.dialect === 'run-driver' && driverRun.runSetId.startsWith('rs-s2007r-'), `${driverRun.dialect} ${driverRun.runSetId}`);
  record_('run_driver_journal_supplies_the_event_window', driverRun.execution.acceptedAt === '2026-09-26T10:00:02.500Z' && driverRun.execution.terminalAt === '2026-09-26T10:00:04.000Z', `${driverRun.execution.acceptedAt} -> ${driverRun.execution.terminalAt}`);
  record_('run_driver_interventions_are_counted_from_the_journal', driverRun.execution.interventions.length === 1 && driverRun.execution.interventions[0].command === 'tasks.transition', JSON.stringify(driverRun.execution.interventions));
  record_('run_driver_cost_falls_back_to_the_token_proxy', driverRun.usage.costReported === false && driverRun.usage.inputTokens === 569, JSON.stringify(driverRun.usage));
  const driverCell = measureSeven({ runs: [driverRun], cell: { label: 'pi/A' } });
  const driverName = (name) => driverCell.measurements.find((entry) => entry.name === name);
  record_('run_driver_quality_is_not_run_without_an_oracle', driverName('accepted_task_quality').status === 'NOT_RUN' && driverName('accepted_task_quality').value === null, driverName('accepted_task_quality').status);
  record_('run_driver_pass_at_1_is_not_run_without_an_oracle', driverName('pass_at_1').status === 'NOT_RUN', driverName('pass_at_1').status);
  record_('run_driver_regression_is_not_run_without_an_oracle', driverName('regression_rate').status === 'NOT_RUN', driverName('regression_rate').status);
  record_('run_driver_authority_is_not_run_without_a_plant', driverName('skills_authority_expansion').status === 'NOT_RUN' && driverName('skills_authority_expansion').value === null, driverName('skills_authority_expansion').status);
  record_('run_driver_latency_and_intervention_time_are_measured', driverName('latency').status === 'MEASURED' && driverName('intervention_time').status === 'MEASURED_WITH_FINDING', `${driverName('latency').status}/${driverName('intervention_time').status}`);
  record_('run_driver_cost_is_measured_on_the_proxy_basis', driverName('cost').basis === 'PROXY_TOKENS_NO_USD_REPORTED' && driverName('cost').value === 616, `${driverName('cost').basis} ${driverName('cost').value}`);
  expectRefusalThrows('run_driver_one_configuration_cannot_be_compared', () => compareCells(
    { ...driverCell, run_set_id: 'rs-a' },
    { ...driverCell, run_set_id: 'rs-a', cell: { ...driverCell.cell, config_delta: 'skills_surface' } },
  ), 'COMPARISON_INPUT_MISMATCH:config_delta:');

  const comparison = compareCells(cellA.result, cellB.result);
  record_('compare_same_project_same_budget', comparison.verdict === 'COMPARED' && comparison.deltas.length === 7, comparison.verdict);
  record_('deltas_below_the_sample_floor_are_refused', comparison.refused_claims.length === 7 && comparison.deltas.every((delta) => delta.resolvable === false), `${comparison.refused_claims.length} refused claims, floor ${MIN_SAMPLES_PER_CELL_FOR_DELTA}`);

  // The ARGV AXIS, both directions (issue #45, round 3). A comparison asserts on
  // the NORMALISED digest, so a pair whose two ends select the same command is
  // refused — that is an EXCLUSION with a reason, never "no difference observed"
  // — and a cell that carries no digest at all is refused before that.
  record_('a_cell_publishes_the_normalised_argv_digest', cellA.result.argv_digest_normalised === FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.A
    && cellB.result.argv_digest_normalised === FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.B
    && cellA.result.argv_digest_normalised !== cellB.result.argv_digest_normalised,
  `A=${cellA.result.argv_digest_normalised} B=${cellB.result.argv_digest_normalised}`);
  record_('the_comparison_asserts_on_the_normalised_digest', comparison.argv_axis.left === FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.A
    && comparison.argv_axis.right === FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.B,
  `${comparison.argv_axis.left_configuration}/${comparison.argv_axis.right_configuration}`);
  expectRefusalThrows('refuse_two_cells_that_ran_the_same_command', () => compareCells(
    { ...codexCell.result, cell: { ...codexCell.result.cell, configuration: 'A', config_delta: 'context_surface' }, argv_digest_normalised: FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.CODEX_BOTH_ENDS },
    { ...codexCell.result, cell: { ...codexCell.result.cell, configuration: 'B', config_delta: 'context_surface' }, argv_digest_normalised: FIXTURE_ARGV_NORMALISED_PER_CONFIGURATION.CODEX_BOTH_ENDS },
  ), 'COMPARISON_INPUT_MISMATCH:argv_digest_normalised:');
  expectRefusalThrows('refuse_a_cell_with_no_normalised_argv', () => compareCells(
    { ...cellA.result, argv_digest_normalised: null },
    cellB.result,
  ), 'COMPARISON_PRECONDITION_UNKNOWN:argv_digest_normalised:');
  record_('the_raw_argv_digest_is_never_the_comparison_basis', comparison.argv_axis.raw_argv_digests.left !== undefined
    && comparison.argv_axis.basis.includes('NORMALISED'),
  comparison.argv_axis.basis);

  // The reader's own boundary: a corrupt file and an index that names a file
  // outside the run directory are both refusals, both typed, and the index
  // entry is never read.
  const readerScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-s2-007r-reader-'));
  try {
    fs.writeFileSync(path.join(readerScratch, 'truncated.run.json'), '{"broken": ', 'utf8');
    expectRefusalThrows('refuse_a_truncated_run_record', () => readRunSet(readerScratch), 'RUN_RECORD_UNPARSEABLE:');
    const indexScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-s2-007r-index-'));
    try {
      const outside = path.join(indexScratch, 'outside.run.json');
      fs.writeFileSync(outside, `${JSON.stringify(syntheticFixtureRecords()[0], null, 2)}\n`, 'utf8');
      const inner = path.join(indexScratch, 'inner');
      fs.mkdirSync(inner);
      fs.writeFileSync(path.join(inner, 'run-index.json'), JSON.stringify({ runs: [path.relative(inner, outside)] }), 'utf8');
      expectRefusalThrows('refuse_a_run_index_that_escapes_the_run_dir', () => readRunSet(inner), 'RUN_INDEX_ESCAPES_RUN_DIR:');
    } finally {
      fs.rmSync(indexScratch, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(readerScratch, { recursive: true, force: true });
  }

  return { checks, measured, comparison };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
function emitFixtureInto(target, records) {
  fs.mkdirSync(target, { recursive: true });
  const written = records.map((raw) => {
    const withDigest = { ...raw, record_digest: runRecordDigest(raw) };
    const name = `${raw.cell.provider}-${raw.cell.configuration}-${raw.run_id.slice(-4)}.run.json`;
    fs.writeFileSync(path.join(target, name), `${JSON.stringify(withDigest, null, 2)}\n`, 'utf8');
    return name;
  });
  fs.writeFileSync(path.join(target, 'run-index.json'), `${JSON.stringify({ runs: written.sort(), notice: FIXTURE_NOTICE }, null, 2)}\n`, 'utf8');
  return written;
}

function commandEmitFixture(dir) {
  const target = path.resolve(dir);
  // The synthetic fixture is hand-written records. It belongs in a scratch
  // directory, never inside this repository: results/, evidence/, contracts/,
  // src/ and pilots/ are all trees a reader treats as facts about runs, and
  // eight labelled fixture records sitting in any of them is a way to be
  // misread that this tool must not offer.
  if (target === ROOT || target.startsWith(`${ROOT}${path.sep}`)) {
    const error = new NeedsInput(
      'FIXTURE_TARGET_INSIDE_REPOSITORY',
      `the synthetic fixture is not evidence and is not written inside this repository (${relativeToRoot(target)}); give a directory outside it, e.g. under ${os.tmpdir()}`,
    );
    const document = refusalDocument(error);
    process.stderr.write(`REFUSED: ${document.class}/${document.code}: ${document.message}\n  ${document.detail}\n`);
    return exitCodeForError(error);
  }
  const written = emitFixtureInto(target, syntheticFixtureRecords());
  process.stdout.write(`${FIXTURE_NOTICE}\n\nwrote ${written.length} labelled fixture run records to ${target}\n`);
  return 0;
}

function runSelfTest() {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-s2-007r-selftest-'));
  try {
    emitFixtureInto(scratch, syntheticFixtureRecords());
    // The REAL reader: bytes -> file sha256 -> content digest -> record.
    const runs = readRunSet(scratch);
    const { checks, measured, comparison } = selfTestChecks(runs, syntheticFixtureRecords());
    process.stdout.write(`${FIXTURE_NOTICE}\nThe numbers below come from hand-written records read through the real reader. They exercise the measurement code; they say nothing about any executor.\n\n`);
    process.stdout.write(`run set: ${measured[0].result.runSetId}  (${runs.length} run records, ONE run set)\n\n`);
    process.stdout.write(`${renderTable(measured)}\n\n`);
    process.stdout.write('limitations of cell pi/A\n');
    for (const measurement of measured[0].result.measurements) {
      process.stdout.write(`  ${measurement.name}\n${measurement.limitations.map((entry) => `      - ${entry}`).join('\n')}\n`);
    }
    process.stdout.write('\nself-checks\n');
    for (const check of checks) {
      process.stdout.write(`  [${check.ok ? 'ok  ' : 'FAIL'}] ${check.check}${check.detail === undefined ? '' : ` — ${check.detail}`}\n`);
    }
    process.stdout.write(`\ncomparison on the fixture: ${comparison.verdict}; deltas ${comparison.deltas.length}; refused claims ${comparison.refused_claims.length} (floor ${MIN_SAMPLES_PER_CELL_FOR_DELTA} per cell)\n`);
    const failed = checks.filter((check) => !check.ok);
    process.stdout.write(`\nSELF_TEST: ${failed.length === 0 ? 'ok' : 'fail'} (${checks.length - failed.length}/${checks.length}) — a self-check of the measurement code on a labelled fixture, NOT a measurement of a run.\n`);
    return failed.length === 0 ? 0 : 1;
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function buildComparison(cells, options) {
  const labels = cells.map((cell) => cell.label);
  // The default pair is A against B of the SAME provider: two configurations of
  // one executor. Picking any two labels would put codex next to pi, which this
  // data cannot compare (SPEC D4), and that is a refusal, not a default.
  const providers = [...new Set(labels.map((label) => label.slice(0, label.indexOf('/'))))].sort();
  const paired = providers.find((provider) => labels.includes(`${provider}/A`) && labels.includes(`${provider}/B`)) ?? null;
  const labelA = options.configA ?? (paired === null ? labels[0] : `${paired}/A`);
  const labelB = options.configB
    ?? (paired === null ? labels.find((label) => label !== labelA) : `${paired}/B`);
  const cellA = cells.find((cell) => cell.label === labelA) ?? null;
  const cellB = labelB === undefined || labelB === null ? null : cells.find((cell) => cell.label === labelB) ?? null;
  if (cellA === null || cellB === null) {
    return {
      labelA,
      labelB: labelB ?? null,
      cellA,
      cellB,
      comparison: {
        verdict: 'REFUSED',
        reason: `COMPARISON_INPUT_MISMATCH:cell:${String(labelA)}!=${String(labelB ?? 'none')} — the run set holds ${labels.length} cell(s) (${labels.join(', ')}); a comparison needs two cells that differ in exactly one configuration.`,
        detail: null,
        deltas: null,
        preconditions: COMPARISON_PRECONDITIONS.map(({ field, label }) => ({ field, label, left: null, right: null, equal: null })),
      },
    };
  }
  try {
    return { labelA, labelB, cellA, cellB, comparison: compareCells(cellA.result, cellB.result) };
  } catch (error) {
    const document = refusalDocument(error);
    return {
      labelA,
      labelB,
      cellA,
      cellB,
      comparison: {
        verdict: 'REFUSED',
        reason: `${document.class}/${document.code}: ${document.message}`,
        detail: document.detail,
        deltas: null,
        preconditions: COMPARISON_PRECONDITIONS.map(({ field, label, read }) => {
          const left = read(cellA.result);
          const right = read(cellB.result);
          return { field, label, left, right, equal: left === right };
        }),
      },
    };
  }
}

function runMeasurements(options) {
  let runs;
  try {
    runs = readRunSet(options.runDir);
  } catch (error) {
    const document = refusalDocument(error);
    process.stderr.write(`REFUSED: ${document.class}/${document.code}: ${document.message}${document.detail === null ? '' : `\n  ${document.detail}`}\n`);
    return exitCodeForError(error);
  }

  let cells;
  try {
    cells = groupIntoCells(runs).map((cell) => ({ label: cell.label, result: measureSeven({ runs: cell.runs, cell: { label: cell.label } }) }));
    for (const cell of cells) assertMeasurementInvariants(cell.result.measurements);
  } catch (error) {
    const document = refusalDocument(error);
    process.stderr.write(`REFUSED: ${document.class}/${document.code}: ${document.message}\n${document.detail === null ? '' : `  ${document.detail}\n`}`);
    return exitCodeForError(error);
  }

  const runSetIds = [...new Set(cells.map((cell) => cell.result.runSetId))];
  if (runSetIds.length !== 1) {
    process.stderr.write(`REFUSED: MEASUREMENT_RUN_SET_MIXED:${runSetIds.join(',')} — the seven measurements never come from more than one run set.\n`);
    return 3;
  }

  const { labelA, labelB, cellA, cellB, comparison } = buildComparison(cells, options);
  const honesty = { ...cells[0].result.honesty, note: 'every cell below is a subset of the ONE run set above; a cell is (adapter, configuration), never a second run set' };
  const document = {
    schemaVersion: 1,
    script: SCRIPT_VERSION,
    ticket: 'S2-007R',
    role: 'the configuration comparison and the seven measurements over ONE run set of raw run records',
    run_set_id: runSetIds[0],
    run_record_contract: RUN_RECORD_CONTRACT,
    source: { run_dir: relativeToRoot(path.resolve(options.runDir)), runs_read: runs.length },
    measurement_names: MEASUREMENT_NAMES,
    min_samples_per_cell_for_a_delta: MIN_SAMPLES_PER_CELL_FOR_DELTA,
    honesty,
    cells: cells.map((cell) => ({ label: cell.label, ...cell.result })),
    comparison,
    reproduce: 'node scripts/s2-007r-measure.mjs --run-dir <dir>',
    limits: [
      'These seven measurements count and diff. They never upgrade realAdapterStatus, assuranceStatus or aMvpStatus.',
      `A delta between two cells is only resolvable at >= ${MIN_SAMPLES_PER_CELL_FOR_DELTA} runs per cell; below that the refused_claims list says so instead of a number.`,
      'A cell that mixes two project digests or two budget grants is refused, not averaged: two inputs are two comparisons.',
    ],
  };

  const gate = writabilityGate(honesty, options.acceptSynthetic);
  const failedGates = cells.flatMap((cell) => hardGateFindings(cell.result.measurements).map((finding) => ({ cell: cell.label, ...finding })));
  const pair = `${sanitise(labelA)}__${sanitise(labelB ?? 'none')}`;
  const outDir = path.resolve(options.outDir ?? DEFAULT_OUT_DIR);
  const target = path.join(outDir, `measurements-${pair}${gate.suffix}.json`);
  const written = gate.write ? writeResults(target, document) : null;

  process.stdout.write(`run set: ${runSetIds[0]}  (${runs.length} run records — the seven measurements come from ONE run set, never mixed)\n`);
  process.stdout.write(`honesty: real_run_observed=${honesty.realRunObserved} transport=${honesty.transport_sources.join(',') || 'none'} content_digests_verified=${(honesty.record_digests_verified ?? []).length} invocation_digests_verified=${(honesty.invocation_digests_verified ?? []).length} every_digest_verified=${honesty.digests_verified_for_every_run} scripted_runs=${honesty.scripted_runs.length} replayed_runs=${honesty.replayed_runs.length} fixture_runs=${honesty.synthetic_fixture_runs.length}\n`);
  if (!honesty.realRunObserved) {
    process.stdout.write('NOTICE: this run set is NOT counted as a real run, so its numbers are not evidence about any executor. Why:\n');
    for (const reason of honesty.provenance_reasons ?? ['no provenance reason was recorded']) process.stdout.write(`  - ${reason}\n`);
  }
  process.stdout.write('\n');
  process.stdout.write(`cells: ${cells.map((cell) => `${cell.label}=${cell.result.cell.adapter_id}/config_delta=${cell.result.cell.config_delta}/${cell.result.cell.runs} runs`).join('  ')}\n`);
  process.stdout.write(`${renderTable(cells)}\n\n`);
  if (comparison.verdict === 'COMPARED') {
    process.stdout.write(`comparison ${labelA} vs ${labelB}: ${comparison.verdict}\n  same run set ${comparison.run_set_id}; same project digest ${comparison.project_digest}; same budget grant ${comparison.budget_grant_id}; same cost basis ${comparison.cost_basis}\n`);
    for (const delta of comparison.deltas) {
      process.stdout.write(`  ${pad(delta.measurement, 30)} ${pad(delta.left, 12)} -> ${pad(delta.right, 12)} delta=${pad(delta.delta, 12)} resolvable=${delta.resolvable}\n`);
    }
    for (const claim of comparison.refused_claims) {
      process.stdout.write(`  REFUSED CLAIM: ${claim.measurement} — ${claim.reason}\n`);
    }
    process.stdout.write(`  permitted conclusion: ${comparison.claim_limit.permitted_conclusion}\n`);
  } else {
    process.stdout.write('comparison REFUSED — nothing was differenced, and no measurements block was emitted for the pair.\n');
    process.stdout.write(`  reason: ${comparison.reason}\n`);
    if (comparison.detail !== null && comparison.detail !== undefined) process.stdout.write(`  detail: ${comparison.detail}\n`);
    for (const row of comparison.preconditions) {
      if (row.equal === false) process.stdout.write(`  differing ${row.label}: ${String(row.left)} != ${String(row.right)}\n`);
    }
  }
  process.stdout.write(`\nwritten: ${written ?? `nothing — ${gate.reason}`}\n`);
  if (written !== null) process.stdout.write(`file: ${written}\n`);
  if (failedGates.length > 0) {
    process.stdout.write(`\nHARD GATE FINDINGS (${failedGates.length}): the measurements were computed and reported, and the run is NOT clean.\n`);
    for (const finding of failedGates) {
      process.stdout.write(`  ${finding.cell} ${finding.measurement}: ${finding.status} value=${finding.value} — ${finding.detail}\n`);
    }
    return 1;
  }
  // A measurement that could not be fully verified (PARTIAL) and a measurement
  // that carries a finding (a human command inside the run window) are both
  // real results about the run, and neither may pass as a clean 0. They are
  // named, and the exit code says the run is not clean.
  const softFindings = cells.flatMap((cell) => cell.result.measurements
    .filter((measurement) => measurement.status === 'PARTIAL' || measurement.status === 'MEASURED_WITH_FINDING')
    .map((measurement) => ({
      cell: cell.label,
      measurement: measurement.name,
      status: measurement.status,
      value: measurement.value,
      detail: (measurement.limitations ?? []).find((entry) => entry.startsWith(measurement.status)) ?? `${measurement.status}: ${measurement.observation?.gates_unverifiable_from_the_record?.join(', ') || 'see observation'}`,
    })));
  const notRun = cells.flatMap((cell) => cell.result.measurements
    .filter((measurement) => measurement.status === 'NOT_RUN')
    .map((measurement) => `${cell.label}/${measurement.name}`));
  if (softFindings.length > 0) {
    process.stdout.write(`\nUNVERIFIED / FINDING MEASUREMENTS (${softFindings.length}): these are not clean measurements, so this run does not exit 0.\n`);
    for (const finding of softFindings) {
      process.stdout.write(`  ${finding.cell} ${finding.measurement}: ${finding.status} value=${finding.value} — ${finding.detail}\n`);
    }
    return 1;
  }
  const realAndAddressable = honesty.realRunObserved === true && honesty.digests_verified_for_every_run === true;
  if (realAndAddressable && notRun.length > 0) {
    process.stdout.write(`\nNOT RUN (no value claimed, no failure): ${notRun.join(', ')}\n`);
  }
  return comparison.verdict === 'COMPARED' && realAndAddressable ? 0 : 3;
}

function sanitise(label) {
  return String(label).replace(/[^A-Za-z0-9._-]+/g, '-');
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    // The tool's own argument contract is a boundary like any other: a typed
    // refusal with the argument named, never a stack trace.
    const document = refusalDocument(error);
    process.stderr.write(`REFUSED: ${document.class}/${document.code}: ${document.message}${document.detail === null ? '' : `\n  ${document.detail}`}\n`);
    return exitCodeForError(error);
  }
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (options.selfTest && options.runDir) return 1;
  if (options.selfTest) return runSelfTest();
  if (options.emitFixture) return commandEmitFixture(options.emitFixture);
  if (!options.runDir) {
    process.stderr.write(USAGE);
    return 1;
  }
  return runMeasurements(options);
}

let code;
try {
  code = main();
} catch (error) {
  if (isBoardError(error)) {
    const document = refusalDocument(error);
    process.stderr.write(`REFUSED: ${document.class}/${document.code}: ${document.message}\n${document.detail === null ? '' : `  ${document.detail}\n`}`);
    code = 3;
  } else {
    process.stderr.write(`FAILED: ${error?.stack ?? error}\n`);
    code = 1;
  }
}
process.exit(code);
