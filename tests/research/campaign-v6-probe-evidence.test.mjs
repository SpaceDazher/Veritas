import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  activeCampaignVersion,
  validateV6ProbeEvidence,
} from '../../scripts/s2-008-campaign-evaluate.mjs';
import { RESEARCH_HARD_GATE_COUNTERS } from '../../src/lib/research/constants.mjs';
import {
  childInvocationArgs,
  resolveProbePreregistrationPath,
  validateProbePreregistration,
} from '../../scripts/s2-008-campaign-probes.mjs';

const commit = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const preregistrationDigest = 'c'.repeat(64);
const probeIds = [
  'P1_INFRA_IMAGE_ABSENT',
  'P2_LOST_EVALUATOR',
  'P3_NO_MEASUREMENT',
  'P4_PREREGISTERED_TIMEOUT',
  'P5_INTERRUPTED_THEN_RESTARTED',
  'P6_EXPIRED_RESERVATION',
  'P7_MISSING_OUTCOME_DETECTABLE',
];
const runA = { base: { commit_sha: commit, tree_sha: tree } };
const runB = { base: { commit_sha: commit, tree_sha: tree } };

function campaignRecord() {
  const probes = probeIds.map((probe) => ({ probe, held: true, observed: { outcome: 'INFRA' } }));
  return {
    kind: 's2-008-campaign-probes/1',
    commit_sha: commit,
    tree_sha: tree,
    preregistration_digest: preregistrationDigest,
    probes,
    summary: { total: 7, held: 7, broken: 0, outcome_classes_exercised: ['INFRA'] },
  };
}

function securityRecord() {
  const counters = Object.fromEntries(RESEARCH_HARD_GATE_COUNTERS.map((counter) => [counter, 0]));
  return {
    status: 'PASS',
    ok: true,
    exitCode: 0,
    base: { commit_sha: commit, tree_sha: tree },
    hardGates: { counters, names: [...RESEARCH_HARD_GATE_COUNTERS], ok: true, moved: [] },
    totals: {
      families: 6, probes: 6, probes_ran: 6, passed: 6, failed: 0, not_run: 0, broken: 0,
      controls_declared: 6, controls_extra_declared: 1, controls_ran: 7, controls_flipped: 7, controls_unaccounted: [],
    },
    probes: { results: Array.from({ length: 6 }, (_, index) => ({ probe: 'probe-' + index, status: 'pass' })), notRun: [], broken: [] },
    controls: {
      allFlipped: true,
      gate: { ok: true, failures: [] },
      notRun: [],
      records: Array.from({ length: 7 }, (_, index) => ({ id: 'control-' + index, flipped: true })),
      digest: 'd'.repeat(64),
    },
  };
}

test('active campaign routing recognizes v6', () => {
  assert.equal(activeCampaignVersion({ preregistration: { file: 'preregistration.v6.in-force.json' } }), 'v6');
});

test('v6 evaluator accepts only complete same-base campaign probes and fresh security controls, then binds both digests', () => {
  const result = validateV6ProbeEvidence({
    campaignProbes: campaignRecord(),
    securityControls: securityRecord(),
    prereg: { preregistration_digest: preregistrationDigest },
    runA, runB,
  });
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.status, 'PASS');
  assert.equal(result.campaign_probe_digest.length, 64);
  assert.equal(result.security_controls_digest.length, 64);
});

test('v6 evaluator refuses missing, duplicate, foreign, or incomplete probe evidence as NOT_RUN', () => {
  const input = {
    campaignProbes: campaignRecord(),
    securityControls: securityRecord(),
    prereg: { preregistration_digest: preregistrationDigest },
    runA, runB,
  };
  assert.equal(validateV6ProbeEvidence({ ...input, campaignProbes: null }).status, 'NOT_RUN');

  const duplicate = campaignRecord();
  duplicate.probes[1].probe = duplicate.probes[0].probe;
  assert.equal(validateV6ProbeEvidence({ ...input, campaignProbes: duplicate }).status, 'NOT_RUN');

  const foreign = campaignRecord();
  foreign.preregistration_digest = 'e'.repeat(64);
  assert.equal(validateV6ProbeEvidence({ ...input, campaignProbes: foreign }).status, 'NOT_RUN');

  const missingCounter = securityRecord();
  delete missingCounter.hardGates.counters[RESEARCH_HARD_GATE_COUNTERS[0]];
  assert.equal(validateV6ProbeEvidence({ ...input, securityControls: missingCounter }).status, 'NOT_RUN');

  const wrongTree = securityRecord();
  wrongTree.base.tree_sha = 'f'.repeat(40);
  assert.equal(validateV6ProbeEvidence({ ...input, securityControls: wrongTree }).status, 'NOT_RUN');
});

test('v6 evaluator reports a failed held-probe assertion and never converts it to PASS', () => {
  const probes = campaignRecord();
  probes.probes[3].held = false;
  const result = validateV6ProbeEvidence({
    campaignProbes: probes,
    securityControls: securityRecord(),
    prereg: { preregistration_digest: preregistrationDigest },
    runA, runB,
  });
  assert.notEqual(result.status, 'PASS');
});

test('campaign probe accepts only an in-force preregistration named by the corpus manifest', () => {
  const prereg = {
    rule: 's2-008-prereg-v6',
    preregistration_id: 'xpr-s2-008c-06',
    preregistration_digest: preregistrationDigest,
    approval: { status: 'APPROVED', in_force: true },
  };
  const manifest = { preregistration: {
    file: 'preregistration.v6.in-force.json', status: 'IN_FORCE',
    preregistration_digest: preregistrationDigest,
  } };
  assert.equal(validateProbePreregistration({ prereg, manifest }).ok, true);
  assert.notEqual(validateProbePreregistration({ prereg: { ...prereg, approval: { ...prereg.approval, in_force: false } }, manifest }).ok, true);
  assert.notEqual(validateProbePreregistration({ prereg, manifest: { preregistration: { ...manifest.preregistration, preregistration_digest: 'e'.repeat(64) } } }).ok, true);
});

test('explicit v6 preregistration path is canonical and reaches both crash and restart child argv', () => {
  const root = '/tmp/veritas-probe-root';
  const selected = resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v6.in-force.json', root);
  assert.equal(selected, root + '/corpus/s2-008-campaign/preregistration.v6.in-force.json');
  assert.throws(() => resolveProbePreregistrationPath('../../etc/passwd', root), /PROBE_PREREG_PATH_INVALID/);
  assert.deepEqual(childInvocationArgs('crash', { preregPath: selected }), [
    'scripts/s2-008-campaign-probes.mjs', '--child', 'crash', '--prereg', selected,
  ]);
  assert.deepEqual(childInvocationArgs('restart', { preregPath: selected, stateFile: '/tmp/state.json', resultOut: '/tmp/result.json' }), [
    'scripts/s2-008-campaign-probes.mjs', '--child', 'restart',
    '--state', '/tmp/state.json', '--result-out', '/tmp/result.json', '--prereg', selected,
  ]);
});
