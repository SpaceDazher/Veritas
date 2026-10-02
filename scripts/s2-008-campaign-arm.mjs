// S2-008 REAL CAMPAIGN — the program that runs INSIDE the isolation profile.
//
// This file is COPIED into the derived executor image and executed by the
// container, not by the host process. It is the real installed executor doing
// the real measurement work: it reads the BLIND holdout input (case ids and
// subject lines, no labels), predicts a label per arm, and draws the seeded
// bootstrap it is asked for.
//
// WHY IT IS BLIND, AND WHY THAT MATTERS
//   A predictor that could read the label it is scored against is not a
//   predictor. The host never passes `label` into this program: the input file
//   is `cases/holdout.blind.json`, whose bytes are sealed by its own digest, and
//   this program refuses an input that carries a `label` member at all
//   (`BLIND_INPUT_CARRIES_LABEL`). The label comparison happens afterwards, on
//   the host, inside the one-shot sealed open.
//
// THE SEED IS REAL AND IT IS HERE
//   The bootstrap draw happens in THIS process, from the preregistered seed, so
//   a seed is a stochastic step performed by the real executor rather than a
//   number the host wrote down. What comes back is the per-case DRAW COUNT
//   vector over `samples` resamples of the n cases, which is a compact and
//   exact summary of the resample multiset: from it the host reconstructs the
//   exact distribution of the resampled agreement sum by a Poisson-binomial
//   recurrence, so no 2000x126 index array has to be committed.
//
//   The draw is a deterministic PRNG of this file's own, seeded by the
//   preregistered seed, so the same seed reproduces the same counts on any host.
//
//   node <this file> <input.json> <out.json> <arm_id> <seed> <samples>

import fs from 'node:fs';

const PREDICTORS = Object.freeze({
  'arm-scope-present': (subject) => (/^[a-z]+(\([^)]*\))?!?:/.test(subject) ? 'MAJOR' : 'MINOR'),
  'arm-type-feat-fix': (subject) => (/^(feat|fix)(\([^)]*\))?!?:/.test(subject) ? 'MAJOR' : 'MINOR'),
  'arm-type-chore': (subject) => (/^chore(\([^)]*\))?!?:/.test(subject) ? 'MINOR' : 'MAJOR'),
});

/** mulberry32 — a small, fully specified PRNG. Its whole job is to be a
 *  function of the seed with no host state, so the same seed is the same draw
 *  on any machine. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function main(argv) {
  const [inputPath, outPath, armId, seedText, samplesText] = argv;
  if (!inputPath || !outPath || !armId || seedText === undefined || samplesText === undefined) {
    process.stderr.write('usage: arm <input.json> <out.json> <arm_id> <seed> <samples>\n');
    return 2;
  }
  const seed = Number(seedText);
  const samples = Number(samplesText);
  const predict = PREDICTORS[armId];
  if (typeof predict !== 'function') {
    process.stderr.write(`unknown arm ${armId}\n`);
    return 2;
  }
  if (!Number.isInteger(seed) || seed < 0 || !Number.isInteger(samples) || samples < 1) {
    process.stderr.write(`seed and samples must be non-negative integers, got ${seedText} ${samplesText}\n`);
    return 2;
  }

  const rows = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  if (!Array.isArray(rows) || rows.length === 0) {
    process.stderr.write('BLIND_INPUT_EMPTY\n');
    return 3;
  }
  // The blindness guard. If a label ever reaches the predictor, the run is void.
  const leaking = rows.findIndex((row) => Object.hasOwn(row ?? {}, 'label'));
  if (leaking >= 0) {
    process.stderr.write(`BLIND_INPUT_CARRIES_LABEL:row=${String(leaking)}\n`);
    return 4;
  }

  const predictions = rows.map((row) => ({ case_id: row.case_id, predicted: predict(String(row.subject ?? '')) }));

  // The predictor does NOT resample. A bootstrap needs the agreement vector,
  // which is a function of the label, and this process must never see a label.
  // The resampling is a second, post-reveal program
  // (`scripts/s2-008-campaign-bootstrap.mjs`) launched on the agreement
  // vectors; an earlier attempt did it here and lost the resample
  // multiplicities, which is recorded in the aborted run.

  const out = {
    kind: 's2-008-campaign-adapter-predict/1',
    arm_id: armId,
    seed,
    n_cases: rows.length,
    predictions,
    // What the container can say about itself. `node_version` is the genuinely
    // installed runtime's own report, not a constant copied from a record.
    container: {
      node_version: process.version,
      pid: process.pid,
      argv_tail: [armId, String(seed)],
      cwd: process.cwd(),
      // The predictor ran with no label and no network; the absence of a
      // label is proved above, not claimed.
      labels_seen: false,
    },
  };
  fs.writeFileSync(outPath, JSON.stringify(out));
  // The container's stdout, chunked. A single 65 KB line is truncated at
  // exactly 65536 characters somewhere between the process and this host, and
  // a truncated payload parses as a corrupt one rather than as a short read —
  // so the payload is emitted as numbered 16 KB chunks and reassembled here.
  process.stdout.write(`ADAPTER_OK arm=${armId} seed=${seed} n=${rows.length} predictions=${predictions.length} pid=${process.pid} node=${process.version}\n`);
  const payload = Buffer.from(JSON.stringify(out), 'utf8').toString('base64');
  const CHUNK = 16384;
  const chunks = Math.ceil(payload.length / CHUNK);
  for (let index = 0; index < chunks; index += 1) {
    process.stdout.write(`ADAPTER_JSON ${index + 1}/${chunks} ${payload.slice(index * CHUNK, (index + 1) * CHUNK)}\n`);
  }
  process.stdout.write(`ADAPTER_JSON_END ${payload.length}\n`);
  return 0;
}

process.exit(main(process.argv.slice(2)));
