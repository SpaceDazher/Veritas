// S2-008 REAL CAMPAIGN — the BOOTSTRAP, in the container.
//
// WHY THIS IS A SECOND PROGRAM AND NOT PART OF THE PREDICTOR
//   The predictor must never see a label. The bootstrap needs the agreement
//   vector, which is a per-case 0/1 derived from a label and a prediction. So
//   the two live in two processes: the predictor runs blind and answers first,
//   the evaluator opens the holdout once at the decision point, and only then is
//   this program launched on the agreement vectors. It never predicted anything,
//   so handing it the agreement costs the experiment nothing.
//
//   An earlier attempt did the resampling INSIDE the blind process and returned
//   the resample composition. That was wrong, and provably so: a membership
//   bitmask collapses multiplicity, so a case drawn three times contributed
//   once, and a bootstrap of 115 agreeing cases out of 126 came back centred at
//   0.578. Here every resample is carried as its full multiplicity vector, so
//   the resample mean is the mean of the data it resampled.
//
// WHAT COMES BACK
//   Per (arm, seed): the exact percentile interval, the resample mean, the
//   extremes, and the sha256 of the full sorted rate vector — so the summary is
//   checkable against a re-run without committing 2000 numbers per arm.
//
//   node <this file> <input.json> <out.json>

import fs from 'node:fs';
import { createHash } from 'node:crypto';

/** mulberry32 — a fully specified PRNG with no host state, so a seed is a seed
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
  const [inputPath, outPath] = argv;
  if (!inputPath || !outPath) {
    process.stderr.write('usage: bootstrap <input.json> <out.json>\n');
    return 2;
  }
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const { vectors, seeds, samples, confidence } = input;
  if (!Array.isArray(vectors) || vectors.length === 0) { process.stderr.write('BOOTSTRAP_NO_VECTORS\n'); return 3; }
  if (!Array.isArray(seeds) || seeds.length === 0) { process.stderr.write('BOOTSTRAP_NO_SEEDS\n'); return 3; }
  if (!Number.isInteger(samples) || samples < 1) { process.stderr.write('BOOTSTRAP_BAD_SAMPLES\n'); return 3; }
  if (typeof confidence !== 'number' || !(confidence > 0 && confidence < 1)) { process.stderr.write('BOOTSTRAP_BAD_CONFIDENCE\n'); return 3; }

  const results = [];
  for (const vector of vectors) {
    const agree = vector.agreement;
    if (!Array.isArray(agree) || agree.length === 0) { process.stderr.write(`BOOTSTRAP_VECTOR_EMPTY:${String(vector.arm_id)}\n`); return 3; }
    const n = agree.length;
    for (const seed of seeds) {
      const next = mulberry32(seed);
      const rates = new Float64Array(samples);
      // The resample is over MULTIPLICITY: `multiplicity[i]` is how many of the
      // n draws landed on case i, and the rate is the agreement over all n
      // draws divided by n. Duplicates count twice, which is the whole point of
      // a bootstrap and the thing the bitmask lost.
      const multiplicity = new Int32Array(n);
      for (let draw = 0; draw < samples; draw += 1) {
        multiplicity.fill(0);
        for (let pick = 0; pick < n; pick += 1) multiplicity[Math.floor(next() * n)] += 1;
        let sum = 0;
        for (let index = 0; index < n; index += 1) sum += agree[index] * multiplicity[index];
        rates[draw] = sum / n;
      }
      const sorted = Array.from(rates).sort((left, right) => left - right);
      const tail = (1 - confidence) / 2;
      // Nearest-rank empirical quantile: it never reports a rate the run did not
      // produce.
      const quantile = (q) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))];
      let mean = 0;
      for (const value of rates) mean += value;
      mean /= samples;
      const observed = agree.reduce((sum, value) => sum + value, 0) / n;
      results.push({
        arm_id: vector.arm_id,
        trial_id: vector.trial_id,
        seed,
        samples,
        n,
        observed_rate: observed,
        resample_mean: mean,
        lower: quantile(tail),
        upper: quantile(1 - tail),
        min: sorted[0],
        max: sorted[sorted.length - 1],
        confidence,
        method: 'PERCENTILE_BOOTSTRAP_WITH_MULTIPLICITY',
        sorted_rates_sha256: createHash('sha256').update(new Float64Array(sorted).buffer).digest('hex'),
        // The mean of a bootstrap of the data converges on the data's own mean.
        // If these two ever diverge by more than the sampling error, the
        // resampling is wrong, and the run says so instead of publishing an
        // interval that describes nothing.
        mean_matches_observed: Math.abs(mean - observed) < 0.05,
      });
    }
  }

  const out = {
    kind: 's2-008-campaign-bootstrap-output/1',
    samples,
    confidence,
    results,
    container: { node_version: process.version, pid: process.pid },
  };
  fs.writeFileSync(outPath, JSON.stringify(out));
  process.stdout.write(`BOOTSTRAP_OK vectors=${vectors.length} seeds=${seeds.length} samples=${samples} pid=${process.pid} node=${process.version}\n`);
  process.stdout.write(`ADAPTER_JSON ${Buffer.from(JSON.stringify(out), 'utf8').toString('base64')}\n`);
  process.stdout.write('ADAPTER_JSON_END 0\n');
  return 0;
}

process.exit(main(process.argv.slice(2)));
