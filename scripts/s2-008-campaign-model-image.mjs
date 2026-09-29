import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../src/lib/verifier/canonical-json.mjs';
import { BASE_IMAGE, normalizeDigest } from '../src/lib/isolation/image.mjs';
import { PODMAN_HOST, buildInvocation, executeIsolated } from '../src/lib/isolation/launch.mjs';
import { SANDBOX_ISOLATION_EXECUTOR } from '../src/lib/isolation/profile.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE = '/home/daniil/.local/lib/node_modules/@earendil-works/pi-coding-agent';
const TAG = 'localhost/veritas-s2-008-model:v3';
const ENV = { PATH: '/tmp/bin:/usr/bin:/bin', XDG_RUNTIME_DIR: '/tmp/xdg-rt', TMPDIR: '/tmp', HOME: '/home/daniil' };

function podman(args) {
  return execFileSync('podman', [...PODMAN_HOST.argvPrefix, ...args], {
    encoding: 'utf8', maxBuffer: 1 << 26, env: ENV,
  }).trim();
}
function sha(file) { return createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

export function buildModelImage() {
  const context = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-model-image-'));
  try {
    const target = path.join(context, 'opt/veritas');
    for (const name of [
      'scripts/s2-008-campaign-arm-model.mjs',
      'src/lib/verifier/canonical-json.mjs',
      'corpus/s2-008-campaign/cases/holdout.blind.json',
      'corpus/s2-008-campaign/preregistration.v3.in-force.json',
    ]) {
      const dest = path.join(target, name);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(ROOT, name), dest);
    }
    fs.cpSync(PACKAGE, path.join(context, 'opt/pi'), { recursive: true });
    const bin = path.join(context, 'usr/local/bin');
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, 'pi'), '#!/bin/sh\nexec /usr/local/bin/node /opt/pi/dist/bundle/cli.js "$@"\n', { mode: 0o755 });
    const recipe = [
      `FROM ${BASE_IMAGE}`,
      'COPY opt/veritas /opt/veritas',
      'COPY opt/pi /opt/pi',
      'COPY usr/local/bin/pi /usr/local/bin/pi',
      '',
    ].join('\n');
    const file = path.join(context, 'Containerfile');
    fs.writeFileSync(file, recipe);
    podman(['build', '--timestamp', '0', '--pull=never', '-f', file, '-t', TAG, context]);
    const [id, digest, architecture] = podman(['inspect', '--format', '{{.Id}}|{{.Digest}}|{{.Architecture}}', TAG]).split('|');
    const sources = {
      arm: sha(path.join(ROOT, 'scripts/s2-008-campaign-arm-model.mjs')),
      blind: sha(path.join(ROOT, 'corpus/s2-008-campaign/cases/holdout.blind.json')),
      prereg: sha(path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v3.in-force.json')),
      pi_bundle: sha(path.join(PACKAGE, 'dist/bundle/cli.js')),
      pi_shrinkwrap: sha(path.join(PACKAGE, 'npm-shrinkwrap.json')),
      recipe: sha(file),
    };
    return { imageId: normalizeDigest(id), digest: normalizeDigest(digest), architecture, source_digest: canonicalDigest(sources), sources };
  } finally {
    fs.rmSync(context, { recursive: true, force: true });
  }
}

export function verifyModelPin() {
  const first = buildModelImage();
  const second = buildModelImage();
  return { first, second, identical: first.imageId === second.imageId && first.digest === second.digest, context_digest_stable: first.source_digest === second.source_digest };
}

export function dryRunModelInImage(pin) {
  const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
    image: pin.imageId,
    argv: [
      '/usr/local/bin/node',
      '/opt/veritas/scripts/s2-008-campaign-arm-model.mjs',
      '/opt/veritas/corpus/s2-008-campaign/cases/holdout.blind.json',
      '/tmp/model-out.json',
      'arm-model-zai-glm53flash',
      '/opt/veritas/corpus/s2-008-campaign/preregistration.v3.in-force.json',
      '20260926',
      '--dry-run',
    ],
    timeoutMs: 180000,
    name: 's2-008-model-v3-dry-run',
  });
  const observation = executeIsolated(invocation, {
    env: { PATH: '/tmp/bin:/usr/bin:/bin', HOME: '/tmp', XDG_RUNTIME_DIR: '/tmp/xdg-rt', TMPDIR: '/tmp' },
  });
  if (observation.exitCode !== 0) {
    throw new Error(`MODEL_DRY_RUN_FAILED:exit=${String(observation.exitCode)}:${observation.stderr.slice(-500)}`);
  }
  const chunks = observation.stdout.split('\n').filter((line) => line.startsWith('ADAPTER_JSON '));
  const payload = chunks.map((line) => line.split(' ').slice(2).join(' ')).join('');
  const output = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  if (output.outcome_class !== 'DRY_RUN' || output.executor?.model_calls !== 0 ||
      output.budget?.spent_tokens !== 0 || output.predictions?.length !== 126) {
    throw new Error('MODEL_DRY_RUN_CONTRACT_FAILED');
  }
  return { outcome_class: output.outcome_class, model_calls: output.executor.model_calls, tokens: output.budget.spent_tokens, predictions: output.predictions.length, image: pin.imageId, exit_code: observation.exitCode, network: invocation.axes.network.policy };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const result = process.argv.includes('--verify-pin') ? verifyModelPin() : process.argv.includes('--dry-run') ? dryRunModelInImage(buildModelImage()) : buildModelImage();
  console.log(JSON.stringify(result, null, 2));
  if (result.identical === false || result.context_digest_stable === false) process.exitCode = 1;
}
