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
const TAG = 'localhost/veritas-s2-008-model:v4';
const ENV = { PATH: '/tmp/bin:/usr/bin:/bin', XDG_RUNTIME_DIR: '/tmp/xdg-rt', TMPDIR: '/tmp', HOME: '/home/daniil' };

/**
 * THE COMMITMENT THE SIGNED DOCUMENT MAY CARRY, AND WHY IT IS NOT THE SAME
 * DIGEST AS THE ONE IN THE PIN FILE.
 *
 * The pin file and the preregistration want opposite things from one build, and
 * conflating them is what made this a cycle in the first place.
 *
 *   * `source_digest` covers EVERY staged byte, preregistration included. It
 *     answers "what was this image built from", and it lives in
 *     `model-image-pin-v4.json` — a file nothing is signed against.
 *   * `content_commitment` covers the same build with the preregistration
 *     REMOVED from the set. It answers "is the program inside this image the one
 *     that was signed for", and it is the only one of the two that may appear
 *     inside the signed body.
 *
 * The reason is a direction, not a preference. The recipe COPYs the preregistration
 * into the image, so the image digest is a function of the document's bytes; a
 * document carrying the image digest would be a document whose own bytes depend
 * on a field inside itself, and no fixed point of sha256 is findable. Excluding
 * the document from the set it commits to leaves exactly one arrow —
 * preregistration -> image — and the signature still binds the program, the
 * corpus, the base and the executor, which is everything the run actually
 * executes.
 *
 * Measured that the dependency is real, not hypothetical: one changed byte inside
 * a COPY moves both the image Id and its Digest under `--timestamp 0`. See
 * Stage 2/.bb/chats/thr_hj2st7xwcz/artifacts/c2-pin-cycle.txt.
 */
export const COMMITMENT_EXCLUDES = Object.freeze(['prereg']);

/**
 * The commitment digest, as a pure function of a recorded `sources` object.
 *
 * Both the build and the verifier go through this one function. If they each
 * assembled the set themselves, a later edit could leave the build committing to
 * the preregistration while the verifier still reported that it does not — and
 * the check that is supposed to prevent the cycle would be the thing that broke.
 */
export function contentCommitmentOf(sources) {
  const committed = { ...sources };
  for (const key of COMMITMENT_EXCLUDES) delete committed[key];
  return Object.freeze({
    digest: canonicalDigest(committed),
    covers: Object.freeze(Object.keys(committed).sort()),
  });
}

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
      // The bridge the model reaches the network THROUGH. It is in the image rather
      // than bind-mounted because the profile mounts exactly one socket and no
      // repository path, and because a program that can change between build and
      // run is not a program a digest can commit to.
      'scripts/s2-008-egress-bridge.mjs',
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
      bridge: sha(path.join(ROOT, 'scripts/s2-008-egress-bridge.mjs')),
      canonical_json: sha(path.join(ROOT, 'src/lib/verifier/canonical-json.mjs')),
      blind: sha(path.join(ROOT, 'corpus/s2-008-campaign/cases/holdout.blind.json')),
      prereg: sha(path.join(ROOT, 'corpus/s2-008-campaign/preregistration.v3.in-force.json')),
      pi_bundle: sha(path.join(PACKAGE, 'dist/bundle/cli.js')),
      pi_shrinkwrap: sha(path.join(PACKAGE, 'npm-shrinkwrap.json')),
      recipe: sha(file),
    };
    // The two digests are computed from the SAME object, so they cannot drift
    // apart by being built at different moments from different state.
    const commitment = contentCommitmentOf(sources);
    return {
      imageId: normalizeDigest(id),
      digest: normalizeDigest(digest),
      architecture,
      source_digest: canonicalDigest(sources),
      content_commitment: commitment.digest,
      content_commitment_covers: commitment.covers,
      sources,
    };
  } finally {
    fs.rmSync(context, { recursive: true, force: true });
  }
}

export function verifyModelPin() {
  const first = buildModelImage();
  const second = buildModelImage();
  return {
    first,
    second,
    identical: first.imageId === second.imageId && first.digest === second.digest,
    context_digest_stable: first.source_digest === second.source_digest,
    // A commitment that moved between two builds of identical content would be a
    // pin that cannot be signed against, so it is checked in the same breath.
    content_commitment_stable: first.content_commitment === second.content_commitment,
    // A commitment that still covered the preregistration would be the cycle this
    // split exists to break. Asserted against the RECORDED covers list, not
    // against the constant: the constant is what the build reads, so checking it
    // would only prove the constant equals itself.
    commitment_excludes_preregistration: !first.content_commitment_covers.includes('prereg')
      && first.content_commitment_covers.join(',') === second.content_commitment_covers.join(','),
  };
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
  const writePin = process.argv.includes('--write-pin');
  const result = process.argv.includes('--verify-pin') || writePin
    ? verifyModelPin()
    : process.argv.includes('--dry-run') ? dryRunModelInImage(buildModelImage()) : buildModelImage();
  if (writePin) {
    // The pin file is WRITTEN BY THE BUILD, never typed. A hand-written pin is
    // the one thing this whole module exists to make impossible, and the cheapest
    // way to keep that true is for the number to have no path to the file except
    // through the two builds that produced it.
    if (result.identical !== true || result.content_commitment_stable !== true
      || result.commitment_excludes_preregistration !== true) {
      process.stderr.write(`MODEL_PIN_NOT_WRITEABLE:${JSON.stringify({
        identical: result.identical,
        content_commitment_stable: result.content_commitment_stable,
        commitment_excludes_preregistration: result.commitment_excludes_preregistration,
      })}\n`);
      process.exitCode = 1;
    } else {
      const target = path.join(ROOT, 'evidence/s2-008-campaign/model-image-pin-v4.json');
      fs.writeFileSync(target, `${JSON.stringify({
        schema: 's2-008-model-image-pin/4',
        image_tag: TAG,
        base_image: BASE_IMAGE,
        // What the SIGNED body may carry, and what it deliberately does not. Kept
        // next to the number so a reader never has to guess which digest is which.
        commitment: {
          field: 'executor.model_image.content_commitment',
          algorithm: 'sha256 over canonical JSON of the covered sources',
          covers: result.first.content_commitment_covers,
          excludes: [...COMMITMENT_EXCLUDES],
          why_excluded: 'the signed body is COPYed into this image, so a commitment covering it would be a digest of a document containing that digest; the direction is preregistration -> image only',
        },
        first: result.first,
        second: result.second,
        identical: result.identical,
        context_digest_stable: result.context_digest_stable,
        content_commitment_stable: result.content_commitment_stable,
        commitment_excludes_preregistration: result.commitment_excludes_preregistration,
      }, null, 2)}\n`);
      process.stdout.write(`${JSON.stringify({ written: target, identical: result.identical, content_commitment: result.first.content_commitment }, null, 2)}\n`);
    }
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
  if (result.identical === false || result.context_digest_stable === false) process.exitCode = 1;
}
