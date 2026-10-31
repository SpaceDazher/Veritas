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
import { assertV6ModelTimeoutPolicy } from './s2-008-campaign-v6-timeout.mjs';
import { assertV14ModelTimeoutPolicy } from './s2-008-campaign-v14-pacing.mjs';
import { V13_MODEL_POLICY } from './s2-008-campaign-credential-env.mjs';
import { assertV15ModelCatalogFiles, V15_MODEL_POLICY } from './s2-008-campaign-v15-policy.mjs';
import { assertV16ModelCatalogFiles, V16_MODEL_POLICY } from './s2-008-campaign-v16-policy.mjs';
import { assertV17ModelCatalogFiles, V17_MODEL_POLICY } from './s2-008-campaign-v17-policy.mjs';
import { assertV18ModelCatalogFiles, V18_MODEL_POLICY } from './s2-008-campaign-v18-policy.mjs';
import { V18_PRIOR_EXECUTION_FILES, V18_RECOVERY_EVIDENCE_DIGEST } from './s2-008-campaign-v18-approval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE = '/home/daniil/.local/lib/node_modules/@earendil-works/pi-coding-agent';
const V11_PI_PACKAGE_NAME = '@earendil-works/pi-coding-agent';
const V11_PI_PACKAGE_VERSION = '0.99.1';
export function modelImagePaths(version = 'v4', { preseal = false } = {}) {
  if (!['v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15', 'v16', 'v17', 'v18'].includes(version)) throw new Error('MODEL_IMAGE_VERSION_INVALID');
  if (preseal && !['v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15', 'v16', 'v17', 'v18'].includes(version)) throw new Error('MODEL_PRESEAL_VERSION_INVALID');
  const stagedVersion = preseal ? `v${Number(version.slice(1)) - 1}` : version;
  return Object.freeze({
    tag: `localhost/veritas-s2-008-model:${version}`,
    stagedPrereg: `corpus/s2-008-campaign/preregistration.${stagedVersion}.in-force.json`,
    pinFile: `evidence/s2-008-campaign/model-image-pin-${version}${preseal ? '-preseal' : ''}.json`,
    schema: `s2-008-model-image-pin/${version.slice(1)}`,
  });
}

/** Policy files copied into the container and source names committed by each image generation. */
export function modelImagePolicyInputs(schema) {
  const match = /^s2-008-model-image-pin\/(0|[1-9][0-9]*)$/.exec(String(schema));
  const version = match ? Number(match[1]) : NaN;
  if (![4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18].includes(version)) throw new Error('MODEL_IMAGE_VERSION_INVALID');
  const stageFiles = [
    ...(version >= 6 ? ['scripts/s2-008-campaign-v6-timeout.mjs'] : []),
    ...(version >= 7 ? ['scripts/s2-008-campaign-credential-env.mjs'] : []),
    ...(version >= 13 ? ['evidence/s2-008-campaign/provider-model-catalog-ling-v13.json'] : []),
    ...(version >= 14 ? ['scripts/s2-008-campaign-v14-pacing.mjs'] : []),
    ...(version === 15 ? ['scripts/s2-008-campaign-v15-policy.mjs', 'evidence/s2-008-campaign/provider-model-catalog-gemma-v15.json', 'evidence/s2-008-campaign/provider-model-endpoints-gemma-v15.json'] : []),
    ...(version === 16 ? ['scripts/s2-008-campaign-v16-policy.mjs', V16_MODEL_POLICY.catalog_response_file,
      V16_MODEL_POLICY.catalog_file, V16_MODEL_POLICY.endpoint_catalog_file] : []),
    ...(version === 17 ? ['scripts/s2-008-campaign-v17-policy.mjs', V17_MODEL_POLICY.catalog_response_file,
      V17_MODEL_POLICY.catalog_file, V17_MODEL_POLICY.endpoint_catalog_file] : []),
    ...(version === 18 ? ['scripts/s2-008-campaign-v18-policy.mjs', 'scripts/s2-008-campaign-v18-approval.mjs',
      'scripts/s2-008-campaign-seal-v18.mjs', ...V18_PRIOR_EXECUTION_FILES.map((row) => row[1]),
      V18_MODEL_POLICY.catalog_response_file, V18_MODEL_POLICY.catalog_file, V18_MODEL_POLICY.endpoint_catalog_file] : []),
  ];
  const sourceNames = [
    ...(version >= 6 ? ['pi_runtime_tree', 'timeout_policy'] : []),
    ...(version >= 7 ? ['credential_env_policy'] : []),
    ...(version >= 11 ? ['pi_package_manifest', 'pi_launcher'] : []),
    ...(version >= 12 ? ['pi_shrinkwrap'] : []),
    ...(version >= 13 ? ['provider_model_catalog'] : []),
    ...(version >= 14 ? ['model_call_pacing_policy'] : []),
    ...(version === 15 ? ['provider_model_endpoint_catalog', 'v15_model_policy'] : []),
    ...(version === 16 ? ['provider_model_catalog_response', 'provider_model_endpoint_catalog', 'v16_model_policy'] : []),
    ...(version === 17 ? ['provider_model_catalog_response', 'provider_model_endpoint_catalog', 'v17_model_policy'] : []),
    ...(version === 18 ? ['provider_model_catalog_response', 'provider_model_endpoint_catalog', 'v18_model_policy',
      'v18_approval_policy', 'v18_seal_policy', 'v18_predecessor_evidence'] : []),
  ].sort();
  return Object.freeze({ stageFiles: Object.freeze(stageFiles), sourceNames: Object.freeze(sourceNames) });
}
export function modelImageVersionFromArgv(argv = process.argv) {
  const versionArgs = argv.filter((arg) => typeof arg === 'string' && arg.startsWith('--v') && arg !== '--verify-pin');
  if (versionArgs.some((arg) => !/^--v\d+$/.test(arg))) throw new Error('MODEL_IMAGE_VERSION_INVALID');
  const values = versionArgs.map((arg) => arg.slice(2));
  const supported = new Set(['v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15', 'v16', 'v17', 'v18']);
  if (values.some((version) => !supported.has(version)) || new Set(values).size > 1) {
    throw new Error('MODEL_IMAGE_VERSION_INVALID');
  }
  return values[0] ?? 'v4';
}

export function parseModelImageCliArgs(argv = process.argv) {
  const version = modelImageVersionFromArgv(argv);
  let packageRoot;
  let seenPackageRoot = false;
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (typeof arg !== 'string') continue;
    if (arg.startsWith('--pi-package-dir=')) throw new Error('MODEL_PI_PACKAGE_SOURCE_INVALID');
    if (arg !== '--pi-package-dir') continue;
    if (seenPackageRoot || index + 1 >= argv.length || typeof argv[index + 1] !== 'string' ||
        argv[index + 1].startsWith('--')) throw new Error('MODEL_PI_PACKAGE_SOURCE_INVALID');
    seenPackageRoot = true;
    packageRoot = argv[index + 1];
    index += 1;
  }
  if (seenPackageRoot && (!['v11', 'v12', 'v13', 'v14', 'v15', 'v16', 'v17'].includes(version) || !path.isAbsolute(packageRoot))) {
    throw new Error('MODEL_PI_PACKAGE_SOURCE_INVALID');
  }
  if (['v11', 'v12', 'v13'].includes(version) && !seenPackageRoot) throw new Error('MODEL_PI_PACKAGE_SOURCE_REQUIRED');
  return Object.freeze({ version, preseal: argv.includes('--preseal'), packageRoot });
}

const MODEL_PATHS = modelImagePaths(modelImageVersionFromArgv(), { preseal: process.argv.includes('--preseal') });
const TAG = MODEL_PATHS.tag;
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

/** Digest every staged pi runtime entry, including nested chunks and link targets. */
export function digestRuntimeTree(root) {
  const entries = [];
  const visit = (directory, prefix = '') => {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const relative = prefix ? prefix + '/' + name : name;
      const stat = fs.lstatSync(absolute);
      const mode = stat.mode & 0o777;
      if (stat.isSymbolicLink()) {
        entries.push({ path: relative, type: 'symlink', mode, target: fs.readlinkSync(absolute) });
      } else if (stat.isDirectory()) {
        entries.push({ path: relative, type: 'directory', mode });
        visit(absolute, relative);
      } else if (stat.isFile()) {
        entries.push({ path: relative, type: 'file', mode, sha256: sha(absolute) });
      } else {
        throw new Error('PI_RUNTIME_TREE_ENTRY_UNSUPPORTED:' + relative);
      }
    }
  };
  visit(root);
  entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return canonicalDigest(entries);
}

function pathIsWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

export function assertPiPackageTreeContained(packageRoot) {
  let rootStat;
  let root;
  try {
    rootStat = fs.lstatSync(packageRoot);
    root = fs.realpathSync(packageRoot);
  } catch {
    throw new Error('PI_PACKAGE_SOURCE_INVALID');
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error('PI_PACKAGE_SOURCE_INVALID');

  const visit = (directory) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const entry = path.join(directory, name);
      const stat = fs.lstatSync(entry);
      if (stat.isSymbolicLink()) {
        const target = fs.readlinkSync(entry);
        if (path.isAbsolute(target)) throw new Error('PI_PACKAGE_SYMLINK_OUTSIDE_ROOT');
        const lexicalTarget = path.resolve(path.dirname(entry), target);
        if (!pathIsWithin(root, lexicalTarget)) throw new Error('PI_PACKAGE_SYMLINK_OUTSIDE_ROOT');
        let realTarget;
        try {
          realTarget = fs.realpathSync(entry);
        } catch {
          throw new Error('PI_PACKAGE_SYMLINK_INVALID');
        }
        if (!pathIsWithin(root, realTarget)) throw new Error('PI_PACKAGE_SYMLINK_OUTSIDE_ROOT');
      } else if (stat.isDirectory()) {
        visit(entry);
      } else if (!stat.isFile()) {
        throw new Error('PI_PACKAGE_TREE_ENTRY_UNSUPPORTED');
      }
    }
  };
  visit(root);
  return root;
}

function readJsonFileOrError(file, missingCode, invalidCode) {
  if (!fs.existsSync(file)) throw new Error(missingCode);
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    throw new Error(invalidCode);
  }
}

export function validateV11PiPackageContext(packageRoot, preregistration) {
  let contract = preregistration;
  if (Buffer.isBuffer(contract) || typeof contract === 'string') {
    try {
      contract = JSON.parse(Buffer.from(contract).toString('utf8'));
    } catch {
      throw new Error('V11_PI_PACKAGE_CONTRACT_INVALID');
    }
  }
  if (!['s2-008-prereg-v10', 's2-008-prereg-v11', 's2-008-prereg-v12', 's2-008-prereg-v13', 's2-008-prereg-v14', 's2-008-prereg-v15', 's2-008-prereg-v16', 's2-008-prereg-v17', 's2-008-prereg-v18'].includes(contract?.rule)) {
    throw new Error('V11_PI_PACKAGE_CONTRACT_INVALID');
  }
  const expectedName = contract.executor?.package;
  const unit = contract.budget_reservation?.unit_definition;
  const versionMatch = typeof unit === 'string' ? /\bpi\s+(\d+\.\d+\.\d+)\b/.exec(unit) : null;
  if (typeof expectedName !== 'string' || !versionMatch) throw new Error('V11_PI_PACKAGE_CONTRACT_INVALID');
  const expectedVersion = versionMatch[1];
  if (expectedName !== V11_PI_PACKAGE_NAME || expectedVersion !== V11_PI_PACKAGE_VERSION) {
    throw new Error('V11_PI_PACKAGE_CONTRACT_MISMATCH');
  }
  if (typeof packageRoot !== 'string' || !path.isAbsolute(packageRoot)) throw new Error('PI_PACKAGE_SOURCE_INVALID');

  const manifest = readJsonFileOrError(path.join(packageRoot, 'package.json'),
    'PI_PACKAGE_MANIFEST_MISSING', 'PI_PACKAGE_METADATA_INVALID');
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('PI_PACKAGE_METADATA_INVALID');
  if (manifest.name !== expectedName) throw new Error('V11_PI_PACKAGE_NAME_MISMATCH');
  if (manifest.version !== expectedVersion) throw new Error('V11_PI_PACKAGE_VERSION_MISMATCH');

  const shrinkwrap = readJsonFileOrError(path.join(packageRoot, 'npm-shrinkwrap.json'),
    'PI_PACKAGE_SHRINKWRAP_MISSING', 'PI_PACKAGE_SHRINKWRAP_INVALID');
  if (!shrinkwrap || typeof shrinkwrap !== 'object' || Array.isArray(shrinkwrap)) throw new Error('PI_PACKAGE_SHRINKWRAP_INVALID');
  if (!Number.isSafeInteger(shrinkwrap.lockfileVersion) || shrinkwrap.lockfileVersion < 1 ||
      shrinkwrap.name !== expectedName || shrinkwrap.version !== expectedVersion ||
      shrinkwrap.packages?.['']?.name !== expectedName ||
      shrinkwrap.packages?.['']?.version !== expectedVersion) {
    throw new Error('PI_PACKAGE_SHRINKWRAP_MISMATCH');
  }
  let bundleStat;
  try {
    bundleStat = fs.statSync(path.join(packageRoot, 'dist/bundle/cli.js'));
  } catch {
    throw new Error('PI_PACKAGE_BUNDLE_MISSING');
  }
  if (!bundleStat.isFile()) throw new Error('PI_PACKAGE_BUNDLE_MISSING');
  return Object.freeze({ name: expectedName, version: expectedVersion });
}

export function assertV13ModelCatalogFile(file) {
  if (sha(file) !== V13_MODEL_POLICY.catalog_sha256) throw new Error('V13_MODEL_CATALOG_ARTIFACT_INVALID');
  return true;
}

export function stageModelImageContext({
  repoRoot = ROOT, contextRoot, packageRoot, version = 'v4', preseal = false,
} = {}) {
  if (typeof contextRoot !== 'string' || !path.isAbsolute(contextRoot)) throw new Error('MODEL_CONTEXT_PATH_INVALID');
  const paths = modelImagePaths(version, { preseal });
  const policyInputs = modelImagePolicyInputs(paths.schema);
  const isV11 = version === 'v11' || version === 'v12' || version === 'v13' || version === 'v14' || version === 'v15' || version === 'v16' || version === 'v17' || version === 'v18';
  if (isV11 && (typeof packageRoot !== 'string' || !path.isAbsolute(packageRoot))) {
    throw new Error('MODEL_PI_PACKAGE_SOURCE_REQUIRED');
  }
  const runtimeSource = isV11 ? packageRoot : PACKAGE;
  if (version === 'v13' || version === 'v14') assertV13ModelCatalogFile(path.join(repoRoot, 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json'));
  if (version === 'v15') assertV15ModelCatalogFiles(path.join(repoRoot, V15_MODEL_POLICY.catalog_file), path.join(repoRoot, V15_MODEL_POLICY.endpoint_catalog_file));
  if (version === 'v16') assertV16ModelCatalogFiles(path.join(repoRoot, V16_MODEL_POLICY.catalog_file), path.join(repoRoot, V16_MODEL_POLICY.endpoint_catalog_file), path.join(repoRoot, V16_MODEL_POLICY.catalog_response_file));
  if (version === 'v17') assertV17ModelCatalogFiles(path.join(repoRoot, V17_MODEL_POLICY.catalog_file), path.join(repoRoot, V17_MODEL_POLICY.endpoint_catalog_file), path.join(repoRoot, V17_MODEL_POLICY.catalog_response_file));
  if (version === 'v18') assertV18ModelCatalogFiles(path.join(repoRoot, V18_MODEL_POLICY.catalog_file), path.join(repoRoot, V18_MODEL_POLICY.endpoint_catalog_file), path.join(repoRoot, V18_MODEL_POLICY.catalog_response_file));
  if (isV11) {
    assertPiPackageTreeContained(runtimeSource);
    const sourcePrereg = JSON.parse(fs.readFileSync(path.join(repoRoot, paths.stagedPrereg), 'utf8'));
    validateV11PiPackageContext(runtimeSource, sourcePrereg);
  }
  fs.mkdirSync(contextRoot, { recursive: true });
  if (fs.readdirSync(contextRoot).length !== 0) throw new Error('MODEL_CONTEXT_NOT_EMPTY');

  const target = path.join(contextRoot, 'opt/veritas');
  for (const name of [
    'scripts/s2-008-campaign-arm-model.mjs',
    'scripts/s2-008-egress-bridge.mjs',
    'src/lib/verifier/canonical-json.mjs',
    'corpus/s2-008-campaign/cases/holdout.blind.json',
    paths.stagedPrereg,
    ...policyInputs.stageFiles,
  ]) {
    const dest = path.join(target, name);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(repoRoot, name), dest);
  }

  if (isV11) assertPiPackageTreeContained(runtimeSource);
  const stagedPi = path.join(contextRoot, 'opt/pi');
  fs.cpSync(runtimeSource, stagedPi, {
    recursive: true,
    ...(isV11 ? { verbatimSymlinks: true } : {}),
  });
  if (version === 'v13' || version === 'v14') assertV13ModelCatalogFile(path.join(target, 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json'));
  if (version === 'v15') assertV15ModelCatalogFiles(path.join(target, V15_MODEL_POLICY.catalog_file), path.join(target, V15_MODEL_POLICY.endpoint_catalog_file));
  if (version === 'v16') assertV16ModelCatalogFiles(path.join(target, V16_MODEL_POLICY.catalog_file), path.join(target, V16_MODEL_POLICY.endpoint_catalog_file), path.join(target, V16_MODEL_POLICY.catalog_response_file));
  if (version === 'v17') assertV17ModelCatalogFiles(path.join(target, V17_MODEL_POLICY.catalog_file), path.join(target, V17_MODEL_POLICY.endpoint_catalog_file), path.join(target, V17_MODEL_POLICY.catalog_response_file));
  if (version === 'v18') assertV18ModelCatalogFiles(path.join(target, V18_MODEL_POLICY.catalog_file), path.join(target, V18_MODEL_POLICY.endpoint_catalog_file), path.join(target, V18_MODEL_POLICY.catalog_response_file));
  if (isV11) {
    assertPiPackageTreeContained(stagedPi);
    const stagedPrereg = JSON.parse(fs.readFileSync(path.join(target, paths.stagedPrereg), 'utf8'));
    validateV11PiPackageContext(stagedPi, stagedPrereg);
  }

  const bin = path.join(contextRoot, 'usr/local/bin');
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, 'pi'), '#!/bin/sh\nexec /usr/local/bin/node /opt/pi/dist/bundle/cli.js "$@"\n', { mode: 0o755 });
  const recipe = [
    'FROM ' + BASE_IMAGE,
    'COPY opt/veritas /opt/veritas',
    'COPY opt/pi /opt/pi',
    'COPY usr/local/bin/pi /usr/local/bin/pi',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(contextRoot, 'Containerfile'), recipe);
  return Object.freeze({ paths, policyInputs });
}

export function assertModelImageSourcesStable(before, after) {
  if (canonicalDigest(before) !== canonicalDigest(after)) throw new Error('MODEL_BUILD_CONTEXT_MUTATED');
  return true;
}

export function modelImageSourcesFromContext(contextRoot, { version = 'v4', preseal = false } = {}) {
  const paths = modelImagePaths(version, { preseal });
  const policyInputs = modelImagePolicyInputs(paths.schema);
  const veritas = path.join(contextRoot, 'opt/veritas');
  const sources = {
    arm: sha(path.join(veritas, 'scripts/s2-008-campaign-arm-model.mjs')),
    bridge: sha(path.join(veritas, 'scripts/s2-008-egress-bridge.mjs')),
    canonical_json: sha(path.join(veritas, 'src/lib/verifier/canonical-json.mjs')),
    blind: sha(path.join(veritas, 'corpus/s2-008-campaign/cases/holdout.blind.json')),
    prereg: sha(path.join(veritas, paths.stagedPrereg)),
    pi_bundle: sha(path.join(contextRoot, 'opt/pi/dist/bundle/cli.js')),
    pi_shrinkwrap: sha(path.join(contextRoot, 'opt/pi/npm-shrinkwrap.json')),
    recipe: sha(path.join(contextRoot, 'Containerfile')),
    ...(policyInputs.sourceNames.includes('timeout_policy') ? {
      timeout_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v6-timeout.mjs')),
    } : {}),
    ...(policyInputs.sourceNames.includes('credential_env_policy') ? {
      credential_env_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-credential-env.mjs')),
    } : {}),
    ...(policyInputs.sourceNames.includes('pi_runtime_tree') ? {
      pi_runtime_tree: digestRuntimeTree(path.join(contextRoot, 'opt/pi')),
    } : {}),
    ...(policyInputs.sourceNames.includes('pi_package_manifest') ? {
      pi_package_manifest: sha(path.join(contextRoot, 'opt/pi/package.json')),
    } : {}),
    ...(policyInputs.sourceNames.includes('pi_launcher') ? {
      pi_launcher: sha(path.join(contextRoot, 'usr/local/bin/pi')),
    } : {}),
    ...(policyInputs.sourceNames.includes('provider_model_catalog') ? {
      provider_model_catalog: sha(path.join(veritas, version === 'v18' ? V18_MODEL_POLICY.catalog_file : version === 'v17' ? V17_MODEL_POLICY.catalog_file : version === 'v16' ? V16_MODEL_POLICY.catalog_file : version === 'v15' ? V15_MODEL_POLICY.catalog_file : 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json')),
    } : {}),
    ...(policyInputs.sourceNames.includes('provider_model_endpoint_catalog') ? {
      provider_model_endpoint_catalog: sha(path.join(veritas, version === 'v18' ? V18_MODEL_POLICY.endpoint_catalog_file : version === 'v17' ? V17_MODEL_POLICY.endpoint_catalog_file : version === 'v16' ? V16_MODEL_POLICY.endpoint_catalog_file : V15_MODEL_POLICY.endpoint_catalog_file)),
    } : {}),
    ...(policyInputs.sourceNames.includes('v15_model_policy') ? {
      v15_model_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v15-policy.mjs')),
    } : {}),
    ...(policyInputs.sourceNames.includes('provider_model_catalog_response') ? {
      provider_model_catalog_response: sha(path.join(veritas, version === 'v18' ? V18_MODEL_POLICY.catalog_response_file : version === 'v17' ? V17_MODEL_POLICY.catalog_response_file : V16_MODEL_POLICY.catalog_response_file)),
    } : {}),
    ...(policyInputs.sourceNames.includes('v16_model_policy') ? {
      v16_model_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v16-policy.mjs')),
    } : {}),
    ...(policyInputs.sourceNames.includes('v17_model_policy') ? {
      v17_model_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v17-policy.mjs')),
    } : {}),
    ...(policyInputs.sourceNames.includes('v18_model_policy') ? {
      v18_model_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v18-policy.mjs')),
      v18_approval_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v18-approval.mjs')),
      v18_seal_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-seal-v18.mjs')),
      v18_predecessor_evidence: V18_RECOVERY_EVIDENCE_DIGEST,
    } : {}),
    ...(policyInputs.sourceNames.includes('model_call_pacing_policy') ? {
      model_call_pacing_policy: sha(path.join(veritas, 'scripts/s2-008-campaign-v14-pacing.mjs')),
    } : {}),
  };
  return Object.freeze(sources);
}

export function buildModelImage({
  version = modelImageVersionFromArgv(),
  preseal = process.argv.includes('--preseal'),
  packageRoot,
} = {}) {
  const paths = modelImagePaths(version, { preseal });
  if (version === 'v11' || version === 'v12' || version === 'v13' || version === 'v14' || version === 'v15' || version === 'v16' || version === 'v17' || version === 'v18') {
    if (typeof packageRoot !== 'string' || !path.isAbsolute(packageRoot)) {
      throw new Error('MODEL_PI_PACKAGE_SOURCE_REQUIRED');
    }
    assertPiPackageTreeContained(packageRoot);
    const sourcePrereg = JSON.parse(fs.readFileSync(path.join(ROOT, paths.stagedPrereg), 'utf8'));
    validateV11PiPackageContext(packageRoot, sourcePrereg);
  }
  if (version === 'v13') assertV13ModelCatalogFile(path.join(ROOT, 'evidence/s2-008-campaign/provider-model-catalog-ling-v13.json'));
  if (version === 'v15') assertV15ModelCatalogFiles();
  if (version === 'v16') assertV16ModelCatalogFiles();
  if (version === 'v17') assertV17ModelCatalogFiles();
  if (version === 'v18') assertV18ModelCatalogFiles();
  const context = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-model-image-'));
  try {
    stageModelImageContext({ contextRoot: context, packageRoot, version, preseal });
    const sources = modelImageSourcesFromContext(context, { version, preseal });
    const contextDigest = canonicalDigest(sources);
    podman(['build', '--no-cache', '--layers=false', '--timestamp', '0', '--pull=never', '-f',
      path.join(context, 'Containerfile'), '-t', paths.tag, context]);
    const postBuildSources = modelImageSourcesFromContext(context, { version, preseal });
    assertModelImageSourcesStable(sources, postBuildSources);
    const [id, digest, architecture] = podman([
      'inspect', '--format', '{{.Id}}|{{.Digest}}|{{.Architecture}}', paths.tag,
    ]).split('|');
    const commitment = contentCommitmentOf(sources);
    return {
      imageId: normalizeDigest(id),
      digest: normalizeDigest(digest),
      architecture,
      source_digest: contextDigest,
      content_commitment: commitment.digest,
      content_commitment_covers: commitment.covers,
      sources,
    };
  } finally {
    fs.rmSync(context, { recursive: true, force: true });
  }
}

export function verifyModelPin(options = {}) {
  const first = buildModelImage(options);
  const second = buildModelImage(options);
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

export function assertRecordedModelPin(rebuilt, recorded) {
  if (rebuilt?.identical !== true || rebuilt.context_digest_stable !== true ||
      rebuilt.content_commitment_stable !== true ||
      rebuilt.commitment_excludes_preregistration !== true ||
      recorded?.schema !== MODEL_PATHS.schema ||
      recorded.image_tag !== TAG || recorded.base_image !== BASE_IMAGE ||
      recorded.identical !== true || recorded.context_digest_stable !== true ||
      recorded.content_commitment_stable !== true ||
      recorded.commitment_excludes_preregistration !== true ||
      canonicalDigest({ first: rebuilt.first, second: rebuilt.second }) !==
        canonicalDigest({ first: recorded.first, second: recorded.second })) {
    throw new Error('MODEL_RECORDED_PIN_MISMATCH');
  }
  return rebuilt;
}

export function modelDryRunTimeoutMs(prereg) {
  if (prereg?.rule === 's2-008-prereg-v14' || prereg?.rule === 's2-008-prereg-v15' || prereg?.rule === 's2-008-prereg-v16' || prereg?.rule === 's2-008-prereg-v17' || prereg?.rule === 's2-008-prereg-v18') {
    return assertV14ModelTimeoutPolicy(prereg.executor?.model_launch_timeout).total_container_timeout_ms;
  }
  if (/^s2-008-prereg-v(?:[6-9]|1[0-3])$/.test(prereg?.rule ?? '')) {
    return assertV6ModelTimeoutPolicy(prereg.executor?.model_launch_timeout).total_container_timeout_ms;
  }
  return 180_000;
}

export function modelDryRunArgv(prereg, paths = MODEL_PATHS) {
  const argv = [
    '/usr/local/bin/node',
    '/opt/veritas/scripts/s2-008-campaign-arm-model.mjs',
    '/opt/veritas/corpus/s2-008-campaign/cases/holdout.blind.json',
    '/tmp/model-out.json',
    'arm-model-zai-glm53flash',
    `/opt/veritas/${paths.stagedPrereg}`,
    '20260926',
    '--dry-run',
  ];
  if (prereg?.rule === 's2-008-prereg-v14' || prereg?.rule === 's2-008-prereg-v15' || prereg?.rule === 's2-008-prereg-v16' || prereg?.rule === 's2-008-prereg-v17' || prereg?.rule === 's2-008-prereg-v18') {
    const policy = assertV14ModelTimeoutPolicy(prereg.executor?.model_launch_timeout);
    argv.push('--min-start-interval-ms', String(policy.min_start_interval_ms));
  }
  return argv;
}

export function dryRunModelInImage(pin) {
  const stagedPrereg = JSON.parse(fs.readFileSync(path.join(ROOT, MODEL_PATHS.stagedPrereg), 'utf8'));
  const timeoutMs = modelDryRunTimeoutMs(stagedPrereg);
  const invocation = buildInvocation(SANDBOX_ISOLATION_EXECUTOR, {
    image: pin.imageId,
    argv: modelDryRunArgv(stagedPrereg, MODEL_PATHS),
    timeoutMs,
    name: `s2-008-model-${MODEL_PATHS.schema.split('/').at(-1)}-dry-run`,
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
  const cli = parseModelImageCliArgs();
  const paths = modelImagePaths(cli.version, { preseal: cli.preseal });
  const writePin = process.argv.includes('--write-pin');
  const result = writePin
    ? verifyModelPin(cli)
    : process.argv.includes('--verify-pin')
      ? assertRecordedModelPin(
        verifyModelPin(cli),
        JSON.parse(fs.readFileSync(path.join(ROOT, paths.pinFile), 'utf8')),
      )
      : process.argv.includes('--dry-run') ? dryRunModelInImage(buildModelImage(cli)) : buildModelImage(cli);
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
      const target = path.join(ROOT, paths.pinFile);
      fs.writeFileSync(target, `${JSON.stringify({
        schema: paths.schema,
        image_tag: paths.tag,
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
