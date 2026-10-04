import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as image from '../../scripts/s2-008-campaign-model-image.mjs';
import { assertV11PresealPin } from '../../scripts/s2-008-campaign-v11-approval.mjs';
import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const PACKAGE_NAME = '@earendil-works/pi-coding-agent';
const PACKAGE_VERSION = '0.99.1';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function writeFile(root, relative, contents) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
  return target;
}

function preregistration() {
  return {
    rule: 's2-008-prereg-v10',
    executor: { package: PACKAGE_NAME },
    budget_reservation: { unit_definition: 'Usage from pi 0.99.1 final assistant messages.' },
  };
}

function makePackage(root, version = PACKAGE_VERSION, { shrinkwrap = true } = {}) {
  writeFile(root, 'package.json', JSON.stringify({ name: PACKAGE_NAME, version }));
  writeFile(root, 'dist/bundle/cli.js', 'pi-cli-bytes');
  if (shrinkwrap) {
    writeFile(root, 'npm-shrinkwrap.json', JSON.stringify({
      name: PACKAGE_NAME,
      version,
      lockfileVersion: 3,
      packages: { '': { name: PACKAGE_NAME, version } },
    }));
  }
  return root;
}

function makeRepository(root) {
  for (const name of [
    'scripts/s2-008-campaign-arm-model.mjs',
    'scripts/s2-008-egress-bridge.mjs',
    'src/lib/verifier/canonical-json.mjs',
    'corpus/s2-008-campaign/cases/holdout.blind.json',
    'scripts/s2-008-campaign-v6-timeout.mjs',
    'scripts/s2-008-campaign-credential-env.mjs',
  ]) writeFile(root, name, 'fixture:' + name);
  writeFile(root, 'corpus/s2-008-campaign/preregistration.v10.in-force.json', JSON.stringify(preregistration()));
  return root;
}

function v11Pin(baseBytes, extraSources = {}) {
  const sources = {
    arm: sha256('arm'),
    bridge: sha256('bridge'),
    canonical_json: sha256('canonical'),
    blind: sha256('blind'),
    prereg: sha256(baseBytes),
    pi_bundle: sha256('bundle'),
    pi_shrinkwrap: sha256('shrinkwrap'),
    recipe: sha256('recipe'),
    timeout_policy: sha256('timeout'),
    credential_env_policy: sha256('credential'),
    pi_runtime_tree: sha256('runtime'),
    ...extraSources,
  };
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]])));
  const build = {
    imageId: 'sha256:' + '1'.repeat(64),
    digest: 'sha256:' + '2'.repeat(64),
    source_digest: canonicalDigest(sources),
    content_commitment: commitment,
    content_commitment_covers: covers,
    sources,
  };
  return {
    schema: 's2-008-model-image-pin/11',
    identical: true,
    context_digest_stable: true,
    content_commitment_stable: true,
    commitment_excludes_preregistration: true,
    commitment: { covers, excludes: ['prereg'] },
    first: build,
    second: structuredClone(build),
  };
}

test('v11 adds package-manifest and launcher commitments without changing v10 pin inputs', () => {
  assert.deepEqual(image.modelImagePolicyInputs('s2-008-model-image-pin/10'), {
    stageFiles: [
      'scripts/s2-008-campaign-v6-timeout.mjs',
      'scripts/s2-008-campaign-credential-env.mjs',
    ],
    sourceNames: ['credential_env_policy', 'pi_runtime_tree', 'timeout_policy'],
  });
  assert.deepEqual(image.modelImagePolicyInputs('s2-008-model-image-pin/11'), {
    stageFiles: [
      'scripts/s2-008-campaign-v6-timeout.mjs',
      'scripts/s2-008-campaign-credential-env.mjs',
    ],
    sourceNames: [
      'credential_env_policy',
      'pi_launcher',
      'pi_package_manifest',
      'pi_runtime_tree',
      'timeout_policy',
    ],
  });
});

test('v11 preseal pins require explicit staged package and launcher hashes', () => {
  const baseBytes = Buffer.from('frozen v10 preregistration fixture');
  const incomplete = v11Pin(baseBytes);
  assert.throws(() => assertV11PresealPin({ pin: incomplete, baseBytes }), /V11_PRESEAL_PIN_INVALID/);
  const noShrinkwrap = v11Pin(baseBytes, {
    pi_package_manifest: sha256('package.json'),
    pi_launcher: sha256('usr/local/bin/pi'),
  });
  delete noShrinkwrap.first.sources.pi_shrinkwrap;
  delete noShrinkwrap.second.sources.pi_shrinkwrap;
  for (const build of [noShrinkwrap.first, noShrinkwrap.second]) {
    build.source_digest = canonicalDigest(build.sources);
    build.content_commitment_covers = Object.keys(build.sources).filter((name) => name !== 'prereg').sort();
    build.content_commitment = canonicalDigest(Object.fromEntries(build.content_commitment_covers.map((name) => [name, build.sources[name]])));
  }
  noShrinkwrap.commitment.covers = noShrinkwrap.first.content_commitment_covers;
  assert.throws(() => assertV11PresealPin({ pin: noShrinkwrap, baseBytes }), /V11_PRESEAL_PIN_INVALID/);
  const complete = v11Pin(baseBytes, {
    pi_package_manifest: sha256('package.json'),
    pi_launcher: sha256('usr/local/bin/pi'),
  });
  assert.equal(assertV11PresealPin({ pin: complete, baseBytes }).ok, true);
});

test('v11 package source requires matching signed package identity and a real shrinkwrap', () => {
  assert.equal(typeof image.validateV11PiPackageContext, 'function');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'v11-pi-package-'));
  try {
    const valid = makePackage(path.join(temp, 'valid'));
    assert.deepEqual(image.validateV11PiPackageContext(valid, preregistration()), {
      name: PACKAGE_NAME,
      version: PACKAGE_VERSION,
    });
    const wrongVersion = makePackage(path.join(temp, 'wrong-version'), '1.0.1');
    assert.throws(() => image.validateV11PiPackageContext(wrongVersion, preregistration()), /V11_PI_PACKAGE_VERSION_MISMATCH/);
    const wrongName = makePackage(path.join(temp, 'wrong-name'));
    writeFile(wrongName, 'package.json', JSON.stringify({ name: 'untrusted-package', version: PACKAGE_VERSION }));
    assert.throws(() => image.validateV11PiPackageContext(wrongName, preregistration()), /V11_PI_PACKAGE_NAME_MISMATCH/);
    const lockMismatch = makePackage(path.join(temp, 'lock-mismatch'));
    const lockPath = path.join(lockMismatch, 'npm-shrinkwrap.json');
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    lock.packages[''].version = '1.0.1';
    writeFile(lockMismatch, 'npm-shrinkwrap.json', JSON.stringify(lock));
    assert.throws(() => image.validateV11PiPackageContext(lockMismatch, preregistration()), /PI_PACKAGE_SHRINKWRAP_MISMATCH/);
    const missingLock = makePackage(path.join(temp, 'missing-lock'), PACKAGE_VERSION, { shrinkwrap: false });
    assert.throws(() => image.validateV11PiPackageContext(missingLock, preregistration()), /PI_PACKAGE_SHRINKWRAP_MISSING/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('v11 staged context preserves relative links and rejects links escaping the package root', () => {
  assert.equal(typeof image.stageModelImageContext, 'function');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'v11-pi-stage-'));
  try {
    const repo = makeRepository(path.join(temp, 'repo'));
    const packageRoot = makePackage(path.join(temp, 'package'));
    fs.symlinkSync('dist/bundle/cli.js', path.join(packageRoot, 'cli-alias'));
    const context = path.join(temp, 'context');
    image.stageModelImageContext({
      repoRoot: repo, contextRoot: context, packageRoot, version: 'v11', preseal: true,
    });
    assert.equal(fs.readlinkSync(path.join(context, 'opt/pi/cli-alias')), 'dist/bundle/cli.js');

    const escapedPackage = makePackage(path.join(temp, 'escaped'));
    fs.symlinkSync(path.join(temp, 'outside'), path.join(escapedPackage, 'escape'));
    assert.throws(() => image.stageModelImageContext({
      repoRoot: repo, contextRoot: path.join(temp, 'escaped-context'),
      packageRoot: escapedPackage, version: 'v11', preseal: true,
    }), /PI_PACKAGE_SYMLINK_OUTSIDE_ROOT/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('source digests come from the staged snapshot even if the host source changes later', () => {
  assert.equal(typeof image.stageModelImageContext, 'function');
  assert.equal(typeof image.modelImageSourcesFromContext, 'function');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'v11-model-snapshot-'));
  try {
    const repo = makeRepository(path.join(temp, 'repo'));
    const packageRoot = makePackage(path.join(temp, 'package'));
    const context = path.join(temp, 'context');
    image.stageModelImageContext({
      repoRoot: repo, contextRoot: context, packageRoot, version: 'v11', preseal: true,
    });
    const before = image.modelImageSourcesFromContext(context, { version: 'v11', preseal: true });
    writeFile(repo, 'scripts/s2-008-campaign-arm-model.mjs', 'mutated host bytes');
    const after = image.modelImageSourcesFromContext(context, { version: 'v11', preseal: true });
    assert.deepEqual(after, before);
    assert.equal(before.arm, sha256('fixture:scripts/s2-008-campaign-arm-model.mjs'));
    assert.equal(before.pi_package_manifest, sha256(fs.readFileSync(path.join(context, 'opt/pi/package.json'))));
    assert.equal(before.pi_launcher, sha256(fs.readFileSync(path.join(context, 'usr/local/bin/pi'))));
    assert.equal(before.pi_shrinkwrap, sha256(fs.readFileSync(path.join(context, 'opt/pi/npm-shrinkwrap.json'))));
    assert.match(before.pi_runtime_tree, /^[0-9a-f]{64}$/);
    writeFile(path.join(context, 'opt/veritas'), 'scripts/s2-008-campaign-arm-model.mjs', 'tampered staged bytes');
    const tampered = image.modelImageSourcesFromContext(context, { version: 'v11', preseal: true });
    assert.throws(() => image.assertModelImageSourcesStable(before, tampered), /MODEL_BUILD_CONTEXT_MUTATED/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('v11 CLI requires an explicit absolute package root and rejects duplicate or legacy use', () => {
  assert.equal(typeof image.parseModelImageCliArgs, 'function');
  assert.deepEqual(image.parseModelImageCliArgs([
    'node', 'builder', '--v11', '--preseal', '--pi-package-dir', '/tmp/pi-0.99.1',
  ]), { version: 'v11', preseal: true, packageRoot: '/tmp/pi-0.99.1' });
  assert.throws(() => image.parseModelImageCliArgs(['node', 'builder', '--v11']), /MODEL_PI_PACKAGE_SOURCE_REQUIRED/);
  assert.deepEqual(image.parseModelImageCliArgs(['node', 'builder']), {
    version: 'v4', preseal: false, packageRoot: undefined,
  });
  for (const argv of [
    ['node', 'builder', '--v11', '--pi-package-dir'],
    ['node', 'builder', '--v11', '--pi-package-dir', 'relative/path'],
    ['node', 'builder', '--v11', '--pi-package-dir', '/tmp/pi-a', '--pi-package-dir', '/tmp/pi-b'],
    ['node', 'builder', '--v10', '--pi-package-dir', '/tmp/pi'],
  ]) {
    assert.throws(() => image.parseModelImageCliArgs(argv), /MODEL_PI_PACKAGE_SOURCE_INVALID/);
  }
});

test('bad package identity and missing shrinkwrap fail in pure staging before build setup', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'v11-preflight-only-'));
  try {
    const repo = makeRepository(path.join(temp, 'repo'));
    const wrongVersion = makePackage(path.join(temp, 'wrong-version'), '1.0.1');
    const wrongContext = path.join(temp, 'wrong-context');
    assert.throws(() => image.stageModelImageContext({
      repoRoot: repo, contextRoot: wrongContext,
      packageRoot: wrongVersion, version: 'v11', preseal: true,
    }), /V11_PI_PACKAGE_VERSION_MISMATCH/);
    assert.equal(fs.existsSync(wrongContext), false);
    const missingLock = makePackage(path.join(temp, 'missing-lock'), PACKAGE_VERSION, { shrinkwrap: false });
    const missingLockContext = path.join(temp, 'missing-lock-context');
    assert.throws(() => image.stageModelImageContext({
      repoRoot: repo, contextRoot: missingLockContext,
      packageRoot: missingLock, version: 'v11', preseal: true,
    }), /PI_PACKAGE_SHRINKWRAP_MISSING/);
    assert.equal(fs.existsSync(missingLockContext), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('actual v11 builder CLI refuses a missing package source before dispatch', () => {
  const result = spawnSync(process.execPath, [
    'scripts/s2-008-campaign-model-image.mjs', '--v11', '--preseal',
  ], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /MODEL_PI_PACKAGE_SOURCE_REQUIRED/);
  assert.equal(result.stdout, '');
});
