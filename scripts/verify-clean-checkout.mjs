import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync, spawnSync} from 'node:child_process';
import {gitText} from './git-client.mjs';

const root = process.cwd();
const git = (...args) => gitText(root, args);
const sourceCommit = git('rev-parse', 'HEAD');
const sourceTree = git('rev-parse', 'HEAD^{tree}');
const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-clean-checkout-'));
const archivePath = path.join(temporaryRoot, 'source.tar');
const checkoutPath = path.join(temporaryRoot, 'checkout');
fs.mkdirSync(checkoutPath, {recursive: true});
const commands = [];
// On Windows npm is npm.cmd and spawnSync without a shell cannot execute it.
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const run = (id, command, args, options = {}) => {
  let result;
  try {
    // Node >= 18.20 refuses to spawn .cmd shims (npm) without a shell; on
    // Windows every command is therefore routed through cmd.exe.
    const usesShell = process.platform === 'win32' && command === NPM;
    result = spawnSync(usesShell ? 'cmd.exe' : command,
      usesShell ? ['/d', '/s', '/c', NPM, ...args] : args,
      {
      cwd: checkoutPath,
      encoding: 'utf8',
      maxBuffer: 30 * 1024 * 1024,
      env: {...process.env, ...options.env},
    });
  } catch (error) {
    const record = {id, command: [command, ...args].join(' '), exitCode: null, status: 'NOT_RUN_SANDBOX', reason: error.message};
    commands.push(record);
    return record;
  }
  const record = {id, command: [command, ...args].join(' '), exitCode: result.status ?? 1, status: (result.status ?? 1) === 0 ? 'PASS' : 'FAIL'};
  const outputTail = ((result.stderr ?? '') + '\n' + (result.stdout ?? '')).trim();
  if (record.status === 'FAIL') {
    record.reason = outputTail.slice(-1200) || 'no output captured';
  }
  commands.push(record);
  return record;
};
try {
  let archiveOk = false;
  try {
    execFileSync('git', ['archive', 'HEAD', '--format=tar', `--output=${archivePath}`], {cwd: root});
    // Relative paths inside temporaryRoot: on Windows GNU tar mangles
    // drive-letter paths (C:\...) as remote hostnames even with
    // --force-local, so tar must never see an absolute path here.
    execFileSync('tar', ['-xf', 'source.tar', '-C', 'checkout'], {cwd: temporaryRoot});
    archiveOk = true;
  } catch (error) {
    commands.push({id: 'archive', command: 'git archive HEAD', exitCode: null, status: 'NOT_RUN_SANDBOX', reason: error.message});
  }
  if (archiveOk) {
    commands.push({id: 'archive', command: 'git archive HEAD', exitCode: 0, status: 'PASS'});
  }
  const cachePath = path.join(temporaryRoot, 'npm-cache');
  fs.mkdirSync(cachePath, {recursive: true});
  // The extracted archive has no .git: git-dependent scripts MUST receive
  // the inventory/commit fallbacks, otherwise they fail closed by design.
  const npmEnv = {
    ...process.env,
    npm_config_cache: cachePath,
    VERITAS_GIT_INVENTORY: git('ls-files'),
    VERITAS_SOURCE_COMMIT: sourceCommit,
    VERITAS_SOURCE_TREE: sourceTree,
    // NOTE: DATABASE_URL is deliberately NOT set here. Its presence changes
    // synthetic-smoke evidence bytes; the build step receives its own
    // compile-time placeholder below.
  };
  // No user:pass@ pair: the credential-shaped form would trip the
  // public-artifacts scan; a passwordless URL is enough for compilation
  // (nothing connects at build time).
  const buildEnv = {
    ...npmEnv,
    DATABASE_URL: 'postgresql://build-placeholder@127.0.0.1:5432/build_placeholder',
  };
  const archiveReady = commands.find((command) => command.id === 'archive')?.status === 'PASS';
  if (archiveReady) {
    run('npm-ci', NPM, ['ci'], {env: npmEnv});
    run('contracts', 'node', ['scripts/validate-contracts.mjs'], {env: npmEnv});
    run('synthetic-smoke', 'node', ['scripts/synthetic-smoke.mjs'], {env: npmEnv});
    run('inventory', 'node', ['scripts/check-inventory.mjs'], {env: npmEnv});
    run('public-artifacts', 'node', ['scripts/check-public-artifacts.mjs'], {env: npmEnv});
    run('typecheck', NPM, ['run', 'typecheck'], {env: npmEnv});
    run('build', NPM, ['run', 'build'], {env: buildEnv});
    run('runtime-audit', NPM, ['audit', '--omit=dev', '--json'], {env: npmEnv});
    run('tooling-audit', NPM, ['audit', '--json'], {env: npmEnv});
    if (fs.existsSync(path.join(checkoutPath, 'evidence/root-manifest.json'))) {
      run('root-manifest', 'node', ['scripts/generate-manifests.mjs', '--check'], {env: npmEnv});
    } else {
      commands.push({id: 'root-manifest', command: 'node scripts/generate-manifests.mjs --check', exitCode: null, status: 'NOT_RUN'});
    }
  } else {
    for (const id of ['npm-ci', 'contracts', 'synthetic-smoke', 'inventory', 'public-artifacts', 'typecheck', 'build', 'runtime-audit', 'tooling-audit', 'root-manifest']) {
      commands.push({id, command: id === 'root-manifest' ? 'node scripts/generate-manifests.mjs --check' : id, exitCode: null, status: 'NOT_RUN_SANDBOX', reason: 'clean archive prerequisite was blocked by the sandbox'});
    }
  }
  commands.push({id: 'database-workspace-smoke', command: 'node scripts/smoke.mjs', exitCode: null, status: process.env.DATABASE_URL ? 'NOT_RUN_REQUIRES_SERVER' : 'NOT_RUN_DATABASE_URL_ABSENT'});
} finally {
  fs.rmSync(temporaryRoot, {recursive: true, force: true});
}
const required = commands.filter((command) => !['tooling-audit', 'database-workspace-smoke'].includes(command.id) && command.status !== 'NOT_RUN');
const passed = required.every((command) => command.exitCode === 0);
const report = {
  schemaVersion: 1,
  method: 'git archive HEAD into an empty temporary directory; npm ci uses an isolated cache and node_modules',
  sourceCommit,
  sourceTree,
  exitCode: passed ? 0 : 1,
  passed,
  commands,
  databaseWorkspaceSmoke: 'NOT_RUN; no dedicated PostgreSQL/server grant was used',
  scope: 'Independent clean-checkout verification; no shared node_modules and no private source or pilot execution',
};
fs.writeFileSync(path.join(root, 'evidence/clean-checkout.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
process.exit(report.exitCode);
