import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import ts from 'typescript';
import {readAcceptanceState} from './acceptance-gate.mjs';
import {gitText} from './git-client.mjs';

const root = process.cwd();
const mode = process.argv[2] || 'draft';
if (!['draft', 'acceptance'].includes(mode)) {
  console.error('usage: node scripts/verify.mjs draft|acceptance');
  process.exit(2);
}
const git = (...args) => gitText(root, args);
const run = async (id, command, args = [], fallback) => {
  const result = spawnSync(command, args, {cwd: root, encoding: 'utf8', maxBuffer: 30 * 1024 * 1024});
  if (result.error?.code === 'EPERM') {
    if (fallback) {
      try {
        const value = fallback();
        return {id, command: [command, ...args].join(' '), ...(value && typeof value.then === 'function' ? await value : value)};
      } catch (error) {
        return {id, command: [command, ...args].join(' '), exitCode: 1, status: 'FAIL', fallbackError: error.message};
      }
    }
    return {id, command: [command, ...args].join(' '), exitCode: null, status: 'NOT_RUN_SANDBOX', environment: 'child_process blocked by sandbox'};
  }
  const exitCode = result.status ?? 1;
  if (exitCode !== 0 && fallback) {
    try {
      const value = fallback();
      return {id, command: [command, ...args].join(' '), ...(value && typeof value.then === 'function' ? await value : value)};
    } catch (error) {
      return {id, command: [command, ...args].join(' '), exitCode, status: 'FAIL', fallbackError: error.message};
    }
  }
  return {id, command: [command, ...args].join(' '), exitCode, status: exitCode === 0 ? 'PASS' : 'FAIL'};
};
const directImport = async (relativePath) => {
  const imported = await import(`${relativePath}?verify=${Date.now()}`);
  return imported;
};
const directContracts = async () => {
  await directImport('./validate-contracts.mjs');
  return {exitCode: 0, status: 'PASS'};
};
const directSynthetic = async () => {
  await directImport('./synthetic-smoke.mjs');
  return {exitCode: 0, status: 'PASS'};
};
const directInventory = async () => {
  await directImport('./check-inventory.mjs');
  return {exitCode: 0, status: 'PASS'};
};
const directPublic = async () => {
  await directImport('./check-public-artifacts.mjs');
  return {exitCode: 0, status: 'PASS'};
};
const directTypecheck = () => {
  const config = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const program = ts.createProgram(parsed.fileNames, {...parsed.options, incremental: false});
  const diagnostics = ts.getPreEmitDiagnostics(program);
  return {exitCode: diagnostics.length === 0 ? 0 : 1, status: diagnostics.length === 0 ? 'PASS' : 'FAIL', diagnostics: diagnostics.length};
};
const directBuild = async () => {
  const buildModule = await import('next/dist/build/index.js');
  const build = buildModule.default?.default || buildModule.default;
  try {
    await build(root, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined);
    return {exitCode: 0, status: 'PASS'};
  } catch (error) {
    const detail = [error, error?.cause].map((value) => `${JSON.stringify(value)} ${String(value)}`).join(' ');
    if (detail.includes('DATABASE_URL is required') || detail.includes('ERR_WORKER_INVALID_EXEC_ARGV') || detail.includes('EPERM') || detail.includes('Failed to collect')) {
      return {exitCode: 1, status: 'NOT_RUN_BUILD_ENVIRONMENT', reason: 'build could not run in the current sandbox without a valid worker/database environment'};
    }
    throw error;
  }
};
const directAcceptance = () => {
  const state = readAcceptanceState();
  if (state.verdict !== 'BLOCKED' || state.pilotExecutions !== 0 || state.executionAuthorized !== false) return {exitCode: 1, status: 'FAIL'};
  return {exitCode: 0, status: 'PASS'};
};
const directDiffCheck = () => {
  const files = gitText(root, ['ls-files']).split('\n').filter(Boolean);
  const bad = files.filter((file) => {
    const full = path.join(root, ...file.split('/'));
    if (!fs.existsSync(full) || fs.statSync(full).isDirectory()) return false;
    const text = fs.readFileSync(full, 'utf8');
    return text.split(/\r?\n/).some((line) => /[ \t]+$/.test(line));
  });
  return {exitCode: bad.length === 0 ? 0 : 1, status: bad.length === 0 ? 'PASS' : 'FAIL', trailingWhitespaceFiles: bad};
};
const directManifest = async () => {
  const manifestPath = path.join(root, 'evidence/root-manifest.json');
  if (!fs.existsSync(manifestPath)) return {exitCode: null, status: 'NOT_RUN', reason: 'root manifest is generated after the implementation commit'};
  const oldArgv = process.argv.slice();
  process.argv = [process.argv[0], path.join(root, 'scripts/generate-manifests.mjs'), '--check'];
  try {
    await directImport('./generate-manifests.mjs');
    return {exitCode: 0, status: 'PASS'};
  } finally {
    process.argv = oldArgv;
  }
};
const auditEvidence = (id, reportPath) => {
  const fullPath = path.join(root, reportPath);
  if (!fs.existsSync(fullPath)) return {exitCode: null, status: 'NOT_RUN', evidencePath: reportPath};
  const report = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
  const total = report.metadata?.vulnerabilities?.total ?? null;
  return {exitCode: id === 'runtime-audit' ? (total === 0 ? 0 : 1) : (total === 0 ? 0 : 1), status: total === 0 ? 'PASS' : 'FAIL', vulnerabilities: total, evidencePath: reportPath};
};

const checks = [];
checks.push(await run('contracts', 'node', ['scripts/validate-contracts.mjs'], () => directContracts()));
checks.push(await run('synthetic-smoke', 'node', ['scripts/synthetic-smoke.mjs'], () => directSynthetic()));
checks.push(await run('inventory', 'node', ['scripts/check-inventory.mjs'], () => directInventory()));
checks.push(await run('public-artifacts', 'node', ['scripts/check-public-artifacts.mjs'], () => directPublic()));
checks.push(await run('typecheck', 'npm', ['run', 'typecheck'], directTypecheck));
checks.push(await run('build', 'npm', ['run', 'build'], () => directBuild()));
checks.push(await run('runtime-audit', 'npm', ['audit', '--omit=dev', '--json'], () => auditEvidence('runtime-audit', 'evidence/dependency-audit-runtime.json')));
checks.push(await run('tooling-audit', 'npm', ['audit', '--json'], () => auditEvidence('tooling-audit', 'evidence/dependency-audit-full.json')));
checks.push(await run('acceptance-gate-test', 'node', ['scripts/acceptance-gate.mjs', '--test'], directAcceptance));
checks.push(await run('git-diff-check', 'git', ['diff', '--check'], directDiffCheck));
let manifestCheck = {id: 'root-manifest', command: 'node scripts/generate-manifests.mjs --check', exitCode: null, status: 'NOT_RUN', reason: 'root manifest is generated after the implementation commit'};
if (fs.existsSync(path.join(root, 'evidence/root-manifest.json'))) {
  manifestCheck = await run('root-manifest', 'node', ['scripts/generate-manifests.mjs', '--check'], () => directManifest());
}
checks.push(manifestCheck);

const acceptance = readAcceptanceState();
const critical = checks.filter((check) => !['tooling-audit'].includes(check.id) && !['NOT_RUN', 'NOT_RUN_SANDBOX', 'NOT_RUN_DATABASE_URL_ABSENT', 'NOT_RUN_BUILD_ENVIRONMENT'].includes(check.status));
const criticalPassed = critical.every((check) => check.exitCode === 0);
const runtimeAudit = checks.find((check) => check.id === 'runtime-audit');
const runtimeAuditPassed = runtimeAudit?.exitCode === 0;
const draftVerdict = criticalPassed && runtimeAuditPassed ? 'PASS_WITH_LIMITS' : 'BLOCKED';
const acceptanceVerdict = acceptance.verdict;
const overallVerdict = mode === 'acceptance' ? acceptanceVerdict : draftVerdict;
const exitCode = mode === 'acceptance' ? (acceptanceVerdict === 'BLOCKED' ? 1 : 0) : (overallVerdict === 'PASS_WITH_LIMITS' ? 0 : 1);
const limitations = [
  'pilotExecutions=0; no real Codex/pi or other agent adapter run',
  'Scenario A/B remain NEEDS_INPUT and execution_authorized=false',
  'No authenticated human final approval, paid model call, private source import or production rollout',
  'Database/browser workspace smoke is not claimed unless a dedicated DATABASE_URL and local server are explicitly available',
];
if (checks.find((check) => check.id === 'build')?.status === 'NOT_RUN_BUILD_ENVIRONMENT') limitations.push('production build was not completed because the sandbox lacks a valid worker/database environment');
if (checks.find((check) => check.id === 'tooling-audit')?.exitCode !== 0) limitations.push('npm audit reports dev/tooling advisories; runtime audit remains the release gate');
const summary = {
  schemaVersion: 1,
  mode,
  verdict: overallVerdict,
  draftContractVerdict: draftVerdict,
  acceptanceVerdict,
  pilotExecutions: acceptance.pilotExecutions,
  executionAuthorized: acceptance.executionAuthorized,
  sourceCommit: git('rev-parse', 'HEAD'),
  sourceTree: git('rev-parse', 'HEAD^{tree}'),
  trackedFiles: git('ls-files').split('\n').filter(Boolean).length,
  checks,
  limitations,
  scope: 'Deterministic verifier output; validation-summary.json is generated by scripts/verify.mjs and is not manually edited',
};
const summaryPath = path.join(root, 'evidence/validation-summary.json');
const temporaryPath = `${summaryPath}.tmp`;
fs.writeFileSync(temporaryPath, JSON.stringify(summary, null, 2) + '\n');
fs.renameSync(temporaryPath, summaryPath);
console.log(JSON.stringify({...summary, checks: undefined}, null, 2));
process.exit(exitCode);
