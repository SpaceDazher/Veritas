import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {gitText, trackedFiles, assertTrackedFilesExist} from './git-client.mjs';

const root = process.cwd();
const execGit = (...args) => gitText(root, args);
const trackedFileList = trackedFiles(root);
const patterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /gh[pousr]_[A-Za-z0-9]{30,}/,
  /github_pat_[A-Za-z0-9_]{40,}/,
  /sk-(?:proj-)?[A-Za-z0-9_-]{35,}/,
  /postgres(?:ql)?:\/\/[^\s/:]+:[^\s@]+@/,
];
const findings = [];
const binaryFiles = [];
let scannedTextFiles = 0;
for (const relativePath of trackedFileList) {
  assertTrackedFilesExist(root, [relativePath]);
  assert(!/^\.env(?:$|\.)/.test(relativePath) || relativePath === '.env.example', `real environment file is tracked: ${relativePath}`);
  const fullPath = path.join(root, ...relativePath.split('/'));
  const buffer = fs.readFileSync(fullPath);
  if (buffer.includes(0)) {
    binaryFiles.push(relativePath);
    continue;
  }
  const text = buffer.toString('utf8');
  scannedTextFiles++;
  for (const pattern of patterns) {
    if (pattern.test(text)) findings.push({path: relativePath, pattern: pattern.toString()});
  }
}
let privateSourceImports = 0;
for (const scenario of ['a', 'b']) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, `pilots/scenario-${scenario}/source-selection-manifest.json`), 'utf8'));
  assert.equal(manifest.contains_private_content, false);
  assert.equal(manifest.import_authorized, false);
  assert(manifest.sources.every((source) => source.selection === 'NOT_IMPORTED'));
  privateSourceImports += manifest.sources.filter((source) => source.selection !== 'NOT_IMPORTED').length;
}
assert.deepEqual(findings, [], 'Potential credential material found; do not publish');
assert.equal(privateSourceImports, 0);
let environmentIgnored = false;
try {
  gitText(root, ['check-ignore', '-q', '.env']);
  environmentIgnored = true;
} catch (error) {
  const noGitRepo = typeof error.message === 'string' && error.message.includes('not a git repository');
  if (error.code === 'EPERM' && !fs.existsSync(path.join(root, '.env')) && fs.readFileSync(path.join(root, '.gitignore'), 'utf8').split(/\r?\n/).includes('.env')) {
    environmentIgnored = true;
  } else if (noGitRepo && !fs.existsSync(path.join(root, '.env')) && fs.readFileSync(path.join(root, '.gitignore'), 'utf8').split(/\r?\n/).includes('.env')) {
    // Clean-archive verification runs without .git; the tracked .gitignore
    // is authoritative proof that .env stays ignored.
    environmentIgnored = true;
  } else if (error.status !== 1) {
    throw error;
  }
}
assert(environmentIgnored, '.env must remain ignored');
const result = {
  schemaVersion: 1,
  exitCode: 0,
  sourceCommit: execGit('rev-parse', 'HEAD'),
  sourceTree: execGit('rev-parse', 'HEAD^{tree}'),
  inventorySource: 'git ls-files -z',
  trackedFiles: trackedFileList.length,
  scannedTextFiles,
  binaryFiles,
  findings,
  privateSourceImports,
  environmentIgnored,
  scope: 'Heuristic scan of the real committed Git inventory; not comprehensive DLP or security certification. No private sources read.',
};
fs.writeFileSync(path.join(root, 'evidence/public-artifact-check.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({...result, sourceCommit: undefined, sourceTree: undefined}, null, 2));
