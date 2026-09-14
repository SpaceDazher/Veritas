import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {gitText, trackedFiles as listTrackedFiles} from './git-client.mjs';

const root = process.cwd();
const metadataFiles = ['evidence/root-manifest.json', 'evidence/closure-record.json', 'evidence/commit-record.json', 'evidence/clean-checkout.json'];
const git = (...args) => gitText(root, args);
const trackedFiles = listTrackedFiles(root);
const payloadFiles = trackedFiles.filter((file) => !metadataFiles.includes(file));
const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
const hasGitMetadata = fs.existsSync(path.join(root, '.git'));
const payloadBytes = (file) => hasGitMetadata
  ? execFileSync('git', ['show', `HEAD:${file}`], {
      cwd: root,
      encoding: null,
      maxBuffer: 30 * 1024 * 1024,
      windowsHide: true,
    })
  : fs.readFileSync(path.join(root, file));
const fileRecords = payloadFiles.map((file) => {
  const buffer = payloadBytes(file);
  return {path: file, sha256: hash(buffer), bytes: buffer.length};
});
const canonical = (value) => JSON.stringify(value);
const payloadManifestSha256 = hash(canonical(fileRecords));
const fileManifestSha256 = hash(canonical(Object.fromEntries(fileRecords.map((record) => [record.path, record.sha256]))));
const sourceCommit = git('rev-parse', 'HEAD');
const sourceTree = git('rev-parse', 'HEAD^{tree}');
const rootManifestPath = path.join(root, 'evidence/root-manifest.json');
const rootManifest = {
  schemaVersion: 1,
  scope: 'All tracked Veritas payload and evidence files; self-referential metadata files are excluded explicitly',
  algorithm: 'SHA-256 raw file bytes',
  sourceCommit,
  sourceTree,
  trackedFileCount: trackedFiles.length,
  manifestFileCount: fileRecords.length,
  payloadManifestSha256,
  fileManifestSha256,
  excludedSelfReferenceFiles: metadataFiles,
  files: fileRecords,
};
const writeJson = (relativePath, value) => fs.writeFileSync(path.join(root, relativePath), JSON.stringify(value, null, 2) + '\n');

if (process.argv.includes('--write')) {
  writeJson('evidence/root-manifest.json', rootManifest);
  console.log(JSON.stringify({
    exitCode: 0,
    mode: 'write',
    sourceCommit,
    sourceTree,
    trackedFileCount: trackedFiles.length,
    manifestFileCount: fileRecords.length,
    payloadManifestSha256,
    fileManifestSha256,
    rootManifestFileSha256: hash(fs.readFileSync(rootManifestPath)),
  }, null, 2));
  process.exit(0);
}

if (process.argv.includes('--write-closure')) {
  assert(fs.existsSync(rootManifestPath), 'write root manifest before closure record');
  const committedManifest = JSON.parse(fs.readFileSync(rootManifestPath, 'utf8'));
  const rootManifestFileSha256 = hash(fs.readFileSync(rootManifestPath));
  assert.equal(committedManifest.payloadManifestSha256, payloadManifestSha256);
  assert.equal(committedManifest.fileManifestSha256, fileManifestSha256);
  const record = {
    schemaVersion: 1,
    branch: git('branch', '--show-current'),
    implementationCommit: committedManifest.sourceCommit,
    implementationTreeSha: committedManifest.sourceTree,
    manifestCommit: sourceCommit,
    manifestTreeSha: sourceTree,
    payloadManifestSha256,
    fileManifestSha256,
    rootManifestFileSha256,
    closureCommit: 'Resolved externally with git log -1 -- evidence/closure-record.json; not embedded in this file',
    selfHashEmbedded: false,
    pushed: false,
    mergedToMain: false,
  };
  writeJson('evidence/commit-record.json', {...record, closureRecord: 'evidence/closure-record.json'});
  writeJson('evidence/closure-record.json', record);
  console.log(JSON.stringify(record, null, 2));
  process.exit(0);
}

if (process.argv.includes('--check')) {
  assert(fs.existsSync(rootManifestPath), 'evidence/root-manifest.json is missing');
  const committedManifest = JSON.parse(fs.readFileSync(rootManifestPath, 'utf8'));
  assert.deepEqual(committedManifest.files, fileRecords, 'root manifest file records differ from git inventory');
  assert.equal(committedManifest.payloadManifestSha256, payloadManifestSha256);
  assert.equal(committedManifest.fileManifestSha256, fileManifestSha256);
  let expectedCommit = sourceCommit;
  let expectedTree = sourceTree;
  if (fs.existsSync(path.join(root, 'evidence/closure-record.json'))) {
    const closure = JSON.parse(fs.readFileSync(path.join(root, 'evidence/closure-record.json'), 'utf8'));
    expectedCommit = closure.implementationCommit;
    expectedTree = closure.implementationTreeSha;
    assert.equal(closure.selfHashEmbedded, false);
  }
  assert.equal(committedManifest.sourceCommit, expectedCommit);
  assert.equal(committedManifest.sourceTree, expectedTree);
  console.log(JSON.stringify({
    exitCode: 0,
    mode: 'check',
    trackedFileCount: trackedFiles.length,
    manifestFileCount: fileRecords.length,
    payloadManifestSha256,
    fileManifestSha256,
    rootManifestFileSha256: hash(fs.readFileSync(rootManifestPath)),
  }, null, 2));
  process.exit(0);
}

console.error('usage: node scripts/generate-manifests.mjs --write|--write-closure|--check');
process.exit(2);
