#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_FILES = 256;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}
function canonicalDigest(value) {
  return sha256(canonicalJson(value));
}
function isWithin(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}
function readSafe(root, relative, maximum, includeContent = false) {
  if (typeof relative !== 'string' || !relative || relative.startsWith('/')
      || relative.includes('\\') || relative.split('/').some((part) => !part || part === '.' || part === '..')
      || path.posix.normalize(relative) !== relative) fail('IMPORT_PATH_INVALID');
  const absolute = path.resolve(root, ...relative.split('/'));
  if (!isWithin(root, absolute)) fail('IMPORT_PATH_INVALID');
  let fd;
  try {
    const parent = fs.realpathSync(path.dirname(absolute));
    if (!isWithin(root, parent)) fail('IMPORT_PATH_INVALID');
    const target = path.join(parent, path.basename(absolute));
    const before = fs.lstatSync(target);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maximum) fail('IMPORT_FILE_INVALID');
    fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    const openedPath = fs.realpathSync('/proc/self/fd/' + fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev
        || opened.ino !== before.ino || !isWithin(root, openedPath)) fail('IMPORT_FILE_INVALID');
    const digest = createHash('sha256');
    const parts = includeContent ? [] : null;
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytes = 0;
    for (;;) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      bytes += count;
      if (bytes > maximum) fail('IMPORT_FILE_INVALID');
      const chunk = buffer.subarray(0, count);
      digest.update(chunk);
      if (parts) parts.push(Buffer.from(chunk));
    }
    if (bytes !== opened.size) fail('IMPORT_FILE_INVALID');
    return { bytes, sha256: digest.digest('hex'), content: parts ? Buffer.concat(parts, bytes) : null };
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('IMPORT_')) throw error;
    fail('IMPORT_FILE_INVALID');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}
function readBundle(bundlePath) {
  const absolute = path.resolve(bundlePath);
  if (path.basename(absolute) !== 'bundle.json') fail('IMPORT_BUNDLE_INVALID');
  const root = fs.realpathSync(path.dirname(absolute));
  const file = readSafe(root, 'bundle.json', 1024 * 1024, true);
  let bundle;
  try { bundle = JSON.parse(file.content.toString('utf8')); }
  catch { fail('IMPORT_BUNDLE_INVALID'); }
  return { root, bundle, bundleSha256: file.sha256 };
}
function validateBundle(bundle) {
  if (!bundle || Object.getPrototypeOf(bundle) !== Object.prototype
      || Object.keys(bundle).sort().join(',') !== 'artifact_manifest_digest,files,fixture_only,kind'
      || bundle.kind !== 's2-008-paid-review-import-bundle/1'
      || typeof bundle.fixture_only !== 'boolean'
      || !SHA256.test(bundle.artifact_manifest_digest)
      || !Array.isArray(bundle.files) || bundle.files.length < 1 || bundle.files.length > MAX_FILES) {
    fail('IMPORT_BUNDLE_INVALID');
  }
  let total = 0;
  const seen = new Set();
  for (const record of bundle.files) {
    if (!record || Object.getPrototypeOf(record) !== Object.prototype
        || Object.keys(record).sort().join(',') !== 'bytes,path,sha256'
        || typeof record.path !== 'string' || !Number.isSafeInteger(record.bytes) || record.bytes < 0
        || record.bytes > MAX_FILE_BYTES || !SHA256.test(record.sha256)
        || seen.has(record.path)) fail('IMPORT_BUNDLE_INVALID');
    seen.add(record.path);
    total += record.bytes;
    if (total > MAX_TOTAL_BYTES) fail('IMPORT_BUNDLE_INVALID');
  }
  if (canonicalDigest(bundle.files) !== bundle.artifact_manifest_digest) fail('IMPORT_BUNDLE_INVALID');
  return total;
}
export function verifyOfflineImportBundle(bundlePath) {
  const { root, bundle, bundleSha256 } = readBundle(bundlePath);
  const totalBytes = validateBundle(bundle);
  for (const record of bundle.files) {
    const actual = readSafe(root, record.path, MAX_FILE_BYTES);
    if (actual.bytes !== record.bytes || actual.sha256 !== record.sha256) fail('IMPORT_CONTENT_MISMATCH');
  }
  return {
    kind: 's2-008-paid-review-import/1',
    status: 'PASS',
    artifact_manifest_digest: bundle.artifact_manifest_digest,
    bundle_sha256: bundleSha256,
    verified_files: bundle.files.length,
    verified_bytes: totalBytes,
    fixture_only: bundle.fixture_only,
    network: 'none',
    model_calls: 0,
    tokens: 0,
  };
}
function parseArgs(argv) {
  if (argv.length !== 4 || argv[0] !== '--bundle' || argv[2] !== '--output'
      || !path.isAbsolute(argv[1]) || !path.isAbsolute(argv[3])
      || path.basename(argv[3]) !== 'import.json') fail('IMPORT_USAGE');
  return { bundle: argv[1], output: argv[3] };
}
function writeOutput(file, report) {
  const directory = path.dirname(file);
  const directoryStat = fs.lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) fail('IMPORT_OUTPUT_INVALID');
  const root = fs.realpathSync(directory);
  const target = path.resolve(file);
  if (!isWithin(root, target) || target === root) fail('IMPORT_OUTPUT_INVALID');
  const bytes = Buffer.from(JSON.stringify(report) + '\n');
  let fd;
  try {
    fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeSync(fd, bytes);
    fs.fsyncSync(fd);
  } catch {
    fail('IMPORT_OUTPUT_INVALID');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  return sha256(bytes);
}
async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const report = verifyOfflineImportBundle(args.bundle);
    const reportSha256 = writeOutput(args.output, report);
    process.stdout.write(JSON.stringify({ status: report.status, report_sha256: reportSha256 }) + '\n');
  } catch (error) {
    process.stderr.write(JSON.stringify({ code: error?.code ?? 'IMPORT_FAILED' }) + '\n');
    process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
