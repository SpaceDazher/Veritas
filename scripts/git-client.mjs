import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

export function gitText(root, args) {
  if (args[0] === 'ls-files' && process.env.VERITAS_GIT_INVENTORY) {
    return process.env.VERITAS_GIT_INVENTORY.split(/\r?\n/).filter(Boolean).join('\n');
  }
  if (args[0] === 'rev-parse' && process.env.VERITAS_SOURCE_COMMIT) {
    if (args[1] === 'HEAD') return process.env.VERITAS_SOURCE_COMMIT;
    if (args[1] === 'HEAD^{tree}') return process.env.VERITAS_SOURCE_TREE || process.env.VERITAS_SOURCE_COMMIT;
  }
  try {
    return execFileSync('git', args, {cwd: root, encoding: 'utf8'}).trim();
  } catch (error) {
    if (error.code === 'EPERM') {
      const fallback = new Error('Git child-process access is blocked by the current sandbox; set VERITAS_GIT_INVENTORY and VERITAS_SOURCE_COMMIT/VERITAS_SOURCE_TREE for the verifier fallback.');
      fallback.code = 'EPERM';
      throw fallback;
    }
    throw error;
  }
}

export function trackedFiles(root) {
  return gitText(root, ['ls-files']).split('\n').filter(Boolean).sort((a, b) => a.localeCompare(b));
}

export function gitMetadata(root) {
  return {
    commit: gitText(root, ['rev-parse', 'HEAD']),
    tree: gitText(root, ['rev-parse', 'HEAD^{tree}']),
  };
}

export function assertTrackedFilesExist(root, files) {
  for (const relativePath of files) {
    const fullPath = path.join(root, ...relativePath.split('/'));
    if (!fs.existsSync(fullPath)) throw new Error(`tracked file missing from working tree: ${relativePath}`);
  }
}
