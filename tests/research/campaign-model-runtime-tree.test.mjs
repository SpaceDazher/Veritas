import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { digestRuntimeTree } from '../../scripts/s2-008-campaign-model-image.mjs';

function makeTree(root, entries) {
  fs.mkdirSync(root, { recursive: true });
  for (const entry of entries) {
    const target = path.join(root, entry.path);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (entry.type === 'link') fs.symlinkSync(entry.target, target);
    else {
      fs.writeFileSync(target, entry.content);
      fs.chmodSync(target, entry.mode ?? 0o644);
      fs.utimesSync(target, new Date(entry.mtime ?? 1000), new Date(entry.mtime ?? 1000));
    }
  }
}

test('pi runtime tree digest binds nested executable bytes and modes, independent of creation order and mtimes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'veritas-pi-tree-'));
  try {
    const first = path.join(root, 'first');
    const second = path.join(root, 'second');
    const entries = [
      { path: 'dist/bundle/cli.js', content: 'import "./chunks/runtime.js";', mode: 0o644, mtime: 1000 },
      { path: 'dist/bundle/chunks/runtime.js', content: 'const answer = 42;', mode: 0o755, mtime: 1000 },
      { path: 'bin/pi', type: 'link', target: '../dist/bundle/cli.js' },
    ];
    makeTree(first, entries);
    makeTree(second, [...entries].reverse().map((entry) => ({ ...entry, mtime: 5000 })));
    assert.equal(digestRuntimeTree(first), digestRuntimeTree(second));

    fs.writeFileSync(path.join(second, 'dist/bundle/chunks/runtime.js'), 'const answer = 43;');
    assert.notEqual(digestRuntimeTree(first), digestRuntimeTree(second));
    fs.writeFileSync(path.join(second, 'dist/bundle/chunks/runtime.js'), 'const answer = 42;');
    fs.chmodSync(path.join(second, 'dist/bundle/chunks/runtime.js'), 0o644);
    assert.notEqual(digestRuntimeTree(first), digestRuntimeTree(second));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
