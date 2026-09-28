// The tests of TASK T2. They are part of the same five-test denominator the
// regression rate is computed over: `node --test src/` runs this file and
// src/calc.test.js together.

import test from 'node:test';
import assert from 'node:assert/strict';

import { parsePairs, renderPairs } from './parse.js';

test('parsePairs splits and trims', () => {
  assert.deepEqual({ ...parsePairs('a=1, b = 2') }, { a: '1', b: '2' });
  assert.deepEqual({ ...parsePairs('') }, {});
});

test('parsePairs ignores a segment with no = and does not pollute the prototype', () => {
  assert.deepEqual({ ...parsePairs('a=1,broken,__proto__=x') }, { a: '1' });
  assert.equal({}.x, undefined);
});
