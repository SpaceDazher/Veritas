// The five pre-existing tests of the ONE S2-007R project. They are the
// denominator of measurement 6 (regression rate): a test that passed on the
// pristine fixture and fails after a run is a regression, whatever the model
// said about it.

import test from 'node:test';
import assert from 'node:assert/strict';

import { add, sub, mul, sumRange } from './calc.js';

test('add', () => {
  assert.equal(add(2, 3), 5);
  assert.equal(add(-1, 1), 0);
});

test('sub', () => {
  assert.equal(sub(5, 2), 3);
  assert.equal(sub(2, 5), -3);
});

test('mul', () => {
  assert.equal(mul(4, 3), 12);
  assert.equal(mul(0, 9), 0);
});

test('sumRange is inclusive of both ends', () => {
  assert.equal(sumRange(1, 4), 10);
  assert.equal(sumRange(1, 1), 1);
});

test('sumRange of an empty range is 0', () => {
  assert.equal(sumRange(4, 1), 0);
  assert.equal(sumRange(0, 0), 0);
});
