import assert from 'node:assert/strict';
import test from 'node:test';

import { parseExecutionMode } from './app-no-ssh-e2e-mode.mjs';

test('no mode selects the strict funded-transfer path', () => {
  assert.equal(parseExecutionMode([]), 'strict');
});

test('review-only mode must be explicitly selected', () => {
  assert.equal(parseExecutionMode(['--review-only']), 'review-only');
});

test('unknown and repeated mode arguments fail closed', () => {
  assert.throws(() => parseExecutionMode(['--skip-funding']), /usage:/);
  assert.throws(() => parseExecutionMode(['--review-only', '--review-only']), /usage:/);
});
