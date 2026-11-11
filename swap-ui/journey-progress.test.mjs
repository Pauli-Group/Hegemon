import test from 'node:test';
import assert from 'node:assert/strict';
import {offerProgress} from './journey-ui.mjs';

const base = {available: true, owner: true, reserved: false, reservationActive: false, closed: false, expired: false, identity: {owner: 'none', taker: 'none'}};
test('offer progress reports who acts without claiming that funds moved', () => {
  assert.equal(offerProgress(base).actor, 'You');
  assert.equal(offerProgress({...base, identity: {owner: 'verified', taker: 'none'}}).actor, 'The other person');
  assert.equal(offerProgress({...base, reservationActive: true, identity: {owner: 'verified', taker: 'none'}}).title, 'Waiting for their signed details');
  const both = offerProgress({...base, reservationActive: true, identity: {owner: 'verified', taker: 'verified'}});
  assert.equal(both.actor, 'Not yet known');
  assert.match(both.detail, /cannot yet coordinate or track/);
  const taker = {...base, owner: false, reserved: true, reservationActive: true};
  assert.equal(offerProgress({...taker, identity: {owner: 'verified', taker: 'none'}}).actor, 'You');
  assert.equal(offerProgress({...taker, identity: {owner: 'none', taker: 'verified'}}).actor, 'The other person');
  assert.equal(offerProgress({...taker, identity: {owner: 'verified', taker: 'partial'}}).title, 'Complete your wallet proofs');
  assert.equal(offerProgress({...taker, identity: {owner: 'partial', taker: 'verified'}}).title, 'Waiting for their wallet proofs');
  assert.equal(offerProgress({...taker, identity: {owner: 'unsupported', taker: 'verified'}}).actor, 'Unknown');
});
test('unknown, stale or invalid state never reports verified swap progress', () => {
  assert.equal(offerProgress({...base, available: false}).actor, 'Unknown');
  assert.equal(offerProgress({...base, closed: true}).actor, 'Unknown');
  assert.equal(offerProgress({...base, expired: true}).actor, 'Unknown');
  assert.equal(offerProgress({...base, identity: {blocked: true}}).actor, 'Unknown');
  assert.equal(offerProgress({...base, identity: {error: true}}).actor, 'Unknown');
  assert.equal(offerProgress({...base, identity: null}).actor, 'Checking');
  assert.equal(offerProgress({...base, owner: false, reservationActive: true}).title, 'This offer is reserved');
});
