import test from 'node:test';
import assert from 'node:assert/strict';
import {IndefiniteArray, Tag, concat, decode, encode, fromHex, mapSpans, spans, toHex} from './cbor.mjs';

// RFC 8949 Appendix A examples.
const vectors = [
  ['00', 0], ['01', 1], ['0a', 10], ['17', 23], ['1818', 24], ['1819', 25], ['1864', 100], ['1903e8', 1000], ['1a000f4240', 1000000],
  ['1b000000e8d4a51000', 1000000000000], ['1bffffffffffffffff', 18446744073709551615n], ['20', -1], ['29', -10], ['3863', -100], ['3903e7', -1000],
  ['40', new Uint8Array(0)], ['4401020304', Uint8Array.of(1, 2, 3, 4)], ['60', ''], ['6161', 'a'], ['6449455446', 'IETF'],
  ['80', []], ['83010203', [1, 2, 3]], ['8301820203820405', [1, [2, 3], [4, 5]]],
  ['a0', new Map()], ['a201020304', new Map([[1, 2], [3, 4]])], ['f4', false], ['f5', true], ['f6', null],
  ['d818456449455446', new Tag(24, Uint8Array.from(Buffer.from('6449455446', 'hex')))],
];

test('RFC 8949 examples decode and (definite forms) re-encode identically', () => {
  for (const [hex, value] of vectors) {
    assert.deepEqual(decode(fromHex(hex)), value, hex);
    assert.equal(toHex(encode(value)), hex, hex);
  }
});

test('indefinite-length items decode and indefinite arrays encode', () => {
  assert.deepEqual(decode(fromHex('9f018202039f0405ffff')), [1, [2, 3], [4, 5]]);
  assert.deepEqual(decode(fromHex('bf61610161629f0203ffff')), new Map([['a', 1], ['b', [2, 3]]]));
  assert.deepEqual(decode(fromHex('5f42010243030405ff')), Uint8Array.of(1, 2, 3, 4, 5));
  assert.equal(toHex(encode(new IndefiniteArray([1, 2]))), '9f0102ff');
});

test('Plutus data constructor 0 with a byte string, as used for the claim redeemer', () => {
  const data = new Tag(121, [new Uint8Array(32).fill(7)]);
  assert.equal(toHex(encode(data)), 'd87981' + '5820' + '07'.repeat(32));
  assert.deepEqual(decode(encode(data)), data);
});

test('rejects malformed, truncated, trailing, float and over-deep input', () => {
  for (const hex of ['', '18', '1a0000', '5801', '8301', 'f90000', 'fb0000000000000000', '0001', 'ff', '9f01', 'a1', '5f01ff']) {
    assert.throws(() => decode(fromHex(hex)), undefined, hex);
  }
  assert.throws(() => decode(fromHex('81'.repeat(100) + '00')), /deeply/);
  assert.throws(() => decode(fromHex('9b' + 'ff'.repeat(8))), /too large|Truncated/);
  assert.throws(() => encode(1.5));
  assert.throws(() => encode(2 ** 60));
  assert.throws(() => encode(undefined));
});

test('negative integers beyond 2^53 use BigInt', () => {
  assert.equal(toHex(encode(-(1n << 60n))), '3b0fffffffffffffff');
  assert.equal(decode(fromHex('3b0fffffffffffffff')), -(1n << 60n));
});

test('spans gives the exact bytes of each top-level element', () => {
  const body = encode(new Map([[0, [new Uint8Array(32)]], [2, 170000]])), witness = encode(new Map()), tx = concat(Uint8Array.of(0x84), body, witness, Uint8Array.of(0xf5, 0xf6));
  const parts = spans(tx).map(([a, b]) => tx.slice(a, b));
  assert.equal(parts.length, 4);
  assert.deepEqual(parts[0], body);
  assert.deepEqual(parts[1], witness);
  assert.throws(() => spans(encode(new Map())), /array/);
  const indefinite = concat(Uint8Array.of(0x9f), body, witness, Uint8Array.of(0xff));
  assert.deepEqual(spans(indefinite).map(([a, b]) => indefinite.slice(a, b)), [body, witness]);
});

test('encodes and decodes a random structure round trip', () => {
  let seed = 12345;
  const next = n => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const make = depth => {
    const kind = depth > 3 ? next(4) : next(8);
    if (kind === 0) return next(2 ** 31) * (next(2) ? 1 : -1);
    if (kind === 1) return Uint8Array.from({length: next(40)}, () => next(256));
    if (kind === 2) return 'x'.repeat(next(30));
    if (kind === 3) return next(2) === 0;
    if (kind === 4) return Array.from({length: next(5)}, () => make(depth + 1));
    if (kind === 5) return new Map(Array.from({length: next(4)}, (_, i) => [i, make(depth + 1)]));
    if (kind === 6) return new Tag(121 + next(7), Array.from({length: next(3)}, () => make(depth + 1)));
    return BigInt(next(2 ** 31)) * 4294967296n;
  };
  for (let i = 0; i < 300; i++) { const v = make(0); assert.deepEqual(decode(encode(v)), v); }
});

test('duplicate map keys are rejected, and mapSpans returns the value bytes', () => {
  assert.throws(() => decode(fromHex('a201020103')), /Duplicate/);
  assert.throws(() => mapSpans(fromHex('a201020103')), /Duplicate/);
  const value = encode([1, 2, 3]), map = concat(Uint8Array.of(0xa2, 0x00), value, Uint8Array.of(0x05, 0x61, 0x78));
  const entries = mapSpans(map);
  assert.deepEqual(entries.map(e => e.key), [0, 5]);
  assert.deepEqual(map.slice(entries[0].start, entries[0].end), value);
  assert.deepEqual(decode(map.slice(entries[1].start, entries[1].end)), 'x');
  assert.throws(() => mapSpans(encode([])), /map/);
});
