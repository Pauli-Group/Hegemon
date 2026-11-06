/** Minimal CBOR (RFC 8949) for Cardano transactions.
 *
 * Decoding returns plain values: unsigned and negative integers as numbers when safe and BigInt otherwise,
 * byte strings as Uint8Array, text as strings, arrays as arrays, maps as `Map` (keys keep their decoded
 * type, order is preserved), tags as `Tag`, booleans, null and undefined. Indefinite-length arrays, maps,
 * byte strings and text are accepted because cardano-cli emits them in Plutus data. Floats are rejected:
 * nothing in a Cardano transaction uses them.
 *
 * `spans` gives the exact byte range of every element of a top-level array, so a caller can hash or compare
 * the original bytes of a transaction body instead of a re-encoding.
 */
export class Tag {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}

const MAX_DEPTH = 64;
const MAX_ITEMS = 100_000;

export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) throw Error('Invalid hexadecimal bytes.');
  return Uint8Array.from(hex.match(/../g) || [], x => parseInt(x, 16));
}

export function toHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

export function equalBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// ---------------------------------------------------------------- encoding

function head(major, value) {
  const v = BigInt(value);
  if (v < 0n || v >= 1n << 64n) throw Error('CBOR integer out of range.');
  if (v < 24n) return Uint8Array.of(major << 5 | Number(v));
  const width = v < 256n ? 1 : v < 65536n ? 2 : v < 4294967296n ? 4 : 8;
  const out = new Uint8Array(1 + width);
  out[0] = major << 5 | (width === 1 ? 24 : width === 2 ? 25 : width === 4 ? 26 : 27);
  for (let i = 0; i < width; i++) out[width - i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return out;
}

/** Bytes that are already CBOR-encoded and must be embedded unchanged (a transaction body that was hashed, a redeemer set). */
export class Raw {
  constructor(bytes) { this.bytes = bytes; }
}

/** Marker for an indefinite-length array (used only to reproduce cardano-cli's Plutus data when needed). */
export class IndefiniteArray {
  constructor(items) { this.items = items; }
}

export function encode(value) {
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (typeof value === 'bigint' || (typeof value === 'number' && Number.isInteger(value))) {
    if (!Number.isSafeInteger(value) && typeof value === 'number') throw Error('Unsafe CBOR integer; use BigInt.');
    return value >= 0 ? head(0, value) : head(1, -1n - BigInt(value));
  }
  if (typeof value === 'string') { const bytes = new TextEncoder().encode(value); return concat(head(3, bytes.length), bytes); }
  if (value === true) return Uint8Array.of(0xf5);
  if (value === false) return Uint8Array.of(0xf4);
  if (value === null) return Uint8Array.of(0xf6);
  if (value instanceof Raw) return value.bytes;
  if (value instanceof IndefiniteArray) return concat(Uint8Array.of(0x9f), ...value.items.map(encode), Uint8Array.of(0xff));
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encode));
  if (value instanceof Map) return concat(head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)]));
  if (value instanceof Tag) return concat(head(6, value.tag), encode(value.value));
  throw Error('Unsupported CBOR value.');
}

// ---------------------------------------------------------------- decoding

function reader(bytes) {
  let pos = 0;
  const need = n => { if (n < 0 || pos + n > bytes.length) throw Error('Truncated CBOR.'); };
  const byte = () => { need(1); return bytes[pos++]; };
  const take = n => { need(n); const out = bytes.subarray(pos, pos + n); pos += n; return out; };
  const argument = info => {
    if (info < 24) return BigInt(info);
    const width = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (!width) throw Error('Unsupported CBOR length encoding.');
    let v = 0n;
    for (const b of take(width)) v = v << 8n | BigInt(b);
    return v;
  };
  const number = v => (v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v);
  const size = v => { if (v > BigInt(MAX_ITEMS) && v > BigInt(bytes.length)) throw Error('CBOR length too large.'); return Number(v); };
  let items = 0;
  function item(depth) {
    if (depth > MAX_DEPTH) throw Error('CBOR nests too deeply.');
    if (++items > MAX_ITEMS * 10) throw Error('CBOR has too many items.');
    const first = byte(), major = first >> 5, info = first & 31;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 23) return undefined;
      throw Error('Unsupported CBOR simple value or float.');
    }
    if (info === 31) {
      if (major === 2 || major === 3) {
        const parts = [];
        for (;;) {
          if (bytes[pos] === 0xff) { pos++; break; }
          const chunk = item(depth + 1);
          if (major === 2 ? !(chunk instanceof Uint8Array) : typeof chunk !== 'string') throw Error('Invalid CBOR chunk.');
          parts.push(chunk);
        }
        return major === 2 ? concat(...parts) : parts.join('');
      }
      if (major === 4) { const out = []; while (bytes[pos] !== 0xff) { need(1); out.push(item(depth + 1)); } pos++; return out; }
      if (major === 5) { const out = new Map(); while (bytes[pos] !== 0xff) { need(1); const k = item(depth + 1); if (out.has(k)) throw Error('Duplicate CBOR map key.'); out.set(k, item(depth + 1)); } pos++; return out; }
      throw Error('Invalid indefinite CBOR item.');
    }
    const arg = argument(info);
    if (major === 0) return number(arg);
    if (major === 1) return arg <= BigInt(Number.MAX_SAFE_INTEGER) ? -1 - Number(arg) : -1n - arg;
    if (major === 2) return take(size(arg)).slice();
    if (major === 3) return new TextDecoder('utf-8', {fatal: true}).decode(take(size(arg)));
    if (major === 4) { const out = []; for (let i = 0, n = size(arg); i < n; i++) out.push(item(depth + 1)); return out; }
    if (major === 5) { const out = new Map(); for (let i = 0, n = size(arg); i < n; i++) { const k = item(depth + 1); if (out.has(k)) throw Error('Duplicate CBOR map key.'); out.set(k, item(depth + 1)); } return out; }
    return new Tag(number(arg), item(depth + 1));
  }
  return {item, position: () => pos, skipTo: p => { pos = p; }, done: () => pos === bytes.length};
}

export function decode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw Error('CBOR input must be bytes.');
  const r = reader(bytes), value = r.item(0);
  if (!r.done()) throw Error('Trailing bytes after CBOR item.');
  return value;
}

/** Byte ranges `[start, end)` of each element of a top-level definite or indefinite array. */
export function spans(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) throw Error('CBOR input must be bytes.');
  const r = reader(bytes), first = bytes[0], major = first >> 5, info = first & 31;
  if (major !== 4) throw Error('Expected a CBOR array.');
  const out = [];
  if (info === 31) {
    r.skipTo(1);
    while (bytes[r.position()] !== 0xff) { const start = r.position(); r.item(1); out.push([start, r.position()]); if (r.position() >= bytes.length) throw Error('Truncated CBOR.'); }
    r.skipTo(r.position() + 1);
  } else {
    const count = decode(encodeHeadOnly(bytes));
    r.skipTo(headLength(info));
    for (let i = 0; i < count; i++) { const start = r.position(); r.item(1); out.push([start, r.position()]); }
  }
  if (!r.done()) throw Error('Trailing bytes after CBOR item.');
  return out;
}

/** Entries of a top-level definite or indefinite map as `{key, start, end}`, where start/end delimit the value's bytes. */
export function mapSpans(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) throw Error('CBOR input must be bytes.');
  const r = reader(bytes), first = bytes[0], major = first >> 5, info = first & 31;
  if (major !== 5) throw Error('Expected a CBOR map.');
  const out = [], one = () => {
    const key = r.item(1), start = r.position();
    r.item(1);
    if (typeof key === 'number' || typeof key === 'string' || typeof key === 'bigint') {
      if (out.some(entry => entry.key === key)) throw Error('Duplicate CBOR map key.');
    }
    out.push({key, start, end: r.position()});
  };
  if (info === 31) {
    r.skipTo(1);
    while (bytes[r.position()] !== 0xff) { one(); if (r.position() >= bytes.length) throw Error('Truncated CBOR.'); }
    r.skipTo(r.position() + 1);
  } else {
    const count = decode(encodeHeadOnly(bytes));
    r.skipTo(headLength(info));
    for (let i = 0; i < count; i++) one();
  }
  if (!r.done()) throw Error('Trailing bytes after CBOR item.');
  return out;
}

function headLength(info) { return info < 24 ? 1 : 1 + (info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 8); }

/** The array length from a definite array head, using the array's own head bytes. */
function encodeHeadOnly(bytes) {
  const info = bytes[0] & 31, length = headLength(info);
  if (length > bytes.length) throw Error('Truncated CBOR.');
  // Re-read the length as an unsigned integer by rewriting the major type to 0.
  const head = bytes.slice(0, length);
  head[0] = info;
  return head;
}

/** Look up a map entry whose key is the number `key` (decoded keys are numbers). */
export function mapGet(map, key) {
  if (!(map instanceof Map)) throw Error('Expected a CBOR map.');
  return map.get(key);
}
