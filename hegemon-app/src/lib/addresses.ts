// Long-address Bech32m codec matching protocol/reward-accounts and wallet V8.
export type AddressNetwork = {
  class: 'testnet' | 'mainnet';
  discriminator: number[];
};
export type AddressKind = 'account' | 'shielded';
const CHARS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function polymod(values: number[]) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
function expand(s: string) {
  return [...s]
    .map((c) => c.charCodeAt(0) >>> 5)
    .concat(
      [0],
      [...s].map((c) => c.charCodeAt(0) & 31),
    );
}
function bits(values: number[], from: number, to: number, pad: boolean) {
  let acc = 0,
    n = 0;
  const out: number[] = [];
  for (const v of values) {
    if (v < 0 || v >> from) throw Error('Invalid address character');
    acc = ((acc << from) | v) & 0x7fffffff;
    n += from;
    while (n >= to) {
      n -= to;
      out.push((acc >>> n) & ((1 << to) - 1));
    }
  }
  if (pad) {
    if (n) out.push((acc << (to - n)) & ((1 << to) - 1));
  } else if (n >= from || ((acc << (to - n)) & ((1 << to) - 1)) !== 0)
    throw Error('Invalid address padding');
  return out;
}
export function cleanAddress(value: string) {
  return value.replace(/[\s\u200B\u200C\u200D\uFEFF]+/g, '').trim();
}
export function decodeBech32m(value: string) {
  const s = cleanAddress(value);
  if (s.length > 4096 || s.length < 8)
    throw Error('Address is truncated or too long');
  if (s !== s.toLowerCase() && s !== s.toUpperCase())
    throw Error('Mixed-case addresses are invalid');
  const lower = s.toLowerCase(),
    at = lower.lastIndexOf('1');
  if (at < 1 || at + 7 > lower.length) throw Error('Invalid address separator');
  const hrp = lower.slice(0, at),
    data = [...lower.slice(at + 1)].map((c) => CHARS.indexOf(c));
  if (
    data.some((v) => v < 0) ||
    polymod([...expand(hrp), ...data]) !== 0x2bc830a3
  )
    throw Error('Address checksum is invalid');
  return {
    hrp,
    bytes: Uint8Array.from(bits(data.slice(0, -6), 5, 8, false)),
    canonical: lower,
  };
}
export function encodeBech32m(hrp: string, bytes: Uint8Array) {
  const data = bits([...bytes], 8, 5, true),
    sum =
      (polymod([...expand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3) >>> 0;
  const check = Array.from(
    { length: 6 },
    (_, i) => (sum >>> (5 * (5 - i))) & 31,
  );
  return `${hrp}1${[...data, ...check].map((x) => CHARS[x]).join('')}`;
}
export function validNetwork(n: AddressNetwork) {
  if (
    !n ||
    !['testnet', 'mainnet'].includes(n.class) ||
    !Array.isArray(n.discriminator) ||
    n.discriminator.length !== 32 ||
    !n.discriminator.every((b) => Number.isInteger(b) && b >= 0 && b <= 255) ||
    n.discriminator.every((b) => b === 0)
  )
    throw Error('Selected address network is invalid');
}
export function validateAddress(
  value: string,
  kind: AddressKind,
  network: AddressNetwork | null,
): string {
  const d = decodeBech32m(value),
    b = d.bytes;
  if (network === null) {
    if (kind !== 'shielded' || d.hrp !== 'shca')
      throw Error('This legacy network requires a shielded shca address');
    if (!(
      (b.length === 1639 && b[0] === 3 && b[1] === 3 && b[2] === 0) ||
      (b.length === 1663 && b[0] === 5 && b[1] === 7 && b[2] === 0)
    ))
      throw Error('Unsupported legacy address format');
    return d.canonical;
  }
  validNetwork(network);
  const hrp =
    (kind === 'account' ? 'heg' : 'heg_shield') +
    (network.class === 'testnet' ? '_test' : '');
  if (d.hrp !== hrp)
    throw Error(
      kind === 'account'
        ? 'Use a public reward-account address for this network'
        : 'Use a shielded payment address for this network',
    );
  if (
    b.length < 35 ||
    b[0] !== 1 ||
    b[1] !== (kind === 'account' ? 0 : 1) ||
    b[2] !== (network.class === 'testnet' ? 0 : 1) ||
    network.discriminator.some((v, i) => b[i + 3] !== v)
  )
    throw Error('Address belongs to another network or address kind');
  const body = b.slice(35);
  if (kind === 'account') {
    if (
      d.canonical.length > 256 ||
      body.length !== 48 ||
      body.every((v) => v === 0)
    )
      throw Error('Invalid public account identifier');
  } else if (
    body.length !== 1663 ||
    body[0] !== 5 ||
    body[1] !== 7 ||
    body[2] !== 0
  )
    throw Error('Full V8 shielded recipient required');
  return d.canonical;
}
export function addressError(
  value: string,
  kind: AddressKind,
  network: AddressNetwork | null,
  label = 'Address',
) {
  if (!cleanAddress(value)) return `${label} is required.`;
  try {
    validateAddress(value, kind, network);
    return null;
  } catch (e) {
    return `${label}: ${e instanceof Error ? e.message : 'invalid address'}.`;
  }
}
export function encodeNetworkAddress(
  kind: AddressKind,
  network: AddressNetwork,
  body: Uint8Array,
) {
  validNetwork(network);
  return encodeBech32m(
    (kind === 'account' ? 'heg' : 'heg_shield') +
      (network.class === 'testnet' ? '_test' : ''),
    Uint8Array.from([
      1,
      kind === 'account' ? 0 : 1,
      network.class === 'testnet' ? 0 : 1,
      ...network.discriminator,
      ...body,
    ]),
  );
}
