/* Cardano transaction builder and independent checker for the pinned Aiken HTLC (PlutusV3, Conway era).
 *
 * The page builds fund, claim and refund transactions itself so that no wallet-supplied builder has to be
 * trusted. `inspectTx` decodes bytes with no knowledge of the builder, and `checkFund` / `checkSpend` compare
 * what the bytes would do to what the user asked for. The wallet is only asked to sign bytes that passed.
 * Outputs use the Babbage map form, redeemers the Conway map form, and sets are plain arrays (accepted by the
 * Conway ledger and by every wallet decoder).
 */
import {blake2b, bech32} from './vendor/hash.mjs';
import {Raw, Tag, concat, decode, encode, equalBytes, fromHex, mapSpans, spans, toHex} from './cbor.mjs';

export const PREVIEW = Object.freeze({magic: 2, systemStart: 1666656000, networkId: 0});
export const SCRIPT_TAG_V3 = 7;
export const MAX_FEE_LOVELACE = 5_000_000n;
const FEE_MARGIN_BYTES = 96;       // room for wallets that serialise witnesses a little larger than a bare array
const CLAIM_SLOT_MARGIN = 30;      // refuse to build a claim that would expire within this many slots
const CLAIM_VALIDITY_SLOTS = 3600; // a Plutus transaction's upper bound must stay inside the ledger's time horizon (about 7 h on preview)
const FEE_SLACK_LOVELACE = 20_000n; // anything above fee(size)+units+slack is refused by the checker
const VKEY_WITNESS_BYTES = 101;    // array(2) + bytes(32) + bytes(64)

const fail = message => { throw Error('Cardano transaction check failed: ' + message); };
const big = value => { try { return BigInt(value); } catch { throw Error('Invalid Cardano number.'); } };

// ------------------------------------------------------------------ script and addresses

let pinned;
export function setPinnedScript(json) { pinned = Object.freeze({...json}); }
export function pinnedScript() {
  if (!pinned) throw Error('Cardano validator not loaded.');
  return pinned;
}
export async function loadPinnedScript(fetcher = globalThis.fetch) {
  const response = await fetcher('/cardano-htlc-script.json', {cache: 'no-store'});
  if (!response.ok) throw Error('Cardano validator file unavailable.');
  const json = await response.json();
  setPinnedScript(json);
  return validateScript(json);
}

export function scriptBytes(compiledCodeHex) { return fromHex(compiledCodeHex); }
export function scriptHash(script) { return toHex(blake2b(concat(Uint8Array.of(3), script), {dkLen: 28})); }
export function enterpriseScriptAddress(hash) { return concat(Uint8Array.of(0x70), fromHex(hash)); }
export function toBech32(bytes, prefix = 'addr_test') { return bech32.encode(prefix, bech32.toWords(bytes), 1000); }
export function fromBech32(text) {
  const {prefix, words} = bech32.decode(text, 1000);
  if (prefix !== 'addr_test') throw Error('Not a Cardano testnet address.');
  return Uint8Array.from(bech32.fromWords(words));
}

/** The pinned file must hash to its own claimed validator hash and address. */
export function validateScript(json = pinnedScript()) {
  const script = scriptBytes(json.compiledCode), hash = scriptHash(script);
  if (json.language !== 'PlutusV3' || hash !== json.hash) throw Error('Cardano validator does not match its pinned hash.');
  if (toBech32(enterpriseScriptAddress(hash)) !== json.address) throw Error('Cardano validator address does not match its hash.');
  return {script, hash, address: enterpriseScriptAddress(hash), bech32: json.address};
}

/** Payment credential of an address, or null for a script credential. Rejects non-testnet and unsupported addresses. */
export function addressInfo(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 29) throw Error('Invalid Cardano address.');
  const type = bytes[0] >> 4, network = bytes[0] & 15;
  if (network !== PREVIEW.networkId) throw Error('Cardano address is not a testnet address.');
  if (type > 7) throw Error('Unsupported Cardano address type.');
  const payment = toHex(bytes.subarray(1, 29));
  return {type, keyHash: type === 0 || type === 2 || type === 4 || type === 6 ? payment : null, scriptHash: type === 1 || type === 3 || type === 5 || type === 7 ? payment : null};
}

// ------------------------------------------------------------------ values

export const emptyValue = () => ({lovelace: 0n, assets: {}});
export function parseAssets(text) {
  const out = {};
  if (typeof text !== 'string') throw Error('Invalid Cardano assets.');
  for (const line of text.split(/\r?\n/).map(x => x.trim()).filter(Boolean)) {
    const m = line.match(/^([0-9a-f]{56}\.(?:[0-9a-f]{2}){0,32})=([1-9][0-9]{0,18})$/);
    if (!m || Object.hasOwn(out, m[1]) || big(m[2]) >= 1n << 63n) throw Error('Invalid Cardano assets.');
    out[m[1]] = big(m[2]);
  }
  return out;
}
export function addValue(a, b, sign = 1n) {
  const assets = {...a.assets};
  for (const [name, quantity] of Object.entries(b.assets)) {
    const sum = (assets[name] ?? 0n) + sign * quantity;
    if (sum < 0n) throw Error('Insufficient Cardano assets.');
    if (sum === 0n) delete assets[name]; else assets[name] = sum;
  }
  const lovelace = a.lovelace + sign * b.lovelace;
  if (lovelace < 0n) throw Error('Insufficient lovelace.');
  return {lovelace, assets};
}
export function sumValues(values) { return values.reduce((acc, v) => addValue(acc, v), emptyValue()); }
export function valueEquals(a, b) {
  const ka = Object.keys(a.assets).sort(), kb = Object.keys(b.assets).sort();
  return a.lovelace === b.lovelace && ka.length === kb.length && ka.every((k, i) => k === kb[i] && a.assets[k] === b.assets[k]);
}
export function valueFromRow(row) {
  const assets = {};
  for (const a of row.asset_list ?? []) {
    const name = `${a.policy_id}.${a.asset_name}`;
    if (!/^[0-9a-f]{56}\.(?:[0-9a-f]{2}){0,32}$/.test(name) || Object.hasOwn(assets, name)) throw Error('Invalid Cardano asset.');
    assets[name] = big(a.quantity);
  }
  return {lovelace: big(row.value), assets};
}
function encodeValue(value) {
  if (!Object.keys(value.assets).length) return value.lovelace;
  const byPolicy = new Map();
  for (const name of Object.keys(value.assets).sort()) {
    const [policy, asset] = name.split('.');
    if (!byPolicy.has(policy)) byPolicy.set(policy, new Map());
    byPolicy.get(policy).set(fromHex(asset), value.assets[name]);
  }
  return [value.lovelace, new Map([...byPolicy].map(([policy, names]) => [fromHex(policy), names]))];
}
function decodeValue(raw) {
  if (typeof raw === 'number' || typeof raw === 'bigint') return {lovelace: big(raw), assets: {}};
  if (!Array.isArray(raw) || raw.length !== 2 || !(raw[1] instanceof Map)) fail('output value is malformed');
  const assets = {};
  for (const [policy, names] of raw[1]) {
    if (!(policy instanceof Uint8Array) || policy.length !== 28 || !(names instanceof Map)) fail('output assets are malformed');
    for (const [asset, quantity] of names) {
      if (!(asset instanceof Uint8Array) || asset.length > 32 || typeof quantity === 'string' || big(quantity) <= 0n) fail('output assets are malformed');
      const key = toHex(policy) + '.' + toHex(asset);
      if (Object.hasOwn(assets, key)) fail('duplicate asset in output');
      assets[key] = big(quantity);
    }
  }
  return {lovelace: big(raw[0]), assets};
}

// ------------------------------------------------------------------ plutus data

export function parseTerms(terms) {
  if (!terms || !/^[0-9a-f]{64}$/.test(terms.hashlock ?? '') || !/^[0-9a-f]{56}$/.test(terms.claimant ?? '') || !/^[0-9a-f]{56}$/.test(terms.refundee ?? '')) throw Error('Invalid Cardano terms.');
  const expiryMs = big(terms.expiry_ms);
  if (expiryMs <= 0n || expiryMs % 1000n !== 0n || expiryMs >= 1n << 53n) throw Error('Cardano expiry must be whole seconds.');
  const lovelace = big(terms.lovelace);
  if (lovelace <= 0n || lovelace >= 1n << 63n) throw Error('Invalid Cardano amount.');
  return {hashlock: terms.hashlock, claimant: terms.claimant, refundee: terms.refundee, expiryMs, value: {lovelace, assets: parseAssets(terms.assets ?? '')}, outref: terms.outref};
}
export function datumBytes(terms) {
  const t = terms.expiryMs === undefined ? parseTerms(terms) : terms;
  return encode(new Tag(121, [fromHex(t.hashlock), fromHex(t.claimant), fromHex(t.refundee), t.expiryMs]));
}
export function redeemerData(op, preimageHex) {
  if (op === 'refund') return new Tag(122, []);
  if (op === 'claim' && /^[0-9a-f]{64}$/.test(preimageHex ?? '')) return new Tag(121, [fromHex(preimageHex)]);
  throw Error('Invalid Cardano redeemer.');
}
export const expirySlot = (terms, systemStart = PREVIEW.systemStart) => Number(terms.expiryMs / 1000n) - systemStart;

// ------------------------------------------------------------------ protocol parameters

export function ratio(pair) {
  if (!Array.isArray(pair) || pair.length !== 2) throw Error('Invalid protocol parameter.');
  const [num, den] = pair.map(big);
  if (num < 0n || den <= 0n) throw Error('Invalid protocol parameter.');
  return {num, den};
}
export function parseParams(p) {
  const out = {
    minFeeA: big(p.minFeeA), minFeeB: big(p.minFeeB), coinsPerUtxoByte: big(p.coinsPerUtxoByte), maxTxSize: Number(p.maxTxSize),
    priceMem: ratio(p.priceMem), priceStep: ratio(p.priceStep), collateralPercent: big(p.collateralPercent), maxCollateralInputs: Number(p.maxCollateralInputs),
    maxTxExMem: big(p.maxTxExMem), maxTxExSteps: big(p.maxTxExSteps), costModelV3: (p.costModelV3 ?? []).map(big),
    claimMarginSlots: Number(p.claimMarginSlots ?? CLAIM_SLOT_MARGIN), validitySlots: Number(p.validitySlots ?? CLAIM_VALIDITY_SLOTS), // only a private test cluster overrides these
    slot: p.slot === undefined ? undefined : Number(p.slot),
    systemStart: Number(p.systemStart ?? p.system_start ?? PREVIEW.systemStart), // only a private test cluster differs from preview
  };
  if (!(out.minFeeA > 0n && out.minFeeB >= 0n && out.coinsPerUtxoByte > 0n && out.maxTxSize > 1024 && out.collateralPercent >= 100n && out.costModelV3.length >= 200 && out.maxCollateralInputs >= 1)) throw Error('Invalid Cardano protocol parameters.');
  return out;
}
export const unitsFee = (params, units) => ceilDiv(big(units.memory) * params.priceMem.num * params.priceStep.den + big(units.steps) * params.priceStep.num * params.priceMem.den, params.priceMem.den * params.priceStep.den);
export const sizeFee = (params, bytes) => params.minFeeA * BigInt(bytes) + params.minFeeB;
export const minUtxo = (params, outputBytes) => (160n + BigInt(outputBytes)) * params.coinsPerUtxoByte;

export function languageViews(params) { return encode(new Map([[2, params.costModelV3]])); }
export function scriptDataHash(redeemerBytes, params) { return blake2b(concat(redeemerBytes, languageViews(params)), {dkLen: 32}); }

// ------------------------------------------------------------------ building blocks

const ceilDiv = (a, b) => (a + b - 1n) / b;
const refKey = r => `${r.txid}#${r.index}`;
export function parseRef(text) {
  const m = /^([0-9a-f]{64})#(0|[1-9][0-9]{0,9})$/.exec(text ?? '');
  if (!m || Number(m[2]) > 0xffffffff) throw Error('Invalid Cardano output reference.');
  return {txid: m[1], index: Number(m[2])};
}
const cmpRef = (a, b) => (a.txid < b.txid ? -1 : a.txid > b.txid ? 1 : a.index - b.index);
const inputItem = r => [fromHex(r.txid), r.index];
const refList = refs => [...refs].sort(cmpRef).map(inputItem);
function outputItem({address, value, datum}) {
  const map = new Map([[0, address], [1, encodeValue(value)]]);
  if (datum) map.set(2, [1, new Tag(24, datum)]);
  return map;
}
const outputSize = o => encode(outputItem(o)).length;
const minFor = (params, address, value) => minUtxo(params, outputSize({address, value: {lovelace: (1n << 63n) - 1n, assets: value.assets}}));

function bodyMap({inputs, outputs, fee, ttl, start, hash, collateral, signers, collateralReturn, totalCollateral}) {
  const body = new Map([[0, refList(inputs)], [1, outputs.map(outputItem)], [2, fee]]);
  if (ttl !== undefined) body.set(3, ttl);
  if (start !== undefined) body.set(8, start);
  if (hash) body.set(11, hash);
  if (collateral) body.set(13, refList(collateral));
  if (signers) body.set(14, signers.map(fromHex));
  body.set(15, PREVIEW.networkId);
  if (collateralReturn) body.set(16, outputItem(collateralReturn));
  if (totalCollateral !== undefined) body.set(17, totalCollateral);
  return body;
}
function fullTx(bodyBytes, witnessBytes) {
  return concat(Uint8Array.of(0x84), bodyBytes, witnessBytes, Uint8Array.of(0xf5, 0xf6));
}
function witnessMap({vkeys, redeemerBytes, script}) {
  const entries = [];
  if (vkeys) entries.push([0, vkeys]);
  if (redeemerBytes) entries.push([5, new Raw(redeemerBytes)]);
  if (script) entries.push([SCRIPT_TAG_V3, [script]]);
  return encode(new Map(entries));
}
const dummyVkeys = n => Array.from({length: n}, (_, i) => [new Uint8Array(32).fill(i + 1), new Uint8Array(64).fill(i + 1)]);

/** Pick wallet UTxOs that cover `need` (lovelace and native assets), preferring ADA-only UTxOs and never `skip`. */
export function selectInputs(utxos, need, skip = new Set(), extra = 0n) {
  const usable = utxos.filter(u => !skip.has(refKey(u)));
  const picked = [];
  let have = emptyValue();
  const take = u => { picked.push(u); have = addValue(have, u.value); };
  for (const name of Object.keys(need.assets)) {
    while ((have.assets[name] ?? 0n) < need.assets[name]) {
      const next = usable.filter(u => !picked.includes(u) && (u.value.assets[name] ?? 0n) > 0n).sort((a, b) => (b.value.assets[name] > a.value.assets[name] ? 1 : -1))[0];
      if (!next) throw Error('Wallet does not hold the required Cardano assets.');
      take(next);
    }
  }
  const rest = usable.filter(u => !picked.includes(u)).sort((a, b) => (Object.keys(a.value.assets).length - Object.keys(b.value.assets).length) || (b.value.lovelace > a.value.lovelace ? 1 : b.value.lovelace < a.value.lovelace ? -1 : 0));
  while (have.lovelace < need.lovelace + extra) {
    const next = rest.shift();
    if (!next) throw Error('Wallet does not hold enough lovelace.');
    take(next);
  }
  return {picked, rest, have};
}

const norm = params => (params?.priceMem?.num !== undefined ? params : parseParams(params));

function settle(makeBody, makeWitness, params, units) {
  // Iterate to a fee that covers the size (including dummy signatures) and the script execution.
  let fee = 300_000n;
  for (let i = 0; i < 8; i++) {
    const size = fullTx(encode(makeBody(fee)), makeWitness()).length + FEE_MARGIN_BYTES;
    const needed = sizeFee(params, size) + (units ? unitsFee(params, units) : 0n);
    if (needed === fee || (needed < fee && i > 0)) return fee;
    fee = needed;
  }
  throw Error('Could not settle the Cardano fee.');
}

const signerKeys = picked => [...new Set(picked.map(u => addressInfo(u.address).keyHash).filter(Boolean))];
const signerCountFor = picked => Math.max(1, signerKeys(picked).length);

// ------------------------------------------------------------------ fund

/** Build the fund transaction: an escrow output with the inline datum, change back to the wallet, no script. */
export function buildFund({terms, walletUtxos, changeAddress, params, maxFee = MAX_FEE_LOVELACE}) {
  const t = parseTerms(terms), script = validateScript(), p = norm(params);
  const escrowOutput = {address: script.address, value: t.value, datum: datumBytes(t)};
  const escrowMin = minFor(p, script.address, t.value);
  if (t.value.lovelace < escrowMin) throw Error(`Cardano escrow needs at least ${escrowMin} lovelace.`);
  let extra = 600_000n + minFor(p, changeAddress, emptyValue());
  for (let attempt = 0; attempt < 8; attempt++) {
    const {picked, have} = selectInputs(walletUtxos, t.value, new Set(), extra);
    const inputs = picked.map(u => ({txid: u.txid, index: u.index}));
    const changeFor = fee => addValue(addValue(have, t.value, -1n), {lovelace: fee, assets: {}}, -1n);
    const build = fee => {
      let change;
      try { change = changeFor(fee); } catch { change = {lovelace: 0n, assets: have.assets}; }
      return bodyMap({inputs, outputs: [escrowOutput, {address: changeAddress, value: change}], fee});
    };
    const fee = settle(build, () => witnessMap({vkeys: dummyVkeys(signerCountFor(picked))}), p);
    if (fee > maxFee) throw Error('Cardano fee is unexpectedly large.');
    let change;
    try { change = changeFor(fee); } catch { extra += 500_000n; continue; }
    const floor = minFor(p, changeAddress, change);
    if (change.lovelace < floor) { extra += floor - change.lovelace + 1n; continue; }
    const bodyBytes = encode(build(fee)), txBytes = fullTx(bodyBytes, witnessMap({}));
    if (txBytes.length > p.maxTxSize) throw Error('Cardano transaction is too large.');
    return {txBytes, bodyBytes, fee, expect: {op: 'fund', terms: t, inputs: picked, changeAddress, params: p}};
  }
  throw Error('Wallet does not hold enough lovelace for the escrow, fee and change.');
}

// ------------------------------------------------------------------ claim / refund

/** Build a claim or refund spend of the escrow. `escrow` is {txid,index,value}; wallet UTxOs are {txid,index,address,value}. */
export function buildSpend({op, terms, escrow, preimage, walletUtxos, collateralUtxos, changeAddress, walletKeyHash, params, budget, nowSlot, maxFee = MAX_FEE_LOVELACE}) {
  if (op !== 'claim' && op !== 'refund') throw Error('Invalid Cardano operation.');
  const t = parseTerms(terms), p = norm(params), validator = validateScript();
  if (!Number.isSafeInteger(nowSlot) || nowSlot < 0) throw Error('Cardano chain head is unavailable.');
  const role = op === 'claim' ? t.claimant : t.refundee, deadline = expirySlot(t, p.systemStart);
  if (walletKeyHash !== role) throw Error('Wallet is not the ' + (op === 'claim' ? 'claimant' : 'refundee') + ' of this escrow.');
  if (op === 'claim' && nowSlot + p.claimMarginSlots >= deadline) throw Error('Cardano escrow is too close to its deadline to claim.');
  if (op === 'refund' && nowSlot < deadline) throw Error('Cardano escrow cannot be refunded before its deadline.');
  const units = {memory: big(budget.memory), steps: big(budget.steps)};
  if (units.memory <= 0n || units.steps <= 0n || units.memory > p.maxTxExMem || units.steps > p.maxTxExSteps) throw Error('Invalid Cardano execution budget.');
  const escrowRef = {txid: escrow.txid, index: escrow.index};
  if (!valueEquals(escrow.value, t.value)) throw Error('Cardano escrow value does not match the terms.');
  const redeemer = redeemerData(op, preimage);
  const isEscrow = u => u.txid === escrow.txid && u.index === escrow.index;
  const collaterals = (collateralUtxos ?? []).filter(u => Object.keys(u.value.assets).length === 0 && !isEscrow(u) && u.value.lovelace >= 1_000_000n)
    .sort((a, b) => (a.value.lovelace < b.value.lovelace ? -1 : a.value.lovelace > b.value.lovelace ? 1 : 0));
  if (!collaterals.length) throw Error('Wallet has no ADA-only collateral UTxO of at least 1 ADA.');
  const sortedInputs = feeUtxos => [escrowRef, ...feeUtxos.map(u => ({txid: u.txid, index: u.index}))].sort(cmpRef);
  const redeemerBytes = feeUtxos => encode(new Map([[[0, sortedInputs(feeUtxos).findIndex(r => r.txid === escrow.txid && r.index === escrow.index)], [redeemer, [units.memory, units.steps]]]]));
  for (const collateral of collaterals) {
    const others = walletUtxos.filter(u => !isEscrow(u) && !(u.txid === collateral.txid && u.index === collateral.index));
    const feeChoices = others.length ? [[selectInputs(others, emptyValue(), new Set(), 1n).picked[0]], []] : [[]];
    for (const feeUtxos of feeChoices) {
      const inputs = sortedInputs(feeUtxos), inputValue = sumValues([escrow.value, ...feeUtxos.map(u => u.value)]), hash = scriptDataHash(redeemerBytes(feeUtxos), p);
      const build = fee => {
        let out;
        try { out = addValue(inputValue, {lovelace: fee, assets: {}}, -1n); } catch { out = {lovelace: 0n, assets: inputValue.assets}; }
        const total = ceilDiv(fee * p.collateralPercent, 100n);
        let back;
        try { back = addValue(collateral.value, {lovelace: total, assets: {}}, -1n); } catch { back = undefined; }
        const returnOutput = back && back.lovelace >= minFor(p, changeAddress, back) ? {address: changeAddress, value: back} : undefined;
        return bodyMap({inputs, outputs: [{address: changeAddress, value: out}], fee, hash, collateral: [collateral], signers: [role],
          ttl: op === 'claim' ? Math.min(deadline, nowSlot + p.validitySlots) : undefined, start: op === 'refund' ? deadline : undefined,
          collateralReturn: returnOutput, totalCollateral: returnOutput ? total : undefined});
      };
      const witnessFor = () => witnessMap({vkeys: dummyVkeys(signerCountFor([...feeUtxos, collateral])), redeemerBytes: redeemerBytes(feeUtxos), script: validator.script});
      const fee = settle(build, witnessFor, p, units);
      if (fee > maxFee) throw Error('Cardano fee is unexpectedly large.');
      if (collateral.value.lovelace < ceilDiv(fee * p.collateralPercent, 100n)) continue;
      let out;
      try { out = addValue(inputValue, {lovelace: fee, assets: {}}, -1n); } catch { continue; }
      if (out.lovelace < minFor(p, changeAddress, out)) continue;
      const bodyBytes = encode(build(fee)), txBytes = fullTx(bodyBytes, witnessMap({redeemerBytes: redeemerBytes(feeUtxos), script: validator.script}));
      if (txBytes.length > p.maxTxSize) throw Error('Cardano transaction is too large.');
      return {txBytes, bodyBytes, fee, expect: {op, terms: t, escrow: {...escrowRef, value: escrow.value}, feeInputs: feeUtxos, collateral, changeAddress, walletKeyHash, preimage, params: p, budget: units, nowSlot}};
    }
  }
  throw Error('Wallet does not hold enough lovelace to pay the Cardano fee and collateral.');
}

// ------------------------------------------------------------------ decoding

const BODY_KEYS = new Set([0, 1, 2, 3, 8, 11, 13, 14, 15, 16, 17]);
const WITNESS_KEYS = new Set([0, 5, 7]);
const asList = (value, what) => {
  if (value instanceof Tag && value.tag === 258) value = value.value;
  if (!Array.isArray(value)) fail(what + ' is malformed');
  return value;
};
function refOf(item) {
  if (!Array.isArray(item) || item.length !== 2 || !(item[0] instanceof Uint8Array) || item[0].length !== 32 || typeof item[1] !== 'number' || item[1] < 0) fail('input reference is malformed');
  return {txid: toHex(item[0]), index: item[1]};
}
export const parseOutputItem = item => parseOutput(item);
function parseOutput(item) {
  let address, value, datum = null, scriptRef = false;
  if (item instanceof Map) {
    for (const key of item.keys()) if (![0, 1, 2, 3].includes(key)) fail('output has an unknown field');
    address = item.get(0); value = item.get(1);
    const option = item.get(2);
    if (option !== undefined) {
      if (!Array.isArray(option) || option.length !== 2) fail('output datum is malformed');
      if (option[0] === 1 && option[1] instanceof Tag && option[1].tag === 24 && option[1].value instanceof Uint8Array) datum = {kind: 'inline', bytes: option[1].value};
      else if (option[0] === 0 && option[1] instanceof Uint8Array) datum = {kind: 'hash'};
      else fail('output datum is malformed');
    }
    scriptRef = item.has(3);
  } else if (Array.isArray(item) && item.length >= 2 && item.length <= 3) {
    [address, value] = item;
    if (item.length === 3) datum = {kind: 'hash'};
  } else fail('output is malformed');
  if (!(address instanceof Uint8Array)) fail('output address is malformed');
  return {address, value: decodeValue(value), datum, scriptRef};
}

/** Decode transaction bytes into plain facts. Nothing here trusts the builder. */
export function inspectTx(txBytes) {
  if (!(txBytes instanceof Uint8Array)) fail('transaction must be bytes');
  const parts = spans(txBytes);
  if (parts.length !== 4) fail('transaction has the wrong number of parts');
  const [bodyBytes, witnessBytes] = [txBytes.slice(...parts[0]), txBytes.slice(...parts[1])];
  const body = decode(bodyBytes), witness = decode(witnessBytes);
  if (!(body instanceof Map) || !(witness instanceof Map)) fail('transaction body is malformed');
  if (decode(txBytes.slice(...parts[2])) !== true) fail('transaction is not marked valid');
  if (decode(txBytes.slice(...parts[3])) !== null) fail('transaction carries auxiliary data');
  const unknownBodyKeys = [...body.keys()].filter(k => !BODY_KEYS.has(k)), unknownWitnessKeys = [...witness.keys()].filter(k => !WITNESS_KEYS.has(k));
  const num = key => { const v = body.get(key); if (v === undefined) return undefined; if (typeof v !== 'number' && typeof v !== 'bigint') fail('field ' + key + ' is malformed'); return big(v); };
  const inputs = asList(body.get(0), 'inputs').map(refOf), outputs = asList(body.get(1), 'outputs').map(parseOutput);
  const collateral = body.has(13) ? asList(body.get(13), 'collateral').map(refOf) : [];
  const signers = body.has(14) ? asList(body.get(14), 'required signers').map(s => { if (!(s instanceof Uint8Array) || s.length !== 28) fail('required signer is malformed'); return toHex(s); }) : [];
  const dataHash = body.get(11);
  const witnessSpans = mapSpans(witnessBytes);
  let redeemers = [], redeemerBytes;
  const redeemerSpan = witnessSpans.find(e => e.key === 5);
  if (redeemerSpan) {
    redeemerBytes = witnessBytes.slice(redeemerSpan.start, redeemerSpan.end);
    const raw = witness.get(5);
    const entries = raw instanceof Map ? [...raw].map(([k, v]) => [...k, ...v]) : Array.isArray(raw) ? raw : fail('redeemers are malformed');
    redeemers = entries.map(e => {
      if (!Array.isArray(e) || e.length !== 4 || !Array.isArray(e[3]) || e[3].length !== 2) fail('redeemer is malformed');
      return {tag: e[0], index: e[1], data: e[2], units: {memory: big(e[3][0]), steps: big(e[3][1])}};
    });
  }
  const vkeys = witness.has(0) ? asList(witness.get(0), 'signatures').map(w => ({key: w[0], signature: w[1]})) : [];
  const scripts = witness.has(SCRIPT_TAG_V3) ? asList(witness.get(SCRIPT_TAG_V3), 'scripts') : [];
  return {
    bodyBytes, witnessBytes, bodyHash: blake2b(bodyBytes, {dkLen: 32}), size: txBytes.length,
    inputs, outputs, fee: num(2), ttl: body.has(3) ? Number(num(3)) : undefined, start: body.has(8) ? Number(num(8)) : undefined,
    scriptDataHash: dataHash instanceof Uint8Array ? toHex(dataHash) : undefined, collateral, signers, networkId: body.get(15),
    collateralReturn: body.has(16) ? parseOutput(body.get(16)) : null, totalCollateral: num(17),
    unknownBodyKeys, unknownWitnessKeys, redeemers, redeemerBytes, scripts, vkeys,
  };
}

const sameRefs = (a, b) => a.length === b.length && new Set(a.map(refKey)).size === a.length && a.every(r => b.some(x => refKey(x) === refKey(r)));
const sameAddress = (a, b) => equalBytes(a, b);
function commonChecks(tx, params) {
  if (tx.unknownBodyKeys.length) fail('unexpected transaction fields ' + tx.unknownBodyKeys.join(','));
  if (tx.unknownWitnessKeys.length) fail('unexpected witness fields ' + tx.unknownWitnessKeys.join(','));
  if (tx.networkId !== PREVIEW.networkId) fail('transaction does not name the Cardano testnet');
  if (tx.size > params.maxTxSize) fail('transaction is too large');
  if (tx.fee === undefined || tx.fee > MAX_FEE_LOVELACE) fail('fee is missing or too large');
  if (tx.vkeys.length) fail('transaction already carries signatures');
}
function feeCheck(tx, params, signers, units) {
  const minimum = sizeFee(params, tx.size + signers * VKEY_WITNESS_BYTES) + (units ? unitsFee(params, units) : 0n);
  if (tx.fee < minimum - BigInt(FEE_MARGIN_BYTES) * params.minFeeA) fail('fee is below the network minimum');
  if (tx.fee > minimum + FEE_SLACK_LOVELACE) fail('fee is larger than the network requires');
}

/** The checker for a fund transaction. Throws unless the bytes do exactly what `expect` says. */
export function checkFund(txBytes, expect) {
  const tx = inspectTx(txBytes), {terms, inputs, changeAddress, params} = expect, script = validateScript();
  commonChecks(tx, params);
  if (tx.redeemers.length || tx.scripts.length || tx.redeemerBytes || tx.scriptDataHash || tx.collateral.length || tx.signers.length || tx.ttl !== undefined || tx.start !== undefined || tx.collateralReturn || tx.totalCollateral !== undefined) fail('fund transaction must not run a script');
  if (!sameRefs(tx.inputs, inputs)) fail('inputs are not exactly the wallet inputs chosen');
  if (tx.outputs.length !== 2) fail('fund transaction must have an escrow output and a change output');
  const [escrow, change] = tx.outputs;
  if (!sameAddress(escrow.address, script.address) || escrow.scriptRef || escrow.datum?.kind !== 'inline' || !equalBytes(escrow.datum.bytes, datumBytes(terms))) fail('escrow output is not the pinned validator with the agreed datum');
  if (!valueEquals(escrow.value, terms.value)) fail('escrow output does not hold exactly the agreed value');
  if (!sameAddress(change.address, changeAddress) || change.datum || change.scriptRef) fail('change does not return to the wallet');
  const total = sumValues(inputs.map(u => u.value)), expected = addValue(addValue(total, terms.value, -1n), {lovelace: tx.fee, assets: {}}, -1n);
  if (!valueEquals(change.value, expected)) fail('change does not return everything not paid to the escrow and the fee');
  if (change.value.lovelace < minFor(params, changeAddress, change.value)) fail('change is below the minimum output');
  if (escrow.value.lovelace < minFor(params, script.address, escrow.value)) fail('escrow is below the minimum output');
  feeCheck(tx, params, signerCountFor(inputs));
  return summarize(tx, 'fund', expect);
}

/** The checker for a claim or refund transaction. */
export function checkSpend(txBytes, expect) {
  const tx = inspectTx(txBytes), {op, terms, escrow, feeInputs, collateral, changeAddress, walletKeyHash, preimage, params, budget} = expect, script = validateScript();
  commonChecks(tx, params);
  const role = op === 'claim' ? terms.claimant : terms.refundee, deadline = expirySlot(terms, params.systemStart);
  if (walletKeyHash !== role) fail('signer is not the ' + (op === 'claim' ? 'claimant' : 'refundee'));
  if (!sameRefs(tx.inputs, [escrow, ...feeInputs])) fail('inputs are not exactly the escrow and the chosen fee inputs');
  if (tx.outputs.length !== 1) fail('transaction must have one output');
  const [out] = tx.outputs;
  if (!sameAddress(out.address, changeAddress) || out.datum || out.scriptRef) fail('output does not go to the wallet');
  const expected = addValue(sumValues([escrow.value, ...feeInputs.map(u => u.value)]), {lovelace: tx.fee, assets: {}}, -1n);
  if (!valueEquals(out.value, expected)) fail('output does not return everything in the inputs, including every token, minus the fee');
  if (out.value.lovelace < minFor(params, changeAddress, out.value)) fail('output is below the minimum');
  if (tx.signers.length !== 1 || tx.signers[0] !== role) fail('required signer is not the ' + (op === 'claim' ? 'claimant' : 'refundee'));
  if (op === 'claim') {
    if (tx.ttl === undefined || tx.ttl > deadline || tx.start !== undefined && tx.start >= tx.ttl) fail('claim must be valid only before the deadline');
    if (expect.nowSlot !== undefined && tx.ttl <= expect.nowSlot) fail('claim validity has already passed');
    if (expect.nowSlot !== undefined && tx.ttl > expect.nowSlot + params.validitySlots) fail('claim validity reaches past the ledger time horizon');
  } else if (tx.start === undefined || tx.start < deadline || tx.ttl !== undefined && tx.ttl <= tx.start) fail('refund must be valid only at or after the deadline');
  if (tx.collateral.length !== 1 || refKey(tx.collateral[0]) !== refKey(collateral)) fail('collateral is not the chosen UTxO');
  const maxForfeit = ceilDiv(tx.fee * params.collateralPercent, 100n);
  const forfeited = tx.totalCollateral ?? collateral.value.lovelace;
  if (forfeited < maxForfeit || forfeited > maxForfeit + 1n) fail('collateral amount does not match the network requirement');
  if (tx.collateralReturn) {
    const back = tx.collateralReturn;
    if (!sameAddress(back.address, changeAddress) || back.datum || back.scriptRef || !valueEquals(back.value, addValue(collateral.value, {lovelace: forfeited, assets: {}}, -1n))) fail('collateral return is wrong');
  } else if (collateral.value.lovelace > maxForfeit + 2_000_000n) fail('collateral without a return would risk too much');
  if (tx.scripts.length !== 1 || !equalBytes(tx.scripts[0], script.script) || scriptHash(tx.scripts[0]) !== pinnedScript().hash) fail('script is not the pinned validator');
  if (tx.redeemers.length !== 1) fail('exactly one redeemer is required');
  const [r] = tx.redeemers, position = [escrow, ...feeInputs].sort(cmpRef).findIndex(x => refKey(x) === refKey(escrow));
  if (r.tag !== 0 || r.index !== position) fail('redeemer does not target the escrow input');
  if (!equalBytes(encode(r.data), encode(redeemerData(op, preimage)))) fail('redeemer is not the expected action');
  if (r.units.memory !== budget.memory || r.units.steps !== budget.steps) fail('execution budget is not the fixed budget');
  if (!tx.scriptDataHash || tx.scriptDataHash !== toHex(scriptDataHash(tx.redeemerBytes, params))) fail('script data hash does not match the redeemer and cost model');
  feeCheck(tx, params, signerCountFor([...feeInputs, collateral]), budget);
  return summarize(tx, op, expect);
}

function describeValue(v) {
  const tokens = Object.entries(v.assets).map(([name, q]) => `${q} of ${name}`);
  return [`${v.lovelace} lovelace`, ...tokens].join(' + ');
}
function summarize(tx, op, expect) {
  const lines = [];
  if (op === 'fund') lines.push(`Lock ${describeValue(expect.terms.value)} in the Hegemon HTLC for claimant ${expect.terms.claimant}, refundable to ${expect.terms.refundee} from ${new Date(Number(expect.terms.expiryMs)).toISOString()}.`);
  if (op === 'claim') lines.push(`Claim ${describeValue(expect.escrow.value)} from ${expect.escrow.txid}#${expect.escrow.index} to your wallet. This reveals the swap secret on chain.`);
  if (op === 'refund') lines.push(`Refund ${describeValue(expect.escrow.value)} from ${expect.escrow.txid}#${expect.escrow.index} to your wallet.`);
  lines.push(`Network fee ${tx.fee} lovelace; transaction ${toHex(tx.bodyHash)}.`);
  return {op, txid: toHex(tx.bodyHash), fee: tx.fee, lines, tx};
}

/** Add the wallet's vkey witnesses to our own witness set and verify each against the body hash. */
export function assembleSigned(txBytes, walletWitnessSetBytes, ed25519verify) {
  const tx = inspectTx(txBytes);
  const witness = decode(walletWitnessSetBytes);
  if (!(witness instanceof Map)) throw Error('Wallet returned a malformed witness set.');
  for (const key of witness.keys()) if (key !== 0) throw Error('Wallet added unexpected witness data.');
  const vkeys = asList(witness.get(0), 'wallet signatures');
  if (!vkeys.length) throw Error('Wallet returned no signatures.');
  const seen = new Set();
  for (const [vk, sig] of vkeys) {
    if (!(vk instanceof Uint8Array) || vk.length !== 32 || !(sig instanceof Uint8Array) || sig.length !== 64) throw Error('Wallet signature is malformed.');
    if (!ed25519verify(sig, tx.bodyHash, vk)) throw Error('Wallet signature does not verify against the transaction.');
    seen.add(toHex(blake2b(vk, {dkLen: 28})));
  }
  const entries = mapSpans(tx.witnessBytes);
  const merged = [[0, vkeys.map(([vk, sig]) => [vk, sig])]];
  for (const e of entries) merged.push([e.key, new Raw(tx.witnessBytes.slice(e.start, e.end))]);
  merged.sort((a, b) => a[0] - b[0]);
  const parts = spans(txBytes);
  return {txBytes: fullTx(txBytes.slice(...parts[0]), encode(new Map(merged))), signers: [...seen]};
}
