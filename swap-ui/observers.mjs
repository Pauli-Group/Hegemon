/* Learn the counterparty's preimage from a public claim, without a manual explorer lookup.
 *
 * The Worker fetches; this module decides. It re-derives everything it relies on: a Bitcoin witness must end in the
 * agreed HTLC script, a Cardano transaction body must hash to the reported transaction ID and its redeemer for this
 * input must carry a value whose SHA-256 is the hashlock, an Ethereum Claimed event must come from the agreed contract.
 * A claim that does not hash to the hashlock is an error, never a result. A provider that has not indexed a spend yet
 * gives `pending`, never `unspent`.
 */
import {blake2b, sha256} from './vendor/hash.mjs';
import {bitcoinWitnessScript, TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';
import {Tag, decode, equalBytes, fromHex, spans, toHex} from './cbor.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const sha = bytes => toHex(sha256(bytes));
const fail = message => { throw Error('Counterparty observation failed: ' + message); };

export const ENOUGH_CONFIRMATIONS = 2;
/** States: unspent (nothing seen), pending (spent but the provider has not indexed the details), claimed, refunded. */
const result = (chain, state, extra = {}) => ({chain, state, ...extra});
const checkLock = hashlock => { if (!HEX64.test(hashlock ?? '')) fail('invalid hashlock'); };

// ---------------------------------------------------------------- Bitcoin

export async function observeBitcoin(terms, read, {confirmations = ENOUGH_CONFIRMATIONS} = {}) {
  checkLock(terms.hashlock);
  const script = bitcoinWitnessScript(terms);
  if (!HEX64.test(terms.txid ?? '') || !Number.isSafeInteger(terms.vout) || terms.vout < 0) fail('invalid escrow output');
  const answer = await read(terms.txid, terms.vout);
  if (answer?.genesis !== TESTNET4_GENESIS || answer.txid !== terms.txid || answer.vout !== terms.vout || !Number.isSafeInteger(answer.tip)) fail('the provider answered for a different output or network');
  if (answer.spent === false) return result('bitcoin', 'unspent', {tip: answer.tip});
  const spend = answer.spend;
  if (answer.spent !== true || !spend || !HEX64.test(spend.txid ?? '') || !Array.isArray(spend.witness)) fail('invalid spend data');
  const w = spend.witness;
  if (w.at(-1) !== script) fail('the spending transaction does not reveal the agreed HTLC script');
  const depth = Number.isSafeInteger(spend.confirmations) ? spend.confirmations : 0, base = {txid: spend.txid, confirmations: depth, enough: depth >= confirmations};
  if (w.length === 4 && w[2] === '01' && /^[0-9a-f]{64}$/.test(w[1])) {
    if (sha(fromHex(w[1])) !== terms.hashlock) fail('the claim witness does not hash to the hashlock');
    return result('bitcoin', 'claimed', {...base, preimage: w[1]});
  }
  if (w.length === 3 && w[1] === '') return result('bitcoin', 'refunded', base);
  fail('the spend is neither a claim nor a refund');
}

// ---------------------------------------------------------------- Ethereum

export async function observeEthereum(terms, read, {confirmations = ENOUGH_CONFIRMATIONS} = {}) {
  checkLock(terms.hashlock);
  if (!/^0x[0-9a-f]{40}$/.test(terms.contract ?? '')) fail('invalid escrow contract');
  const answer = await read(terms.contract, terms.from_block ?? 0);
  if (answer?.chain_id !== 11155111 || answer.contract !== terms.contract || !Array.isArray(answer.events)) fail('the provider answered for a different contract or network');
  if (answer.deployed === false) return result('ethereum', 'unspent', {note: 'no contract is deployed at this address yet'});
  const events = answer.events.filter(e => e.kind === 'claimed' || e.kind === 'refunded');
  if (!events.length) return result('ethereum', answer.spent ? 'pending' : 'unspent', answer.spent ? {note: 'the contract is spent but its event is not visible yet'} : {});
  if (new Set(events.map(e => e.kind)).size > 1) fail('the contract reports both a claim and a refund');
  const first = events[0], depth = Number.isSafeInteger(first.confirmations) ? first.confirmations : 0;
  const base = {txid: first.tx_hash, confirmations: depth, enough: depth >= confirmations};
  if (first.kind === 'refunded') return result('ethereum', 'refunded', base);
  if (typeof first.data !== 'string' || !/^0x[0-9a-f]{64,}$/.test(first.data)) fail('the claim event has no preimage');
  const preimage = first.data.slice(2, 66);
  if (sha(fromHex(preimage)) !== terms.hashlock) fail('the claim event does not hash to the hashlock');
  return result('ethereum', 'claimed', {...base, preimage});
}

// ---------------------------------------------------------------- Cardano

const asList = value => { if (value instanceof Tag && value.tag === 258) value = value.value; if (!Array.isArray(value)) fail('transaction inputs are malformed'); return value; };
const compareRefs = (a, b) => { for (let i = 0; i < 32; i++) if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i]; return a[1] - b[1]; };

/** The spend redeemer of `outref` in a Plutus transaction: 'refund', or the claim preimage (hex). Pure; used by tests too. */
export function cardanoSpendOutcome(txBytes, txid, outref) {
  const parts = spans(txBytes);
  if (parts.length !== 4) fail('the spending transaction has the wrong shape');
  const bodyBytes = txBytes.slice(...parts[0]), witnessBytes = txBytes.slice(...parts[1]);
  if (toHex(blake2b(bodyBytes, {dkLen: 32})) !== txid) fail('the spending transaction does not match its ID');
  if (decode(txBytes.slice(...parts[2])) !== true) fail('the spending transaction is not a valid-script transaction');
  const body = decode(bodyBytes), witness = decode(witnessBytes);
  if (!(body instanceof Map) || !(witness instanceof Map)) fail('the spending transaction is malformed');
  const [hash, indexText] = outref.split('#'), target = [fromHex(hash), Number(indexText)];
  const inputs = asList(body.get(0)).map(i => {
    if (!Array.isArray(i) || i.length !== 2 || !(i[0] instanceof Uint8Array) || i[0].length !== 32 || typeof i[1] !== 'number') fail('an input is malformed');
    return i;
  });
  const position = inputs.slice().sort(compareRefs).findIndex(i => equalBytes(i[0], target[0]) && i[1] === target[1]);
  if (position < 0) fail('the spending transaction does not spend the escrow');
  const raw = witness.get(5);
  let entries = [];
  if (raw instanceof Map) entries = [...raw].map(([k, v]) => [...k, ...v]);
  else if (Array.isArray(raw)) entries = raw;
  const mine = entries.filter(e => Array.isArray(e) && e[0] === 0 && e[1] === position);
  if (mine.length !== 1) fail('the spending transaction has no single spend redeemer for the escrow');
  const data = mine[0][2];
  if (data instanceof Tag && data.tag === 122 && Array.isArray(data.value) && data.value.length === 0) return 'refund';
  if (data instanceof Tag && data.tag === 121 && Array.isArray(data.value) && data.value.length === 1 && data.value[0] instanceof Uint8Array && data.value[0].length === 32) return toHex(data.value[0]);
  fail('the redeemer is neither a claim nor a refund');
}

export async function observeCardano(terms, read, {confirmations = ENOUGH_CONFIRMATIONS} = {}) {
  checkLock(terms.hashlock);
  if (!/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(terms.outref ?? '')) fail('invalid escrow output');
  const answer = await read(terms.outref);
  if (answer?.network !== 'preview' || answer.outref !== terms.outref) fail('the provider answered for a different output or network');
  if (answer.spent === false) return result('cardano', 'unspent');
  if (answer.spent !== true) fail('invalid spend data');
  if (answer.indexed !== true) return result('cardano', 'pending', {note: 'the escrow is spent but the provider has not indexed the spending transaction yet'});
  if (!HEX64.test(answer.spender ?? '') || typeof answer.cbor !== 'string') fail('invalid spend data');
  const outcome = cardanoSpendOutcome(fromHex(answer.cbor), answer.spender, terms.outref), depth = Number.isSafeInteger(answer.confirmations) ? answer.confirmations : 0;
  const base = {txid: answer.spender, confirmations: depth, enough: depth >= confirmations};
  if (outcome === 'refund') return result('cardano', 'refunded', base);
  if (sha(fromHex(outcome)) !== terms.hashlock) fail('the claim redeemer does not hash to the hashlock');
  return result('cardano', 'claimed', {...base, preimage: outcome});
}

export const observe = {bitcoin: observeBitcoin, ethereum: observeEthereum, cardano: observeCardano};

// ---------------------------------------------------------------- saving

/** Put a learned preimage into the encrypted vault. Nothing is saved unless it hashes to the agreed hashlock. */
export async function saveLearnedPreimage({preimage, hashlock, label, passphrase, confirm}, {encryptRecovery, addVault, listVault}) {
  checkLock(hashlock);
  if (typeof preimage !== 'string' || !HEX64.test(preimage) || sha(fromHex(preimage)) !== hashlock) fail('the preimage does not match the hashlock');
  if ((await listVault()).some(item => item.envelope.hashlock === hashlock)) return {saved: false, reason: 'An encrypted backup for this hashlock already exists.'};
  if (typeof passphrase !== 'string' || passphrase !== confirm || passphrase.length < 12 || passphrase.length > 1024) fail('backup passphrases must match and contain at least 12 characters');
  const secret = fromHex(preimage);
  try {
    const envelope = await encryptRecovery(secret, passphrase);
    await addVault({label, envelope});
    return {saved: true, envelope};
  } finally { secret.fill(0); }
}
