import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {blake2b, sha256} from './vendor/hash.mjs';
import {bitcoinWitnessScript, TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';
import {Tag, encode, fromHex, toHex} from './cbor.mjs';
import * as ct from './cardano-tx.mjs';
import {cardanoSpendOutcome, observeBitcoin, observeCardano, observeEthereum, saveLearnedPreimage} from './observers.mjs';

const preimage = '5a'.repeat(32), hashlock = toHex(sha256(fromHex(preimage)));

// ------------------------------------------------------------ Bitcoin
const btcTerms = () => ({txid: 'aa'.repeat(32), vout: 1, hashlock, claimant_key: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa', refund_key: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27', refund_height: 200_000, amount_sats: 5000});
const btcRead = spend => async (txid, vout) => ({genesis: TESTNET4_GENESIS, txid, vout, tip: 1000, ...spend});

test('Bitcoin: a claim witness yields the preimage with its depth; a refund yields none; unspent and mempool spends are told apart', async () => {
  const t = btcTerms(), script = bitcoinWitnessScript(t), sig = '30' + 'ab'.repeat(70);
  const claim = await observeBitcoin(t, btcRead({spent: true, spend: {txid: 'bb'.repeat(32), confirmations: 3, witness: [sig, preimage, '01', script]}}));
  assert.deepEqual([claim.state, claim.preimage, claim.confirmations, claim.enough], ['claimed', preimage, 3, true]);
  const mempool = await observeBitcoin(t, btcRead({spent: true, spend: {txid: 'bb'.repeat(32), confirmations: 0, witness: [sig, preimage, '01', script]}}));
  assert.deepEqual([mempool.state, mempool.preimage, mempool.enough], ['claimed', preimage, false], 'a mempool claim already reveals the secret but is not deep enough');
  const refund = await observeBitcoin(t, btcRead({spent: true, spend: {txid: 'bb'.repeat(32), confirmations: 5, witness: [sig, '', script]}}));
  assert.deepEqual([refund.state, refund.preimage], ['refunded', undefined]);
  assert.equal((await observeBitcoin(t, btcRead({spent: false}))).state, 'unspent');
});

test('Bitcoin: a spend that is not this HTLC, a wrong preimage, a wrong network and a different output are errors, never results', async () => {
  const t = btcTerms(), script = bitcoinWitnessScript(t), sig = '30' + 'ab'.repeat(70), good = {txid: 'bb'.repeat(32), confirmations: 3};
  const spend = witness => btcRead({spent: true, spend: {...good, witness}});
  await assert.rejects(observeBitcoin(t, spend([sig, preimage, '01', bitcoinWitnessScript({...t, refund_height: 200_001})])), /agreed HTLC script/);
  await assert.rejects(observeBitcoin(t, spend([sig, '77'.repeat(32), '01', script])), /does not hash/);
  await assert.rejects(observeBitcoin(t, spend([sig, preimage.slice(2), '01', script])), /neither a claim nor a refund/);
  await assert.rejects(observeBitcoin(t, spend([sig, script])), /neither a claim nor a refund/);
  await assert.rejects(observeBitcoin(t, async (txid, vout) => ({genesis: '0'.repeat(64), txid, vout, tip: 1, spent: false})), /different output or network/);
  await assert.rejects(observeBitcoin(t, async () => ({genesis: TESTNET4_GENESIS, txid: 'cc'.repeat(32), vout: 1, tip: 1, spent: false})), /different output or network/);
  await assert.rejects(observeBitcoin({...t, hashlock: 'zz'}, btcRead({spent: false})), /hashlock/);
});

// ------------------------------------------------------------ Ethereum
const contract = '0x' + 'ab'.repeat(20);
const ethRead = answer => async (address, from) => ({chain_id: 11155111, contract: address, tip: 100, deployed: true, spent: false, events: [], ...answer});
const claimedEvent = (data, extra = {}) => ({kind: 'claimed', tx_hash: '0x' + 'cd'.repeat(32), block_number: 90, confirmations: 11, data, ...extra});

test('Ethereum: the Claimed event data is the preimage; token and ether event layouts both work; spent-without-event is pending', async () => {
  const t = {contract, hashlock};
  const ether = await observeEthereum(t, ethRead({spent: true, events: [claimedEvent('0x' + preimage + '00'.repeat(32) + '00'.repeat(32))]}));
  assert.deepEqual([ether.state, ether.preimage, ether.enough], ['claimed', preimage, true]);
  const token = await observeEthereum(t, ethRead({spent: true, events: [claimedEvent('0x' + preimage)]}));
  assert.equal(token.preimage, preimage);
  const shallow = await observeEthereum(t, ethRead({spent: true, events: [claimedEvent('0x' + preimage, {confirmations: 1})]}));
  assert.deepEqual([shallow.state, shallow.enough], ['claimed', false]);
  assert.equal((await observeEthereum(t, ethRead({spent: true, events: [{kind: 'refunded', tx_hash: '0x' + 'ef'.repeat(32), confirmations: 4, data: '0x'}]}))).state, 'refunded');
  assert.equal((await observeEthereum(t, ethRead({spent: true, events: []}))).state, 'pending');
  assert.equal((await observeEthereum(t, ethRead({spent: false, events: []}))).state, 'unspent');
  assert.equal((await observeEthereum(t, ethRead({deployed: false}))).state, 'unspent');
});

test('Ethereum: a claim that does not hash to the hashlock, both events, the wrong network and a different contract are errors', async () => {
  const t = {contract, hashlock};
  await assert.rejects(observeEthereum(t, ethRead({spent: true, events: [claimedEvent('0x' + '77'.repeat(32))]})), /does not hash/);
  await assert.rejects(observeEthereum(t, ethRead({spent: true, events: [claimedEvent('0x1234')]})), /no preimage/);
  await assert.rejects(observeEthereum(t, ethRead({spent: true, events: [claimedEvent('0x' + preimage), {kind: 'refunded', tx_hash: '0x' + 'ef'.repeat(32), confirmations: 4, data: '0x'}]})), /both a claim and a refund/);
  await assert.rejects(observeEthereum(t, async () => ({chain_id: 1, contract, events: []})), /different contract or network/);
  await assert.rejects(observeEthereum(t, async () => ({chain_id: 11155111, contract: '0x' + 'cd'.repeat(20), events: []})), /different contract or network/);
  await assert.rejects(observeEthereum({contract: '0xAB', hashlock}, ethRead({})), /contract/);
});

// ------------------------------------------------------------ Cardano
const here = new URL('.', import.meta.url);
const claimTx = fs.readFileSync(new URL('fixtures/37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d.cbor.hex', here), 'utf8').trim();
const CLAIM_TXID = '37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d';

function synthetic({inputs, redeemers, valid = true, setTag = false}) {
  const list = inputs.map(([h, i]) => [fromHex(h), i]), body = encode(new Map([[0, setTag ? new Tag(258, list) : list], [2, 200000]]));
  const witness = encode(new Map([[5, redeemers]]));
  const bytes = new Uint8Array([0x84, ...body, ...witness, valid ? 0xf5 : 0xf4, 0xf6]);
  return {bytes, txid: toHex(blake2b(body, {dkLen: 32}))};
}
const units = [1, 2];

test('Cardano: the real preview claim yields its preimage by the ledger index of the spent escrow input', () => {
  const tx = ct.inspectTx(fromHex(claimTx));
  assert.equal(toHex(tx.bodyHash), CLAIM_TXID);
  const escrowRef = tx.inputs.map(i => i.txid + '#' + i.index).find(r => r.startsWith('3554254f'));
  assert.ok(escrowRef, 'the fixture spends the fixture escrow');
  const outcome = cardanoSpendOutcome(fromHex(claimTx), CLAIM_TXID, escrowRef);
  assert.match(outcome, /^[0-9a-f]{64}$/);
  const other = tx.inputs.map(i => i.txid + '#' + i.index).find(r => !r.startsWith('3554254f'));
  assert.throws(() => cardanoSpendOutcome(fromHex(claimTx), CLAIM_TXID, other), /no single spend redeemer/, 'a non-script input has no spend redeemer');
  assert.throws(() => cardanoSpendOutcome(fromHex(claimTx), '00'.repeat(32), escrowRef), /does not match its ID/);
});

test('Cardano: synthetic spends cover claim, refund, set tags, map and array redeemers, and input ordering', () => {
  const escrow = 'ee'.repeat(32) + '#0', others = [['11'.repeat(32), 3], ['ff'.repeat(32), 0]];
  // sorted order: 11..#3 (0), ee..#0 (1), ff..#0 (2): the escrow is at ledger index 1
  const claimed = synthetic({inputs: [others[1], ['ee'.repeat(32), 0], others[0]], redeemers: new Map([[[0, 1], [new Tag(121, [fromHex(preimage)]), units]]])});
  assert.equal(cardanoSpendOutcome(claimed.bytes, claimed.txid, escrow), preimage);
  const asArray = synthetic({inputs: others.concat([['ee'.repeat(32), 0]]), setTag: true, redeemers: [[0, 1, new Tag(121, [fromHex(preimage)]), units]]});
  assert.equal(cardanoSpendOutcome(asArray.bytes, asArray.txid, escrow), preimage);
  const refund = synthetic({inputs: others.concat([['ee'.repeat(32), 0]]), redeemers: new Map([[[0, 1], [new Tag(122, []), units]]])});
  assert.equal(cardanoSpendOutcome(refund.bytes, refund.txid, escrow), 'refund');
  const wrongIndex = synthetic({inputs: others.concat([['ee'.repeat(32), 0]]), redeemers: new Map([[[0, 0], [new Tag(121, [fromHex(preimage)]), units]]])});
  assert.throws(() => cardanoSpendOutcome(wrongIndex.bytes, wrongIndex.txid, escrow), /no single spend redeemer/, 'a redeemer for another input is not this escrow\'s');
  const mint = synthetic({inputs: others.concat([['ee'.repeat(32), 0]]), redeemers: new Map([[[1, 1], [new Tag(121, [fromHex(preimage)]), units]]])});
  assert.throws(() => cardanoSpendOutcome(mint.bytes, mint.txid, escrow), /no single spend redeemer/, 'only spend redeemers count');
  const junk = synthetic({inputs: others.concat([['ee'.repeat(32), 0]]), redeemers: new Map([[[0, 1], [new Tag(121, [fromHex('5a'.repeat(16))]), units]]])});
  assert.throws(() => cardanoSpendOutcome(junk.bytes, junk.txid, escrow), /neither a claim nor a refund/);
  const failedScript = synthetic({inputs: others.concat([['ee'.repeat(32), 0]]), valid: false, redeemers: new Map([[[0, 1], [new Tag(121, [fromHex(preimage)]), units]]])});
  assert.throws(() => cardanoSpendOutcome(failedScript.bytes, failedScript.txid, escrow), /valid-script/, 'a transaction whose script failed is not a claim');
  assert.throws(() => cardanoSpendOutcome(claimed.bytes, claimed.txid, 'dd'.repeat(32) + '#0'), /does not spend the escrow/);
});

test('Cardano: unindexed data is pending, indexed claims are verified against the hashlock, and anything inconsistent is refused', async () => {
  const escrow = 'ee'.repeat(32) + '#0', tx = synthetic({inputs: [[ 'ee'.repeat(32), 0]], redeemers: new Map([[[0, 0], [new Tag(121, [fromHex(preimage)]), units]]])});
  const read = answer => async outref => ({network: 'preview', outref, spent: true, indexed: true, spender: tx.txid, confirmations: 5, cbor: toHex(tx.bytes), ...answer});
  const t = {outref: escrow, hashlock};
  const claimed = await observeCardano(t, read({}));
  assert.deepEqual([claimed.state, claimed.preimage, claimed.enough, claimed.txid], ['claimed', preimage, true, tx.txid]);
  assert.equal((await observeCardano(t, read({indexed: false, cbor: undefined, spender: undefined}))).state, 'pending');
  assert.equal((await observeCardano(t, read({spent: false}))).state, 'unspent');
  await assert.rejects(observeCardano({...t, hashlock: '00'.repeat(32)}, read({})), /does not hash/);
  await assert.rejects(observeCardano(t, read({spender: '99'.repeat(32)})), /does not match its ID/);
  await assert.rejects(observeCardano(t, read({network: 'preprod'})), /different output or network/);
  await assert.rejects(observeCardano({...t, outref: 'ee'.repeat(32) + '#1'}, read({outref: 'ee'.repeat(32) + '#1'})), /does not spend the escrow/);
});

// ------------------------------------------------------------ saving
test('A learned preimage is saved only if it hashes to the hashlock, once, with matching passphrases', async () => {
  const saved = [], vault = [], deps = {encryptRecovery: async (secret, pass) => ({hashlock: toHex(sha256(secret)), pass}), addVault: async e => { saved.push(e); vault.push({envelope: e.envelope}); }, listVault: async () => vault};
  await assert.rejects(saveLearnedPreimage({preimage: '77'.repeat(32), hashlock, label: 'x', passphrase: 'a long enough pass', confirm: 'a long enough pass'}, deps), /does not match/);
  await assert.rejects(saveLearnedPreimage({preimage, hashlock, label: 'x', passphrase: 'a long enough pass', confirm: 'different pass word'}, deps), /passphrases/);
  await assert.rejects(saveLearnedPreimage({preimage, hashlock, label: 'x', passphrase: 'short', confirm: 'short'}, deps), /passphrases/);
  assert.equal(saved.length, 0);
  const done = await saveLearnedPreimage({preimage, hashlock, label: 'learned', passphrase: 'a long enough pass', confirm: 'a long enough pass'}, deps);
  assert.equal(done.saved, true);
  assert.equal(saved.length, 1);
  assert.equal(JSON.stringify(saved).includes(preimage), false, 'the plaintext secret never reaches storage');
  assert.deepEqual(await saveLearnedPreimage({preimage, hashlock, label: 'again', passphrase: 'a long enough pass', confirm: 'a long enough pass'}, deps), {saved: false, reason: 'An encrypted backup for this hashlock already exists.'});
});
