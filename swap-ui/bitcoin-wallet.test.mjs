import test from 'node:test';
import assert from 'node:assert/strict';
import {Address, SigHash, TEST_NETWORK, Transaction, secp256k1, sha256} from './vendor/btc-signer.mjs';
import * as psbt from './bitcoin-psbt.mjs';
import {BitcoinWalletError, finishBitcoinPsbt, journalRequest, prepareBitcoinPsbt} from './bitcoin-wallet.mjs';

const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const claimantPriv = new Uint8Array(32).fill(5), refundPriv = new Uint8Array(32).fill(6), walletPriv = new Uint8Array(32).fill(8);
const pub = priv => hex(secp256k1.getPublicKey(priv, true));
const preimage = '11'.repeat(32), hashlock = hex(sha256(Uint8Array.from(preimage.match(/../g), x => parseInt(x, 16))));
const walletAddress = Address(TEST_NETWORK).encode({type: 'wpkh', hash: new Uint8Array(20).fill(3)});
const destination = Address(TEST_NETWORK).encode({type: 'wpkh', hash: new Uint8Array(20).fill(4)});
const terms = {hashlock, claimant_key: pub(claimantPriv), refund_key: pub(refundPriv), refund_height: 130_000, amount_sats: 50_000};
const escrowTerms = {...terms, txid: 'ee'.repeat(32), vout: 1};

function signSpend(session, priv, flag = SigHash.ALL) {
  const tx = Transaction.fromPSBT(session.built.psbt), digest = psbt.htlcDigest(tx, session.built.expect);
  tx.updateInput(0, {partialSig: [[secp256k1.getPublicKey(priv, true), new Uint8Array([...secp256k1.sign(digest, priv, {prehash: false, format: 'der'}), flag])]]});
  return psbt.encodePsbt(tx.toPSBT());
}
function world({tip = 129_000, spent = false} = {}) {
  const log = {journal: [], broadcasts: [], verified: 0};
  const state = {tip, spent, broadcast: async hexTx => { log.broadcasts.push(hexTx); return {txid: log.expected}; }};
  const read = {
    utxos: async address => ({address, tip: state.tip, utxos: [{txid: '01'.repeat(32), vout: 0, amount_sats: 200_000, confirmations: 5}, {txid: '02'.repeat(32), vout: 0, amount_sats: 900_000, confirmations: 0}]}),
    broadcast: hexTx => state.broadcast(hexTx),
  };
  const verifyEscrow = async (t, {op} = {}) => {
    log.verified++;
    if (state.spent) throw Error('Bitcoin escrow is spent or unavailable.');
    if (t.refund_height - state.tip < 6 && op !== 'refund') throw Error('Bitcoin refund height is too close.');
    return {tip: state.tip, confirmations: 3};
  };
  const journal = {
    begin: async (chain, operation, request) => { log.journal.push(['begin', chain, operation, request]); return 'id1'; },
    finish: async (id, receipt) => log.journal.push(['finish', id, receipt]),
    uncertain: async id => log.journal.push(['uncertain', id]),
    remove: async id => log.journal.push(['remove', id]),
  };
  return {state, log, read, verifyEscrow, journal};
}

test('claim: the PSBT carries no preimage, the journal record is public only, and the signed result is broadcast and recorded', async () => {
  const w = world(), session = await prepareBitcoinPsbt({op: 'claim', terms: escrowTerms, address: destination, feeRate: 2, ...w});
  w.log.expected = session.txid;
  assert.ok(!session.psbt.includes(preimage) && !Buffer.from(session.psbt, 'base64').toString('hex').includes(preimage));
  assert.deepEqual(w.log.journal[0].slice(0, 3), ['begin', 'bitcoin', 'claim']);
  assert.deepEqual(w.log.journal[0][3], journalRequest('claim', session.terms, destination));
  const done = await finishBitcoinPsbt({session, signedPsbt: signSpend(session, claimantPriv), preimage, ...w});
  assert.equal(done.state, 'submitted');
  assert.equal(done.txid, session.txid);
  assert.deepEqual(w.log.journal.at(-1), ['finish', 'id1', {submitted: true, txid: session.txid}]);
  assert.ok(!JSON.stringify(w.log.journal).includes(preimage), 'the secret never reaches the journal');
  assert.equal(w.log.broadcasts.length, 1);
  assert.ok(w.log.verified >= 2, 'the escrow is re-verified before finalizing');
});

test('claim refuses inside the cutoff, a spent escrow, a wrong key, a wrong preimage and a hash type other than ALL', async () => {
  const near = world({tip: 129_995});
  await assert.rejects(prepareBitcoinPsbt({op: 'claim', terms: escrowTerms, address: destination, feeRate: 2, ...near}), /too close/);
  assert.equal(near.log.journal.length, 0, 'no record is written for a refused request');
  const w = world(), session = await prepareBitcoinPsbt({op: 'claim', terms: escrowTerms, address: destination, feeRate: 2, ...w});
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signSpend(session, refundPriv), preimage, ...w}), BitcoinWalletError);
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signSpend(session, claimantPriv), preimage: '22'.repeat(32), ...w}), /hashlock|preimage/);
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signSpend(session, claimantPriv, SigHash.NONE), preimage, ...w}), /SIGHASH_ALL|hash type/i);
  assert.equal(w.log.broadcasts.length, 0);
  w.state.spent = true;
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signSpend(session, claimantPriv), preimage, ...w}), /spent/);
  assert.equal(w.log.broadcasts.length, 0, 'a head that changed while the user was signing stops the claim');
});

test('refund is refused before the refund height and works after it', async () => {
  const early = world({tip: 129_999});
  await assert.rejects(prepareBitcoinPsbt({op: 'refund', terms: escrowTerms, address: destination, feeRate: 2, ...early}), /not valid yet/);
  const w = world({tip: 130_000}), session = await prepareBitcoinPsbt({op: 'refund', terms: escrowTerms, address: destination, feeRate: 2, ...w});
  w.log.expected = session.txid;
  const done = await finishBitcoinPsbt({session, signedPsbt: signSpend(session, refundPriv), read: w.read, verifyEscrow: w.verifyEscrow, journal: w.journal});
  assert.equal(done.state, 'submitted');
  assert.equal(Transaction.fromRaw(Uint8Array.from(done.txHex.match(/../g), x => parseInt(x, 16))).lockTime, 130_000);
});

test('a lost broadcast response is uncertain, a rejection is not, and a different txid is uncertain', async () => {
  const w = world(), session = await prepareBitcoinPsbt({op: 'claim', terms: escrowTerms, address: destination, feeRate: 2, ...w});
  const signed = signSpend(session, claimantPriv);
  w.state.broadcast = async () => { throw Error('network down'); };
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signed, preimage, ...w}), /may have been accepted/);
  assert.deepEqual(w.log.journal.at(-1), ['uncertain', 'id1']);
  w.state.broadcast = async () => ({txid: 'ab'.repeat(32)});
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signed, preimage, ...w}), /different transaction ID/);
  assert.deepEqual(w.log.journal.at(-1), ['uncertain', 'id1']);
  w.state.broadcast = async () => { throw Object.assign(Error('bad-txns-inputs-missingorspent'), {rejected: true}); };
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: signed, preimage, ...w}), /rejected the transaction/);
  assert.deepEqual(w.log.journal.at(-1), ['remove', 'id1']);
});

test('finalize-only mode never broadcasts and leaves the record uncertain', async () => {
  const w = world(), session = await prepareBitcoinPsbt({op: 'claim', terms: escrowTerms, address: destination, feeRate: 2, ...w});
  const done = await finishBitcoinPsbt({session, signedPsbt: signSpend(session, claimantPriv), preimage, broadcast: false, ...w});
  assert.equal(done.state, 'finalized');
  assert.match(done.txHex, /^[0-9a-f]+$/);
  assert.equal(w.log.broadcasts.length, 0);
  assert.deepEqual(w.log.journal.at(-1), ['uncertain', 'id1']);
});

test('fund uses only confirmed coins, rejects an address the service did not return, and stops if a coin disappears', async () => {
  const w = world(), session = await prepareBitcoinPsbt({op: 'fund', terms, address: walletAddress, feeRate: 2, ...w});
  assert.equal(session.built.expect.inputs.length, 1);
  assert.equal(session.built.expect.inputs[0].amount, 200_000n, 'the unconfirmed 900,000 sat coin is not used');
  assert.deepEqual(w.log.journal[0].slice(0, 3), ['begin', 'bitcoin', 'lock']);
  const other = {...w.read, utxos: async () => ({address: destination, tip: 1, utxos: []})};
  await assert.rejects(prepareBitcoinPsbt({op: 'fund', terms, address: walletAddress, feeRate: 2, ...w, read: other}), /different address/);
  const gone = {...w.read, utxos: async address => ({address, tip: 1, utxos: []})};
  await assert.rejects(finishBitcoinPsbt({session, signedPsbt: session.psbt, read: gone, verifyEscrow: w.verifyEscrow, journal: w.journal}), /no longer available/);
});

test('bad input is refused before anything is written', async () => {
  const w = world();
  for (const [op, bad] of [['claim', {...escrowTerms, txid: 'zz'}], ['fund', {...terms, hashlock: 'ab'}], ['fund', {...terms, amount_sats: 100}], ['sweep', terms]]) {
    await assert.rejects(prepareBitcoinPsbt({op, terms: bad, address: destination, feeRate: 2, ...w}), BitcoinWalletError);
  }
  await assert.rejects(prepareBitcoinPsbt({op: 'claim', terms: escrowTerms, address: 'bc1qnotatestnetaddress', feeRate: 2, ...w}));
  assert.equal(w.log.journal.length, 0);
});
