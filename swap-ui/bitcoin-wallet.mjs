/* Bitcoin testnet4 fund, claim and refund through a PSBT signer the user controls (Sparrow, Bitcoin Core, a hardware
 * wallet, embit). The page never holds a wallet key: it builds the PSBT, checks it again from the bytes, writes an
 * action record, and hands the PSBT out. The signed PSBT comes back, is checked against the same expectations, and
 * only then finalized and broadcast. A claim's preimage is used at finalize and never appears in a PSBT or a record.
 *
 * Everything the page needs is passed in, so the same code runs in Node tests and in the browser.
 */
import {TEST_NETWORK} from './vendor/btc-signer.mjs';
import {buildFund, buildSpend, checkPsbt, decodePsbt, encodePsbt, finalizeFund, finalizeSpend} from './bitcoin-psbt.mjs';

export class BitcoinWalletError extends Error {}
const refuse = message => { throw new BitcoinWalletError(message); };
const HEX64 = /^[0-9a-f]{64}$/;
const OPS = {fund: 'lock', claim: 'claim', refund: 'refund'};

/** The public part of a record: terms and, for a spend, the output and destination. No keys, preimages or signatures. */
export function journalRequest(op, terms, address) {
  const request = {operation: OPS[op], hashlock: terms.hashlock, claimant_key: terms.claimant_key, refund_key: terms.refund_key,
    refund_height: String(terms.refund_height), amount_sats: String(terms.amount_sats)};
  if (op !== 'fund') Object.assign(request, {txid: terms.txid, vout: String(terms.vout), destination: address});
  return request;
}

function normalise(op, terms) {
  if (!OPS[op]) refuse('Choose fund, claim or refund.');
  const t = {hashlock: terms.hashlock, claimant_key: terms.claimant_key, refund_key: terms.refund_key,
    refund_height: Number(terms.refund_height), amount_sats: Number(terms.amount_sats)};
  if (!HEX64.test(t.hashlock)) refuse('Enter the 64-hex hashlock.');
  if (!Number.isSafeInteger(t.amount_sats) || t.amount_sats < 546) refuse('Enter the escrow amount in satoshis.');
  if (op !== 'fund') {
    t.txid = terms.txid; t.vout = Number(terms.vout);
    if (!HEX64.test(t.txid) || !Number.isSafeInteger(t.vout) || t.vout < 0) refuse('Enter the escrow transaction ID and output index.');
  }
  return t;
}

/** Build and check a PSBT, write the action record, return what to export. Nothing is signed. */
export async function prepareBitcoinPsbt({op, terms, address, feeRate, read, verifyEscrow, journal, network = TEST_NETWORK}) {
  const t = normalise(op, terms);
  let built, tip;
  if (op === 'fund') {
    const found = await read.utxos(address);
    if (!found || found.address !== address || !Array.isArray(found.utxos)) refuse('The Bitcoin service returned a different address.');
    const inputs = found.utxos.filter(u => u.confirmations >= 1).map(u => ({txid: u.txid, vout: u.vout, amount: BigInt(u.amount_sats), address}));
    if (!inputs.length) refuse('The funding address has no confirmed coins.');
    tip = found.tip;
    built = buildFund({terms: t, inputs, changeAddress: address, feeRate, network});
  } else {
    const snapshot = await verifyEscrow(t, {op});   // unspent, confirmed, matches terms, claim cutoff (claim) or any time (refund)
    tip = snapshot.tip;
    if (op === 'refund' && tip < t.refund_height) refuse(`The refund is not valid yet: it needs block ${t.refund_height} and the chain is at ${tip}.`);
    built = buildSpend({op, terms: t, escrow: {txid: t.txid, vout: t.vout, amount: BigInt(t.amount_sats)}, destination: address, feeRate, network});
  }
  const checked = checkPsbt(built.psbt, built.expect);
  if (checked.txid !== built.txid) refuse('The built transaction does not match its check.');
  const id = await journal.begin('bitcoin', OPS[op], journalRequest(op, t, address));
  return {op, terms: t, address, feeRate, network, built, tip, journalId: id, txid: checked.txid, fee: checked.fee, lines: checked.lines, psbt: encodePsbt(built.psbt)};
}

/** Check the signed PSBT against the session, re-verify the chain, finalize, and either broadcast or hand back the raw transaction. */
export async function finishBitcoinPsbt({session, signedPsbt, preimage, read, verifyEscrow, journal, broadcast = true}) {
  const {op, terms} = session;
  let bytes;
  try { bytes = decodePsbt(signedPsbt); } catch (error) { refuse(error.message); }
  if (op === 'fund') {
    const found = await read.utxos(session.address);
    for (const input of session.built.expect.inputs) {
      if (!found.utxos?.some(u => u.txid === input.txid && u.vout === input.vout && BigInt(u.amount_sats) === input.amount)) refuse('A coin this transaction spends is no longer available. Build the PSBT again.');
    }
  } else {
    const snapshot = await verifyEscrow(terms, {op});
    if (op === 'refund' && snapshot.tip < terms.refund_height) refuse('The refund is not valid yet.');
  }
  let done;
  try {
    done = op === 'fund' ? finalizeFund(bytes, session.built.expect) : finalizeSpend(bytes, session.built.expect, {preimage});
  } catch (error) { refuse(error.message); }
  if (done.txid !== session.txid) refuse('The signed transaction is not the one that was prepared.');
  if (!broadcast) {
    await journal.uncertain(session.journalId);
    return {state: 'finalized', txid: done.txid, txHex: done.txHex, fee: done.fee, vsize: done.vsize,
      message: 'The transaction is signed and checked but not broadcast by this page. If you broadcast it elsewhere, confirm it on a Bitcoin testnet4 explorer.'};
  }
  let answer;
  try {
    answer = await read.broadcast(done.txHex);
  } catch (error) {
    if (error?.rejected) {
      await journal.remove(session.journalId);
      refuse('The Bitcoin network rejected the transaction: ' + error.message + ' Nothing was broadcast; build the PSBT again.');
    }
    await journal.uncertain(session.journalId);
    throw new BitcoinWalletError('The broadcast response was lost. The transaction may have been accepted: look up ' + done.txid + ' before building another.');
  }
  if (answer?.txid !== done.txid) {
    await journal.uncertain(session.journalId);
    throw new BitcoinWalletError('The service reported a different transaction ID. Look up ' + done.txid + ' before retrying.');
  }
  await journal.finish(session.journalId, {submitted: true, txid: done.txid});
  return {state: 'submitted', txid: done.txid, txHex: done.txHex, fee: done.fee, vsize: done.vsize, message: 'Broadcast. Wait for confirmations on Bitcoin testnet4.'};
}
