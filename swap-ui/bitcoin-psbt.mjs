/* Bitcoin P2WSH HTLC fund, claim and refund through PSBTs.
 *
 * The page builds an unsigned PSBT, checks the bytes against the agreed terms with `checkPsbt` (which reads the
 * PSBT back rather than trusting the builder), and hands it to a PSBT-capable signer outside the page. The signed
 * PSBT comes back through `finalizeSpend` / `finalizeFund`, which check it again, verify the HTLC signature
 * against our own BIP143 digest, and attach the claim witness. The claim preimage is only needed at that last
 * step; it is never part of the PSBT sent to a signer.
 *
 * Script: or_i(and_v(v:sha256(h), pk(claimant)), and_v(v:after(height), pk(refundee))) as built by
 * bitcoin-testnet-verifier.mjs. Claim witness is [sig, preimage, 1, script]; refund is [sig, '', script] with
 * nLockTime = height and a non-final sequence.
 */
import {Address, OutScript, SigHash, TEST_NETWORK, Transaction, secp256k1, sha256} from './vendor/btc-signer.mjs';
import {bitcoinWitnessScript} from './bitcoin-testnet-verifier.mjs';

export const MAX_FEE_SATS = 50_000n;
export const DUST_SATS = 546n;
export const CLAIM_SEQUENCE = 0xffffffff;
export const REFUND_SEQUENCE = 0xfffffffe;
const MAX_FEE_RATE = 200;   // sat/vB

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = text => {
  if (typeof text !== 'string' || text.length % 2 || !/^[0-9a-f]*$/.test(text)) throw Error('Invalid hex.');
  return Uint8Array.from(text.match(/../g) ?? [], x => parseInt(x, 16));
};
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const fail = message => { throw Error('Bitcoin transaction check failed: ' + message); };
const big = value => { try { return BigInt(value); } catch { throw Error('Invalid Bitcoin amount.'); } };

// ------------------------------------------------------------------ scripts and addresses

export function witnessScriptFor(terms) { return unhex(bitcoinWitnessScript(terms)); }
export function escrowScriptPubKey(terms) { return OutScript.encode({type: 'wsh', hash: sha256(witnessScriptFor(terms))}); }

/** Script bytes for an address on `network`. Only witness addresses are accepted (the PSBT carries witnessUtxo, not full previous transactions). */
export function addressScript(address, network = TEST_NETWORK, {allowTaproot = true} = {}) {
  let decoded;
  try { decoded = Address(network).decode(address); } catch { throw Error('Invalid Bitcoin address for this network.'); }
  if (!['wpkh', 'wsh', ...(allowTaproot ? ['tr'] : [])].includes(decoded.type)) throw Error('Only segwit addresses are supported.');
  return OutScript.encode(decoded);
}

const INPUT_VBYTES = {wpkh: 68, tr: 58};
function inputVbytes(script) {
  const type = OutScript.decode(script).type;
  if (!INPUT_VBYTES[type]) throw Error('Unsupported funding input type.');
  return INPUT_VBYTES[type];
}
const ceil = (n, d) => (n + d - 1n) / d;
const rateOf = feeRate => {
  if (!Number.isFinite(feeRate) || feeRate < 1 || feeRate > MAX_FEE_RATE) throw Error('Fee rate must be between 1 and ' + MAX_FEE_RATE + ' sat/vB.');
  return BigInt(Math.round(feeRate * 1000));
};
const feeFor = (vbytes, rate) => ceil(BigInt(vbytes) * rate, 1000n);

// ------------------------------------------------------------------ build

function terminalTerms(terms) {
  const t = {...terms};
  if (!Number.isSafeInteger(t.refund_height) || t.refund_height < 1 || t.refund_height >= 500_000_000) throw Error('Invalid Bitcoin refund height.');
  witnessScriptFor(t);  // validates hashlock and keys
  return t;
}

/** Fund: the escrow output first, change second. `inputs` are {txid, vout, amount, address}; each must be a witness address. */
export function buildFund({terms, inputs, changeAddress, feeRate = 2, network = TEST_NETWORK, maxFeeSats = MAX_FEE_SATS}) {
  const t = terminalTerms(terms), amount = big(t.amount_sats), rate = rateOf(feeRate);
  if (amount < DUST_SATS) throw Error('Escrow amount is below the dust limit.');
  const spk = escrowScriptPubKey(t), changeScript = addressScript(changeAddress, network);
  const sorted = [...inputs].map(i => ({...i, amount: big(i.amount), script: addressScript(i.address, network)})).sort((a, b) => (b.amount > a.amount ? 1 : b.amount < a.amount ? -1 : 0));
  const outputsVbytes = 8 + 1 + spk.length + (8 + 1 + changeScript.length);
  for (let take = 1; take <= sorted.length; take++) {
    const picked = sorted.slice(0, take), total = picked.reduce((s, i) => s + i.amount, 0n);
    const vbytes = 11 + picked.reduce((s, i) => s + inputVbytes(i.script), 0) + outputsVbytes;
    const fee = feeFor(vbytes, rate), change = total - amount - fee;
    if (change < 0n) continue;
    const withChange = change >= DUST_SATS;
    const finalFee = withChange ? fee : total - amount;
    if (finalFee > maxFeeSats) throw Error('Bitcoin fee is unexpectedly large.');
    const tx = new Transaction({version: 2, lockTime: 0, allowUnknownOutputs: false});
    for (const i of picked) tx.addInput({txid: i.txid, index: i.vout, witnessUtxo: {script: i.script, amount: i.amount}, sequence: 0xfffffffd, sighashType: SigHash.ALL});
    tx.addOutput({script: spk, amount});
    if (withChange) tx.addOutput({script: changeScript, amount: change});
    const psbt = tx.toPSBT(0);
    return {psbt, fee: finalFee, txid: tx.id, expect: {op: 'fund', terms: t, network, inputs: picked.map(i => ({txid: i.txid, vout: i.vout, amount: i.amount, script: i.script})), changeScript, fee: finalFee, unsigned: hex(tx.unsignedTx), maxFeeSats}};
  }
  throw Error('Wallet does not hold enough bitcoin for the escrow and fee.');
}

/** Claim or refund the escrow output `escrow` ({txid, vout, amount}) to `destination`. */
export function buildSpend({op, terms, escrow, destination, feeRate = 2, network = TEST_NETWORK, maxFeeSats = MAX_FEE_SATS}) {
  if (op !== 'claim' && op !== 'refund') throw Error('Invalid Bitcoin operation.');
  const t = terminalTerms(terms), rate = rateOf(feeRate), amount = big(escrow.amount);
  if (amount !== big(t.amount_sats)) throw Error('Escrow amount does not match the terms.');
  if (!/^[0-9a-f]{64}$/.test(escrow.txid) || !Number.isSafeInteger(escrow.vout) || escrow.vout < 0) throw Error('Invalid Bitcoin escrow outpoint.');
  const script = witnessScriptFor(t), spk = escrowScriptPubKey(t), destinationScript = addressScript(destination, network, {allowTaproot: true});
  const make = out => {
    const tx = new Transaction({version: 2, lockTime: op === 'refund' ? t.refund_height : 0, allowUnknownOutputs: false});
    tx.addInput({txid: escrow.txid, index: escrow.vout, witnessUtxo: {script: spk, amount}, witnessScript: script, sequence: op === 'refund' ? REFUND_SEQUENCE : CLAIM_SEQUENCE, sighashType: SigHash.ALL});
    tx.addOutput({script: destinationScript, amount: out});
    return tx;
  };
  // Measure the exact virtual size with a worst-case dummy witness, then price it.
  const probe = make(amount);
  probe.updateInput(0, {finalScriptWitness: op === 'claim' ? [new Uint8Array(73), new Uint8Array(32), Uint8Array.of(1), script] : [new Uint8Array(73), new Uint8Array(0), script]});
  const fee = feeFor(probe.vsize, rate), out = amount - fee;
  if (fee > maxFeeSats) throw Error('Bitcoin fee is unexpectedly large.');
  if (out < DUST_SATS) throw Error('Escrow is too small to pay the Bitcoin fee.');
  const tx = make(out), psbt = tx.toPSBT(0);
  return {psbt, fee, txid: tx.id, expect: {op, terms: t, network, escrow: {txid: escrow.txid, vout: escrow.vout, amount}, destinationScript, fee, unsigned: hex(tx.unsignedTx), maxFeeSats}};
}

// ------------------------------------------------------------------ check

function read(psbtBytes, network) {
  try { return Transaction.fromPSBT(psbtBytes, {allowUnknownOutputs: false, allowUnknownInputs: false}); } catch (error) { return fail('the PSBT cannot be read (' + (error?.message ?? 'malformed') + ')'); }
}
/** An ECDSA signature (DER plus flag) must end in SIGHASH_ALL; a 64-byte Schnorr signature is the default type, 65 bytes carry a flag. */
const allSighash = sig => (sig.length === 64 ? true : sig.at(-1) === SigHash.ALL);
const sameBytes = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && equal(a, b);

/** Read a PSBT back and compare it with what the user asked for. Throws unless it does exactly that. Returns what it would do. */
export function checkPsbt(psbtBytes, expect) {
  const tx = read(psbtBytes, expect.network);
  if (hex(tx.unsignedTx) !== expect.unsigned) fail('the transaction differs from the one built for this action');
  if (tx.version !== 2) fail('unexpected transaction version');
  const spk = escrowScriptPubKey(expect.terms);
  if (expect.op === 'fund') {
    if (tx.inputsLength !== expect.inputs.length) fail('unexpected number of inputs');
    let total = 0n;
    for (let i = 0; i < tx.inputsLength; i++) {
      const input = tx.getInput(i), want = expect.inputs[i];
      if (input.txid === undefined || hex(input.txid) !== want.txid || input.index !== want.vout) fail('input ' + i + ' is not a chosen wallet coin');
      if (!input.witnessUtxo || !sameBytes(input.witnessUtxo.script, want.script) || input.witnessUtxo.amount !== want.amount) fail('input ' + i + ' amount or script differs from the chain data');
      if (input.sighashType !== undefined && input.sighashType !== SigHash.ALL) fail('input ' + i + ' asks for a signature hash type other than ALL');
      for (const [, sig] of input.partialSig ?? []) if (!allSighash(sig)) fail('input ' + i + ' is signed with a hash type other than ALL');
      if (input.tapKeySig && !allSighash(input.tapKeySig)) fail('input ' + i + ' is signed with a hash type other than ALL');
      for (const item of input.finalScriptWitness ?? []) if (item.length >= 70 && item.length <= 73 && !allSighash(item)) fail('input ' + i + ' is signed with a hash type other than ALL');
      if (input.sighashType !== undefined && input.sighashType !== SigHash.ALL) fail('input ' + i + ' asks for an unexpected signature hash type');
      total += want.amount;
    }
    if (tx.lockTime !== 0) fail('unexpected locktime');
    const outs = Array.from({length: tx.outputsLength}, (_, i) => tx.getOutput(i));
    if (outs.length < 1 || outs.length > 2) fail('a fund transaction has an escrow output and at most one change output');
    if (!sameBytes(outs[0].script, spk) || outs[0].amount !== big(expect.terms.amount_sats)) fail('escrow output is not the agreed HTLC script and amount');
    if (outs[1] && !sameBytes(outs[1].script, expect.changeScript)) fail('change does not return to your address');
    const paid = outs.reduce((s, o) => s + o.amount, 0n), fee = total - paid;
    if (fee !== expect.fee || fee < 0n || fee > expect.maxFeeSats) fail('fee differs from the one shown');
    return {op: 'fund', txid: tx.id, fee, lines: [`Lock ${expect.terms.amount_sats} sats in the HTLC for claimant key ${expect.terms.claimant_key}, refundable by ${expect.terms.refund_key} from block ${expect.terms.refund_height}.`, `Network fee ${fee} sats; transaction ${tx.id}.`], tx};
  }
  if (tx.inputsLength !== 1) fail('a claim or refund spends exactly one output');
  const input = tx.getInput(0), role = expect.op === 'claim' ? expect.terms.claimant_key : expect.terms.refund_key;
  if (hex(input.txid) !== expect.escrow.txid || input.index !== expect.escrow.vout) fail('the input is not the escrow output');
  if (!input.witnessUtxo || !sameBytes(input.witnessUtxo.script, spk) || input.witnessUtxo.amount !== expect.escrow.amount) fail('the input does not carry the HTLC script and amount');
  if (!sameBytes(input.witnessScript, witnessScriptFor(expect.terms))) fail('the PSBT carries a different witness script');
  if (expect.op === 'refund' ? tx.lockTime !== expect.terms.refund_height || input.sequence !== REFUND_SEQUENCE : tx.lockTime !== 0 || input.sequence !== CLAIM_SEQUENCE) fail('locktime or sequence is not the one this action needs');
  if (input.sighashType !== undefined && input.sighashType !== SigHash.ALL) fail('unexpected signature hash type');
  if (tx.outputsLength !== 1) fail('the output count is not one');
  const out = tx.getOutput(0), fee = expect.escrow.amount - out.amount;
  if (!sameBytes(out.script, expect.destinationScript)) fail('the output does not go to the chosen address');
  if (fee !== expect.fee || fee > expect.maxFeeSats || out.amount < DUST_SATS) fail('fee differs from the one shown');
  const verb = expect.op === 'claim' ? 'Claim' : 'Refund';
  return {op: expect.op, txid: tx.id, fee, role, lines: [`${verb} ${expect.escrow.amount} sats from ${expect.escrow.txid}:${expect.escrow.vout} to ${tx.getOutput(0).address ?? 'your address'}${expect.op === 'claim' ? '. This reveals the swap secret on chain.' : '.'}`, `Network fee ${fee} sats; transaction ${tx.id}.`], tx};
}

// ------------------------------------------------------------------ finalize

/** Our own BIP143 digest for the HTLC input: what an honest signer signs. */
export function htlcDigest(tx, expect) { return tx.preimageWitnessV0(0, witnessScriptFor(expect.terms), SigHash.ALL, expect.escrow.amount); }

/** Check a signed spend PSBT, verify the HTLC signature, attach the witness, and return the raw transaction. */
export function finalizeSpend(psbtBytes, expect, {preimage} = {}) {
  const checked = checkPsbt(psbtBytes, expect), tx = checked.tx, input = tx.getInput(0);
  const sigs = input.partialSig ?? [];
  const roleKey = unhex(checked.role);
  const match = sigs.find(([pub]) => sameBytes(pub, roleKey));
  if (!match || sigs.length !== 1) fail('the PSBT has no single signature by the ' + (expect.op === 'claim' ? 'claimant' : 'refund') + ' key');
  const sig = match[1];
  if (sig.at(-1) !== SigHash.ALL) fail('the signature does not use SIGHASH_ALL');
  const digest = htlcDigest(tx, expect);
  let valid = false;
  try { valid = secp256k1.verify(sig.slice(0, -1), digest, roleKey, {prehash: false, format: 'der', lowS: true}); } catch { valid = false; }
  if (!valid) fail('the signature does not verify against this transaction');
  const script = witnessScriptFor(expect.terms);
  let witness;
  if (expect.op === 'claim') {
    const secret = typeof preimage === 'string' ? unhex(preimage) : preimage;
    if (!(secret instanceof Uint8Array) || secret.length !== 32 || hex(sha256(secret)) !== expect.terms.hashlock) fail('the preimage does not match the hashlock');
    witness = [sig, secret, Uint8Array.of(1), script];
  } else witness = [sig, new Uint8Array(0), script];
  tx.updateInput(0, {finalScriptWitness: witness});
  return {txHex: hex(tx.extract()), txid: tx.id, vsize: tx.vsize, fee: checked.fee, lines: checked.lines};
}

/** Check a signed fund PSBT and finalize standard wallet inputs. */
export function finalizeFund(psbtBytes, expect) {
  const checked = checkPsbt(psbtBytes, expect), tx = checked.tx;
  try { if (!tx.isFinal) tx.finalize(); } catch (error) { fail('a funding input is not fully signed (' + (error?.message ?? 'unknown') + ')'); }
  if (!tx.isFinal) fail('a funding input is not fully signed');
  return {txHex: hex(tx.extract()), txid: tx.id, vsize: tx.vsize, fee: checked.fee, lines: checked.lines};
}

export const encodePsbt = bytes => btoa(String.fromCharCode(...bytes));
export function decodePsbt(text) {
  const clean = String(text).trim();
  if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) return unhex(clean.toLowerCase());
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean) || clean.length > 400_000) throw Error('Paste a PSBT as base64 or hex.');
  return Uint8Array.from(atob(clean), c => c.charCodeAt(0));
}
