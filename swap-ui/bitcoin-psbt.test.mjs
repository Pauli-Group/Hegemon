import test from 'node:test';
import assert from 'node:assert/strict';
import {Address, OutScript, SigHash, TEST_NETWORK, Transaction, secp256k1, sha256} from './vendor/btc-signer.mjs';
import * as psbt from './bitcoin-psbt.mjs';

const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const unhex = s => Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
const claimantPriv = new Uint8Array(32).fill(5), refundPriv = new Uint8Array(32).fill(6), otherPriv = new Uint8Array(32).fill(7);
const pub = priv => hex(secp256k1.getPublicKey(priv, true));
const preimage = new Uint8Array(32).fill(0x11), hashlock = hex(sha256(preimage));
const terms = (extra = {}) => ({hashlock, claimant_key: pub(claimantPriv), refund_key: pub(refundPriv), refund_height: 120_000, amount_sats: 50_000, ...extra});
const addr = (n, type = 'wpkh') => Address(TEST_NETWORK).encode(type === 'tr' ? {type: 'tr', pubkey: secp256k1.getPublicKey(new Uint8Array(32).fill(n), true).slice(1)} : {type: 'wpkh', hash: new Uint8Array(20).fill(n)});
const wallet = [{txid: '01'.repeat(32), vout: 0, amount: 30_000n, address: addr(1)}, {txid: '02'.repeat(32), vout: 1, amount: 80_000n, address: addr(2)}];
const escrow = {txid: 'ee'.repeat(32), vout: 1, amount: 50_000n};

function signWith(built, priv, flag = SigHash.ALL) {
  const tx = Transaction.fromPSBT(built.psbt), digest = psbt.htlcDigest(tx, built.expect);
  const sig = new Uint8Array([...secp256k1.sign(digest, priv, {prehash: false, format: 'der'}), flag]);
  tx.updateInput(0, {partialSig: [[secp256k1.getPublicKey(priv, true), sig]]});
  return {bytes: tx.toPSBT(), sig};
}

test('fund PSBT passes the independent check, pays exactly the agreed HTLC output and returns change', () => {
  const built = psbt.buildFund({terms: terms(), inputs: wallet, changeAddress: addr(9), feeRate: 2});
  const checked = psbt.checkPsbt(built.psbt, built.expect);
  const tx = checked.tx;
  assert.equal(tx.outputsLength, 2);
  assert.deepEqual(tx.getOutput(0).script, psbt.escrowScriptPubKey(terms()));
  assert.equal(tx.getOutput(0).amount, 50_000n);
  assert.equal(built.expect.inputs.length, 1, 'the largest coin alone covers the escrow and fee');
  assert.equal(80_000n - 50_000n - built.fee, tx.getOutput(1).amount);
  assert.equal(built.fee, 2n * 153n, 'one P2WPKH input, an HTLC output and a change output weigh 153 vbytes');
  assert.equal(checked.txid, built.txid);
  assert.match(checked.lines[0], /Lock 50000 sats/);
});

test('fund selects more coins when needed, drops dust change into the fee, and refuses impossible funding', () => {
  const many = psbt.buildFund({terms: terms({amount_sats: 90_000}), inputs: wallet, changeAddress: addr(9)});
  assert.equal(many.expect.inputs.length, 2);
  const exact = psbt.buildFund({terms: terms({amount_sats: 79_700}), inputs: [wallet[1]], changeAddress: addr(9), feeRate: 1});
  assert.equal(Transaction.fromPSBT(exact.psbt).outputsLength, 1, 'change below dust goes to the fee');
  assert.ok(exact.fee <= 300n);
  assert.throws(() => psbt.buildFund({terms: terms({amount_sats: 200_000}), inputs: wallet, changeAddress: addr(9)}), /does not hold enough/);
  assert.throws(() => psbt.buildFund({terms: terms({amount_sats: 100}), inputs: wallet, changeAddress: addr(9)}), /dust/);
  assert.throws(() => psbt.buildFund({terms: terms(), inputs: wallet, changeAddress: addr(9), feeRate: 100_000}), /Fee rate/);
  assert.throws(() => psbt.buildFund({terms: terms(), inputs: [{...wallet[1], amount: 100_000_000n}], changeAddress: addr(9), feeRate: 200, maxFeeSats: 100n}), /unexpectedly large/);
  assert.throws(() => psbt.buildFund({terms: terms(), inputs: wallet, changeAddress: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'}), /Invalid Bitcoin address/);
  assert.throws(() => psbt.buildFund({terms: terms(), inputs: wallet, changeAddress: 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'}), /Invalid Bitcoin address|segwit/);
  assert.throws(() => psbt.buildFund({terms: terms({claimant_key: pub(refundPriv)}), inputs: wallet, changeAddress: addr(9)}), /must differ/);
  assert.throws(() => psbt.buildFund({terms: terms({refund_height: 0}), inputs: wallet, changeAddress: addr(9)}), /refund height/);
  assert.equal(Transaction.fromPSBT(psbt.buildFund({terms: terms(), inputs: [{...wallet[1], address: addr(4, 'tr')}], changeAddress: addr(9, 'tr')}).psbt).inputsLength, 1, 'taproot coins can fund');
});

test('claim: PSBT sent to the signer has no preimage; the signed PSBT finalizes to a valid witness [sig, preimage, 1, script]', () => {
  const built = psbt.buildSpend({op: 'claim', terms: terms(), escrow, destination: addr(8), feeRate: 2});
  assert.equal(hex(built.psbt).includes(hex(preimage)), false);
  psbt.checkPsbt(built.psbt, built.expect);
  const signed = signWith(built, claimantPriv);
  const done = psbt.finalizeSpend(signed.bytes, built.expect, {preimage: hex(preimage)});
  const raw = Transaction.fromRaw(unhex(done.txHex), {allowUnknownOutputs: false});
  assert.equal(raw.id, built.txid, 'the txid does not change when the witness is attached');
  assert.equal(raw.getOutput(0).amount, 50_000n - built.fee);
  const witness = raw.getInput(0).finalScriptWitness;
  assert.deepEqual(witness.map(x => x.length), [signed.sig.length, 32, 1, psbt.witnessScriptFor(terms()).length]);
  assert.deepEqual(witness[1], preimage);
  assert.equal(raw.lockTime, 0);
  assert.ok(Math.abs(Number(done.fee) - Math.ceil(done.vsize * 2)) <= 2, `fee ${done.fee} vs vsize ${done.vsize}`);
});

test('refund: locktime is the refund height, sequence is non-final, witness is [sig, empty, script]', () => {
  const built = psbt.buildSpend({op: 'refund', terms: terms(), escrow, destination: addr(8), feeRate: 2});
  const signed = psbt.finalizeSpend(signWith(built, refundPriv).bytes, built.expect);
  const raw = Transaction.fromRaw(unhex(signed.txHex));
  assert.equal(raw.lockTime, 120_000);
  assert.equal(raw.getInput(0).sequence, 0xfffffffe);
  assert.equal(raw.getInput(0).finalScriptWitness[1].length, 0);
  assert.equal(raw.getInput(0).finalScriptWitness.length, 3);
});

test('small escrows can be spent when the actual fee leaves a non-dust output', () => {
  for (const op of ['claim', 'refund']) {
    const t = terms({amount_sats: 900});
    const built = psbt.buildSpend({op, terms: t, escrow: {...escrow, amount: 900n}, destination: addr(8), feeRate: 1});
    const signed = signWith(built, op === 'claim' ? claimantPriv : refundPriv);
    const done = psbt.finalizeSpend(signed.bytes, built.expect, op === 'claim' ? {preimage: hex(preimage)} : {});
    const raw = Transaction.fromRaw(unhex(done.txHex));
    assert.equal(raw.getOutput(0).amount, 900n - done.fee);
    assert.ok(raw.getOutput(0).amount >= 546n);
    assert.throws(() => psbt.buildSpend({op, terms: terms({amount_sats: 600}), escrow: {...escrow, amount: 600n}, destination: addr(8), feeRate: 1}), /too small/);
  }
});

test('signatures by the wrong key, over the wrong data, with the wrong hash type, or for the wrong action are never finalized', () => {
  const claim = psbt.buildSpend({op: 'claim', terms: terms(), escrow, destination: addr(8)});
  assert.throws(() => psbt.finalizeSpend(signWith(claim, refundPriv).bytes, claim.expect, {preimage: hex(preimage)}), /single signature/);
  assert.throws(() => psbt.finalizeSpend(signWith(claim, otherPriv).bytes, claim.expect, {preimage: hex(preimage)}), /single signature/);
  assert.throws(() => psbt.finalizeSpend(signWith(claim, claimantPriv, SigHash.NONE).bytes, claim.expect, {preimage: hex(preimage)}), /SIGHASH_ALL/);
  assert.throws(() => psbt.finalizeSpend(claim.psbt, claim.expect, {preimage: hex(preimage)}), /single signature/);
  const forged = Transaction.fromPSBT(claim.psbt), digest = new Uint8Array(32).fill(1);
  forged.updateInput(0, {partialSig: [[secp256k1.getPublicKey(claimantPriv, true), new Uint8Array([...secp256k1.sign(digest, claimantPriv, {prehash: false, format: 'der'}), 1])]]});
  assert.throws(() => psbt.finalizeSpend(forged.toPSBT(), claim.expect, {preimage: hex(preimage)}), /does not verify/);
  const good = signWith(claim, claimantPriv).bytes;
  assert.throws(() => psbt.finalizeSpend(good, claim.expect, {preimage: '22'.repeat(32)}), /does not match the hashlock/);
  assert.throws(() => psbt.finalizeSpend(good, claim.expect, {}), /does not match the hashlock|preimage/);
  const refund = psbt.buildSpend({op: 'refund', terms: terms(), escrow, destination: addr(8)});
  assert.throws(() => psbt.finalizeSpend(signWith(refund, claimantPriv).bytes, refund.expect), /single signature/);
  assert.throws(() => psbt.finalizeSpend(good, refund.expect), /differs from the one built/);
});

test('any change to the transaction in a returned PSBT is refused', () => {
  const claim = psbt.buildSpend({op: 'claim', terms: terms(), escrow, destination: addr(8)});
  const refund = psbt.buildSpend({op: 'refund', terms: terms(), escrow, destination: addr(8)});
  const rebuilt = (base, over = {}) => {
    const o = {outputs: [{script: base.expect.destinationScript, amount: 50_000n - base.fee}], lockTime: base.expect.op === 'refund' ? 120_000 : 0, sequence: base.expect.op === 'refund' ? 0xfffffffe : 0xffffffff, index: 1, amount: 50_000n, txid: 'ee'.repeat(32), version: 2, ...over};
    const tx = new Transaction({version: o.version, lockTime: o.lockTime, allowUnknownOutputs: false});
    tx.addInput({txid: o.txid, index: o.index, witnessUtxo: {script: o.script ?? psbt.escrowScriptPubKey(terms()), amount: o.amount}, witnessScript: o.witnessScript ?? psbt.witnessScriptFor(terms()), sequence: o.sequence, sighashType: o.sighash ?? SigHash.ALL});
    for (const out of o.outputs) tx.addOutput(out);
    return tx.toPSBT();
  };
  for (const base of [claim, refund]) {
    assert.deepEqual(rebuilt(base), base.psbt, 'the helper reproduces the builder exactly');
    psbt.checkPsbt(rebuilt(base), base.expect);
  }
  const refuse = (base, over, pattern) => assert.throws(() => psbt.checkPsbt(rebuilt(base, over), base.expect), pattern, JSON.stringify(Object.keys(over)));
  const dest = claim.expect.destinationScript;
  refuse(claim, {outputs: [{script: dest, amount: 50_000n - claim.fee - 1n}]}, /differs from the one built/);
  refuse(claim, {outputs: [{script: dest, amount: 50_000n - claim.fee}, {script: dest, amount: 1000n}]}, /differs from the one built/);
  refuse(claim, {outputs: [{script: OutScript.encode({type: 'wpkh', hash: new Uint8Array(20).fill(66)}), amount: 50_000n - claim.fee}]}, /differs from the one built/);
  refuse(claim, {lockTime: 1}, /differs from the one built/);
  refuse(claim, {sequence: 0xfffffffe}, /differs from the one built/);
  refuse(claim, {index: 0}, /differs from the one built/);
  refuse(claim, {txid: 'ed'.repeat(32)}, /differs from the one built/);
  refuse(claim, {version: 1}, /differs from the one built/);
  refuse(refund, {lockTime: 119_999}, /differs from the one built/);
  refuse(refund, {sequence: 0xffffffff}, /differs from the one built/);
  // Same unsigned transaction, but the PSBT's own claims about the input are wrong.
  refuse(claim, {amount: 49_999n}, /amount|script|differs/);
  const other = terms({refund_height: 120_001});
  refuse(claim, {script: psbt.escrowScriptPubKey(other), witnessScript: psbt.witnessScriptFor(other)}, /HTLC script|witness script/);
  refuse(claim, {sighash: SigHash.NONE}, /hash type/);
  assert.throws(() => psbt.checkPsbt(new Uint8Array([1, 2, 3]), claim.expect), /cannot be read/);
  assert.throws(() => psbt.checkPsbt(refund.psbt, claim.expect), /differs from the one built/);
});

test('every single-byte change to a built PSBT is refused unless it leaves the checked transaction and facts unchanged', () => {
  for (const built of [psbt.buildSpend({op: 'claim', terms: terms(), escrow, destination: addr(8)}), psbt.buildSpend({op: 'refund', terms: terms(), escrow, destination: addr(8)}), psbt.buildFund({terms: terms(), inputs: wallet, changeAddress: addr(9)})]) {
    const survivors = [];
    for (let i = 0; i < built.psbt.length; i++) {
      for (const bit of [0x01, 0x80]) {
        const copy = built.psbt.slice(); copy[i] ^= bit;
        try { psbt.checkPsbt(copy, built.expect); survivors.push(copy); } catch { /* refused */ }
      }
    }
    // A change may only be accepted if it turns a field into an unknown one that the reader drops: every field
    // that is still read must be the same as before, and the transaction is byte-identical.
    const original = Transaction.fromPSBT(built.psbt);
    for (const copy of survivors) {
      const parsed = Transaction.fromPSBT(copy);
      assert.equal(hex(parsed.unsignedTx), hex(original.unsignedTx));
      for (let n = 0; n < parsed.inputsLength; n++) for (const [key, value] of Object.entries(parsed.getInput(n))) assert.deepEqual(value, original.getInput(n)[key], 'input field ' + key);
      for (let n = 0; n < parsed.outputsLength; n++) for (const [key, value] of Object.entries(parsed.getOutput(n))) assert.deepEqual(value, original.getOutput(n)[key], 'output field ' + key);
    }
    assert.ok(survivors.length <= 6, `${built.expect.op}: too many accepted changes (${survivors.length})`);
  }
});

test('fund PSBT finalizes only when every input is signed, and a finalized PSBT is accepted as is', () => {
  const built = psbt.buildFund({terms: terms(), inputs: [wallet[1]], changeAddress: addr(9)});
  assert.throws(() => psbt.finalizeFund(built.psbt, built.expect), /not fully signed/);
  const tx = Transaction.fromPSBT(built.psbt), key = new Uint8Array(32).fill(2), pubkey = secp256k1.getPublicKey(key, true);
  // A real wallet derives this address from its key; here the key's hash160 must match the input script.
  const spk = built.expect.inputs[0].script;
  assert.equal(OutScript.decode(spk).type, 'wpkh');
  tx.updateInput(0, {finalScriptWitness: [new Uint8Array(71).fill(1), pubkey]});
  const done = psbt.finalizeFund(tx.toPSBT(), built.expect);
  assert.equal(done.txid, built.txid);
  assert.equal(Transaction.fromRaw(unhex(done.txHex)).id, built.txid);
});

test('a funding input signed with a hash type other than ALL is refused', () => {
  const built = psbt.buildFund({terms: terms(), inputs: [wallet[1]], changeAddress: addr(9)});
  const none = Transaction.fromPSBT(built.psbt), key = new Uint8Array(32).fill(2);
  none.updateInput(0, {partialSig: [[secp256k1.getPublicKey(key, true), new Uint8Array([...new Uint8Array(70).fill(1), SigHash.NONE | SigHash.ANYONECANPAY])]]});
  assert.throws(() => psbt.checkPsbt(none.toPSBT(), built.expect), /other than ALL/);
  const asked = Transaction.fromPSBT(built.psbt);
  asked.updateInput(0, {sighashType: SigHash.NONE});
  assert.throws(() => psbt.checkPsbt(asked.toPSBT(), built.expect), /other than ALL/);
});

test('PSBT text is accepted as base64 or hex only', () => {
  const bytes = psbt.buildSpend({op: 'claim', terms: terms(), escrow, destination: addr(8)}).psbt;
  assert.deepEqual(psbt.decodePsbt(psbt.encodePsbt(bytes)), bytes);
  assert.deepEqual(psbt.decodePsbt(hex(bytes)), bytes);
  assert.throws(() => psbt.decodePsbt('not a psbt!'), /base64 or hex/);
});
