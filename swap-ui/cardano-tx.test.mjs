import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {blake2b, ed25519, sha256} from './vendor/hash.mjs';
import * as ct from './cardano-tx.mjs';
import {Tag, decode, encode, fromHex, toHex} from './cbor.mjs';

const here = new URL('.', import.meta.url);
const script = JSON.parse(fs.readFileSync(new URL('cardano-htlc-script.json', here), 'utf8'));
ct.setPinnedScript(script);
const rawParams = JSON.parse(fs.readFileSync(new URL('fixtures/cardano-preview-params.json', here), 'utf8'));
const params = ct.parseParams(rawParams);
const BUDGET = {memory: 700_000, steps: 300_000_000};

const seedA = new Uint8Array(32).fill(7), seedB = new Uint8Array(32).fill(9);
const keyOf = seed => { const pub = ed25519.getPublicKey(seed); return {seed, pub, hash: toHex(blake2b(pub, {dkLen: 28}))}; };
const alice = keyOf(seedA), bob = keyOf(seedB);
const addrOf = key => new Uint8Array([0x60, ...fromHex(key.hash)]);
const POLICY = 'ab'.repeat(28), TOKEN = POLICY + '.' + '746f6b656e', OTHER = 'cd'.repeat(28) + '.';
const preimage = '11'.repeat(32), hashlock = toHex(sha256(fromHex(preimage)));
const nowSeconds = 1_667_000_000, expiry = nowSeconds + 86_400;
const utxo = (n, lovelace, assets = {}, key = alice) => ({txid: n.toString(16).padStart(64, '0'), index: 0, address: addrOf(key), value: {lovelace: BigInt(lovelace), assets: Object.fromEntries(Object.entries(assets).map(([k, v]) => [k, BigInt(v)]))}});
const baseTerms = (extra = {}) => ({hashlock, claimant: bob.hash, refundee: alice.hash, expiry_ms: String(expiry * 1000), lovelace: '10000000', assets: '', ...extra});
const nowSlot = nowSeconds - ct.PREVIEW.systemStart;

test('pinned script hashes to the pinned hash and enterprise address, and equals the validator on chain', () => {
  const v = ct.validateScript();
  assert.equal(v.hash, '361aa77052a3f9cbf29afa83b2c548feff9c244402a0afd45b15ffc1');
  assert.equal(v.bech32, 'addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv');
  const claim = ct.inspectTx(fromHex(fs.readFileSync(new URL('fixtures/37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d.cbor.hex', here), 'utf8').trim()));
  assert.deepEqual(claim.scripts[0], v.script);
  assert.throws(() => ct.validateScript({...script, hash: '00'.repeat(28)}), /pinned hash/);
  assert.throws(() => ct.validateScript({...script, address: ct.toBech32(new Uint8Array([0x70, ...new Uint8Array(28)]))}), /address/);
});

test('decoder agrees with a real ledger-accepted claim: id, redeemer, validity, script data hash', () => {
  const raw = fromHex(fs.readFileSync(new URL('fixtures/37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d.cbor.hex', here), 'utf8').trim());
  const tx = ct.inspectTx(raw);
  assert.equal(toHex(tx.bodyHash), '37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d');
  assert.equal(tx.ttl, 127291597);
  assert.equal(tx.redeemers.length, 1);
  assert.equal(tx.redeemers[0].data.tag, 121);
  assert.equal(tx.signers[0], 'c526918111bb0b514bdd60981690a056a82b0bd497acf8a28d302533');
  assert.equal(tx.scriptDataHash, toHex(ct.scriptDataHash(tx.redeemerBytes, params)));
  assert.equal(tx.unknownBodyKeys.length + tx.unknownWitnessKeys.length, 0);
});

test('fund transaction passes the independent check, keeps unrelated tokens, and respects minimums', () => {
  const wallet = [utxo(1, 3_000_000), utxo(2, 40_000_000, {[OTHER]: 5}), utxo(3, 9_000_000, {[TOKEN]: 100})];
  const built = ct.buildFund({terms: baseTerms({assets: TOKEN + '=60'}), walletUtxos: wallet, changeAddress: addrOf(alice), params});
  const checked = ct.checkFund(built.txBytes, built.expect);
  assert.equal(checked.txid, toHex(ct.inspectTx(built.txBytes).bodyHash));
  const tx = ct.inspectTx(built.txBytes);
  const change = tx.outputs[1].value;
  assert.equal(change.assets[TOKEN], 40n);
  const inputs = ct.sumValues(built.expect.inputs.map(u => u.value));
  assert.deepEqual(Object.keys(change.assets).sort(), Object.keys(inputs.assets).sort());
  assert.equal(change.lovelace + 10_000_000n + built.fee, inputs.lovelace);
  assert.ok(built.fee > 150_000n && built.fee < 400_000n, String(built.fee));
  assert.deepEqual(tx.outputs[0].datum.bytes, ct.datumBytes(baseTerms({assets: TOKEN + '=60'})));
});

test('fund refuses too little ADA, missing tokens, sub-minimum escrow and a wrong-network address', () => {
  const t = baseTerms();
  assert.throws(() => ct.buildFund({terms: t, walletUtxos: [utxo(1, 5_000_000)], changeAddress: addrOf(alice), params}), /enough lovelace/);
  assert.throws(() => ct.buildFund({terms: baseTerms({assets: TOKEN + '=1'}), walletUtxos: [utxo(1, 50_000_000)], changeAddress: addrOf(alice), params}), /required Cardano assets/);
  assert.throws(() => ct.buildFund({terms: baseTerms({lovelace: '100000'}), walletUtxos: [utxo(1, 50_000_000)], changeAddress: addrOf(alice), params}), /at least/);
  assert.throws(() => ct.addressInfo(new Uint8Array([0x61, ...new Uint8Array(28)])), /testnet/);
  assert.throws(() => ct.buildFund({terms: baseTerms({expiry_ms: '1700000000500'}), walletUtxos: [utxo(1, 50_000_000)], changeAddress: addrOf(alice), params}), /whole seconds/);
});

test('escrow minimum includes its inline datum, not just address and value', () => {
  const terms=baseTerms(),scriptAddress=ct.validateScript().address,datum=ct.datumBytes(terms);
  const value=(1n<<63n)-1n;
  const withDatum=new Map([[0,scriptAddress],[1,value],[2,[1,new Tag(24,datum)]]]);
  const withoutDatum=new Map([[0,scriptAddress],[1,value]]);
  const expected=(160n+BigInt(encode(withDatum).length))*params.coinsPerUtxoByte;
  const oldFloor=(160n+BigInt(encode(withoutDatum).length))*params.coinsPerUtxoByte;
  assert.equal(ct.minimumEscrowLovelace(terms,params),expected);
  assert.ok(expected>oldFloor,'the inline datum contributes to minimum ADA');
  assert.throws(()=>ct.buildFund({terms:baseTerms({lovelace:String(oldFloor)}),walletUtxos:[utxo(1,50_000_000)],changeAddress:addrOf(alice),params}),/escrow needs at least/);
  const built=ct.buildFund({terms:baseTerms({lovelace:String(expected)}),walletUtxos:[utxo(1,50_000_000)],changeAddress:addrOf(alice),params});
  assert.doesNotThrow(()=>ct.checkFund(built.txBytes,built.expect));
});

const escrowRef = {txid: 'ee'.repeat(32), index: 0};
function spend(op, extra = {}, termsExtra = {}) {
  const terms = baseTerms({outref: 'ee'.repeat(32) + '#0', ...termsExtra});
  const t = ct.parseTerms(terms);
  const key = op === 'claim' ? bob : alice;
  return ct.buildSpend({op, terms, escrow: {...escrowRef, value: t.value}, preimage: op === 'claim' ? preimage : undefined, walletUtxos: [utxo(5, 20_000_000, {[OTHER]: 3}, key), utxo(6, 6_000_000, {}, key)],
    collateralUtxos: [utxo(7, 5_000_000, {}, key)], changeAddress: addrOf(key), walletKeyHash: key.hash, params, budget: BUDGET, nowSlot: op === 'claim' ? nowSlot : expiry - ct.PREVIEW.systemStart + 5, ...extra});
}

test('claim: bytes pass the check; preimage, signer, validity, hash, budget and tokens are as intended', () => {
  const built = spend('claim', {walletUtxos: [utxo(5, 20_000_000, {[OTHER]: 3}, bob)]}), checked = ct.checkSpend(built.txBytes, built.expect), tx = checked.tx;
  assert.equal(tx.signers[0], bob.hash);
  assert.equal(tx.ttl, nowSlot + 3600, 'validity stays inside the ledger time horizon, not the far deadline');
  assert.equal(tx.start, undefined);
  assert.deepEqual(tx.redeemers[0].data, new (tx.redeemers[0].data.constructor)(121, [fromHex(preimage)]));
  assert.equal(tx.redeemers[0].units.memory, 700_000n);
  assert.equal(tx.outputs.length, 1);
  assert.equal(tx.outputs[0].value.assets[OTHER], 3n);  // unrelated token survives in change
  assert.equal(tx.outputs[0].value.lovelace + built.fee, 10_000_000n + 20_000_000n);
  assert.match(checked.lines[0], /reveals the swap secret/);
  assert.ok(tx.totalCollateral !== undefined && tx.collateralReturn, 'collateral return limits what a failed script can cost');
  assert.ok(built.fee < 600_000n, String(built.fee));
});

test('refund: valid only at or after the deadline, refundee signs, redeemer is Refund', () => {
  const built = spend('refund'), checked = ct.checkSpend(built.txBytes, built.expect), tx = checked.tx;
  assert.equal(tx.start, expiry - ct.PREVIEW.systemStart);
  assert.equal(tx.ttl, undefined);
  assert.equal(tx.signers[0], alice.hash);
  assert.equal(tx.redeemers[0].data.tag, 122);
});

test('builder refuses wrong role, early refund, late claim, bad budget, wrong value and missing collateral', () => {
  assert.throws(() => spend('claim', {walletKeyHash: alice.hash}), /not the claimant/);
  assert.throws(() => spend('refund', {walletKeyHash: bob.hash}), /not the refundee/);
  assert.throws(() => spend('refund', {nowSlot: nowSlot}), /before its deadline/);
  assert.throws(() => spend('claim', {nowSlot: expiry - ct.PREVIEW.systemStart - 10}), /too close/);
  assert.throws(() => spend('claim', {budget: {memory: 1, steps: 10 ** 12}}), /budget/);
  assert.throws(() => spend('claim', {nowSlot: -1}), /head is unavailable/);
  assert.throws(() => spend('claim', {collateralUtxos: []}), /collateral/);
  assert.throws(() => spend('claim', {collateralUtxos: [utxo(7, 5_000_000, {[OTHER]: 1}, bob)]}), /collateral/);
  const terms = baseTerms({outref: escrowRef.txid + '#0'});
  assert.throws(() => ct.buildSpend({op: 'claim', terms, escrow: {...escrowRef, value: {lovelace: 1n, assets: {}}}, preimage, walletUtxos: [utxo(5, 9_000_000, {}, bob)], collateralUtxos: [utxo(7, 5_000_000, {}, bob)], changeAddress: addrOf(bob), walletKeyHash: bob.hash, params, budget: BUDGET, nowSlot}), /value does not match/);
  assert.throws(() => spend('claim', {preimage: 'zz'}), /redeemer/);
});

test('every single-bit change to a claim, refund or fund transaction is refused by the checker', () => {
  const cases = [
    [spend('claim'), ct.checkSpend], [spend('refund'), ct.checkSpend],
    [ct.buildFund({terms: baseTerms({assets: TOKEN + '=60'}), walletUtxos: [utxo(1, 30_000_000), utxo(3, 9_000_000, {[TOKEN]: 100})], changeAddress: addrOf(alice), params}), ct.checkFund],
  ];
  for (const [built, check] of cases) {
    check(built.txBytes, built.expect);
    const survivors = [];
    for (let i = 0; i < built.txBytes.length; i++) {
      for (const bit of [0x01, 0x80]) {
        const copy = built.txBytes.slice(); copy[i] ^= bit;
        try { check(copy, built.expect); survivors.push(i); } catch { /* refused */ }
      }
    }
    // The only changes the checker may accept keep the transaction no weaker: a claim that expires earlier
    // than the deadline, or a refund that becomes valid later than the deadline.
    const original = ct.inspectTx(built.txBytes);
    for (const i of survivors) {
      const picked = [0x01, 0x80].map(bit => { const copy = built.txBytes.slice(); copy[i] ^= bit; try { check(copy, built.expect); return ct.inspectTx(copy); } catch { return null; } }).filter(Boolean);
      assert.ok(picked.length && built.expect.op !== 'fund', `${built.expect.op}: byte ${i} change was accepted`);
      for (const tx of picked) {
        const claim = built.expect.op === 'claim';
        assert.ok(claim ? tx.ttl < original.ttl && tx.ttl > built.expect.nowSlot && tx.start === original.start : tx.start > original.start && tx.ttl === original.ttl, `byte ${i} changed more than the validity bound`);
        assert.equal(tx.fee, original.fee);
      }
    }
  }
});

test('checker rejects semantically altered transactions built with the same machinery', () => {
  const built = spend('claim'), good = built.expect;
  const bad = (patch, pattern) => assert.throws(() => ct.checkSpend(built.txBytes, {...good, ...patch}), pattern);
  bad({changeAddress: addrOf(alice)}, /does not go to the wallet/);
  bad({walletKeyHash: alice.hash}, /not the claimant/);
  bad({feeInputs: []}, /inputs are not exactly/);
  bad({collateral: utxo(99, 5_000_000, {}, bob)}, /collateral/);
  bad({budget: {...good.budget, memory: good.budget.memory + 1n}}, /fixed budget/);
  bad({budget: {...good.budget, steps: good.budget.steps + 1n}}, /fixed budget/);
  bad({preimage: '22'.repeat(32)}, /redeemer is not/);
  bad({nowSlot: expiry}, /already passed/);
  bad({nowSlot: nowSlot - 10}, /time horizon/);
  bad({escrow: {...good.escrow, value: {lovelace: 1n, assets: {}}}}, /return everything/);
  bad({terms: {...good.terms, claimant: alice.hash}}, /signer|claimant/);
  bad({params: {...good.params, costModelV3: good.params.costModelV3.map((x, i) => (i === 3 ? x + 1n : x))}}, /script data hash/);
  assert.throws(() => ct.checkFund(built.txBytes, {...good, op: 'fund'}), /script/);
});

test('unexpected body fields, outputs, scripts and signatures are refused', () => {
  const built = spend('claim');
  const tx = decode(built.txBytes), body = tx[0];
  const redo = mutate => { const b = new Map(body); mutate(b); return encode([b, tx[1], true, null]); };
  const must = (bytes, pattern) => assert.throws(() => ct.checkSpend(bytes, built.expect), pattern);
  must(redo(b => b.set(9, new Map([[fromHex(POLICY), new Map([[new Uint8Array(0), 1n]])]]))), /unexpected transaction fields/);  // mint
  must(redo(b => b.set(4, [])), /unexpected transaction fields/);  // certificates
  must(redo(b => b.set(5, new Map())), /unexpected transaction fields/);  // withdrawals
  must(redo(b => b.set(15, 1)), /testnet/);
  must(redo(b => b.set(1, [...b.get(1), new Map([[0, addrOf(alice)], [1, 1_000_000n]])])), /one output/);
  must(encode([body, new Map([...tx[1], [3, [new Uint8Array(10)]]]), true, null]), /unexpected witness/);
  must(encode([body, tx[1], false, null]), /not marked valid/);
  must(encode([body, tx[1], true, new Map()]), /auxiliary/);
  must(encode([body, new Map([...tx[1], [0, [[alice.pub, new Uint8Array(64)]]]]), true, null]), /already carries signatures/);
});

test('wallet witnesses are verified against our body hash and merged without touching the body', () => {
  const built = spend('claim'), tx = ct.inspectTx(built.txBytes);
  const witness = signature => encode(new Map([[0, [[bob.pub, signature]]]]));
  const ok = ct.assembleSigned(built.txBytes, witness(ed25519.sign(tx.bodyHash, bob.seed)), ed25519.verify);
  assert.deepEqual(ok.signers, [bob.hash]);
  const signed = ct.inspectTx(ok.txBytes);
  assert.deepEqual(signed.bodyBytes, tx.bodyBytes);
  assert.equal(signed.vkeys.length, 1);
  assert.deepEqual(signed.redeemerBytes, tx.redeemerBytes);
  assert.throws(() => ct.assembleSigned(built.txBytes, witness(ed25519.sign(sha256(tx.bodyHash), bob.seed)), ed25519.verify), /does not verify/);
  assert.throws(() => ct.assembleSigned(built.txBytes, witness(new Uint8Array(10)), ed25519.verify), /malformed/);
  assert.throws(() => ct.assembleSigned(built.txBytes, encode(new Map([[1, []]])), ed25519.verify), /unexpected witness/);
  assert.throws(() => ct.assembleSigned(built.txBytes, encode(new Map([[0, []]])), ed25519.verify), /no signatures/);
});

test('protocol parameters and fee arithmetic: exact fractions, validation', () => {
  assert.equal(ct.unitsFee(params, {memory: 1_000_000, steps: 1_000_000_000}), 57_700n + 72_100n);
  assert.equal(ct.sizeFee(params, 1000), 44n * 1000n + 155381n);
  assert.throws(() => ct.parseParams({...rawParams, costModelV3: [1, 2]}), /Invalid/);
  assert.throws(() => ct.parseParams({...rawParams, priceMem: ['1', '0']}), /Invalid/);
  assert.throws(() => ct.parseParams({...rawParams, minFeeA: 0}), /Invalid/);
});
