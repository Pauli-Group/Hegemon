/* Fund, claim and refund the pinned Cardano HTLC through a CIP-30 wallet.
 *
 * Order of events, each step fail-safe:
 *  1. prove the wallet is on preview (its UTxOs must exist, unspent, with the same value, in the Worker's preview view);
 *  2. verify the escrow with the existing verifier and re-check the policy cutoff;
 *  3. build the transaction ourselves and check the bytes independently (cardano-tx.mjs);
 *  4. show the user what the bytes do, then write the action journal;
 *  5. only then ask the wallet to sign. The wallet's signatures are verified against our body hash;
 *  6. submit, and compare the id the wallet returns with the id we computed.
 * A lost response after step 5 leaves an `uncertain` journal record and a known transaction id to look up.
 */
import {ed25519} from './vendor/hash.mjs';
import {
  PREVIEW, addressInfo, assembleSigned, buildFund, buildSpend, checkFund, checkSpend, expirySlot, parseOutputItem, parseParams, parseTerms, toBech32, valueEquals, valueFromRow,
} from './cardano-tx.mjs';
import {decode, fromHex, toHex} from './cbor.mjs';

export class WalletError extends Error {
  constructor(message, code) { super(message); this.code = code; }
}
const refText = u => `${u.txid}#${u.index}`;

/** CIP-30 TransactionUnspentOutput hex -> {txid, index, address, value}. */
export function parseWalletUtxo(hex) {
  const item = decode(fromHex(hex));
  if (!Array.isArray(item) || item.length !== 2 || !Array.isArray(item[0]) || !(item[0][0] instanceof Uint8Array) || item[0][0].length !== 32 || typeof item[0][1] !== 'number') throw new WalletError('Wallet returned a malformed UTxO.');
  const output = parseOutputItem(item[1]);
  return {txid: toHex(item[0][0]), index: item[0][1], address: output.address, value: output.value, hasScript: output.scriptRef || !!output.datum};
}

function expectedValue(value) {
  const out = {lovelace: value.lovelace.toString()};
  for (const [name, quantity] of Object.entries(value.assets)) {
    const [policy, asset] = name.split('.');
    (out[policy] ??= {})[asset] = quantity.toString();
  }
  return out;
}

/** Everything the wallet reports, checked against the preview chain view. */
export async function verifiedWalletState(api, read, {role} = {}) {
  const network = await api.getNetworkId();
  if (network !== PREVIEW.networkId) throw new WalletError('Wallet is not on a Cardano test network.', 'wrong-network');
  const [rawUtxos, rawCollateral, used, unused, change] = await Promise.all([
    api.getUtxos?.() ?? null, (api.getCollateral ?? api.experimental?.getCollateral)?.call(api) ?? null,
    api.getUsedAddresses?.() ?? [], api.getUnusedAddresses?.() ?? [], api.getChangeAddress(),
  ]);
  const wallet = (rawUtxos ?? []).map(parseWalletUtxo);
  const collateral = (rawCollateral ?? []).map(parseWalletUtxo);
  const keyHashes = new Set();
  for (const hex of [...used, ...unused, change]) {
    const info = addressInfo(fromHex(hex));
    if (info.keyHash) keyHashes.add(info.keyHash);
  }
  const changeBytes = fromHex(change);
  if (!addressInfo(changeBytes).keyHash && !addressInfo(changeBytes).scriptHash) throw new WalletError('Wallet change address is unusable.');
  if (role && !keyHashes.has(role)) throw new WalletError('This wallet does not hold the key this escrow names.', 'wrong-key');
  // Verify at most 24 UTxOs: collateral first, then the largest by lovelace.
  const byRef = new Map();
  for (const u of [...collateral, ...wallet]) byRef.set(refText(u), u);
  const ordered = [...byRef.values()].sort((a, b) => (a.value.lovelace < b.value.lovelace ? 1 : a.value.lovelace > b.value.lovelace ? -1 : 0));
  const refs = [...new Set([...collateral.map(refText), ...ordered.map(refText)])].slice(0, 24);
  if (!refs.length) throw new WalletError('Wallet reports no UTxOs, so it cannot pay a Cardano fee.', 'no-utxos');
  const view = await read.utxos(refs);
  const verified = new Map();
  view.outputs.forEach((row, i) => {
    if (!row || row.is_spent) return;
    const u = byRef.get(refs[i]);
    if (!u) return;
    if (row.address !== toBech32(u.address) || !valueEquals(valueFromRow(row), u.value)) throw new WalletError('Wallet UTxO differs from the preview chain; the wallet may be on another network.', 'wrong-network');
    verified.set(refs[i], u);
  });
  if (!verified.size) throw new WalletError('None of the wallet UTxOs exist on Cardano preview (wrong network, or the indexer is behind).', 'wrong-network');
  const pick = list => list.filter(u => verified.has(refText(u))).map(u => verified.get(refText(u)));
  return {walletUtxos: pick(wallet).filter(u => !u.hasScript), collateralUtxos: pick(collateral).filter(u => !u.hasScript), changeAddress: changeBytes, keyHashes, slot: view.slot};
}

/** Run one Cardano action end to end. Returns {state, txid, fee}. */
export async function cardanoWalletAction({op, terms, preimage, api, read, verifyEscrow, verifyBeforeSign, verifyBeforeSubmit, journal, confirm, budget, cutoffSeconds, nowSeconds = () => Math.floor(Date.now() / 1000), verify = ed25519.verify}) {
  if (!['fund', 'claim', 'refund'].includes(op)) throw new WalletError('Unknown Cardano operation.');
  if (typeof confirm !== 'function' || !journal?.begin || !journal.finish || !journal.uncertain || !journal.remove) throw new WalletError('Confirmation and the action journal are required before a wallet request.');
  if (verifyBeforeSubmit !== undefined && typeof verifyBeforeSubmit !== 'function') throw new WalletError('The swap safety check is unavailable.', 'swap-check');
  if (verifyBeforeSign !== undefined && typeof verifyBeforeSign !== 'function') throw new WalletError('The swap safety check is unavailable.', 'swap-check');
  const t = parseTerms(terms), role = op === 'claim' ? t.claimant : op === 'refund' ? t.refundee : t.refundee;
  const params = parseParams(await read.params());
  let escrow;
  if (op !== 'fund') {
    if (!t.outref) throw new WalletError('The escrow output reference is required.');
    await verifyEscrow(terms);  // throws unless the escrow is confirmed, unspent, matches the terms and the policy limits
    escrow = {...parseRefText(t.outref), value: t.value};
  }
  const state = await verifiedWalletState(api, read, {role});
  const nowSlot = Math.max(params.slot ?? 0, state.slot ?? 0);
  const claimOk = () => {
    if (op !== 'claim' || cutoffSeconds === undefined) return;
    if (nowSeconds() >= cutoffSeconds) throw new WalletError('Too close to the deadline to claim safely.', 'claim-cutoff');
  };
  claimOk();
  let built, checked;
  if (op === 'fund') {
    built = buildFund({terms: {...terms}, walletUtxos: state.walletUtxos, changeAddress: state.changeAddress, params});
    checked = checkFund(built.txBytes, built.expect);
  } else {
    built = buildSpend({op, terms, escrow, preimage, walletUtxos: state.walletUtxos, collateralUtxos: state.collateralUtxos.length ? state.collateralUtxos : state.walletUtxos.filter(u => !Object.keys(u.value.assets).length && u.value.lovelace >= 5_000_000n),
      changeAddress: state.changeAddress, walletKeyHash: role, params, budget, nowSlot});
    checked = checkSpend(built.txBytes, built.expect);
    if (!built.expect.feeInputs.length) throw new WalletError('The wallet needs a separate ADA UTxO to pay the fee.', 'no-fee-input');
  }
  if (!(await confirm({op, lines: checked.lines, txid: checked.txid, fee: checked.fee}))) throw new WalletError('Declined before the wallet was asked.', 'declined-locally');
  // The journal is written before the first wallet request. If it cannot be written the wallet is never contacted.
  const request = journalRequest(op, built, t);
  const id = await journal.begin('cardano', op === 'fund' ? 'lock' : op, request);
  // Re-read the chain head one last time: a stale page must not request a claim signature near the cutoff.
  try {
    const fresh = await read.params();
    if (!Number.isSafeInteger(fresh.slot) || fresh.slot < 0 || fresh.slot + 5 < nowSlot) throw new WalletError('Cardano chain view went backwards; try again.', 'stale-head');
    if (op === 'claim' && fresh.slot + params.claimMarginSlots >= expirySlot(t, params.systemStart)) throw new WalletError('Too close to the deadline to claim safely.', 'claim-cutoff');
    claimOk();
    if (verifyBeforeSign) {
      try { await verifyBeforeSign({op, slot: fresh.slot}); }
      catch (error) { throw new WalletError(error instanceof Error ? error.message : 'The swap safety check failed.', 'swap-check'); }
    }
    claimOk();
  } catch (error) {
    await journal.remove(id);
    throw error;
  }
  let witnessHex;
  try {
    witnessHex = await api.signTx(toHex(built.txBytes), true);
  } catch (error) {
    if (isDecline(error)) { await journal.remove(id); throw new WalletError('The wallet declined to sign.', 'declined'); }
    await journal.uncertain(id);
    throw new WalletError('The wallet did not return a signature; no transaction was submitted. It may still hold a signing request.', 'sign-failed');
  }
  let signed;
  try {
    signed = assembleSigned(built.txBytes, fromHex(witnessHex), verify);
    const needKeys = op === 'fund' ? built.expect.inputs.map(u => addressInfo(u.address).keyHash).filter(Boolean) : [role];
    if (!needKeys.every(h => signed.signers.includes(h))) throw new WalletError('Wallet did not sign with every key this action needs.', 'wrong-signer');
  } catch (error) {
    await journal.uncertain(id);  // the wallet produced a signature we cannot use; nothing was submitted
    throw error;
  }
  // A wallet approval can take longer than the remaining safe window. Recheck after it returns and before this
  // page submits. A swap coordinator can also recheck the other leg for any operation through verifyBeforeSubmit.
  // The wallet has already seen the transaction (including a claim's secret), so any failure remains uncertain.
  if (op === 'claim' || verifyBeforeSubmit) {
    try {
      const fresh = await read.params();
      if (!Number.isSafeInteger(fresh.slot) || fresh.slot < 0 || fresh.slot + 5 < nowSlot) throw new WalletError('Cardano chain view went backwards.', 'stale-head');
      if (op === 'claim' && fresh.slot + params.claimMarginSlots >= expirySlot(t, params.systemStart)) throw new WalletError('Too close to the deadline to claim safely.', 'claim-cutoff');
      claimOk();
      if (op !== 'fund') await verifyEscrow(terms);
      claimOk();
      const latest = await read.params();
      if (!Number.isSafeInteger(latest.slot) || latest.slot < 0 || latest.slot + 5 < fresh.slot) throw new WalletError('Cardano chain view went backwards.', 'stale-head');
      if (op === 'claim' && latest.slot + params.claimMarginSlots >= expirySlot(t, params.systemStart)) throw new WalletError('Too close to the deadline to claim safely.', 'claim-cutoff');
      if (verifyBeforeSubmit) await verifyBeforeSubmit({op, slot: latest.slot});
      claimOk();
    } catch (error) {
      await journal.uncertain(id);
      throw new WalletError((error instanceof Error ? error.message : 'The swap safety check failed.') + ' The wallet signed, but this page did not submit; check the action record before retrying.', error instanceof WalletError ? error.code : 'swap-check');
    }
  }
  let returned;
  try {
    returned = await api.submitTx(toHex(signed.txBytes));
  } catch (error) {
    await journal.uncertain(id);
    return {state: 'uncertain', txid: checked.txid, fee: checked.fee, message: 'The wallet did not confirm submission. The transaction id is known; look it up on a Cardano preview explorer before trying again.'};
  }
  if (typeof returned === 'string' && returned.toLowerCase() !== checked.txid) {
    await journal.uncertain(id);
    throw new WalletError('Wallet returned a different transaction id than the one checked.', 'txid-mismatch');
  }
  await journal.finish(id, {submitted: true, txid: checked.txid});
  return {state: 'submitted', txid: checked.txid, fee: checked.fee, lines: checked.lines};
}

function parseRefText(text) {
  const [txid, index] = text.split('#');
  return {txid, index: Number(index)};
}
const isDecline = error => error?.code === 2 || error?.code === 'UserDeclined' || /declin|reject|cancel|denied/i.test(String(error?.info ?? error?.message ?? ''));

function journalRequest(op, built, t) {
  const base = {operation: op === 'fund' ? 'lock' : op, hashlock: t.hashlock, claimant: t.claimant, refundee: t.refundee, expiry_ms: t.expiryMs.toString(), expected_value: expectedValue(t.value)};
  if (op === 'fund') return {...base, inputs: built.expect.inputs.map(refText)};
  return {...base, outref: refText(built.expect.escrow), fee_input: refText(built.expect.feeInputs[0]), collateral: refText(built.expect.collateral)};
}
