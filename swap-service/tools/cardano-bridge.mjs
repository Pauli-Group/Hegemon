#!/usr/bin/env node
/* Test bridge: runs the page's real Cardano wallet flow (swap-ui/cardano-wallet.mjs) against chain data supplied
 * as JSON on stdin, with a software CIP-30 wallet that signs with an ed25519 key file. It prints the signed
 * transaction instead of submitting it, so a harness (the local cluster test, or a qualification run) decides
 * where it goes. The key file path is read from the request; keys never go in argv or logs.
 */
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {blake2b, ed25519} from '../../swap-ui/vendor/hash.mjs';
import {fromBech32, setPinnedScript} from '../../swap-ui/cardano-tx.mjs';
import {cardanoWalletAction, WalletError} from '../../swap-ui/cardano-wallet.mjs';
import {encode, fromHex, spans, toHex} from '../../swap-ui/cbor.mjs';

const root = fileURLToPath(new URL('../../swap-ui/', import.meta.url));

/** A CIP-30 wallet over a fixed UTxO set. `declines` and `failSign` exist so tests can exercise wallet failures. */
export function softwareWallet({seed, address, utxos, collateral, networkId = 0, declines = false, failSign = false, failSubmit = false, tamper, onSubmit}) {
  const publicKey = ed25519.getPublicKey(seed);
  const toHexUtxo = u => toHex(encode([[fromHex(u.ref.split('#')[0]), Number(u.ref.split('#')[1])], new Map([[0, fromBech32(u.address)], [1, valueOf(u)]])]));
  const addressHex = toHex(fromBech32(address));
  return {
    publicKeyHash: toHex(blake2b(publicKey, {dkLen: 28})),
    getNetworkId: async () => networkId,
    getUtxos: async () => utxos.map(toHexUtxo),
    getCollateral: async () => (collateral?.length ? utxos.filter(u => collateral.includes(u.ref)).map(toHexUtxo) : null),
    getUsedAddresses: async () => [addressHex],
    getUnusedAddresses: async () => [],
    getChangeAddress: async () => addressHex,
    signTx: async txHex => {
      if (declines) throw Object.assign(new Error('user declined'), {code: 2, info: 'User declined'});
      if (failSign) throw Error('wallet connection lost');
      const raw = fromHex(txHex), body = raw.slice(...spans(raw)[0]);
      const signature = ed25519.sign(blake2b(body, {dkLen: 32}), seed);
      const witness = encode(new Map([[0, [[publicKey, signature]]]]));
      return toHex(tamper ? tamper(witness) : witness);
    },
    submitTx: async txHex => {
      onSubmit?.(txHex);
      if (failSubmit) throw Error('response lost');
      const raw = fromHex(txHex);
      return toHex(blake2b(raw.slice(...spans(raw)[0]), {dkLen: 32}));
    },
  };
}
function valueOf(u) {
  const lovelace = BigInt(u.lovelace), policies = new Map();
  for (const [name, quantity] of Object.entries(u.assets ?? {})) {
    const [policy, asset] = name.split('.');
    if (!policies.has(policy)) policies.set(policy, new Map());
    policies.get(policy).set(fromHex(asset), BigInt(quantity));
  }
  return policies.size ? [lovelace, new Map([...policies].map(([p, m]) => [fromHex(p), m]))] : lovelace;
}

export function rowOf(u, spent = false) {
  const [txid, index] = [u.ref.split('#')[0], Number(u.ref.split('#')[1])];
  return {tx_hash: txid, tx_index: index, address: u.address, value: String(u.lovelace), is_spent: spent,
    asset_list: Object.entries(u.assets ?? {}).map(([name, quantity]) => ({policy_id: name.split('.')[0], asset_name: name.split('.')[1], quantity: String(quantity)}))};
}

async function main() {
  const request = JSON.parse(fs.readFileSync(0, 'utf8'));
  setPinnedScript(JSON.parse(fs.readFileSync(root + 'cardano-htlc-script.json', 'utf8')));
  const seedText = JSON.parse(fs.readFileSync(request.signingKeyFile, 'utf8')).cborHex;
  const seed = fromHex(seedText).slice(2);
  const rows = new Map(request.utxos.map(u => [u.ref, rowOf(u)]));
  let signedHex;
  const api = softwareWallet({seed, address: request.changeAddress, utxos: request.utxos, collateral: request.collateral, onSubmit: hex => { signedHex = hex; }});
  const journal = {records: [], async begin(chain, op, req) { this.records.push({chain, op, req, state: 'pending'}); return String(this.records.length - 1); }, async finish(id) { this.records[id].state = 'completed'; }, async uncertain(id) { this.records[id].state = 'uncertain'; }, async remove(id) { this.records[id].state = 'removed'; }};
  const result = await cardanoWalletAction({
    op: request.op, terms: request.terms, preimage: request.preimage, api, journal, budget: request.budget, cutoffSeconds: request.cutoffSeconds,
    nowSeconds: () => request.nowSeconds ?? Math.floor(Date.now() / 1000), confirm: async () => true,
    read: {params: async () => request.params, utxos: async refs => ({slot: request.params.slot, outputs: refs.map(ref => rows.get(ref) ?? null)})},
    verifyEscrow: async () => ({slot: request.params.slot}),
  });
  process.stdout.write(JSON.stringify({...result, fee: String(result.fee), signedHex, journal: journal.records.map(r => r.state)}) + '\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(error => { process.stdout.write(JSON.stringify({error: error.message, code: error instanceof WalletError ? error.code : undefined}) + '\n'); process.exitCode = 1; });
}
