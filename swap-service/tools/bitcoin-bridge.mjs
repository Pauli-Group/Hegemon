#!/usr/bin/env node
/* Test bridge: runs the page's real Bitcoin PSBT code (swap-ui/bitcoin-psbt.mjs) for a harness that supplies chain
 * data and an independent signer. Stateless: `finalize` rebuilds the same PSBT from the same request, so the checks
 * run against exactly what `build` produced. Reads one JSON request from stdin, writes one JSON line to stdout.
 */
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {TEST_NETWORK} from '../../swap-ui/vendor/btc-signer.mjs';
import * as psbt from '../../swap-ui/bitcoin-psbt.mjs';

const NETWORKS = {testnet4: TEST_NETWORK, regtest: {...TEST_NETWORK, bech32: 'bcrt'}};

export function run(request) {
  const network = NETWORKS[request.network ?? 'testnet4'];
  if (!network) throw Error('Unknown network.');
  const common = {terms: request.terms, network, feeRate: request.feeRate ?? 2};
  const built = request.op === 'fund'
    ? psbt.buildFund({...common, inputs: request.inputs, changeAddress: request.address})
    : psbt.buildSpend({...common, op: request.op, escrow: {...request.escrow, amount: BigInt(request.escrow.amount)}, destination: request.address});
  if (request.action === 'build') {
    const checked = psbt.checkPsbt(built.psbt, built.expect);
    return {psbt: psbt.encodePsbt(built.psbt), fee: String(built.fee), txid: checked.txid, lines: checked.lines};
  }
  if (request.action === 'finalize') {
    const bytes = psbt.decodePsbt(request.signedPsbt);
    const done = request.op === 'fund' ? psbt.finalizeFund(bytes, built.expect) : psbt.finalizeSpend(bytes, built.expect, {preimage: request.preimage});
    return {txHex: done.txHex, txid: done.txid, fee: String(done.fee), vsize: done.vsize};
  }
  throw Error('Unknown action.');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const request = JSON.parse(fs.readFileSync(0, 'utf8'));
    for (const input of request.inputs ?? []) input.amount = BigInt(input.amount);
    process.stdout.write(JSON.stringify(run(request)) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({error: error.message}) + '\n');
    process.exitCode = 1;
  }
}
