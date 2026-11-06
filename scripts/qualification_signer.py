#!/usr/bin/env python3
"""Independent test signers for the hosted-page qualification run (swap-service/qualify/hosted-ui.mjs).

These stand in for external wallets: the page builds a request, this process checks it against the key it holds and
signs with different code than the page uses. It is for disposable public-testnet keys only. Key file paths come from
the command line, key material is never printed, and the process reads one JSON request from stdin.

  eth-send --wallet KEYFILE --journal DIR   {from,to?,data?,value?}   -> {"txid":"0x.."}
  btc-sign --wallet KEYFILE                 {psbt: base64}            -> {"psbt": base64}
"""
import argparse
import base64
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def eth_send(wallet, journal, request):
    from public_sepolia_driver import load_test_wallet, send
    _, address = load_test_wallet(wallet)
    allowed = {'from', 'to', 'data', 'value', 'gas', 'chainId', 'type'}
    if not isinstance(request, dict) or set(request) - allowed or str(request.get('from', '')).lower() != address.lower():
        raise ValueError('Transaction request is not from this wallet or has unexpected fields')
    to = request.get('to')
    if to is not None and not re.fullmatch('0x[0-9a-fA-F]{40}', to):
        raise ValueError('Invalid destination')
    data = request.get('data', '0x')
    if not re.fullmatch('0x(?:[0-9a-fA-F]{2})*', data) or len(data) > 100_000:
        raise ValueError('Invalid data')
    value = int(request.get('value', '0x0'), 16)
    result = send(journal, wallet, to, value, bytes.fromhex(data[2:]))
    return {'txid': result['txid'] if str(result['txid']).startswith('0x') else '0x' + result['txid']}


def btc_sign(wallet, request):
    from embit import script
    from embit.psbt import PSBT
    from public_bitcoin_driver import load_test_key
    key = load_test_key(wallet)
    pub = key.get_public_key()
    psbt = PSBT.parse(base64.b64decode(request['psbt']))
    signed = 0
    for index, item in enumerate(psbt.inputs):
        amount = item.witness_utxo.value
        if item.witness_script is not None:
            # An HTLC spend: sign only when our key is one of the two keys in the script.
            if pub.sec() not in bytes(item.witness_script.data):
                continue
            digest = psbt.tx.sighash_segwit(index, item.witness_script, amount)
        else:
            if bytes(item.witness_utxo.script_pubkey.data) != bytes(script.p2wpkh(pub).data):
                continue
            digest = psbt.tx.sighash_segwit(index, script.p2pkh(pub), amount)
        item.partial_sigs[pub] = key.sign(digest).serialize() + b'\x01'
        signed += 1
    if not signed:
        raise ValueError('No input of this transaction belongs to this key')
    return {'psbt': base64.b64encode(psbt.serialize()).decode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('operation', choices=['eth-send', 'btc-sign'])
    parser.add_argument('--wallet', type=Path, required=True)
    parser.add_argument('--journal', type=Path)
    args = parser.parse_args()
    raw = sys.stdin.read(400_001)
    if len(raw) > 400_000:
        raise ValueError('Request too large')
    request = json.loads(raw)
    if args.operation == 'eth-send':
        if args.journal is None:
            raise ValueError('--journal is required')
        print(json.dumps(eth_send(args.wallet, args.journal, request)))
    else:
        print(json.dumps(btc_sign(args.wallet, request)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:  # report, never include key material
        print(json.dumps({'error': str(error)[:300]}))
        sys.exit(1)
