#!/usr/bin/env python3
"""Refund leftover native Sepolia HTLC escrows with a disposable test wallet.

For each contract: refuse unless its runtime has code and spent() is false, simulate refund() from the wallet
with eth_call (a revert means the deadline has not passed or the caller is not allowed), submit it once through
the journaled driver, wait for a successful receipt and check that the escrow balance is zero. Never retries a
submission; a lost response is left in the journal for a human to resolve.

    PYTHONPATH=scripts python3 scripts/sweep_sepolia_escrows.py --wallet KEY --journal DIR 0xescrow...
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from public_sepolia_driver import load_test_wallet, send  # noqa: E402
from public_testnet_probe import rpc  # noqa: E402

REFUND = '0x590e1ae3'
SPENT = '0x7ab71b7a'


def sweep(wallet, journal, contract, wait=300):
    _, address = load_test_wallet(wallet)
    contract = contract.lower()
    if rpc('eth_getCode', [contract, 'latest']) in (None, '0x'):
        return {'contract': contract, 'result': 'no-code'}
    if int(rpc('eth_call', [{'to': contract, 'data': SPENT}, 'latest']), 16):
        return {'contract': contract, 'result': 'already-spent'}
    try:
        rpc('eth_call', [{'from': address, 'to': contract, 'data': REFUND}, 'latest'])
    except Exception as error:
        return {'contract': contract, 'result': 'refund-would-revert', 'detail': str(error)[:200]}
    sent = send(journal, wallet, contract, 0, bytes.fromhex(REFUND[2:]))
    txid = sent['txid'] if str(sent['txid']).startswith('0x') else '0x' + sent['txid']
    deadline = time.time() + wait
    receipt = None
    while time.time() < deadline:
        receipt = rpc('eth_getTransactionReceipt', [txid])
        if receipt:
            break
        time.sleep(6)
    if not receipt:
        return {'contract': contract, 'result': 'unconfirmed', 'refund_tx': txid}
    spent = int(rpc('eth_call', [{'to': contract, 'data': SPENT}, 'latest']), 16)
    balance = int(rpc('eth_getBalance', [contract, 'latest']), 16)
    ok = receipt['status'] == '0x1' and spent == 1 and balance == 0
    return {'contract': contract, 'result': 'refunded' if ok else 'unexpected', 'refund_tx': txid, 'block': int(receipt['blockNumber'], 16)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--wallet', type=Path, required=True)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('contracts', nargs='+')
    args = parser.parse_args()
    results = []
    for contract in args.contracts:
        results.append(sweep(args.wallet, args.journal, contract))
        print(json.dumps(results[-1]), flush=True)
    return 0 if all(r['result'] in ('refunded', 'already-spent') for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
