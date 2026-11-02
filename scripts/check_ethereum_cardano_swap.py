#!/usr/bin/env python3
"""Swap local Ethereum fixture tokens for local Cardano fixture tokens."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from htlc_counterpart import Ethereum, Cardano, TOOLS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--tools',type=Path,default=TOOLS)
    p.add_argument('--ethereum-token',choices=['erc20','erc721','erc1155'],default='erc20')
    a=p.parse_args();os.umask(0o077)
    output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    eth=cardano=None
    receipt={'status':'failed','note':'Local disposable fixtures; no production timing or finality claim.'}
    try:
        eth=Ethereum(output/'eth',a.tools,test_token=a.ethereum_token)
        cardano=Cardano(output/'ada',a.tools,test_tokens=True)
        eth.isolated();cardano.isolated()
        secret=os.urandom(32);digest=hashlib.sha256(secret).digest()
        # Ethereum bob and Cardano alice are participant B; Ethereum alice and
        # Cardano bob are participant A. B locks first with the longer deadline.
        eth.lock(digest)
        cardano.lock(digest)
        # B claims A's shorter escrow. A observes the confirmed secret and uses
        # it to claim B's longer Ethereum escrow.
        revealed=cardano.claim(secret)
        assert hashlib.sha256(revealed).digest()==digest
        assert eth.claim(revealed)==revealed
        eth.isolated();cardano.isolated()
        receipt.update(status='passed',ethereum=eth.receipt,cardano=cardano.receipt)
    finally:
        if cardano:cardano.close()
        if eth:eth.close()
        (output/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
