#!/usr/bin/env python3
"""Swap local Ethereum fixture tokens for local Cardano fixture tokens."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from htlc_counterpart import Ethereum, Cardano, TOOLS
from cardano_escrow_verifier import verify_cardano_htlc


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
        terms={'outref':cardano.locked,'hashlock':digest.hex(),
               'claimant':cardano.actors['alice']['hash'],'refundee':cardano.actors['bob']['hash'],
               'expiry_ms':cardano.expiry_ms,'expected_value':{'lovelace':cardano.amount,**cardano.tokens},
               'genesis_sha256':hashlib.sha256((cardano.net/'shelley-genesis.json').read_bytes()).hexdigest(),
               'aiken':a.tools/'aiken/aiken-x86_64-unknown-linux-musl/aiken'}
        snapshot=verify_cardano_htlc(cardano,**terms)
        for bad in ({**terms,'hashlock':'00'*32},{**terms,'claimant':cardano.actors['outsider']['hash']},
                    {**terms,'expiry_ms':cardano.expiry_ms+1},{**terms,'expected_value':{'lovelace':cardano.amount}}):
            try:verify_cardano_htlc(cardano,**bad)
            except ValueError:pass
            else:raise RuntimeError('Cardano verifier accepted altered terms')
        # B claims A's shorter escrow. A observes the confirmed secret and uses
        # it to claim B's longer Ethereum escrow.
        revealed=cardano.claim(secret)
        try:verify_cardano_htlc(cardano,**terms)
        except ValueError:pass
        else:raise RuntimeError('Cardano verifier accepted a spent output')
        assert hashlib.sha256(revealed).digest()==digest
        assert eth.claim(revealed)==revealed
        eth.isolated();cardano.isolated()
        receipt.update(status='passed',ethereum=eth.receipt,cardano=cardano.receipt,cardano_snapshot=snapshot)
    finally:
        if cardano:cardano.close()
        if eth:eth.close()
        (output/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
