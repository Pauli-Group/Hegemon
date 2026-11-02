#!/usr/bin/env python3
"""Swap two native-token fixtures through HTLCs on one isolated Cardano chain."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
from htlc_counterpart import Cardano, TOOLS
from local_private_spend_swap import require


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS)
    a=p.parse_args();os.umask(0o077)
    output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    chain=None;receipt={'status':'failed','note':'Local disposable fixtures; no public-chain timing or finality claim.'}
    try:
        chain=Cardano(output/'ada',a.tools,test_tokens=True,epoch_length=5000);chain.isolated()
        policy=next(iter(chain.tokens)); fungible='46554e47';nft='4e4654'
        body,signed=chain.files('distribute-fixtures')
        alice=chain.actors['alice']['address'];bob=chain.actors['bob']['address']
        chain.build(['--tx-in',chain.token_input,'--tx-in',chain.fee_input('bob'),
                     '--tx-out',alice+'+10000000+1 '+policy+'.'+nft,
                     '--tx-out',bob+'+20000000','--change-address',bob],body)
        _,alice_out=chain.submit(body,signed,'bob',alice)
        chain.tokens={policy:{fungible:11}}
        chain.token_input=next(k for k,v in chain.utxos(bob).items() if chain.has_tokens(v))
        # Reuse the same node, but reverse the two actors for the second escrow.
        other=copy.copy(chain);other.actors=dict(chain.actors)
        other.actors['alice'],other.actors['bob']=chain.actors['bob'],chain.actors['alice']
        other.tokens={policy:{nft:1}};other.serial=10000
        other.receipt={'chain':'cardano','checks':{},'transactions':{}}
        other.token_input=next(k for k,v in alice_out.items() if other.has_tokens(v))
        secret=os.urandom(32);digest=hashlib.sha256(secret).digest()
        chain.lock(digest,ttl_slots=1200)
        other.lock(digest,ttl_slots=600)
        require(other.expiry_slot<chain.expiry_slot,'deadlines are not staggered')
        revealed=other.claim(secret)
        require(hashlib.sha256(revealed).digest()==digest,'revealed secret mismatch')
        require(chain.claim(revealed)==secret,'first escrow claim failed')
        chain.isolated()
        receipt.update(status='passed',fungible=chain.receipt,nft=other.receipt)
    finally:
        if chain:chain.close()
        (output/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
