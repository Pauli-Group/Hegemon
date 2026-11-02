#!/usr/bin/env python3
"""Swap an ERC-20 fixture for an ERC-721 fixture on one isolated Anvil chain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from htlc_counterpart import Ethereum, TOOLS, ROOT
from release_private_spend_lifecycle_io import rpc
from local_private_spend_swap import require


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS)
    a=p.parse_args();os.umask(0o077)
    output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    chain=None;receipt={'status':'failed','note':'Local disposable fixtures; no production timing or finality claim.'}
    try:
        chain=Ethereum(output/'eth',a.tools,test_token='erc20')
        chain.isolated();secret=os.urandom(32);digest=hashlib.sha256(secret).digest()
        # Bob's ERC-20 escrow has the later deadline and is funded first.
        chain.lock(digest)
        artifact=json.loads((ROOT/'contracts/ethereum/out/TokenHTLC.t.sol/Sample721.json').read_text())
        token=chain.send(chain.alice,artifact['bytecode']['object']+chain.word_address(chain.alice))['contractAddress']
        short_expiry=int(rpc(chain.url,'eth_getBlockByNumber',['latest',False])['timestamp'],16)+300
        require(short_expiry<chain.expiry,'deadlines are not staggered')
        args=chain.word_number(1)+chain.word_address(token)+chain.word_number(42)+chain.word_number(1)+digest.hex()+chain.word_address(chain.bob)+chain.word_number(short_expiry)
        escrow=chain.send(chain.alice,chain.artifact['bytecode']['object']+args)['contractAddress']
        approve='0x'+artifact['methodIdentifiers']['approve(address,uint256)']+chain.word_address(escrow)+chain.word_number(42)
        chain.send(chain.alice,approve,token);chain.send(chain.alice,chain.data('fund()'),escrow)
        call='0x'+artifact['methodIdentifiers']['ownerOf(uint256)']+chain.word_number(42)
        def owner():return rpc(chain.url,'eth_call',[{'to':token,'data':call},'latest'])[-40:].lower()
        require(owner()==escrow[2:].lower(),'NFT not escrowed')
        short_claim=chain.send(chain.bob,chain.data('claim(bytes32)',secret.hex()),escrow)
        logs=[entry for entry in short_claim['logs'] if entry['address'].lower()==escrow.lower()]
        require(len(logs)==1,'short escrow event missing')
        revealed=bytes.fromhex(logs[0]['data'][2:66])
        require(hashlib.sha256(revealed).digest()==digest,'wrong secret in event')
        require(owner()==chain.bob[2:].lower(),'NFT not paid to claimant')
        require(chain.claim(revealed)==secret,'fungible escrow claim failed')
        chain.isolated()
        receipt.update(status='passed',ethereum=chain.receipt,nft={'token':token,'escrow':escrow,'claim_txid':short_claim['transactionHash'],'token_id':42})
    finally:
        if chain:chain.close()
        (output/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('passed:',output/'summary.json')

if __name__=='__main__':main()
