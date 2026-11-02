#!/usr/bin/env python3
"""Check a client's pinned-bytecode verifier against real local EVM state."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from htlc_counterpart import Ethereum, TOOLS, ROOT, wait_for
from local_private_spend_swap import require
from release_private_spend_lifecycle_io import rpc


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS)
    a=p.parse_args();os.umask(0o077)
    output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False)
    results=[]
    try:
        for kind in ('eth','erc20','erc721','erc1155'):
            chain=Ethereum(output/kind,a.tools,test_token=None if kind=='eth' else kind)
            try:
                secret=os.urandom(32);digest=hashlib.sha256(secret).digest();chain.lock(digest)
                terms={'chainId':'0x7a69','contract':chain.contract,'kind':'eth' if kind=='eth' else str(chain.token_kind),
                       'amount':str(chain.amount if kind=='eth' else chain.token_amount),'hashlock':'0x'+digest.hex(),
                       'claimant':chain.alice,'refundee':chain.bob,'expiry':str(chain.expiry)}
                if kind!='eth':terms.update(token=chain.token,tokenId=str(chain.token_id))
                def check(data,expected,switch=False,late=False,recent=False):
                    run=subprocess.run(['node',str(ROOT/'scripts/verify_ethereum_escrow.mjs')],input=json.dumps({'url':chain.url,'terms':data,'simulateChainSwitch':switch,'simulateLate':late,'simulateRecentSpend':recent}),text=True,capture_output=True,timeout=30)
                    require((run.returncode==0)==expected,'verifier returned unexpected result: '+run.stderr[-500:])
                    return run
                valid=check(terms,True)
                switched=check(terms,False,switch=True)
                require('snapshot or chain changed' in switched.stderr,'chain switch rejected for an unexpected reason')
                late=check(terms,False,late=True)
                require('escrow deadline too close' in late.stderr,'late escrow rejected for an unexpected reason')
                recent=check(terms,False,recent=True)
                require('not funded and unspent at current head' in recent.stderr,'recent spend rejected for an unexpected reason')
                bad={**terms,'hashlock':'0x'+'ff'*32};check(bad,False)
                bad={**terms,'chainId':'0x1'};check(bad,False)
                bad={**terms,'claimant':chain.outsider};check(bad,False)
                # Mine the actual claim without the adapter's extra blocks:
                # the confirmed snapshot remains unspent but the head is spent.
                ident=rpc(chain.url,'eth_sendTransaction',[{'from':chain.alice,'to':chain.contract,
                          'data':chain.data('claim(bytes32)',secret.hex()),'gas':hex(2_000_000)}])
                receipt=wait_for(lambda:rpc(chain.url,'eth_getTransactionReceipt',[ident]),'claim receipt')
                require(receipt and int(receipt['status'],16)==1,'claim failed')
                recent_real=check(terms,False)
                require('not funded and unspent at current head' in recent_real.stderr,'actual recent spend rejected for an unexpected reason')
                rpc(chain.url,'evm_mine');rpc(chain.url,'evm_mine')
                spent=check(terms,False)
                require('not funded and unspent' in spent.stderr,'spent escrow rejected for an unexpected reason')
                chain.isolated();results.append({'kind':kind,'status':'passed','snapshot':json.loads(valid.stdout)['snapshot']})
                print(kind,'passed',flush=True)
            finally:chain.close()
    finally:
        (output/'summary.json').write_text(json.dumps({'status':'passed' if len(results)==4 else 'failed','scenarios':results},indent=2)+'\n')
    print('summary:',output/'summary.json')

if __name__=='__main__':main()
