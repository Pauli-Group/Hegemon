#!/usr/bin/env python3
"""Exercise token HTLCs on fresh, isolated local Ethereum chains."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from htlc_counterpart import Ethereum, TOOLS


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--tools',type=Path,default=TOOLS)
    args=parser.parse_args()
    os.umask(0o077)
    output=args.output.resolve()
    output.mkdir(mode=0o700,exist_ok=False)
    results=[]
    try:
        for kind in ('erc20','erc721','erc1155'):
            for action in ('claim','refund'):
                chain=Ethereum(output/(kind+'-'+action),args.tools,test_token=kind)
                try:
                    chain.isolated()
                    secret=os.urandom(32)
                    chain.lock(hashlib.sha256(secret).digest())
                    if action=='claim':
                        assert chain.claim(secret)==secret
                    else:
                        chain.refund()
                    chain.isolated()
                    results.append({'scenario':action,'status':'passed',**chain.receipt})
                    print(kind,action,'passed',flush=True)
                finally:
                    chain.close()
    finally:
        (output/'summary.json').write_text(json.dumps({'status':'passed' if len(results)==6 else 'failed','scenarios':results},indent=2)+'\n')
    print('summary:',output/'summary.json')


if __name__=='__main__':
    main()
