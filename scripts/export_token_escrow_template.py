#!/usr/bin/env python3
"""Export a source-pinned Solidity runtime template for client escrow checks."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'contracts/ethereum/TokenHTLC.sol'
ARTIFACT=ROOT/'contracts/ethereum/out/TokenHTLC.sol/TokenHTLC.json'
OUTPUT=ROOT/'swap-ui/token-escrow-template.json'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solc',type=Path,default=Path('/workspace/chain-tools/solc'))
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--native',action='store_true',help='export the native ETH escrow template')
    args=parser.parse_args()
    source=ROOT/'contracts/ethereum/HegemonHTLC.sol' if args.native else SOURCE
    artifact_path=ROOT/'contracts/ethereum/out/HegemonHTLC.sol/HegemonHTLC.json' if args.native else ARTIFACT
    output=ROOT/'swap-ui/ether-escrow-template.json' if args.native else OUTPUT
    contract_name='HegemonHTLC' if args.native else 'TokenHTLC'
    raw=subprocess.check_output([args.solc,'--ast-compact-json',source],text=True)
    ast=json.loads(raw[raw.index('{'):])
    contract=next(n for n in ast['nodes'] if n.get('name')==contract_name)
    names={str(n['id']):n['name'] for n in contract['nodes'] if n.get('nodeType')=='VariableDeclaration' and n.get('mutability')=='immutable'}
    expected={'hashlock','claimant','refundee','expiry'} if args.native else {'kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'}
    if set(names.values())!=expected:raise RuntimeError('unexpected immutable variables')
    artifact=json.loads(artifact_path.read_text());deployed=artifact['deployedBytecode']
    refs={names[k]:v for k,v in deployed['immutableReferences'].items()}
    if set(refs)!=expected:raise RuntimeError('artifact immutable references do not match source AST; rebuild with pinned solc')
    code=deployed['object'].removeprefix('0x')
    if any(x['length']!=32 or code[x['start']*2:(x['start']+32)*2]!='0'*64 for ranges in refs.values() for x in ranges):raise RuntimeError('unexpected immutable template')
    creation=artifact['bytecode']['object'].removeprefix('0x')
    if not creation or any(c not in '0123456789abcdef' for c in creation):raise RuntimeError('invalid or unlinked creation bytecode')
    payload={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'creation':creation,'runtime':code,'immutableReferences':refs,'methods':artifact['methodIdentifiers']}
    result=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    if args.check:
        if not output.exists() or output.read_text()!=result:raise SystemExit('runtime template is stale')
        print('runtime template matches artifact and source')
    else:
        output.write_text(result);print('wrote',output)

if __name__=='__main__':main()
