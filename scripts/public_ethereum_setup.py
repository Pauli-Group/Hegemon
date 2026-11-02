#!/usr/bin/env python3
"""Deploy disposable Sepolia token fixtures through locally signed actions.

These deliberately minimal test contracts are not production token contracts.
`advance` makes at most one submission and refuses to retry an inflight action.
"""
import argparse
import json
from pathlib import Path
from eth_abi import encode,decode
from eth_utils import keccak
from public_btc_eth_rehearsal import _directory,_locked,_receipt,_write
from public_sepolia_driver import load_test_wallet,send
from public_testnet_probe import rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]
FIXTURES={'erc20':('Sample20','alice'),'erc721':('Sample721','bob'),'erc1155':('Sample1155','alice')}


def _actor(root,name):return load_test_wallet(root/name/'ethereum-sepolia.key')[1]
def _save(work,state,exclusive=False):_write(work/'state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),exclusive)
def _state(work):
    state=json.loads((work/'state.json').read_text())
    if state.get('version')!=1 or state.get('kind')!='ethereum-fixtures':raise ValueError('Invalid Ethereum fixture state')
    return state


def initialize(root):
    root=_directory(root);verify_network('ethereum-sepolia');work=root/'ethereum-setup';work.mkdir(mode=0o700)
    actors={name:_actor(root,name) for name in ('alice','bob')};public=json.loads((root/'addresses.json').read_text())
    if any(actors[name].lower()!=public[name]['ethereum_sepolia'].lower() for name in actors):raise ValueError('Ethereum test addresses do not match keys')
    state={'version':1,'kind':'ethereum-fixtures','phase':'created','actors':actors,'contracts':{}}
    _save(work,state,True);return {'phase':'created'}


def _bytecode(fixture):
    name,_=FIXTURES[fixture];artifact=json.loads((ROOT/'contracts/ethereum/out/TokenHTLC.t.sol'/f'{name}.json').read_text())
    creation=bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))
    runtime=artifact['deployedBytecode']['object'].lower()
    if not creation or not runtime.startswith('0x'):raise ValueError('Token fixture artifact is unavailable')
    return creation,runtime


def _check_contract(fixture,address,owner):
    _,runtime=_bytecode(fixture)
    if str(rpc('eth_getCode',[address,'latest'])).lower()!=runtime:raise ValueError('Deployed fixture code differs from local artifact')
    if fixture=='erc721':signature='ownerOf(uint256)';args=encode(['uint256'],[42]);types=['address'];expected=owner.lower()
    elif fixture=='erc1155':signature='balanceOf(address,uint256)';args=encode(['address','uint256'],[owner,7]);types=['uint256'];expected=100
    else:signature='balanceOf(address)';args=encode(['address'],[owner]);types=['uint256'];expected=1000
    data='0x'+(keccak(text=signature)[:4]+args).hex();result=rpc('eth_call',[{'to':address,'data':data},'latest']);actual=decode(types,bytes.fromhex(result.removeprefix('0x')))[0]
    if types==['address']:actual=actual.lower()
    if actual!=expected:raise ValueError('Deployed fixture ownership or balance mismatch')


def advance(root):
    root=_directory(root);work=_directory(root/'ethereum-setup');state=_state(work);phase=state['phase'];actors=state['actors']
    if any(_actor(root,name).lower()!=actors[name].lower() for name in actors):raise ValueError('Ethereum fixture wallet changed')
    if phase.endswith('_inflight'):raise ValueError('Uncertain fixture action; inspect journal and chain before recovery')
    if phase=='created':
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False]);base=int(head['baseFeePerGas'],16);priority=int(rpc('eth_maxPriorityFeePerGas',[]),16)
        required=max(10**15,10_000_000*(2*base+priority));bob=int(rpc('eth_getBalance',[actors['bob'],'latest']),16)
        if bob>=required:state['phase']='deploy_erc20';_save(work,state)
        else:
            available=int(rpc('eth_getBalance',[actors['alice'],'pending']),16)
            if available<required+25200*(2*base+priority):raise ValueError('Insufficient Sepolia ETH for fixture gas')
            state['phase']='gas_inflight';_save(work,state);result=send(work,root/'alice/ethereum-sepolia.key',actors['bob'],required,b'')
            state.update(phase='gas_submitted',gas_tx=result['txid']);_save(work,state)
    elif phase=='gas_submitted':
        if _receipt(state['gas_tx']) is not None:state['phase']='deploy_erc20';_save(work,state)
    elif phase.startswith('deploy_'):
        fixture=phase.removeprefix('deploy_')
        if fixture not in FIXTURES:raise ValueError('Unknown token fixture')
        code,_=_bytecode(fixture);owner=actors[FIXTURES[fixture][1]];state['phase']=fixture+'_inflight';_save(work,state)
        result=send(work,root/'alice/ethereum-sepolia.key',None,0,code+encode(['address'],[owner]))
        state.update(phase=fixture+'_submitted',pending_tx=result['txid']);_save(work,state)
    elif phase.endswith('_submitted'):
        fixture=phase.removesuffix('_submitted')
        if fixture not in FIXTURES:raise ValueError('Unknown token fixture')
        receipt=_receipt(state['pending_tx'])
        if receipt is not None:
            address=receipt.get('contractAddress');_check_contract(fixture,address,actors[FIXTURES[fixture][1]])
            state['contracts'][fixture]={'address':address,'txid':state['pending_tx']};state.pop('pending_tx')
            state['phase']={'erc20':'deploy_erc721','erc721':'deploy_erc1155','erc1155':'complete'}[fixture];_save(work,state)
    elif phase!='complete':raise ValueError('Unknown Ethereum fixture phase')
    return {'phase':state['phase'],'contracts':state['contracts']}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    with _locked(args.directory) as root:
        if args.operation=='init':result=initialize(root)
        elif args.operation=='advance':result=advance(root)
        else:result=_state(_directory(root/'ethereum-setup'))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
