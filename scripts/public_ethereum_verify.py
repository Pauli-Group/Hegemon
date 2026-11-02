"""Verify a native ETH escrow against the pinned runtime at remote snapshots.

The RPC provider remains trusted; this is neither finality nor authentication
of participants, nor proof the other swap leg or time margins are safe.
"""
import hashlib
import json
import re
from pathlib import Path
from eth_utils import keccak
from public_testnet_probe import rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]


def _address(value):
    if not isinstance(value,str) or not re.fullmatch('0x[0-9a-fA-F]{40}',value):raise ValueError('Invalid Ethereum address')
    return value.lower()


def expected_runtime(hashlock,claimant,refundee,expiry):
    if not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock):raise ValueError('Invalid hashlock')
    claimant=_address(claimant);refundee=_address(refundee)
    if claimant==refundee or type(expiry) is not int or not 0<expiry<2**256:raise ValueError('Invalid Ethereum terms')
    template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text())
    if hashlib.sha256((ROOT/'contracts/ethereum/HegemonHTLC.sol').read_bytes()).hexdigest()!=template['source_sha256']:raise ValueError('Ethereum escrow template does not match source')
    code=bytearray.fromhex(template['runtime']);refs=template['immutableReferences']
    values={'hashlock':bytes.fromhex(hashlock),'claimant':bytes.fromhex(claimant[2:]).rjust(32,b'\0'),'refundee':bytes.fromhex(refundee[2:]).rjust(32,b'\0'),'expiry':expiry.to_bytes(32,'big')}
    if set(refs)!=set(values):raise ValueError('Ethereum immutable template mismatch')
    occupied=set()
    for name,points in refs.items():
        for point in points:
            start=point['start'];length=point['length']
            if type(start) is not int or length!=32 or start<0 or start+length>len(code) or any(i in occupied for i in range(start,start+length)) or any(code[start:start+length]):raise ValueError('Invalid Ethereum immutable offsets')
            occupied.update(range(start,start+length));code[start:start+length]=values[name]
    return '0x'+code.hex()


def verify_native(contract,hashlock,claimant,refundee,expiry,amount,confirmations=2):
    contract=_address(contract)
    if type(confirmations) is not int or not 1<=confirmations<=1000 or type(amount) is not int or not 0<amount<=10**18:raise ValueError('Invalid Ethereum amount or confirmations')
    runtime=expected_runtime(hashlock,claimant,refundee,expiry);verify_network('ethereum-sepolia')
    height=int(rpc('eth_blockNumber',[]),16);snapshot=height-confirmations+1
    if snapshot<0:raise ValueError('Ethereum chain is too short')
    pinned=rpc('eth_getBlockByNumber',[hex(snapshot),False]);latest=rpc('eth_getBlockByNumber',[hex(height),False])
    if not pinned or not latest or int(latest['timestamp'],16)>=expiry:raise ValueError('Ethereum escrow is expired or chain unavailable')
    spent_selector='0x'+keccak(text='spent()')[:4].hex()
    for block in (snapshot,height):
        tag=hex(block)
        if str(rpc('eth_getCode',[contract,tag])).lower()!=runtime:raise ValueError('Ethereum escrow code or terms mismatch')
        if int(rpc('eth_getBalance',[contract,tag]),16)!=amount:raise ValueError('Ethereum escrow amount mismatch')
        if int(rpc('eth_call',[{'to':contract,'data':spent_selector},tag]),16)!=0:raise ValueError('Ethereum escrow already spent')
    if rpc('eth_getBlockByNumber',[hex(snapshot),False])['hash']!=pinned['hash'] or rpc('eth_getBlockByNumber',[hex(height),False])['hash']!=latest['hash']:raise ValueError('Ethereum chain changed during verification')
    return {'chain':'ethereum-sepolia','contract':contract,'snapshot_hash':pinned['hash'],'snapshot_height':snapshot,'confirmations':confirmations,'current_height':height,'expiry':expiry,'amount':str(amount)}
