"""Verify source-pinned token HTLC terms and holdings on trusted Sepolia RPC."""
import hashlib
import json
from pathlib import Path
from eth_abi import encode,decode
from eth_utils import keccak
from public_ethereum_verify import _address
from public_testnet_probe import rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]


def expected_runtime(kind,token,token_id,amount,hashlock,claimant,refundee,expiry):
    import re
    token=_address(token);claimant=_address(claimant);refundee=_address(refundee)
    if type(kind) is not int or kind not in (0,1,2) or type(token_id) is not int or not 0<=token_id<2**256 or type(amount) is not int or not 0<amount<2**256 or (kind==0 and token_id!=0) or (kind==1 and amount!=1):raise ValueError('Invalid token terms')
    if claimant==refundee or not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock) or type(expiry) is not int or not 0<expiry<2**256:raise ValueError('Invalid escrow terms')
    template=json.loads((ROOT/'swap-ui/token-escrow-template.json').read_text())
    if hashlib.sha256((ROOT/'contracts/ethereum/TokenHTLC.sol').read_bytes()).hexdigest()!=template['source_sha256']:raise ValueError('Token escrow template does not match source')
    code=bytearray.fromhex(template['runtime']);refs=template['immutableReferences']
    values={'kind':kind.to_bytes(32,'big'),'token':bytes.fromhex(token[2:]).rjust(32,b'\0'),'tokenId':token_id.to_bytes(32,'big'),'amount':amount.to_bytes(32,'big'),'hashlock':bytes.fromhex(hashlock),'claimant':bytes.fromhex(claimant[2:]).rjust(32,b'\0'),'refundee':bytes.fromhex(refundee[2:]).rjust(32,b'\0'),'expiry':expiry.to_bytes(32,'big')}
    if set(refs)!=set(values):raise ValueError('Token immutable template mismatch')
    occupied=set()
    for name,points in refs.items():
        for point in points:
            start=point['start'];length=point['length']
            if type(start) is not int or length!=32 or start<0 or start+length>len(code) or any(i in occupied for i in range(start,start+length)) or any(code[start:start+length]):raise ValueError('Invalid token immutable offsets')
            occupied.update(range(start,start+length));code[start:start+length]=values[name]
    return '0x'+code.hex()


def verify_token(contract,kind,token,token_id,amount,hashlock,claimant,refundee,expiry,confirmations=2):
    contract=_address(contract);token=_address(token)
    if type(confirmations) is not int or not 1<=confirmations<=1000:raise ValueError('Invalid confirmation threshold')
    runtime=expected_runtime(kind,token,token_id,amount,hashlock,claimant,refundee,expiry);verify_network('ethereum-sepolia')
    height=int(rpc('eth_blockNumber',[]),16);snapshot=height-confirmations+1
    if snapshot<0:raise ValueError('Ethereum chain is too short')
    pinned=rpc('eth_getBlockByNumber',[hex(snapshot),False]);latest=rpc('eth_getBlockByNumber',[hex(height),False])
    if not pinned or not latest or int(latest['timestamp'],16)>=expiry:raise ValueError('Ethereum escrow is expired or chain unavailable')
    def call(target,signature,types,args,block,returns):
        data='0x'+(keccak(text=signature)[:4]+encode(types,args)).hex()
        return decode(returns,bytes.fromhex(rpc('eth_call',[{'to':target,'data':data},hex(block)]).removeprefix('0x')))[0]
    for block in (snapshot,height):
        if str(rpc('eth_getCode',[contract,hex(block)])).lower()!=runtime:raise ValueError('Token escrow code or terms mismatch')
        if not call(contract,'funded()',[],[],block,['bool']) or call(contract,'spent()',[],[],block,['bool']):raise ValueError('Token escrow is unfunded or spent')
        if kind==0:balance=call(token,'balanceOf(address)',['address'],[contract],block,['uint256']);valid=balance==amount
        elif kind==1:owner=call(token,'ownerOf(uint256)',['uint256'],[token_id],block,['address']);valid=owner.lower()==contract
        else:balance=call(token,'balanceOf(address,uint256)',['address','uint256'],[contract,token_id],block,['uint256']);valid=balance==amount
        if not valid:raise ValueError('Token escrow holdings mismatch')
    if rpc('eth_getBlockByNumber',[hex(snapshot),False])['hash']!=pinned['hash'] or rpc('eth_getBlockByNumber',[hex(height),False])['hash']!=latest['hash']:raise ValueError('Ethereum chain changed during verification')
    return {'chain':'ethereum-sepolia','contract':contract,'snapshot_hash':pinned['hash'],'snapshot_height':snapshot,'confirmations':confirmations,'kind':kind,'token':token,'amount':str(amount)}
