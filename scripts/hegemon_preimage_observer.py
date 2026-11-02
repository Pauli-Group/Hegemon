"""Observe released private-spend preimages on a peerless Development node.

Canonical action bytes and proof acceptance are supplied by the trusted local
node. The framing checks here do not independently verify a proof or establish
public-network finality.
"""
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
from check_native_asset_lifecycle import canonical_body,pending_action_public_args,rpc


IDENTITY=bytes([1,0,12,0,7,0,1,0,15,0,8,0,2,12,1,0])


def released_preimage(carrier,*,chain_id,relation_prefix,hashlock):
    if not isinstance(carrier,(bytes,bytearray)) or not 5788<=len(carrier)<=177632 or carrier[:8]!=b'HGPSLC02' or carrier[8:24]!=IDENTITY or carrier[24:72]!=relation_prefix or carrier[72:104]!=chain_id or carrier[5784:5788]!=b'SMZL':raise ValueError('invalid private-spend carrier')
    flag=int.from_bytes(carrier[528:536],'little');secret=bytearray(carrier[536:568])
    if flag not in (0,1) or (flag==0 and any(secret)):
        secret[:]=b'\0'*len(secret);raise ValueError('invalid private-spend secret release')
    if flag==0 or hashlib.sha256(secret).hexdigest()!=hashlock:
        secret[:]=b'\0'*len(secret);return None
    return secret


def observe_hegemon_preimage(url,*,manifest,genesis,hashlock,start_height,confirmations=2,timeout=120):
    endpoint=urlsplit(url)
    if endpoint.scheme!='http' or endpoint.hostname!='127.0.0.1' or not endpoint.port or endpoint.username or endpoint.path not in ('','/') or endpoint.query or endpoint.fragment:raise ValueError('Hegemon RPC must be an explicit loopback endpoint')
    genesis=genesis.removeprefix('0x') if isinstance(genesis,str) else None
    if not isinstance(genesis,str) or not re.fullmatch('[0-9a-f]{64}',genesis) or not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock):raise ValueError('invalid Hegemon observation terms')
    if type(start_height) is not int or not 1<=start_height<2**48 or type(confirmations) is not int or not 1<=confirmations<=100 or not 0<timeout<=3600:raise ValueError('invalid Hegemon observation limits')
    data=json.loads(Path(manifest).read_text());source=data.get('development_candidate') if isinstance(data,dict) else None
    if not isinstance(data,dict) or data.get('profile')!='development' or not isinstance(source,dict) or source.get('private_spend_only') is not True:raise ValueError('Hegemon observer requires a private-spend Development manifest')
    relation=source.get('private_spend_source',{}).get('relation_digest')
    if not isinstance(relation,str) or not re.fullmatch('[0-9a-f]{128}',relation):raise ValueError('invalid private-spend relation identity')
    prefix=bytes.fromhex(relation[:96]);deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if rpc(url,'system_health')['peers']!=0 or rpc(url,'chain_getBlockHash',[0]).removeprefix('0x')!=genesis:raise ValueError('Hegemon node is not the configured isolated chain')
        header=rpc(url,'chain_getHeader');height=int(header['number'],16) if isinstance(header['number'],str) and header['number'].startswith('0x') else int(header['number'])
        if start_height>height or height-start_height>512:raise ValueError('invalid Hegemon observation block range')
        tip=rpc(url,'chain_getBlockHash',[height]);first=rpc(url,'chain_getBlockHash',[1]);reward=rpc(url,'hegemon_blockReward',[first])
        if not isinstance(reward,dict) or reward.get('canonical') is not True or not re.fullmatch('(0x)?[0-9a-f]{64}',reward.get('chain_id','')):raise ValueError('Hegemon chain identity unavailable')
        chain_id=bytes.fromhex(reward['chain_id'].removeprefix('0x'));end=height-confirmations+1
        for number in range(start_height,end+1):
            block_hash=rpc(url,'chain_getBlockHash',[number]);actions,meta,_=canonical_body(url,block_hash)
            if meta['height']!=number:raise ValueError('Hegemon block height mismatch')
            for action in actions:
                if len(action)<56 or tuple(int.from_bytes(action[i:i+2],'little') for i in (48,50,52,54))!=(12,7,1,15):continue
                carrier,outer=pending_action_public_args(action)
                if outer['vector_counts']!=[0,0,2,2]:raise ValueError('unexpected private-spend action framing')
                secret=released_preimage(carrier,chain_id=chain_id,relation_prefix=prefix,hashlock=hashlock)
                if secret is not None:
                    try:
                        if rpc(url,'chain_getBlockHash',[height])!=tip or rpc(url,'chain_getBlockHash',[number])!=block_hash or rpc(url,'system_health')['peers']!=0:raise ValueError('Hegemon chain changed during observation')
                        result=secret;secret=None
                        return result,{'block_hash':block_hash,'block_height':number,'confirmations':height-number+1}
                    finally:
                        if secret is not None:secret[:]=b'\0'*len(secret)
        if rpc(url,'chain_getBlockHash',[height])!=tip:raise ValueError('Hegemon chain changed during observation')
        remaining=deadline-time.monotonic()
        if remaining>0:time.sleep(min(1,remaining))
    raise ValueError('Hegemon observation timed out')
