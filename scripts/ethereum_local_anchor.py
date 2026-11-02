"""Inspect a trusted, non-forked local Anvil chain without starting a node."""
import re
from urllib.parse import urlsplit
from release_private_spend_lifecycle_io import rpc


def ethereum_local_head(url):
    endpoint=urlsplit(url)
    if endpoint.scheme!='http' or endpoint.hostname not in ('127.0.0.1','localhost') or endpoint.username or not endpoint.port or endpoint.path not in ('','/') or endpoint.query or endpoint.fragment:
        raise ValueError('Ethereum RPC must be an explicit loopback HTTP endpoint')
    chain=rpc(url,'eth_chainId');meta=rpc(url,'anvil_metadata')
    if chain!='0x7a69' or not isinstance(meta,dict) or meta.get('chainId')!=31337 or meta.get('forkedNetwork') is not None or not str(meta.get('clientVersion','')).startswith('anvil/'):
        raise ValueError('Ethereum node must be non-forked local Anvil chain 31337')
    genesis=rpc(url,'eth_getBlockByNumber',['0x0',False]);head=rpc(url,'eth_getBlockByNumber',['latest',False])
    if not genesis or not head or not re.fullmatch('0x[0-9a-fA-F]{64}',genesis.get('hash','')) or not re.fullmatch('0x[0-9a-fA-F]{64}',head.get('hash','')):
        raise ValueError('Ethereum node returned invalid block hashes')
    again=rpc(url,'anvil_metadata')
    if again.get('forkedNetwork') is not None or again.get('chainId')!=31337 or again.get('latestBlockHash')!=head['hash']:
        raise ValueError('Ethereum node changed during observation')
    return {'genesis':genesis['hash'][2:].lower(),'tip_hash':head['hash'].lower(),
            'height':str(int(head['number'],16)),'time_seconds':str(int(head['timestamp'],16))}
