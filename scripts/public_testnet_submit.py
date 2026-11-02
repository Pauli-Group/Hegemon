"""Journal and submit a signed transaction to the specified public testnet.

Public providers can censor, equivocate or reorganize. A successful response
means accepted for submission, not confirmed. Claims expose their preimages.
"""
import json
import re
import urllib.request
from public_swap_journal import prepare
from public_testnet_probe import BITCOIN,BITCOIN_GENESIS,CARDANO,ETHEREUM,ETHEREUM_GENESIS,request,rpc


def verify_network(chain):
    if chain=='bitcoin-testnet4':
        if request(BITCOIN+'/block-height/0').decode().strip()!=BITCOIN_GENESIS:raise ValueError('Bitcoin endpoint is not testnet4')
    elif chain=='ethereum-sepolia':
        if rpc('eth_chainId',[])!='0xaa36a7' or rpc('eth_getBlockByNumber',['0x0',False])['hash'].lower()!=ETHEREUM_GENESIS:raise ValueError('Ethereum endpoint is not Sepolia')
    elif chain=='cardano-preview':
        genesis=json.loads(request(CARDANO+'/genesis'))
        if len(genesis)!=1 or genesis[0].get('networkmagic')!='2' or genesis[0].get('networkid')!='Testnet' or genesis[0].get('systemstart')!=1666656000:raise ValueError('Cardano endpoint is not preview')
    else:raise ValueError('Unsupported testnet')


def _broadcast(url,raw,content_type):
    req=urllib.request.Request(url,data=raw,headers={'User-Agent':'Mozilla/5.0','Content-Type':content_type,'Accept':'application/json'})
    with urllib.request.urlopen(req,timeout=30) as response:
        value=response.read(1_000_001)
    if len(value)>1_000_000:raise ValueError('Public service response too large')
    return value


def submit(directory,chain,raw):
    verify_network(chain)
    record=prepare(directory,chain,raw)
    # From this point, any failure may mean the transaction was sent. Do not
    # retry blindly: inspect this transaction ID and the chain first.
    if chain=='bitcoin-testnet4':
        returned=_broadcast(BITCOIN+'/tx',raw.hex().encode(),'text/plain').decode().strip()
    elif chain=='ethereum-sepolia':
        payload=json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_sendRawTransaction','params':['0x'+raw.hex()]},separators=(',',':')).encode()
        response=json.loads(_broadcast(ETHEREUM,payload,'application/json'))
        if response.get('id')!=1 or 'error' in response:raise RuntimeError('Ethereum submission outcome is uncertain; inspect journal')
        returned=str(response.get('result','')).removeprefix('0x')
    else:
        returned=json.loads(_broadcast(CARDANO+'/submittx',raw,'application/cbor'))
    if not isinstance(returned,str) or not re.fullmatch('[0-9a-f]{64}',returned) or returned!=record['txid']:raise RuntimeError('Submission returned an unexpected transaction ID; inspect journal')
    return {'chain':chain,'txid':returned,'confirmed':False,'state':'submitted'}
