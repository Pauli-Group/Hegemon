#!/usr/bin/env python3
"""Read public testnet tips and disposable wallet balances without a local node.

These HTTPS services are trusted sources, not independently verified light clients.
No private keys, transactions or unrevealed preimages are sent by this program.
"""
import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

BITCOIN = 'https://blockstream.info/testnet4/api'
ETHEREUM = 'https://ethereum-sepolia-rpc.publicnode.com'
CARDANO = 'https://preview.koios.rest/api/v1'
BITCOIN_GENESIS = '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043'
ETHEREUM_GENESIS = '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'


def request(url, body=None):
    data=None if body is None else json.dumps(body,separators=(',',':')).encode()
    headers={'User-Agent':'Mozilla/5.0','Accept':'application/json'}
    if body is not None:headers['Content-Type']='application/json'
    cardano_reads={'/genesis','/tip','/address_info','/address_utxos','/tx_status','/tx_cbor','/tx_info','/cli_protocol_params'}
    ethereum_reads={'eth_chainId','eth_getBlockByNumber','eth_blockNumber','eth_getBalance','eth_getTransactionCount','eth_maxPriorityFeePerGas','eth_estimateGas','eth_getTransactionReceipt','eth_getTransactionByHash','eth_getCode','eth_call'}
    retryable=data is None or (url.startswith(CARDANO) and url[len(CARDANO):].split('?',1)[0] in cardano_reads) or (url==ETHEREUM and isinstance(body,dict) and body.get('method') in ethereum_reads)
    for attempt in range(3 if retryable else 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url,data=data,headers=headers),timeout=15) as response:raw=response.read(4*1024*1024+1)
            break
        except urllib.error.HTTPError as error:
            if not retryable or error.code not in (429,500,502,503,504) or attempt==2:raise
        except (urllib.error.URLError,TimeoutError):
            if not retryable or attempt==2:raise
        time.sleep(1<<attempt)
    if len(raw)>4*1024*1024:raise ValueError('Public service response too large')
    return raw


def rpc(method,params):
    result=json.loads(request(ETHEREUM,{'jsonrpc':'2.0','id':1,'method':method,'params':params}))
    if result.get('id')!=1 or 'error' in result or 'result' not in result:raise ValueError('Ethereum RPC failed')
    return result['result']


def check_addresses(addresses):
    if not isinstance(addresses,dict) or set(addresses)!={'alice','bob'}:raise ValueError('Invalid actor list')
    for actor in addresses.values():
        if not isinstance(actor,dict) or set(actor)!={'bitcoin_testnet4','ethereum_sepolia','cardano_preview'}:raise ValueError('Invalid public address record')
        if not re.fullmatch(r'tb1q[ac-hj-np-z02-9]{38}',actor['bitcoin_testnet4']):raise ValueError('Invalid testnet Bitcoin address')
        if not re.fullmatch(r'0x[0-9a-fA-F]{40}',actor['ethereum_sepolia']):raise ValueError('Invalid Ethereum address')
        if not re.fullmatch(r'addr_test1[ac-hj-np-z02-9]+',actor['cardano_preview']):raise ValueError('Invalid Cardano test address')
    return addresses


def probe(addresses):
    check_addresses(addresses)
    genesis=request(BITCOIN+'/block-height/0').decode().strip()
    if genesis!=BITCOIN_GENESIS:raise ValueError('Bitcoin endpoint is not testnet4')
    bitcoin_tip=int(request(BITCOIN+'/blocks/tip/height'))
    if rpc('eth_chainId',[])!='0xaa36a7' or rpc('eth_getBlockByNumber',['0x0',False])['hash'].lower()!=ETHEREUM_GENESIS:raise ValueError('Ethereum endpoint is not Sepolia')
    eth_tip=int(rpc('eth_blockNumber',[]),16)
    cg=json.loads(request(CARDANO+'/genesis'))
    if len(cg)!=1 or cg[0].get('networkmagic')!='2' or cg[0].get('networkid')!='Testnet' or cg[0].get('systemstart')!=1666656000:raise ValueError('Cardano endpoint is not preview')
    ct=json.loads(request(CARDANO+'/tip'))
    if len(ct)!=1 or not isinstance(ct[0].get('abs_slot'),int):raise ValueError('Invalid Cardano tip')
    actors={}
    for name,actor in addresses.items():
        btc=json.loads(request(BITCOIN+'/address/'+actor['bitcoin_testnet4']))
        stats=btc['chain_stats'];bitcoin_balance=stats['funded_txo_sum']-stats['spent_txo_sum']
        eth_balance=int(rpc('eth_getBalance',[actor['ethereum_sepolia'],'latest']),16)
        ada=json.loads(request(CARDANO+'/address_info',{'_addresses':[actor['cardano_preview']]}))
        if len(ada)>1:raise ValueError('Invalid Cardano balance response')
        ada_balance=int(ada[0]['balance']) if ada else 0
        actors[name]={'bitcoin_confirmed_sats':bitcoin_balance,'ethereum_wei':eth_balance,'cardano_lovelace':ada_balance}
    return {'bitcoin_testnet4':{'genesis':genesis,'height':bitcoin_tip},'ethereum_sepolia':{'genesis':ETHEREUM_GENESIS,'height':eth_tip},'cardano_preview':{'magic':2,'slot':ct[0]['abs_slot'],'block':ct[0]['block_no']},'actors':actors}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--addresses',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(probe(json.loads(args.addresses.read_text())),indent=2))


if __name__=='__main__':main()
