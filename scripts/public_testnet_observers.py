"""Read a confirmed preimage from a specified public testnet claim.

These checks trust the configured public service and do not prove finality.
The returned preimage must be protected until the caller deliberately reveals
it on the other chain; never put it in an application log or public receipt.
"""
import hashlib
import json
import re
from eth_utils import keccak
from cardano_preimage_observer import claim_preimage
from public_testnet_probe import BITCOIN,CARDANO,request,rpc
from public_testnet_submit import verify_network


def _hash(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('Invalid hash')
    return value


def _depth(value):
    if type(value) is not int or not 1<=value<=1000:raise ValueError('Invalid confirmation threshold')
    return value


def bitcoin_claim(txid,funding_txid,vout,hashlock,confirmations=2):
    _hash(txid);_hash(funding_txid);_hash(hashlock);_depth(confirmations)
    if type(vout) is not int or not 0<=vout<=0xffffffff:raise ValueError('Invalid Bitcoin output index')
    verify_network('bitcoin-testnet4');tx=json.loads(request(BITCOIN+'/tx/'+txid))
    status=tx.get('status',{});height=status.get('block_height');block=status.get('block_hash')
    if tx.get('txid')!=txid or status.get('confirmed') is not True or type(height) is not int or not isinstance(block,str):raise ValueError('Bitcoin claim is unconfirmed')
    tip=int(request(BITCOIN+'/blocks/tip/height'))
    if tip-height+1<confirmations or request(BITCOIN+'/block-height/'+str(height)).decode().strip()!=block:raise ValueError('Bitcoin claim lacks canonical confirmations')
    matches=[]
    for entry in tx.get('vin',[]):
        if entry.get('txid')!=funding_txid or entry.get('vout')!=vout:continue
        for item in entry.get('witness',[]):
            if isinstance(item,str) and re.fullmatch('[0-9a-f]{64}',item):
                candidate=bytes.fromhex(item)
                if hashlib.sha256(candidate).hexdigest()==hashlock:matches.append(candidate)
    if len(matches)!=1:raise ValueError('Matching Bitcoin claim preimage not found')
    return bytearray(matches[0]),{'txid':txid,'confirmations':tip-height+1,'block_hash':block}


def ethereum_claim(txid,contract,hashlock,confirmations=2):
    _hash(txid);_hash(hashlock);_depth(confirmations)
    if not isinstance(contract,str) or not re.fullmatch('0x[0-9a-fA-F]{40}',contract):raise ValueError('Invalid Ethereum escrow address')
    verify_network('ethereum-sepolia');ident='0x'+txid
    receipt=rpc('eth_getTransactionReceipt',[ident]);tx=rpc('eth_getTransactionByHash',[ident])
    if not receipt or not tx or receipt.get('status')!='0x1' or str(receipt.get('transactionHash','')).lower()!=ident:raise ValueError('Ethereum claim is unconfirmed or failed')
    height=int(receipt['blockNumber'],16);tip=int(rpc('eth_blockNumber',[]),16);block=rpc('eth_getBlockByNumber',[hex(height),False])
    if tip-height+1<confirmations or str(block.get('hash','')).lower()!=str(receipt.get('blockHash','')).lower() or str(tx.get('blockHash','')).lower()!=str(receipt.get('blockHash','')).lower():raise ValueError('Ethereum claim lacks canonical confirmations')
    if str(tx.get('hash','')).lower()!=ident or str(tx.get('to','')).lower()!=contract.lower():raise ValueError('Ethereum claim transaction mismatch')
    data=str(tx.get('input','')).lower();selector=keccak(text='claim(bytes32)')[:4].hex()
    if not re.fullmatch('0x'+selector+'[0-9a-f]{64}',data):raise ValueError('Unexpected Ethereum claim data')
    secret=bytes.fromhex(data[10:])
    if hashlib.sha256(secret).hexdigest()!=hashlock:raise ValueError('Ethereum claim preimage mismatch')
    return bytearray(secret),{'txid':txid,'confirmations':tip-height+1,'block_hash':receipt['blockHash']}


def cardano_claim(txid,outref,hashlock,confirmations=2):
    _hash(txid);_hash(hashlock);_depth(confirmations)
    if not isinstance(outref,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]{0,9})',outref):raise ValueError('Invalid Cardano output reference')
    verify_network('cardano-preview');query={'_tx_hashes':[txid]}
    status=json.loads(request(CARDANO+'/tx_status',query))
    if len(status)!=1 or status[0].get('tx_hash')!=txid or type(status[0].get('num_confirmations')) is not int or status[0]['num_confirmations']<confirmations:raise ValueError('Cardano claim lacks confirmations')
    rows=json.loads(request(CARDANO+'/tx_cbor',query))
    if len(rows)!=1 or rows[0].get('tx_hash')!=txid or rows[0].get('valid_contract') is not True:raise ValueError('Cardano claim transaction unavailable or invalid')
    secret=claim_preimage(txid,rows[0].get('cbor'),outref,hashlock)
    if secret is None:raise ValueError('Matching Cardano claim preimage not found')
    again=json.loads(request(CARDANO+'/tx_status',query))
    if len(again)!=1 or again[0].get('tx_hash')!=txid or type(again[0].get('num_confirmations')) is not int or again[0]['num_confirmations']<confirmations:
        secret[:]=b'\0'*len(secret);raise ValueError('Cardano claim changed during observation')
    return secret,{'txid':txid,'confirmations':again[0]['num_confirmations'],'block_hash':rows[0]['block_hash']}
