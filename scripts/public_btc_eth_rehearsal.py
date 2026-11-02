#!/usr/bin/env python3
"""Step a disposable BTC testnet4/Sepolia native-ETH HTLC rehearsal.

Run `init` once and `advance` repeatedly. Each call performs at most one
public submission. Before submission its state becomes `*_inflight`, and a
signed transaction is journaled privately. If interrupted there, stop and
inspect the journal and both chains; this program will not automatically
retry. Testnet deadlines and third-party APIs do not establish real-fund safety.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from eth_abi import encode
from eth_utils import keccak
from public_bitcoin_driver import fund as bitcoin_fund,load_test_key,spend_contract
from public_bitcoin_transactions import contract as bitcoin_contract
from public_ethereum_verify import verify_native
from public_sepolia_driver import load_test_wallet,send as ethereum_send
from public_testnet_observers import bitcoin_claim,ethereum_claim
from public_testnet_probe import BITCOIN,request,rpc
from public_testnet_submit import verify_network

ROOT=Path(__file__).resolve().parents[1]
BTC_AMOUNT=1_500
ETH_AMOUNT=10**14
GAS_TRANSFER=10**14


def _directory(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Scenario directory cannot be a symlink')
    st=path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Scenario directory must be private and user-owned')
    return path


def _write(path,data,exclusive=False):
    if exclusive:
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
        with os.fdopen(os.open(path,flags,0o600),'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
    else:
        temp=path.with_suffix('.new');_write(temp,data,True);temp.replace(path)
    fd=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(fd)
    finally:os.close(fd)


def _state(directory):
    path=directory/'btc-eth-state.json';st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>8192:raise ValueError('Scenario state must be private')
    value=json.loads(path.read_text())
    if not isinstance(value,dict) or value.get('version')!=1 or value.get('scenario')!='btc-eth' or not re.fullmatch('[0-9a-f]{64}',value.get('hashlock','')):raise ValueError('Invalid scenario state')
    return value


def _save(directory,state):_write(directory/'btc-eth-state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode())


def _wallets(directory):
    alice_btc=load_test_key(directory/'alice/bitcoin-testnet4.key');bob_btc=load_test_key(directory/'bob/bitcoin-testnet4.key')
    _,alice_eth=load_test_wallet(directory/'alice/ethereum-sepolia.key');_,bob_eth=load_test_wallet(directory/'bob/ethereum-sepolia.key')
    return {'btc_refund':alice_btc.get_public_key().sec().hex(),'btc_claimant':bob_btc.get_public_key().sec().hex(),'eth_refundee':alice_eth,'eth_claimant':bob_eth}


@contextmanager
def _locked(directory):
    directory=_directory(directory);flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(directory/'btc-eth.lock',flags,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield directory
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def _initialize(directory):
    directory=_directory(directory);verify_network('bitcoin-testnet4');verify_network('ethereum-sepolia')
    terms=_wallets(directory);secret=secrets.token_bytes(32);digest=hashlib.sha256(secret).hexdigest()
    _write(directory/'btc-eth.secret',secret,True)
    state={'version':1,'scenario':'btc-eth','phase':'created','hashlock':digest,'terms':terms,'btc_amount_sats':BTC_AMOUNT,'eth_amount_wei':str(ETH_AMOUNT)}
    _write(directory/'btc-eth-state.json',(json.dumps(state,sort_keys=True,indent=2)+'\n').encode(),True)
    return {'phase':state['phase'],'hashlock':digest}


def _receipt(txid,confirmations=2):
    verify_network('ethereum-sepolia');ident='0x'+txid
    receipt=rpc('eth_getTransactionReceipt',[ident])
    if receipt is None:return None
    if str(receipt.get('transactionHash','')).lower()!=ident or receipt.get('status')!='0x1':raise ValueError('Ethereum transaction failed or mismatched')
    height=int(receipt['blockNumber'],16);tip=int(rpc('eth_blockNumber',[]),16)
    if tip-height+1<confirmations:return None
    block=rpc('eth_getBlockByNumber',[hex(height),False])
    if not block or block.get('hash','').lower()!=receipt.get('blockHash','').lower():raise ValueError('Ethereum transaction is not canonical')
    return receipt


def _bitcoin_lock(state):
    verify_network('bitcoin-testnet4');txid=state['btc_lock'];height=int(request(BITCOIN+'/blocks/tip/height'))
    tx=json.loads(request(BITCOIN+'/tx/'+txid));status=tx.get('status',{});confirmed_height=status.get('block_height')
    if status.get('confirmed') is not True or type(confirmed_height) is not int or height-confirmed_height+1<2:return None
    if tx.get('txid')!=txid or request(BITCOIN+'/block-height/'+str(confirmed_height)).decode().strip()!=status.get('block_hash'):raise ValueError('Bitcoin escrow block is not canonical')
    _,expected=bitcoin_contract(state['hashlock'],state['terms']['btc_claimant'],state['terms']['btc_refund'],state['btc_refund_height'])
    outputs=tx.get('vout');out=outputs[0] if isinstance(outputs,list) and outputs else None
    if not out or out.get('value')!=BTC_AMOUNT or out.get('scriptpubkey')!=expected.data.hex():raise ValueError('Bitcoin escrow does not match terms')
    if json.loads(request(BITCOIN+'/tx/'+txid+'/outspend/0')).get('spent') is not False:raise ValueError('Bitcoin escrow is spent or unavailable')
    return height


def _begin(directory,state,name):
    state['phase']=name+'_inflight';_save(directory,state)


def _advance(directory):
    directory=_directory(directory);state=_state(directory)
    if state.get('terms')!=_wallets(directory):raise ValueError('Scenario wallet identities changed')
    phase=state.get('phase');terms=state['terms']
    if not isinstance(phase,str) or phase.endswith('_inflight'):raise ValueError('Uncertain action: inspect private journal and chain before manual recovery')
    if phase=='created':
        verify_network('ethereum-sepolia');balance=int(rpc('eth_getBalance',[terms['eth_claimant'],'latest']),16)
        head=rpc('eth_getBlockByNumber',['latest',False]);base=int(head['baseFeePerGas'],16);priority=int(rpc('eth_maxPriorityFeePerGas',[]),16)
        needed=max(GAS_TRANSFER,250000*(2*base+priority))
        if balance>=needed:state['phase']='gas_ready';_save(directory,state)
        else:
            available=int(rpc('eth_getBalance',[terms['eth_refundee'],'pending']),16)
            if available<needed+25200*(2*base+priority):raise ValueError('Alice needs more Sepolia ETH before funding Bob gas')
            _begin(directory,state,'eth_gas');result=ethereum_send(directory,directory/'alice/ethereum-sepolia.key',terms['eth_claimant'],needed,b'')
            state.update(phase='eth_gas_submitted',eth_gas=result['txid']);_save(directory,state)
    elif phase=='eth_gas_submitted':
        if _receipt(state['eth_gas']) is not None:state['phase']='gas_ready';_save(directory,state)
    elif phase=='gas_ready':
        verify_network('bitcoin-testnet4');tip=int(request(BITCOIN+'/blocks/tip/height'));state['btc_refund_height']=tip+144
        _begin(directory,state,'btc_lock');result=bitcoin_fund(directory,directory/'alice/bitcoin-testnet4.key',state['hashlock'],terms['btc_claimant'],state['btc_refund_height'],BTC_AMOUNT)
        state.update(phase='btc_lock_submitted',btc_lock=result['txid']);_save(directory,state)
    elif phase=='btc_lock_submitted':
        if _bitcoin_lock(state) is not None:state['phase']='btc_lock_confirmed';_save(directory,state)
    elif phase=='btc_lock_confirmed':
        height=_bitcoin_lock(state)
        if height is None or state['btc_refund_height']-height<72:raise ValueError('Bitcoin escrow is unconfirmed or refund margin too small')
        verify_network('ethereum-sepolia');head=rpc('eth_getBlockByNumber',['latest',False]);state['eth_expiry']=int(head['timestamp'],16)+3600
        template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text());data=bytes.fromhex(template['creation'])+encode(['bytes32','address','uint256'],[bytes.fromhex(state['hashlock']),terms['eth_claimant'],state['eth_expiry']])
        _begin(directory,state,'eth_lock');result=ethereum_send(directory,directory/'alice/ethereum-sepolia.key',None,ETH_AMOUNT,data)
        state.update(phase='eth_lock_submitted',eth_lock=result['txid']);_save(directory,state)
    elif phase=='eth_lock_submitted':
        receipt=_receipt(state['eth_lock'])
        if receipt is not None:
            contract=receipt.get('contractAddress')
            verify_native(contract,state['hashlock'],terms['eth_claimant'],terms['eth_refundee'],state['eth_expiry'],ETH_AMOUNT)
            state.update(phase='both_verified',eth_contract=contract);_save(directory,state)
    elif phase=='both_verified':
        height=_bitcoin_lock(state)
        if height is None or state['btc_refund_height']-height<36:raise ValueError('Bitcoin escrow is unconfirmed or refund margin too small')
        snap=verify_native(state['eth_contract'],state['hashlock'],terms['eth_claimant'],terms['eth_refundee'],state['eth_expiry'],ETH_AMOUNT)
        head=rpc('eth_getBlockByNumber',['latest',False])
        if state['eth_expiry']-int(head['timestamp'],16)<600:raise ValueError('Ethereum deadline too close')
        secret_path=directory/'btc-eth.secret';st=secret_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Secret backup must be private')
        secret=secret_path.read_bytes()
        if len(secret)!=32 or hashlib.sha256(secret).hexdigest()!=state['hashlock']:raise ValueError('Secret backup does not match')
        data=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[secret])
        _begin(directory,state,'eth_claim');result=ethereum_send(directory,directory/'bob/ethereum-sepolia.key',state['eth_contract'],0,data)
        state.update(phase='eth_claim_submitted',eth_claim=result['txid']);_save(directory,state)
    elif phase=='eth_claim_submitted':
        if _receipt(state['eth_claim']) is not None:
            secret,_=ethereum_claim(state['eth_claim'],state['eth_contract'],state['hashlock'])
            try:
                _begin(directory,state,'btc_claim');result=spend_contract(directory,directory/'bob/bitcoin-testnet4.key',state['btc_lock'],0,BTC_AMOUNT,state['hashlock'],terms['btc_claimant'],terms['btc_refund'],state['btc_refund_height'],bytes(secret))
                state.update(phase='btc_claim_submitted',btc_claim=result['txid']);_save(directory,state)
            finally:secret[:]=b'\0'*len(secret)
    elif phase=='btc_claim_submitted':
        try:secret,_=bitcoin_claim(state['btc_claim'],state['btc_lock'],0,state['hashlock'])
        except ValueError as error:
            if 'unconfirmed' in str(error) or 'lacks canonical confirmations' in str(error):return {'phase':phase,'pending':True}
            raise
        secret[:]=b'\0'*len(secret);state['phase']='complete';_save(directory,state)
    elif phase!='complete':raise ValueError('Unknown scenario phase')
    return {'phase':state['phase'],'pending':state['phase'].endswith('_submitted')}


def initialize(directory):
    with _locked(directory) as locked:return _initialize(locked)


def advance(directory):
    with _locked(directory) as locked:return _advance(locked)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['init','advance','status']);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    directory=_directory(args.directory)
    if args.operation=='init':result=initialize(directory)
    elif args.operation=='advance':result=advance(directory)
    else:
        state=_state(directory);result={key:value for key,value in state.items() if key!='terms'}
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
