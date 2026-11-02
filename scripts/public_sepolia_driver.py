"""Locally sign, durably journal and submit bounded Sepolia transactions.

The caller must coordinate swap terms, backups and both legs before invoking
this driver. Simulation and gas estimation disclose calldata to the RPC; in
particular a claim preimage is exposed to the provider before broadcast.
"""
import fcntl
import os
import re
import stat
from pathlib import Path
from eth_account import Account
from public_ethereum_transactions import sign_transaction
from public_testnet_probe import rpc
from public_testnet_submit import submit,verify_network


def load_test_wallet(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Wallet key cannot be a symlink')
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>1024:raise ValueError('Test wallet key must be a private user-owned file')
    parts=path.read_text().split()
    if len(parts)!=2 or not re.fullmatch('0x[0-9a-fA-F]{40}',parts[0]) or not re.fullmatch('0x[0-9a-fA-F]{64}',parts[1]):raise ValueError('Invalid test wallet file')
    key=bytes.fromhex(parts[1][2:]);address=Account.from_key(key).address
    if address.lower()!=parts[0].lower():raise ValueError('Test wallet address does not match key')
    return key,address


def send(journal,wallet,to,value,data):
    """Estimate and send once; returns an unconfirmed transaction ID.

    Signed bytes are journaled before submission. On an exception after that
    point inspect the journal and chain; never automatically retry the action.
    """
    path=Path(journal)
    if path.is_symlink() or not path.is_dir() or path.stat().st_uid!=os.getuid() or stat.S_IMODE(path.stat().st_mode)&0o077:raise ValueError('Journal directory must be private and user-owned')
    key,address=load_test_wallet(wallet)
    flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path/('ethereum-'+address[2:].lower()+'.lock'),flags,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        verify_network('ethereum-sepolia')
        nonce=int(rpc('eth_getTransactionCount',[address,'pending']),16)
        head=rpc('eth_getBlockByNumber',['latest',False]);base=int(head['baseFeePerGas'],16)
        priority=int(rpc('eth_maxPriorityFeePerGas',[]),16);max_fee=2*base+priority
        call={'from':address,'value':hex(value),'data':'0x'+data.hex()}
        if to is not None:call['to']=to
        estimate=int(rpc('eth_estimateGas',[call]),16);gas=max(21000,(estimate*12+9)//10)
        balance=int(rpc('eth_getBalance',[address,'pending']),16)
        if balance<value+gas*max_fee:raise ValueError('Insufficient Sepolia ETH for value and maximum gas cost')
        raw,_=sign_transaction(key,address,nonce=nonce,to=to,value=value,data=data,gas=gas,max_fee=max_fee,priority_fee=priority)
        return submit(path,'ethereum-sepolia',raw)
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
