"""Locally sign bounded EIP-1559 Sepolia test transactions.

This module neither queries nor broadcasts. The caller must verify the public
endpoint's chain ID and genesis and independently validate transaction terms.
"""
import re
from eth_account import Account
from eth_utils import to_checksum_address

SEPOLIA_CHAIN_ID=11155111


def _number(value,maximum,minimum=0):
    if type(value) is not int or not minimum<=value<=maximum:raise ValueError('Invalid Ethereum transaction value')
    return value


def sign_transaction(private_key,expected_sender,*,nonce,to,value,data,gas,max_fee,priority_fee):
    if not isinstance(private_key,bytes) or len(private_key)!=32:raise ValueError('Invalid Ethereum private key')
    if not isinstance(expected_sender,str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}',expected_sender):raise ValueError('Invalid Ethereum sender')
    account=Account.from_key(private_key)
    if account.address.lower()!=expected_sender.lower():raise ValueError('Ethereum signing key does not match sender')
    if to is not None and (not isinstance(to,str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}',to)):raise ValueError('Invalid Ethereum recipient')
    if not isinstance(data,bytes) or len(data)>100000:raise ValueError('Invalid Ethereum transaction data')
    _number(nonce,2**64-1);_number(value,10**18);_number(gas,10_000_000,21000)
    _number(max_fee,100_000_000_000,1);_number(priority_fee,max_fee)
    if gas*max_fee+value>10**18:raise ValueError('Ethereum transaction exceeds test budget')
    tx={'type':2,'chainId':SEPOLIA_CHAIN_ID,'nonce':nonce,'value':value,'data':data,'gas':gas,'maxFeePerGas':max_fee,'maxPriorityFeePerGas':priority_fee}
    if to is not None:tx['to']=to_checksum_address(to)
    signed=account.sign_transaction(tx)
    return bytes(signed.raw_transaction),'0x'+signed.hash.hex().removeprefix('0x')
