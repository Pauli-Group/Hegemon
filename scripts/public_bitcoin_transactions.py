"""Locally sign simple Bitcoin testnet HTLC transactions using embit.

This module does not contact a node or broadcast. Callers must verify UTxOs,
network identity, fees, counterparty terms and the other leg independently.
"""
import hashlib
import re
from embit import descriptor,ec,script,transaction


def _uint(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:raise ValueError('Invalid Bitcoin integer')
    return value


def _key(value):
    if not isinstance(value,ec.PrivateKey):raise ValueError('Invalid signing key')
    return value


def _pub(value):
    if not isinstance(value,str) or not re.fullmatch(r'(02|03)[0-9a-f]{64}',value):raise ValueError('Invalid compressed public key')
    ec.PublicKey.parse(bytes.fromhex(value));return value


def contract(hashlock,claimant,refund,refund_height):
    if not isinstance(hashlock,str) or not re.fullmatch(r'[0-9a-f]{64}',hashlock):raise ValueError('Invalid hashlock')
    claimant,refund=_pub(claimant),_pub(refund)
    if claimant==refund:raise ValueError('Claim and refund keys must differ')
    _uint(refund_height,499999999)
    if refund_height==0:raise ValueError('Invalid refund height')
    policy=f'wsh(or_i(and_v(v:sha256({hashlock}),pk({claimant})),and_v(v:after({refund_height}),pk({refund}))))'
    parsed=descriptor.Descriptor.from_string(policy)
    return parsed.witness_script(),parsed.script_pubkey()


def _outpoint(txid,vout):
    if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid):raise ValueError('Invalid transaction ID')
    return transaction.TransactionInput(bytes.fromhex(txid),_uint(vout,0xffffffff))


def _amount(value):
    _uint(value,2100000000000000)
    if value<546:raise ValueError('Bitcoin output is dust')
    return value


def funding(txid,vout,input_amount,key,output_script,amount,fee):
    key=_key(key);_amount(input_amount);_amount(amount);_uint(fee,100000)
    if fee<1 or fee>=amount:raise ValueError('Invalid Bitcoin fee')
    change=input_amount-amount-fee
    if change<0 or (0<change<546):raise ValueError('Insufficient funds or dust change')
    if not isinstance(output_script,script.Script) or len(output_script.data)!=34 or output_script.data[:2]!=b'\x00\x20':raise ValueError('Expected a P2WSH contract')
    pub=key.get_public_key();outputs=[transaction.TransactionOutput(amount,output_script)]
    if change:outputs.append(transaction.TransactionOutput(change,script.p2wpkh(pub)))
    tx=transaction.Transaction(vin=[_outpoint(txid,vout)],vout=outputs)
    digest=tx.sighash_segwit(0,script.p2pkh(pub),input_amount)
    tx.vin[0].witness=transaction.Witness([key.sign(digest).serialize()+b'\x01',pub.sec()])
    return tx


def split(txid,vout,input_amount,key,amounts,fee):
    """Split one wallet output into independently spendable wallet outputs."""
    key=_key(key);_amount(input_amount);_uint(fee,100000)
    if not isinstance(amounts,list) or not 2<=len(amounts)<=5:raise ValueError('Invalid split output count')
    for amount in amounts:_amount(amount)
    if fee<1 or sum(amounts)+fee!=input_amount:raise ValueError('Split amounts and fee do not match input')
    pub=key.get_public_key();destination=script.p2wpkh(pub)
    tx=transaction.Transaction(vin=[_outpoint(txid,vout)],vout=[transaction.TransactionOutput(amount,destination) for amount in amounts])
    tx.vin[0].witness=transaction.Witness([key.sign(tx.sighash_segwit(0,script.p2pkh(pub),input_amount)).serialize()+b'\x01',pub.sec()])
    return tx


def spend(txid,vout,input_amount,key,witness_script,destination,fee,*,hashlock,claimant,refund,contract_refund_height,preimage=None):
    key=_key(key);_amount(input_amount);_uint(fee,100000)
    if fee<1 or fee>=input_amount:raise ValueError('Invalid Bitcoin fee')
    _amount(input_amount-fee)
    if not isinstance(witness_script,script.Script) or not isinstance(destination,script.Script):raise ValueError('Invalid Bitcoin scripts')
    expected,_=contract(hashlock,claimant,refund,contract_refund_height)
    if witness_script.data!=expected.data:raise ValueError('Witness script does not match terms')
    expected_key=claimant if preimage is not None else refund
    if key.get_public_key().sec().hex()!=expected_key:raise ValueError('Signing key does not match spend branch')
    inp=_outpoint(txid,vout)
    if preimage is not None:
        if not isinstance(preimage,bytes) or len(preimage)!=32 or hashlib.sha256(preimage).hexdigest()!=hashlock:raise ValueError('Preimage does not match hashlock')
        locktime=0;tail=[preimage,b'\x01',witness_script.data]
    else:
        locktime=_uint(contract_refund_height,499999999)
        if locktime==0:raise ValueError('Invalid refund height')
        inp.sequence=0xfffffffe;tail=[b'',witness_script.data]
    tx=transaction.Transaction(vin=[inp],vout=[transaction.TransactionOutput(input_amount-fee,destination)],locktime=locktime)
    sig=key.sign(tx.sighash_segwit(0,witness_script,input_amount)).serialize()+b'\x01'
    tx.vin[0].witness=transaction.Witness([sig,*tail])
    return tx
