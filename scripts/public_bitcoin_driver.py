"""Fund a testnet4 HTLC with locally signed transactions.

The provider is trusted for UTxOs, fees and chain identity. The caller must
independently verify the other swap leg, timeout, backup and recovery plan.
"""
import json
import math
import os
import re
import stat
from pathlib import Path
from embit import ec,networks,script
from public_bitcoin_transactions import contract,funding,spend
from public_testnet_probe import BITCOIN,request
from public_testnet_submit import submit,verify_network
from public_testnet_utxos import bitcoin_utxos


def load_test_key(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Bitcoin key cannot be a symlink')
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>128:raise ValueError('Bitcoin test key must be a private user-owned file')
    value=path.read_text().strip()
    if not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('Invalid Bitcoin test key')
    return ec.PrivateKey(bytes.fromhex(value))


def _fee():
    estimates=json.loads(request(BITCOIN+'/fee-estimates'));rate=estimates.get('6')
    if type(rate) not in (int,float) or not math.isfinite(rate) or not 0<rate<=100:raise ValueError('Bitcoin testnet fee estimate unavailable or excessive')
    # 250 vbytes bounds these single-input, two-output P2WPKH/P2WSH fixtures.
    return math.ceil(max(rate,1)*250)


def fund(journal,key_file,hashlock,claimant,refund_height,amount):
    if type(amount) is not int or not 546<=amount<=2100000000000000:raise ValueError('Invalid Bitcoin escrow amount')
    key=load_test_key(key_file);refund=key.get_public_key().sec().hex();_,output=contract(hashlock,claimant,refund,refund_height)
    verify_network('bitcoin-testnet4');height=int(request(BITCOIN+'/blocks/tip/height'))
    if type(refund_height) is not int or refund_height-height<6:raise ValueError('Bitcoin refund height too close')
    fee=_fee();address=script.p2wpkh(key.get_public_key()).address(networks.NETWORKS['test'])
    coins=bitcoin_utxos(address)
    eligible=[x for x in coins if x['amount_sats']>=amount+fee and (x['amount_sats']==amount+fee or x['amount_sats']>=amount+fee+546)]
    if not eligible:raise ValueError('No confirmed Bitcoin testnet UTxO can fund this escrow')
    coin=min(eligible,key=lambda x:x['amount_sats']);tx=funding(coin['txid'],coin['vout'],coin['amount_sats'],key,output,amount,fee)
    return submit(journal,'bitcoin-testnet4',tx.serialize())


def spend_contract(journal,key_file,txid,vout,amount,hashlock,claimant,refund,refund_height,preimage=None):
    key=load_test_key(key_file);witness,output=contract(hashlock,claimant,refund,refund_height)
    if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid) or type(vout) is not int or not 0<=vout<=0xffffffff:raise ValueError('Invalid Bitcoin funding outpoint')
    verify_network('bitcoin-testnet4');tip=int(request(BITCOIN+'/blocks/tip/height'))
    if preimage is None and tip<refund_height:raise ValueError('Bitcoin refund is not yet eligible')
    if preimage is not None and tip>=refund_height:raise ValueError('Bitcoin escrow is already refundable; refusing claim')
    tx=json.loads(request(BITCOIN+'/tx/'+txid));status=tx.get('status',{});height=status.get('block_height');block=status.get('block_hash');outputs=tx.get('vout')
    if tx.get('txid')!=txid or status.get('confirmed') is not True or type(height) is not int or tip-height+1<2 or not isinstance(block,str) or request(BITCOIN+'/block-height/'+str(height)).decode().strip()!=block:raise ValueError('Bitcoin escrow lacks canonical confirmations')
    if not isinstance(outputs,list) or vout>=len(outputs) or outputs[vout].get('value')!=amount or outputs[vout].get('scriptpubkey')!=output.data.hex():raise ValueError('Bitcoin escrow terms do not match output')
    if json.loads(request(BITCOIN+'/tx/'+txid+'/outspend/'+str(vout))).get('spent') is not False:raise ValueError('Bitcoin escrow is spent or unknown')
    fee=_fee();destination=script.p2wpkh(key.get_public_key())
    signed=spend(txid,vout,amount,key,witness,destination,fee,hashlock=hashlock,claimant=claimant,refund=refund,contract_refund_height=refund_height,preimage=preimage)
    return submit(journal,'bitcoin-testnet4',signed.serialize())
