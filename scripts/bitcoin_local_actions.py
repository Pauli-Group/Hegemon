"""Terminal-approved, peerless Bitcoin Core regtest HTLC actions.

The wallet name and optional backup are configured by the local operator, not
the HTTP caller. The exact descriptor must already be imported into the wallet.
This does not verify the other chain or establish public-network fee policy.
"""
import getpass
import hashlib
import json
import re
from decimal import Decimal
from development_atomic_swap_rehearsal import btc_amount, spend_contract
from unlock_swap_backup import unlock_backup


def decimal(value,maximum,positive=False):
    if not isinstance(value,str) or not re.fullmatch(r'0|[1-9][0-9]{0,15}',value) or int(value)>maximum or (positive and value=='0'):
        raise ValueError('invalid Bitcoin integer')
    return int(value)


def prepare_terms(btc,data,genesis):
    common={'operation','hashlock','claimant_key','refund_key','refund_height','amount_sats'}
    operation=data.get('operation') if isinstance(data,dict) else None
    if operation not in ('lock','claim','refund') or set(data)!=(common if operation=='lock' else common|{'txid','vout','destination'}):raise ValueError('invalid Bitcoin action fields')
    digest=data['hashlock'];a=data['claimant_key'];b=data['refund_key']
    if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('invalid hashlock')
    if any(not isinstance(k,str) or not re.fullmatch('(02|03)[0-9a-f]{64}',k) for k in (a,b)) or a==b:raise ValueError('invalid Bitcoin public keys')
    height=decimal(data['refund_height'],499999999,True);amount=decimal(data['amount_sats'],2_100_000_000_000_000,True)
    if amount<=500:raise ValueError('amount must exceed the local fixed 500 satoshi spend fee')
    if btc.call('getblockchaininfo')['chain']!='regtest' or btc.call('getblockhash',0)!=genesis or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not the configured isolated regtest chain')
    desc=f'wsh(or_i(and_v(v:sha256({digest}),pk({a})),and_v(v:after({height}),pk({b}))))'
    canonical=btc.call('getdescriptorinfo',desc)['descriptor'];address=btc.call('deriveaddresses',canonical)[0]
    script=btc.call('validateaddress',address)['scriptPubKey']
    if operation!='lock':
        if not isinstance(data['txid'],str) or not re.fullmatch('[0-9a-f]{64}',data['txid']):raise ValueError('invalid transaction id')
        decimal(data['vout'],0xffffffff)
        if not isinstance(data['destination'],str) or not btc.call('validateaddress',data['destination']).get('isvalid'):raise ValueError('invalid local Bitcoin destination')
    return operation,height,amount,address,script


def run_bitcoin_action(*,btc,wallet,genesis,request,backup=None,confirm=input,password=getpass.getpass):
    operation,height,amount,address,script=prepare_terms(btc,request,genesis)
    tip=btc.call('getbestblockhash');current=btc.call('getblockcount')
    if operation=='lock' and height-current<2:raise ValueError('refund height too close for local test')
    if operation=='claim' and current>=height:raise ValueError('claim is too close to or past refund height')
    if operation=='refund' and current<height:raise ValueError('refund is not yet available')
    info=btc.call('getaddressinfo',address,wallet=wallet)
    if not info.get('ismine') or not info.get('solvable') or not isinstance(info.get('hex'),str):raise ValueError('the exact private HTLC descriptor is not imported in the configured wallet')
    witness=bytes.fromhex(info['hex']);script_bytes=bytes.fromhex(script)
    if script_bytes!=b'\x00\x20'+hashlib.sha256(witness).digest():raise ValueError('wallet witness script mismatch')
    if operation!='lock':
        utxo=btc.call('gettxout',request['txid'],decimal(request['vout'],0xffffffff),True)
        if not utxo or utxo.get('bestblock')!=tip or utxo.get('confirmations',0)<1 or utxo.get('scriptPubKey',{}).get('hex')!=script or Decimal(str(utxo['value']))*100_000_000!=amount:raise ValueError('Bitcoin output is absent, unconfirmed, spent, or mismatched')
    print('\nBitcoin local regtest action (not an atomic swap):\n'+json.dumps(request,indent=2),flush=True)
    if operation=='claim':print('The claim preimage is sent to the local Bitcoin wallet before broadcast and becomes public on submission.',flush=True)
    if confirm('Type APPROVE to continue this local Bitcoin action: ').strip()!='APPROVE':raise ValueError('action declined locally')
    wallet_info=btc.call('getwalletinfo',wallet=wallet);locked='unlocked_until' in wallet_info and wallet_info['unlocked_until']<=0
    buffers=[]
    try:
        if locked:
            phrase=password('Bitcoin wallet passphrase (local terminal only): ')
            if not phrase:raise ValueError('wallet passphrase required')
            try:btc.call('walletpassphrase',phrase,120,wallet=wallet,sensitive=True)
            finally:del phrase
        if btc.call('getbestblockhash')!=tip or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node changed before action')
        if operation=='lock':
            # Sign a synthetic, never-broadcast refund to prove this wallet owns
            # the refund branch, not merely the counterparty's claim branch.
            try:spend_contract(btc,wallet,'00'*32,0,amount,script_bytes,witness,address,0xfffffffe,height,broadcast=False)
            except Exception as e:raise ValueError('wallet cannot sign the refund branch; no funds were sent') from e
            if btc.call('getbestblockhash')!=tip or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node changed before funding')
            try:txid=btc.call('sendtoaddress',address,btc_amount(amount),wallet=wallet,sensitive=True)
            except Exception as e:raise ValueError('Funding outcome uncertain. Check wallet history before retrying.') from e
        else:
            secret=None
            if operation=='claim':
                if backup:
                    phrase=bytearray(password('Encrypted preimage backup passphrase (local terminal only): ').encode());buffers.append(phrase)
                    secret=unlock_backup(backup,phrase);buffers.append(secret)
                else:
                    value=password('Claim preimage as 64 lowercase hexadecimal characters (local terminal only): ')
                    if not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('invalid claim preimage')
                    secret=bytearray.fromhex(value);buffers.append(secret);del value
                if hashlib.sha256(secret).hexdigest()!=request['hashlock']:raise ValueError('preimage does not match hashlock')
            if btc.call('getbestblockhash')!=tip or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node changed before spending')
            try:txid=spend_contract(btc,wallet,request['txid'],decimal(request['vout'],0xffffffff),amount,script_bytes,witness,request['destination'],0xffffffff if operation=='claim' else 0xfffffffe,0 if operation=='claim' else height,bytes(secret) if secret is not None else None)
            except Exception as e:raise ValueError('Spend outcome uncertain. Check wallet history before retrying.') from e
        if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid):raise ValueError('Transaction ID unavailable. Check wallet history before retrying.')
        if btc.call('getconnectioncount')!=0 or btc.call('getblockhash',0)!=genesis:raise ValueError('Node changed; action outcome may be uncertain. Check wallet history.')
        return {'operation':operation,'txid':txid,'submitted':True,'confirmed':False,'address':address}
    finally:
        for value in buffers:value[:]=b'\0'*len(value)
        if locked:
            try:btc.call('walletlock',wallet=wallet,sensitive=True)
            except Exception:print('Warning: wallet could not be locked again; lock it locally.',flush=True)
