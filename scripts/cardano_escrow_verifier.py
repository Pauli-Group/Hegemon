"""Check a Cardano HTLC UTxO against a locally pinned Plutus validator.

This is a read-only local snapshot check. It assumes an honest local node and
a trusted locally compiled blueprint. The CLI UTxO query provides no inclusion
history, so this function cannot prove confirmation depth or finality.
"""
import datetime
import hashlib
import json
import re
import subprocess
import time
from htlc_counterpart import ROOT, TOOLS


def verify_cardano_htlc(chain, *, outref, hashlock, claimant, refundee, expiry_ms,
                        expected_value, genesis_sha256, minimum_remaining_ms=1000,
                        aiken=TOOLS/'aiken/aiken-x86_64-unknown-linux-musl/aiken', allow_expired=False):
    if not isinstance(outref,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]*)',outref):raise ValueError('invalid output reference')
    if not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock):raise ValueError('invalid hashlock')
    if any(not isinstance(key,str) or not re.fullmatch('[0-9a-f]{56}',key) for key in (claimant,refundee)):raise ValueError('invalid payment key hash')
    if type(expiry_ms) is not int or expiry_ms<=0 or type(minimum_remaining_ms) is not int or minimum_remaining_ms<1:raise ValueError('invalid expiry or margin')
    if not isinstance(genesis_sha256,str) or not re.fullmatch('[0-9a-f]{64}',genesis_sha256):raise ValueError('invalid genesis hash')
    if not isinstance(expected_value,dict) or type(expected_value.get('lovelace')) is not int or expected_value['lovelace']<=0:raise ValueError('invalid lovelace')
    for policy,assets in expected_value.items():
        if policy=='lovelace':continue
        if not re.fullmatch('[0-9a-f]{56}',policy) or not isinstance(assets,dict) or not assets:raise ValueError('invalid asset policy')
        for name,quantity in assets.items():
            if not isinstance(name,str) or not re.fullmatch('(?:[0-9a-f]{2}){0,32}',name) or type(quantity) is not int or not 0<quantity<2**63:raise ValueError('invalid asset name or quantity')
    raw=(chain.net/'shelley-genesis.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=genesis_sha256:raise ValueError('wrong genesis')
    genesis=json.loads(raw)
    if genesis.get('networkId')!='Testnet' or genesis.get('networkMagic')!=424242 or chain.magic!='424242':raise ValueError('wrong local network')
    start=int(datetime.datetime.fromisoformat(genesis['systemStart'].replace('Z','+00:00')).timestamp()*1000)
    slot_ms=round(genesis['slotLength']*1000)
    trusted_script=subprocess.check_output([str(aiken),'blueprint','convert',str(ROOT/'contracts/cardano')],text=True)
    if chain.script.read_text()!=trusted_script:raise ValueError('validator differs from pinned blueprint')
    script_hash=hashlib.sha256(trusted_script.encode()).hexdigest()
    expected_address=chain.run('address','build','--payment-script-file',chain.script,'--testnet-magic',chain.magic).strip()
    datum={'constructor':0,'fields':[{'bytes':hashlock},{'bytes':claimant},{'bytes':refundee},{'int':expiry_ms}]}
    for _ in range(8):
        before=chain.tip()
        if not allow_expired and expiry_ms-(start+before['slot']*slot_ms)<minimum_remaining_ms:raise ValueError('refund deadline too close')
        output=chain.utxos(expected_address).get(outref)
        after=chain.tip()
        if before.get('hash')!=after.get('hash'):
            time.sleep(.05)
            continue
        if output is None:raise ValueError('output absent or spent')
        if output.get('address')!=expected_address or output.get('inlineDatum')!=datum:raise ValueError('validator or datum mismatch')
        if output.get('value')!=expected_value:raise ValueError('asset value mismatch')
        return {'chain':'local-cardano','genesis_sha256':genesis_sha256,'tip_hash':after['hash'],
                'tip_block':after['block'],'outref':outref,'script_sha256':script_hash,
                'confirmations':None}
    raise ValueError('tip changed during snapshot; retry')
