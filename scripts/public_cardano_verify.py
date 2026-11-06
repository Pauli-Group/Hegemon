"""Verify an unspent Cardano preview HTLC using a trusted public indexer.

This verifies a snapshot and provider-reported confirmation depth, not chain
finality, independently validated consensus, or the other swap leg.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path
import cbor2
from public_cardano_transactions import CLI,_assets
from swap_engine.timelock_policy import load_timing,leg_requirements
from public_testnet_probe import CARDANO,request
from public_testnet_submit import verify_network
from public_testnet_utxos import cardano_utxos

ROOT=Path(__file__).resolve().parents[1]
from swap_engine.tools import find_tool
AIKEN=find_tool('aiken') or Path('/workspace/chain-tools/aiken/aiken-x86_64-unknown-linux-musl/aiken')  # HEGEMON_CHAIN_TOOLS or HEGEMON_TOOL_AIKEN override the legacy path


def verify_preview(script_file,outref,hashlock,claimant,refundee,expiry_ms,lovelace,assets,confirmations=None,minimum_remaining_ms=None,allow_expired=False):
    need=leg_requirements(load_timing(),'cardano')
    confirmations=max(2,need['confirmations']) if confirmations is None else confirmations
    minimum_remaining_ms=max(60000,need['minClaimWindowSeconds']*1000) if minimum_remaining_ms is None else minimum_remaining_ms
    if not isinstance(outref,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]{0,9})',outref):raise ValueError('Invalid Cardano output reference')
    for value,length in ((hashlock,64),(claimant,56),(refundee,56)):
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{'+str(length)+'}',value):raise ValueError('Invalid Cardano escrow terms')
    if claimant==refundee or type(expiry_ms) is not int or expiry_ms<=0 or type(lovelace) is not int or lovelace<=0 or type(confirmations) is not int or not 1<=confirmations<=1000 or type(minimum_remaining_ms) is not int or minimum_remaining_ms<1 or type(allow_expired) is not bool:raise ValueError('Invalid Cardano escrow amounts or timing')
    expected_assets=_assets(assets);script_file=Path(script_file)
    compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],text=True,timeout=30)
    if json.loads(script_file.read_text())!=json.loads(compiled):raise ValueError('Cardano validator differs from pinned blueprint')
    address=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(script_file),'--testnet-magic','2'],text=True,timeout=30).strip()
    verify_network('cardano-preview');txid=outref.split('#')[0];query={'_tx_hashes':[txid]}
    def status():
        rows=json.loads(request(CARDANO+'/tx_status',query))
        if len(rows)!=1 or rows[0].get('tx_hash')!=txid or type(rows[0].get('num_confirmations')) is not int or rows[0]['num_confirmations']<confirmations:raise ValueError('Cardano escrow lacks confirmations')
        return rows[0]['num_confirmations']
    depth=status();tip=json.loads(request(CARDANO+'/tip'))
    if len(tip)!=1 or type(tip[0].get('abs_slot')) is not int:raise ValueError('Cardano tip unavailable')
    if not allow_expired and expiry_ms-(1666656000+tip[0]['abs_slot'])*1000<minimum_remaining_ms:raise ValueError('Cardano escrow deadline too close')
    rows=[row for row in cardano_utxos(address) if row['outref']==outref]
    if len(rows)!=1 or rows[0]['lovelace']!=lovelace or rows[0]['assets']!=expected_assets:raise ValueError('Cardano escrow output or value mismatch')
    datum=rows[0]['inline_datum'];expected={'constructor':0,'fields':[{'bytes':hashlock},{'bytes':claimant},{'bytes':refundee},{'int':expiry_ms}]}
    if not isinstance(datum,dict) or datum.get('value')!=expected or not isinstance(datum.get('bytes'),str) or not re.fullmatch('[0-9a-f]+',datum['bytes']) or len(datum['bytes'])%2:raise ValueError('Cardano escrow datum mismatch')
    try:
        decoded=cbor2.loads(bytes.fromhex(datum['bytes']))
        fields=[bytes.fromhex(hashlock),bytes.fromhex(claimant),bytes.fromhex(refundee),expiry_ms]
        if not isinstance(decoded,cbor2.CBORTag) or decoded.tag!=121 or not isinstance(decoded.value,(list,tuple)) or list(decoded.value)!=fields:raise ValueError('Cardano escrow datum bytes mismatch')
    except Exception as error:raise ValueError('Cardano escrow datum bytes mismatch') from error
    depth=status();again=[row for row in cardano_utxos(address) if row['outref']==outref]
    if len(again)!=1 or again[0]!=rows[0]:raise ValueError('Cardano escrow changed during verification')
    return {'chain':'cardano-preview','outref':outref,'confirmations':depth,'slot':tip[0]['abs_slot'],'expiry_ms':expiry_ms,'validator_sha256':hashlib.sha256(compiled.encode()).hexdigest()}
