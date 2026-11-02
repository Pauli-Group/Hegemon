"""Read confirmed public-testnet UTxOs from trusted external indexers.

These are snapshots, not an independently validated chain or a reservation.
The caller must recheck them before signing and handle reorgs and races.
"""
import json
import re
from embit import script
from public_testnet_probe import BITCOIN,CARDANO,request
from public_testnet_submit import verify_network


def bitcoin_utxos(address,confirmations=2):
    if not isinstance(address,str) or not re.fullmatch(r'tb1q[ac-hj-np-z02-9]{38}',address):raise ValueError('Expected Bitcoin testnet P2WPKH address')
    if type(confirmations) is not int or not 1<=confirmations<=1000:raise ValueError('Invalid confirmation count')
    expected=script.address_to_scriptpubkey(address).data.hex()
    verify_network('bitcoin-testnet4');tip=int(request(BITCOIN+'/blocks/tip/height'))
    rows=json.loads(request(BITCOIN+'/address/'+address+'/utxo'))
    if not isinstance(rows,list) or len(rows)>1000:raise ValueError('Invalid Bitcoin UTxO list')
    result=[];seen=set()
    for row in rows:
        txid=row.get('txid');vout=row.get('vout');amount=row.get('value');status=row.get('status',{})
        if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid) or type(vout) is not int or not 0<=vout<=0xffffffff or type(amount) is not int or not 0<amount<=2100000000000000:raise ValueError('Invalid Bitcoin UTxO')
        if (txid,vout) in seen:raise ValueError('Duplicate Bitcoin UTxO')
        seen.add((txid,vout))
        if status.get('confirmed') is not True:continue
        height=status.get('block_height');block=status.get('block_hash')
        if type(height) is not int or not isinstance(block,str) or not re.fullmatch('[0-9a-f]{64}',block):raise ValueError('Invalid Bitcoin block')
        if tip-height+1<confirmations:continue
        if request(BITCOIN+'/block-height/'+str(height)).decode().strip()!=block:raise ValueError('Bitcoin block is not canonical')
        tx=json.loads(request(BITCOIN+'/tx/'+txid));outs=tx.get('vout')
        if tx.get('txid')!=txid or tx.get('status',{}).get('block_hash')!=block or not isinstance(outs,list) or vout>=len(outs) or outs[vout].get('value')!=amount or outs[vout].get('scriptpubkey')!=expected:raise ValueError('Bitcoin UTxO does not match transaction')
        if json.loads(request(BITCOIN+'/tx/'+txid+'/outspend/'+str(vout))).get('spent') is not False:raise ValueError('Bitcoin UTxO is spent or unknown')
        if request(BITCOIN+'/block-height/'+str(height)).decode().strip()!=block:raise ValueError('Bitcoin chain changed during verification')
        result.append({'txid':txid,'vout':vout,'amount_sats':amount,'confirmations':tip-height+1,'block_hash':block})
    return result


def cardano_utxos(address):
    if not isinstance(address,str) or not re.fullmatch('addr_test1[ac-hj-np-z02-9]+',address):raise ValueError('Expected Cardano testnet address')
    verify_network('cardano-preview');rows=json.loads(request(CARDANO+'/address_utxos',{'_addresses':[address],'_extended':True}))
    if not isinstance(rows,list) or len(rows)>1000:raise ValueError('Invalid Cardano UTxO list')
    result=[];seen=set()
    for row in rows:
        txid=row.get('tx_hash');index=row.get('tx_index');amount=row.get('value')
        if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid) or type(index) is not int or not 0<=index<=0xffffffff or row.get('address')!=address or not isinstance(amount,str) or not re.fullmatch('[1-9][0-9]{0,18}',amount):raise ValueError('Invalid Cardano UTxO')
        ref=txid+'#'+str(index)
        if ref in seen or row.get('is_spent') is True:raise ValueError('Duplicate or spent Cardano UTxO')
        seen.add(ref);assets={}
        for item in row.get('asset_list') or []:
            name=str(item.get('policy_id'))+'.'+str(item.get('asset_name'));quantity=item.get('quantity')
            if not re.fullmatch(r'[0-9a-f]{56}\.(?:[0-9a-f]{2}){0,32}',name) or not isinstance(quantity,str) or not re.fullmatch('[1-9][0-9]{0,18}',quantity) or name in assets:raise ValueError('Invalid Cardano asset')
            assets[name]=int(quantity)
        result.append({'outref':ref,'lovelace':int(amount),'assets':assets,'inline_datum':row.get('inline_datum'),'block_height':row.get('block_height')})
    return result
