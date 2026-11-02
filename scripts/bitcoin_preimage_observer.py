"""Recover an HTLC preimage from confirmed blocks on peerless Bitcoin regtest.

The caller supplies the exact funding outpoint and hashlock. The trusted local
node provides canonical blocks; a reorganization or changing tip fails closed.
"""
import hashlib
import re
import time


def observe_bitcoin_preimage(btc,*,genesis,txid,vout,hashlock,start_height,confirmations=2,timeout=120):
    if any(not isinstance(x,str) or not re.fullmatch('[0-9a-f]{64}',x) for x in (genesis,txid,hashlock)):raise ValueError('invalid Bitcoin observation terms')
    if type(vout) is not int or not 0<=vout<=0xffffffff or type(start_height) is not int or not 0<=start_height<500_000_000 or type(confirmations) is not int or not 1<=confirmations<=100 or not 0<timeout<=3600:raise ValueError('invalid Bitcoin observation limits')
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if btc.call('getblockchaininfo')['chain']!='regtest' or btc.call('getblockhash',0)!=genesis or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not the configured isolated regtest chain')
        tip=btc.call('getbestblockhash');height=btc.call('getblockcount');end=height-confirmations+1
        if start_height>height or height-start_height>10000:raise ValueError('invalid Bitcoin observation block range')
        for number in range(start_height,end+1):
            block_hash=btc.call('getblockhash',number);block=btc.call('getblock',block_hash,2)
            if not isinstance(block,dict) or block.get('hash')!=block_hash or block.get('height')!=number or not isinstance(block.get('tx'),list):raise ValueError('invalid Bitcoin block response')
            for transaction in block['tx']:
                if not isinstance(transaction,dict) or not isinstance(transaction.get('vin'),list):raise ValueError('invalid Bitcoin transaction')
                for vin in transaction['vin']:
                    if vin.get('txid')!=txid or vin.get('vout')!=vout:continue
                    witness=vin.get('txinwitness',[])
                    if not isinstance(witness,list):raise ValueError('invalid Bitcoin witness')
                    matches=set()
                    for element in witness:
                        if isinstance(element,str) and re.fullmatch('[0-9a-f]{64}',element) and hashlib.sha256(bytes.fromhex(element)).hexdigest()==hashlock:matches.add(element)
                    if len(matches)>1:raise ValueError('ambiguous Bitcoin claim preimage')
                    if matches:
                        if not isinstance(transaction.get('txid'),str) or not re.fullmatch('[0-9a-f]{64}',transaction['txid']):raise ValueError('invalid Bitcoin claim transaction ID')
                        if btc.call('getbestblockhash')!=tip or btc.call('getblockhash',number)!=block_hash or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin chain changed during observation')
                        return bytearray.fromhex(matches.pop()),{'transaction':transaction['txid'],'block_hash':block_hash,'block_height':number,'confirmations':height-number+1}
        if btc.call('getbestblockhash')!=tip:raise ValueError('Bitcoin chain changed during observation')
        remaining=deadline-time.monotonic()
        if remaining>0:time.sleep(min(1,remaining))
    raise ValueError('Bitcoin observation timed out')
