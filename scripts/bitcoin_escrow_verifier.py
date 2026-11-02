"""Read-only verification of the local Bitcoin regtest HTLC output.

The caller supplies independently authenticated terms and a trusted Bitcoin Core
RPC object. This verifies a point-in-time snapshot, not public-chain finality,
node honesty, wallet ownership, or the terms of the other swap leg.
"""
from decimal import Decimal
import re


def verify_bitcoin_htlc(btc, *, txid, vout, amount_sats, hashlock, claimant_key,
                        refund_key, refund_height, genesis_hash, confirmations=2,
                        minimum_refund_blocks=1):
    if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid):raise ValueError('invalid transaction id')
    if not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock):raise ValueError('invalid hashlock')
    if not isinstance(genesis_hash,str) or not re.fullmatch('[0-9a-f]{64}',genesis_hash):raise ValueError('invalid genesis hash')
    if any(not isinstance(key,str) or not re.fullmatch('(02|03)[0-9a-f]{64}',key) for key in (claimant_key,refund_key)):raise ValueError('invalid compressed public key')
    if claimant_key==refund_key:raise ValueError('claim and refund keys must differ')
    if type(vout) is not int or not 0<=vout<=0xffffffff:raise ValueError('invalid output index')
    if type(amount_sats) is not int or not 0<amount_sats<=2_100_000_000_000_000:raise ValueError('invalid amount')
    if type(refund_height) is not int or not 0<refund_height<500_000_000:raise ValueError('refund must be a block height')
    if type(confirmations) is not int or not 1<=confirmations<=10000:raise ValueError('invalid confirmation count')
    if type(minimum_refund_blocks) is not int or minimum_refund_blocks<1:raise ValueError('invalid refund margin')
    if btc.call('getblockchaininfo')['chain']!='regtest' or btc.call('getblockhash',0)!=genesis_hash:raise ValueError('wrong chain identity')
    tip=btc.call('getbestblockhash');height=btc.call('getblockcount')
    if refund_height-height<minimum_refund_blocks:raise ValueError('refund height too close')
    # Construct the exact script policy used by the local swap harness. Only
    # public keys are accepted; private descriptors never enter this function.
    desc=f'wsh(or_i(and_v(v:sha256({hashlock}),pk({claimant_key})),and_v(v:after({refund_height}),pk({refund_key}))))'
    canonical=btc.call('getdescriptorinfo',desc)['descriptor']
    destination=btc.call('deriveaddresses',canonical)[0]
    expected_script=btc.call('validateaddress',destination)['scriptPubKey']
    output=btc.call('gettxout',txid,vout,True)
    if output is None:raise ValueError('output absent or spent')
    if output.get('bestblock')!=tip or output.get('confirmations',0)<confirmations:raise ValueError('insufficient or inconsistent confirmations')
    if output.get('scriptPubKey',{}).get('hex')!=expected_script:raise ValueError('script or terms mismatch')
    if Decimal(str(output.get('value')))*100_000_000!=amount_sats:raise ValueError('amount mismatch')
    if btc.call('getbestblockhash')!=tip:raise ValueError('snapshot changed')
    return {'chain':'regtest','genesis':genesis_hash,'block_hash':tip,'block_height':height,
            'confirmations':output['confirmations'],'txid':txid,'vout':vout,'amount_sats':amount_sats,
            'refund_height':refund_height,'script_pub_key':expected_script}
