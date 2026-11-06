#!/usr/bin/env python3
"""Independently verify the finished public Bitcoin swap cases from public chain data.

For each Bitcoin pair (BTC with ETH, ERC-20, ADA and an ADA token) and the Bitcoin
refund case, this reads the public chains only and checks, from raw bytes where
possible:

* every transaction's raw bytes hash to the recorded transaction ID (Bitcoin);
* the Bitcoin escrow output pays the P2WSH of the witness script that the spend reveals,
  and the script's hashlock, claim key, refund key and refund height equal the recorded terms;
* the claim witness preimage hashes (SHA-256) to the hashlock, and the ECDSA signature
  verifies against the claim key; a refund uses the refund branch, the locktime and a
  non-final sequence, and its signature verifies against the refund key;
* the payout goes to the key's own P2WPKH script with the expected amount;
* the paired Cardano or Ethereum leg used the same hashlock, the intended parties, the
  exact amount and assets, the pinned validator or the source-pinned escrow runtime, and its
  claim revealed a preimage that hashes to the same hashlock;
* the order and timing of the claims against both legs' deadlines, and the verdict the
  current P1 policy gives the pair at the moment the second leg was confirmed.

It reads only the public fields of the scenario `state.json` files (terms, IDs, deadlines).
It never opens a `secret` file, never prints a preimage that is not already public on chain, and
writes public identifiers and observations only.

    PYTHONPATH=scripts python3 scripts/verify_public_btc_cases.py \
        --journals ~/.hegemon-private/restore/historical-testnet-journals-20261102 --out /tmp/p4.json
"""
import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from embit import ec, script, transaction

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from swap_engine import timelock_policy  # noqa: E402
from public_bitcoin_transactions import contract as btc_contract  # noqa: E402

BTC_PROVIDERS = ['https://mempool.space/testnet4/api', 'https://blockstream.info/testnet4/api']
BTC_GENESIS = '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043'
KOIOS = 'https://preview.koios.rest/api/v1'
BLOCKSCOUT = 'https://eth-sepolia.blockscout.com/api/v2'
SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com'
SCRIPT_FILE = ROOT / 'swap-ui' / 'cardano-htlc-script.json'
PUBLIC_STATE_KEYS = {
    'ada_amount_lovelace', 'ada_assets', 'ada_claim', 'ada_expiry_ms', 'ada_expiry_slot', 'ada_lock', 'btc_amount_sats',
    'btc_claim', 'btc_lock', 'btc_refund_height', 'hashlock', 'phase', 'scenario', 'terms', 'eth_amount_wei', 'eth_claim',
    'eth_contract', 'eth_expiry', 'eth_lock', 'token', 'refund', 'version', 'amount', 'claimant', 'contract', 'expiry', 'lock', 'refundee',
}


class Check:
    def __init__(self, name):
        self.name, self.items = name, []

    def ok(self, label, passed, detail=''):
        self.items.append({'check': label, 'ok': bool(passed), 'detail': str(detail)})
        return bool(passed)

    @property
    def passed(self):
        return all(item['ok'] for item in self.items)


def _get(url, body=None, headers=None, tries=5):
    """GET or POST JSON or text. Backs off on 429 and 5xx; reports failures instead of hiding them."""
    last = None
    for attempt in range(tries):
        try:
            request = urllib.request.Request(url, data=body, headers={'User-Agent': 'hegemon-p4-verify', **(headers or {})})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            last = error
            if error.code not in (429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError) as error:
            last = error
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f'{url} unavailable: {last}')


def get_json(url, body=None):
    headers = {'content-type': 'application/json'} if body is not None else None
    return json.loads(_get(url, json.dumps(body).encode() if body is not None else None, headers))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_state(journals, name):
    raw = json.loads((journals / name / 'state.json').read_text()) if (journals / name / 'state.json').exists() else json.loads((journals / name).read_text())
    return {k: v for k, v in raw.items() if k in PUBLIC_STATE_KEYS}


# ---------------------------------------------------------------- Bitcoin

def btc_providers_agree():
    """Return the providers that really are testnet4 (genesis check) and answer."""
    live = []
    for base in BTC_PROVIDERS:
        try:
            if _get(base + '/block-height/0').decode().strip() == BTC_GENESIS:
                live.append(base)
        except Exception:
            pass
    return live


def btc_raw(base, txid):
    raw = bytes.fromhex(_get(f'{base}/tx/{txid}/hex').decode().strip())
    tx = transaction.Transaction.parse(raw)
    return tx, raw


def btc_status(base, txid):
    return get_json(f'{base}/tx/{txid}/status')


def parse_htlc_script(data):
    """Parse the one script shape this system uses; return its terms or raise ValueError.

    OP_IF OP_SIZE 0x20 OP_EQUALVERIFY OP_SHA256 <32> OP_EQUALVERIFY <33> OP_CHECKSIG
    OP_ELSE <n> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <33> OP_CHECKSIG OP_ENDIF
    """
    head = bytes.fromhex('6382012088a820')
    if data[:7] != head:
        raise ValueError('script does not start with the expected claim branch')
    pos = 7
    hashlock = data[pos:pos + 32]
    pos += 32
    if data[pos:pos + 2] != b'\x88\x21':
        raise ValueError('hash comparison is not followed by a 33-byte key push')
    pos += 2
    claimant = data[pos:pos + 33]
    pos += 33
    if data[pos:pos + 2] != b'\xac\x67':
        raise ValueError('claim branch does not end with CHECKSIG ELSE')
    pos += 2
    length = data[pos]
    if not 1 <= length <= 5:
        raise ValueError('unexpected locktime push')
    height = int.from_bytes(data[pos + 1:pos + 1 + length], 'little')
    pos += 1 + length
    if data[pos:pos + 3] != b'\xb1\x75\x21' and data[pos:pos + 3] != b'\xb1\x69\x21':
        raise ValueError('refund branch does not use CHECKLOCKTIMEVERIFY then a key push')
    pos += 3
    refund = data[pos:pos + 33]
    pos += 33
    if data[pos:] != b'\xac\x68':
        raise ValueError('script has trailing or missing bytes')
    return {'hashlock': hashlock.hex(), 'claimant': claimant.hex(), 'refund': refund.hex(), 'height': height}


def check_bitcoin_leg(c, state, spend_txid, kind, providers):
    """Verify funding and a spend (kind 'claim' or 'refund') of one escrow. Returns facts."""
    facts = {}
    fund_id = state['btc_lock']
    terms = state['terms']
    base = providers[0]
    fund, fund_raw = btc_raw(base, fund_id)
    spend, spend_raw = btc_raw(base, spend_txid)
    c.ok('funding raw bytes hash to the recorded txid', fund.txid().hex() == fund_id)
    c.ok(f'{kind} raw bytes hash to the recorded txid', spend.txid().hex() == spend_txid)
    c.ok(f'{kind} has exactly one input spending funding output 0',
         len(spend.vin) == 1 and spend.vin[0].txid.hex() == fund_id and spend.vin[0].vout == 0)
    witness = [bytes(item) for item in spend.vin[0].witness.items]
    witness_script = witness[-1]
    try:
        parsed = parse_htlc_script(witness_script)
    except ValueError as error:
        c.ok('witness script has the expected HTLC shape', False, error)
        return facts
    c.ok('witness script has the expected HTLC shape', True)
    c.ok('script hashlock equals the recorded hashlock', parsed['hashlock'] == state['hashlock'])
    c.ok('script claim key equals the recorded claimant key', parsed['claimant'] == terms['btc_claimant'])
    c.ok('script refund key equals the recorded refund key', parsed['refund'] == terms['btc_refund'])
    c.ok('script refund height equals the recorded height', parsed['height'] == state['btc_refund_height'], parsed['height'])
    expected, expected_spk = btc_contract(state['hashlock'], terms['btc_claimant'], terms['btc_refund'], state['btc_refund_height'])
    c.ok('script equals the one the repository builds from the terms', expected.data == witness_script)
    program = script.p2wsh(script.Script(witness_script))
    c.ok('funding output 0 pays the P2WSH of that script', fund.vout[0].script_pubkey.data == program.data)
    c.ok('funding output 0 holds the recorded amount', fund.vout[0].value == state['btc_amount_sats'], fund.vout[0].value)
    c.ok('repository descriptor yields the same output script', expected_spk.data == fund.vout[0].script_pubkey.data)
    sighash = spend.sighash_segwit(0, script.Script(witness_script), fund.vout[0].value)
    sig_item = witness[0]
    c.ok('signature uses SIGHASH_ALL', sig_item[-1:] == b'\x01')
    sig = ec.Signature.parse(sig_item[:-1])
    if kind == 'claim':
        c.ok('claim witness has four items [sig, preimage, 01, script]', len(witness) == 4 and witness[2] == b'\x01', len(witness))
        preimage = witness[1]
        c.ok('preimage is 32 bytes', len(preimage) == 32)
        c.ok('SHA-256 of the witness preimage equals the hashlock', sha256(preimage) == state['hashlock'])
        facts['claim_preimage_sha256'] = sha256(preimage)
        key = ec.PublicKey.parse(bytes.fromhex(terms['btc_claimant']))
        c.ok('claim signature verifies against the claim key', key.verify(sig, sighash))
        payee = script.p2wpkh(key)
    else:
        c.ok('refund witness has three items [sig, empty, script]', len(witness) == 3 and witness[1] == b'', len(witness))
        c.ok('refund locktime equals the refund height', spend.locktime == state['btc_refund_height'], spend.locktime)
        c.ok('refund input sequence is not final', spend.vin[0].sequence < 0xffffffff, spend.vin[0].sequence)
        key = ec.PublicKey.parse(bytes.fromhex(terms['btc_refund']))
        c.ok('refund signature verifies against the refund key', key.verify(sig, sighash))
        payee = script.p2wpkh(key)
    c.ok(f'{kind} pays only the key owner P2WPKH script', len(spend.vout) == 1 and spend.vout[0].script_pubkey.data == payee.data)
    fee = fund.vout[0].value - sum(o.value for o in spend.vout)
    c.ok(f'{kind} fee is positive and below 1000 sats', 0 < fee < 1000, fee)
    facts['payout_sats'] = spend.vout[0].value
    facts['fee_sats'] = fee
    # Provider-reported confirmation, compared across every live provider.
    statuses = {}
    for provider in providers:
        statuses[provider] = {
            'fund': btc_status(provider, fund_id), 'spend': btc_status(provider, spend_txid),
            'tip': int(_get(provider + '/blocks/tip/height').decode()),
        }
    for name, tx_id in (('funding', fund_id), (kind, spend_txid)):
        key_ = 'fund' if name == 'funding' else 'spend'
        reported = [s[key_] for s in statuses.values()]
        c.ok(f'{name} confirmed on {len(providers)} provider(s)', all(r.get('confirmed') for r in reported))
        c.ok(f'{name} block hash and height agree across providers',
             len({(r.get('block_hash'), r.get('block_height')) for r in reported}) == 1)
    first = statuses[providers[0]]
    facts.update({
        'fund_height': first['fund']['block_height'], 'fund_time': first['fund']['block_time'],
        'spend_height': first['spend']['block_height'], 'spend_time': first['spend']['block_time'],
        'tip_at_check': first['tip'], 'providers': len(providers),
    })
    if kind == 'refund':
        c.ok('refund was mined at a height above its locktime', facts['spend_height'] > state['btc_refund_height'], facts['spend_height'])
    else:
        c.ok('claim was mined before the refund height', facts['spend_height'] < state['btc_refund_height'],
             f"{facts['spend_height']} < {state['btc_refund_height']}")
    return facts


# ---------------------------------------------------------------- Cardano

def koios(path, body):
    return get_json(KOIOS + path, body)


def check_cardano_leg(c, state, facts):
    terms = state['terms']
    pinned = json.loads(SCRIPT_FILE.read_text())
    lock_id, claim_id = state['ada_lock'], state['ada_claim']
    by_id = {}
    for attempt in range(8):
        # Koios backends lag and may return an empty or partial list for confirmed data, so ask per transaction and retry.
        for tx_hash in (lock_id, claim_id):
            if tx_hash in by_id:
                continue
            reply = koios('/tx_info', {'_tx_hashes': [tx_hash], '_inputs': True, '_metadata': False, '_assets': True,
                                       '_withdrawals': False, '_certs': False, '_scripts': True, '_bytecode': False})
            if reply and reply[0].get('outputs') and reply[0].get('block_height') is not None:
                by_id[tx_hash] = reply[0]
        if len(by_id) == 2:
            break
        time.sleep(3)
    c.ok('Koios returns both Cardano transactions', set(by_id) == {lock_id, claim_id})
    if set(by_id) != {lock_id, claim_id}:
        return
    lock, claim = by_id[lock_id], by_id[claim_id]
    # The escrow is the output the claim's script run spends, not necessarily output 0 of the lock transaction.
    index = 0
    for run in claim.get('plutus_contracts') or []:
        if (run.get('spends_input') or {}).get('tx_hash') == lock_id:
            index = run['spends_input']['tx_index']
    out = next(o for o in lock['outputs'] if o['tx_index'] == index)
    c.ok('lock output is at the pinned validator address', out['payment_addr']['bech32'] == pinned['address'], index)
    c.ok('lock output holds the recorded lovelace', int(out['value']) == state['ada_amount_lovelace'], out['value'])
    wanted = {k: v for k, v in (state.get('ada_assets') or {}).items()}
    held = {f"{a['policy_id']}.{a['asset_name']}": int(a['quantity']) for a in out['asset_list']}
    c.ok('lock output holds exactly the recorded assets', held == wanted, held)
    datum = (out['inline_datum'] or {}).get('value') or {}
    fields = [f.get('bytes', f.get('int')) for f in datum.get('fields', [])]
    c.ok('inline datum has hashlock, claimant, refundee and expiry equal to the recorded terms',
         fields == [state['hashlock'], terms['ada_claimant'], terms['ada_refundee'], state['ada_expiry_ms']], fields)
    c.ok('datum expiry equals the recorded expiry', state['ada_expiry_ms'] == fields[3] if len(fields) == 4 else False)
    contracts = claim.get('plutus_contracts') or []
    c.ok('claim ran exactly one Plutus script', len(contracts) == 1)
    if contracts:
        run = contracts[0]
        c.ok('script hash is the pinned validator', run['script_hash'] == pinned['hash'])
        c.ok('script was valid (phase 2 passed)', run['valid_contract'] is True)
        c.ok('script spent the lock output', run['spends_input'] == {'tx_hash': lock_id, 'tx_index': index})
        redeemer = run['input']['redeemer']['datum']['value']['fields'][0]['bytes']
        c.ok('SHA-256 of the redeemer preimage equals the hashlock', sha256(bytes.fromhex(redeemer)) == state['hashlock'])
        facts['cardano_preimage_sha256'] = sha256(bytes.fromhex(redeemer))
    pays = [o for o in claim['outputs'] if o['payment_addr']['bech32'] == terms['ada_claim_address']]
    got_assets = {}
    for o in pays:
        for a in o['asset_list']:
            key = f"{a['policy_id']}.{a['asset_name']}"
            got_assets[key] = got_assets.get(key, 0) + int(a['quantity'])
    c.ok('claim paid the recorded claim address at least the locked lovelace',
         any(int(o['value']) >= state['ada_amount_lovelace'] for o in pays))
    c.ok('claim paid the recorded claim address every recorded asset', all(got_assets.get(k) == v for k, v in wanted.items()), got_assets)
    c.ok('claim transaction was mined', claim.get('block_height') is not None and lock.get('block_height') is not None)
    c.ok('claim upper validity bound is before the datum expiry slot',
         claim['invalid_after'] is not None and int(claim['invalid_after']) <= state['ada_expiry_slot'], claim['invalid_after'])
    tip = get_json(KOIOS + '/tip')
    facts.update({
        'ada_lock_time': lock['tx_timestamp'], 'ada_claim_time': claim['tx_timestamp'],
        'ada_lock_height': lock['block_height'], 'ada_claim_height': claim['block_height'],
        'ada_claim_confirmations': tip[0]['block_no'] - claim['block_height'] + 1,
    })
    # The pinned validator address holds nothing now: no escrow is live.
    utxos = get_json(KOIOS + '/address_utxos', {'_addresses': [pinned['address']]})
    c.ok('the escrow output of this scenario is not among the validator address UTxOs now',
         all((u['tx_hash'], u['tx_index']) != (lock_id, index) for u in utxos), len(utxos))
    facts['validator_utxos_not_from_this_scenario'] = sorted(f"{u['tx_hash']}#{u['tx_index']}" for u in utxos if u['tx_hash'] != lock_id)
    # Pinned script bytes hash to the pinned script hash (Plutus V3 tag 3).
    digest = hashlib.blake2b(b'\x03' + bytes.fromhex(pinned['compiledCode']), digest_size=28).hexdigest()
    c.ok('pinned validator bytes hash to the pinned script hash', digest == pinned['hash'], digest)


# ---------------------------------------------------------------- Ethereum

def rpc(method, params):
    reply = get_json(SEPOLIA_RPC, {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    if 'error' in reply:
        raise RuntimeError(reply['error'])
    return reply['result']


def blockscout(path):
    return get_json(BLOCKSCOUT + path)


def check_ethereum_leg(c, state, facts, native):
    terms = state['terms']
    from public_ethereum_token_verify import expected_runtime as token_runtime
    from public_ethereum_verify import expected_runtime as native_runtime
    contract = state['eth_contract'].lower()
    if native:
        runtime = native_runtime(state['hashlock'], terms['eth_claimant'], terms['eth_refundee'], state['eth_expiry'])
    else:
        runtime = token_runtime(0, state['token'], 0, 10, state['hashlock'], terms['eth_claimant'], terms['eth_refundee'], state['eth_expiry'])
    code = rpc('eth_getCode', [contract, 'latest'])
    c.ok('escrow runtime equals the source-pinned runtime for the recorded terms', str(code).lower() == str(runtime).lower())
    spent = int(rpc('eth_call', [{'to': contract, 'data': '0x7ab71b7a'}, 'latest']), 16)
    c.ok('escrow spent() is true now', spent == 1)
    lock = blockscout('/transactions/0x' + state['eth_lock'])
    claim = blockscout('/transactions/0x' + state['eth_claim'])
    c.ok('lock transaction succeeded', lock['status'] == 'ok')
    c.ok('claim transaction succeeded', claim['status'] == 'ok')
    c.ok('lock was sent by the refundee to (or created) the escrow', lock['from']['hash'].lower() == terms['eth_refundee'].lower() and ((lock.get('to') or lock.get('created_contract'))['hash'].lower() == contract))
    c.ok('claim was sent by the claimant to the escrow', claim['from']['hash'].lower() == terms['eth_claimant'].lower() and claim['to']['hash'].lower() == contract)
    arg = claim['decoded_input']['parameters'][0]['value']
    c.ok('SHA-256 of the claim calldata preimage equals the hashlock', sha256(bytes.fromhex(arg[2:])) == state['hashlock'])
    facts['ethereum_preimage_sha256'] = sha256(bytes.fromhex(arg[2:]))
    if native:
        amount = int(state['eth_amount_wei'])
        c.ok('lock sent exactly the recorded wei', int(lock['value']) == amount, lock['value'])
        internal = blockscout('/transactions/0x' + state['eth_claim'] + '/internal-transactions')['items']
        paid = [i for i in internal if i['to']['hash'].lower() == terms['eth_claimant'].lower() and int(i['value']) == amount]
        c.ok('claim paid exactly the recorded wei to the claimant', len(paid) == 1, len(paid))
    else:
        for name, tx_hash, sender, receiver in (('lock', state['eth_lock'], terms['eth_refundee'], contract),
                                                 ('claim', state['eth_claim'], contract, terms['eth_claimant'])):
            items = blockscout('/transactions/0x' + tx_hash + '/token-transfers')['items']
            good = [i for i in items if i['from']['hash'].lower() == sender.lower() and i['to']['hash'].lower() == receiver.lower()
                    and i['total']['value'] == '10' and i['token']['address_hash'].lower() == state['token'].lower()]
            c.ok(f'{name} moved exactly 10 fixture token units from the right sender to the right receiver', len(good) == 1, len(items))
    for name, tx_hash in (('lock', state['eth_lock']), ('claim', state['eth_claim'])):
        receipt = rpc('eth_getTransactionReceipt', ['0x' + tx_hash])
        if receipt is not None:
            c.ok(f'publicnode agrees the {name} succeeded', receipt['status'] == '0x1')
        else:
            # The primary public RPC prunes old history; Blockscout is then the only source for this transaction.
            facts.setdefault('receipts_pruned_on_primary_rpc', []).append(name)
    facts.update({
        'eth_lock_time': int(time.mktime(time.strptime(lock['timestamp'][:19], '%Y-%m-%dT%H:%M:%S'))) - time.timezone,
        'eth_claim_time': int(time.mktime(time.strptime(claim['timestamp'][:19], '%Y-%m-%dT%H:%M:%S'))) - time.timezone,
        'eth_lock_block': lock['block_number'], 'eth_claim_block': claim['block_number'],
    })
    c.ok('claim was mined before the escrow expiry', facts['eth_claim_time'] < state['eth_expiry'],
         f"{facts['eth_claim_time']} < {state['eth_expiry']}")


# ---------------------------------------------------------------- policy and ordering

def btc_height_at(providers, timestamp):
    for base in providers:
        try:
            reply = get_json(f'{base}/v1/mining/blocks/timestamp/{timestamp}')
            return reply['height']
        except Exception:
            continue
    return None


def policy_verdict(state, facts, other_chain, providers):
    """Verdict of the current policy for the pair at the moment its second leg was confirmed."""
    config = timelock_policy.load_timing()
    lock_times = {'bitcoin': facts['fund_time']}
    if other_chain == 'cardano':
        lock_times['cardano'] = facts['ada_lock_time']
        other_expiry = state['ada_expiry_ms'] // 1000
    else:
        lock_times['ethereum'] = facts['eth_lock_time']
        other_expiry = state['eth_expiry']
    when = max(lock_times.values())
    height = max(facts['fund_height'], btc_height_at(providers, when) or facts['fund_height'])
    heads = {
        'bitcoin': {'height': height, 'observedAt': when},
        other_chain: {'timestamp': when, 'observedAt': when},
    }
    legs = {'bitcoin': {'chain': 'bitcoin', 'expiry': state['btc_refund_height']}, other_chain: {'chain': other_chain, 'expiry': other_expiry}}
    verdict = timelock_policy.check_pair(config, legs['bitcoin'], legs[other_chain], {'a': heads['bitcoin'], 'b': heads[other_chain]}, when)
    return {
        'decision_time': when, 'bitcoin_head_height': height, 'long_leg': 'bitcoin' if verdict['long'] == 'a' else other_chain,
        'ok': verdict['ok'], 'reasons': [r['code'] for r in verdict['reasons']], 'metrics': verdict['metrics'],
        'bitcoin_blocks_to_refund_height': state['btc_refund_height'] - height,
    }


def order_report(state, facts, other_chain):
    if other_chain == 'cardano':
        other_claim, other_expiry = facts['ada_claim_time'], state['ada_expiry_ms'] // 1000
    else:
        other_claim, other_expiry = facts['eth_claim_time'], state['eth_expiry']
    return {
        'first_claim_chain': other_chain if other_claim <= facts['spend_time'] else 'bitcoin',
        'other_claim_before_bitcoin_claim': other_claim <= facts['spend_time'],
        'other_claim_seconds_before_its_expiry': other_expiry - other_claim,
        'bitcoin_claim_height_blocks_before_refund_height': state['btc_refund_height'] - facts['spend_height'],
        'bitcoin_claim_after_other_leg_expiry': facts['spend_time'] > other_expiry,
    }


def run_pair(journals, name, other, kind='claim', native=False):
    state = load_state(journals, name)
    name = state.get('scenario', name)
    providers = btc_providers_agree()
    c = Check(name)
    c.ok('scenario state records phase complete', state.get('phase') == 'complete')
    c.ok('at least one genuine testnet4 Bitcoin provider answered', len(providers) >= 1, len(providers))
    if not providers:
        return {'scenario': name, 'passed': False, 'checks': c.items}
    facts = check_bitcoin_leg(c, state, state['btc_claim'], 'claim', providers)
    if other == 'cardano':
        check_cardano_leg(c, state, facts)
    else:
        check_ethereum_leg(c, state, facts, native)
    c.ok('both legs revealed the same preimage hash',
         len({facts.get('claim_preimage_sha256'), facts.get('cardano_preimage_sha256', facts.get('claim_preimage_sha256')),
              facts.get('ethereum_preimage_sha256', facts.get('claim_preimage_sha256'))}) == 1)
    result = {
        'scenario': name, 'passed': c.passed, 'checks': c.items, 'facts': facts,
        'order': order_report(state, facts, other), 'policy_at_second_confirmation': policy_verdict(state, facts, other, providers),
        'ids': {k: state[k] for k in ('btc_lock', 'btc_claim', 'hashlock', 'btc_refund_height') if k in state},
    }
    for key in ('ada_lock', 'ada_claim', 'eth_lock', 'eth_claim', 'eth_contract', 'ada_expiry_ms', 'eth_expiry', 'token'):
        if key in state:
            result['ids'][key] = state[key]
    return result


def run_refund(journals):
    state = load_state(journals, 'bitcoin-refund')
    providers = btc_providers_agree()
    c = Check('bitcoin-refund')
    c.ok('scenario state records phase complete', state.get('phase') == 'complete')
    c.ok('at least one genuine testnet4 Bitcoin provider answered', len(providers) >= 1, len(providers))
    if not providers:
        return {'scenario': 'bitcoin-refund', 'passed': False, 'checks': c.items}
    facts = check_bitcoin_leg(c, state, state['refund'], 'refund', providers)
    outspend = get_json(f"{providers[0]}/tx/{state['btc_lock']}/outspend/0")
    c.ok('escrow output 0 is spent by the recorded refund', outspend.get('spent') is True and outspend.get('txid') == state['refund'])
    config = timelock_policy.load_timing()
    return {
        'scenario': 'bitcoin-refund', 'passed': c.passed, 'checks': c.items, 'facts': facts,
        'ids': {'btc_lock': state['btc_lock'], 'refund': state['refund'], 'btc_refund_height': state['btc_refund_height'], 'hashlock': state['hashlock']},
        'refund_margin_blocks_from_funding_height': state['btc_refund_height'] - facts['fund_height'],
        'policy_minimum_blocks_to_expiry': timelock_policy.leg_requirements(config, 'bitcoin').get('minBlocksToExpiry'),
    }



def _utc(stamp):
    return int(time.mktime(time.strptime(stamp[:19], '%Y-%m-%dT%H:%M:%S'))) - time.timezone


def run_sepolia_fixture(journals, name):
    """A native Sepolia verification fixture: deployed with the right runtime, funded, refunded after expiry."""
    from public_ethereum_verify import expected_runtime as native_runtime
    state = load_state(journals, name)
    c = Check(name)
    c.ok('scenario state records phase complete', state.get('phase') == 'complete')
    contract = state['contract'].lower()
    runtime = native_runtime(state['hashlock'], state['claimant'], state['refundee'], state['expiry'])
    c.ok('escrow runtime equals the source-pinned runtime for the recorded terms', str(rpc('eth_getCode', [contract, 'latest'])).lower() == str(runtime).lower())
    c.ok('escrow spent() is true now', int(rpc('eth_call', [{'to': contract, 'data': '0x7ab71b7a'}, 'latest']), 16) == 1)
    c.ok('escrow balance is zero now', int(rpc('eth_getBalance', [contract, 'latest']), 16) == 0)
    lock = blockscout('/transactions/0x' + state['lock'])
    refund = blockscout('/transactions/0x' + state['refund'])
    c.ok('funding succeeded, was sent by the refundee and carried the recorded wei',
         lock['status'] == 'ok' and lock['from']['hash'].lower() == state['refundee'].lower() and int(lock['value']) == int(state['amount']))
    created = (lock.get('created_contract') or lock.get('to') or {}).get('hash', '').lower()
    c.ok('funding created or paid the recorded escrow', created == contract, created)
    c.ok('refund succeeded and called refund() on the escrow', refund['status'] == 'ok' and refund['to']['hash'].lower() == contract and refund.get('method') == 'refund', refund.get('method'))
    c.ok('refund was mined after the expiry', _utc(refund['timestamp']) >= state['expiry'], f"{_utc(refund['timestamp'])} >= {state['expiry']}")
    internal = blockscout('/transactions/0x' + state['refund'] + '/internal-transactions')['items']
    c.ok('refund returned exactly the recorded wei to the refundee',
         len([i for i in internal if i['to']['hash'].lower() == state['refundee'].lower() and int(i['value']) == int(state['amount'])]) == 1)
    return {'scenario': name, 'passed': c.passed, 'checks': c.items,
            'ids': {'lock': state['lock'], 'refund': state['refund'], 'contract': state['contract'], 'expiry': state['expiry']},
            'facts': {'refund_block': refund['block_number'], 'refund_time': _utc(refund['timestamp']), 'lock_block': lock['block_number']}}


def outspend_checks(results, journals, providers):
    """Every escrow output named by a scenario is spent by exactly the recorded transaction."""
    out = []
    for result in results:
        ids = result.get('ids', {})
        if 'btc_lock' in ids and 'btc_claim' in ids:
            spend = get_json(f"{providers[0]}/tx/{ids['btc_lock']}/outspend/0")
            out.append({'scenario': result['scenario'], 'ok': spend.get('spent') is True and spend.get('txid') == ids['btc_claim']})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--journals', required=True, type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    results = [
        run_pair(args.journals, 'btc-cardano', 'cardano'),
        run_pair(args.journals, 'btc-cardano-token', 'cardano'),
        run_pair(args.journals, 'btc-erc20', 'ethereum'),
    ]
    eth_state = args.journals / 'btc-eth-state.json'
    if eth_state.exists():
        results.append(run_pair(args.journals, 'btc-eth-state.json', 'ethereum', native=True))
    results.append(run_refund(args.journals))
    fixtures = [run_sepolia_fixture(args.journals, 'sepolia-ui-fixture'), run_sepolia_fixture(args.journals, 'sepolia-ui-action-fixture')]
    for fixture in fixtures:
        fixture['scenario'] = fixture['scenario'] + ' (' + fixture['ids']['contract'][:10] + ')'
    results.extend(fixtures)
    providers = btc_providers_agree()
    report = {
        'verified_at': int(time.time()), 'bitcoin_providers': providers,
        'outspends': outspend_checks(results, args.journals, providers) if providers else [],
        'results': results, 'all_passed': all(r['passed'] for r in results),
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + '\n')
    for r in results:
        failed = [i for i in r['checks'] if not i['ok']]
        print(f"{r['scenario']}: {'PASS' if r['passed'] else 'FAIL'} ({len(r['checks'])} checks)")
        for item in failed:
            print('   FAILED:', item['check'], item['detail'])
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
