"""Drive the hosted page's real Bitcoin PSBT code against a private bitcoind regtest node.

The page's builder, checker and finalizer (swap-ui/bitcoin-psbt.mjs) run in Node through
swap-service/tools/bitcoin-bridge.mjs. The signer here is independent of the page: embit computes its own BIP143
digests and signs with a key file, the way an external PSBT wallet would. bitcoind then applies consensus rules
to what the page finalized.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from embit import ec, script
from embit.psbt import PSBT

try:
    from swap_engine.adapters.local_bitcoin import LocalBitcoinProfile
except ImportError:  # pragma: no cover
    from adapters.local_bitcoin import LocalBitcoinProfile

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / 'swap-service' / 'tools' / 'bitcoin-bridge.mjs'


def node_binary():
    return os.environ.get('NODE') or shutil.which('node')


class BitcoinHarness:
    def __init__(self):
        self.work = Path(tempfile.mkdtemp(prefix='hbb-', dir='/dev/shm'))
        os.chmod(self.work, 0o700)
        self.profile = LocalBitcoinProfile(self.work / 'btc')
        self.wallets = {}

    def close(self):
        self.profile.close()
        shutil.rmtree(self.work, ignore_errors=True)

    def wallet(self, label, sats=2_000_000, coins=3):
        if label not in self.wallets:
            path, address = self.profile.new_key_file(label, sats=sats, coins=coins)
            self.wallets[label] = {'key': ec.PrivateKey(bytes.fromhex(path.read_text().strip())), 'address': address}
        return self.wallets[label]

    def coins(self, label):
        w = self.wallet(label)
        found = self.profile._call('scantxoutset', 'start', [f"addr({w['address']})"])
        return [{'txid': u['txid'], 'vout': u['vout'], 'amount': str(round(u['amount'] * 100_000_000)), 'address': w['address']} for u in found['unspents']]

    def tip(self):
        return self.profile.tip_height()

    def page(self, action, op, terms, address, **extra):
        request = {'action': action, 'op': op, 'terms': terms, 'address': address, 'network': 'regtest', **extra}
        result = subprocess.run([node_binary(), str(BRIDGE)], input=json.dumps(request), capture_output=True, text=True, timeout=60)
        try:
            out = json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            raise RuntimeError('bridge failed: ' + result.stderr[-1500:])
        if 'error' in out:
            raise PageRefused(out['error'])
        return out

    # ---- an independent signer, as an external PSBT wallet would be
    @staticmethod
    def sign_fund(psbt_b64, key):
        psbt = PSBT.parse(base64.b64decode(psbt_b64))
        pub = key.get_public_key()
        for index, item in enumerate(psbt.inputs):
            amount = item.witness_utxo.value
            digest = psbt.tx.sighash_segwit(index, script.p2pkh(pub), amount)
            item.partial_sigs[pub] = key.sign(digest).serialize() + b'\x01'
        return base64.b64encode(psbt.serialize()).decode()

    @staticmethod
    def sign_spend(psbt_b64, key, flag=b'\x01'):
        psbt = PSBT.parse(base64.b64decode(psbt_b64))
        item = psbt.inputs[0]
        digest = psbt.tx.sighash_segwit(0, item.witness_script, item.witness_utxo.value)
        item.partial_sigs[key.get_public_key()] = key.sign(digest).serialize() + flag
        return base64.b64encode(psbt.serialize()).decode()

    # ---- consensus
    def accept(self, tx_hex):
        verdict = self.profile._call('testmempoolaccept', [tx_hex])[0]
        if not verdict['allowed']:
            raise RuntimeError('bitcoind rejected the transaction: ' + verdict.get('reject-reason', '?'))
        txid = self.profile._call('sendrawtransaction', tx_hex)
        self.profile.mine(1)
        return txid

    def reject_reason(self, tx_hex):
        verdict = self.profile._call('testmempoolaccept', [tx_hex])[0]
        return None if verdict['allowed'] else verdict.get('reject-reason', '?')

    def terms(self, claimant, refunder, preimage=None, blocks=20, amount=60_000):
        preimage = preimage or os.urandom(32).hex()
        return {'hashlock': hashlib.sha256(bytes.fromhex(preimage)).hexdigest(), 'claimant_key': claimant['key'].get_public_key().sec().hex(),
                'refund_key': refunder['key'].get_public_key().sec().hex(), 'refund_height': self.tip() + blocks, 'amount_sats': amount}, preimage

    def fund(self, label, terms, fee_rate=2):
        w = self.wallet(label)
        built = self.page('build', 'fund', terms, w['address'], inputs=self.coins(label), feeRate=fee_rate)
        signed = self.sign_fund(built['psbt'], w['key'])
        done = self.page('finalize', 'fund', terms, w['address'], inputs=self.coins(label), feeRate=fee_rate, signedPsbt=signed)
        txid = self.accept(done['txHex'])
        assert txid == done['txid'] == built['txid']
        raw = self.profile._call('getrawtransaction', txid, True)
        vout = next(i for i, o in enumerate(raw['vout']) if o['scriptPubKey']['hex'].startswith('0020') and round(o['value'] * 100_000_000) == terms['amount_sats'])
        return {'txid': txid, 'vout': vout, 'amount': str(terms['amount_sats'])}


class PageRefused(Exception):
    pass
