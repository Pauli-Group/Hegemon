"""Drive the hosted page's real Cardano transaction code against the private local cluster.

The page's builder, checker and wallet flow (swap-ui/cardano-wallet.mjs) run in Node through
swap-service/tools/cardano-bridge.mjs with a software CIP-30 wallet. This harness supplies chain data from
the cluster, submits what the page produced through cardano-cli, and lets a test confirm the real ledger
and the real Plutus validator accept it. Also measures script execution units for the fixed budget.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from fractions import Fraction
from pathlib import Path

try:
    from swap_engine.adapters.local_cardano import LocalCardanoProfile
except ImportError:  # pragma: no cover
    from adapters.local_cardano import LocalCardanoProfile

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / 'swap-service' / 'tools' / 'cardano-bridge.mjs'
SCRIPT = json.loads((ROOT / 'swap-ui' / 'cardano-htlc-script.json').read_text())


def node_binary():
    return os.environ.get('NODE') or shutil.which('node')


def ratio(value):
    fraction = Fraction(str(value))
    return [str(fraction.numerator), str(fraction.denominator)]


class Harness:
    def __init__(self):
        # The node socket path must stay under 100 bytes, so the cluster lives under /tmp.
        self.work = Path(tempfile.mkdtemp(prefix='hcb-', dir='/tmp'))
        self.profile = LocalCardanoProfile(self.work)
        self.profile.watch_script(SCRIPT['address'])
        self.profile.prepare_wallets(count=4, lovelace=100_000_000)
        self.params_overrides = {'validitySlots': 20, 'claimMarginSlots': 4}
        self.serial = 0

    def close(self):
        self.profile.close()
        shutil.rmtree(self.work, ignore_errors=True)

    # ------------------------------------------------------------------ chain data
    def params(self):
        pp = self.profile.protocol_parameters()
        models = pp['costModels']['PlutusV3']
        if isinstance(models, dict):
            models = list(models.values())
        prices = pp['executionUnitPrices']
        return {
            'minFeeA': pp['txFeePerByte'], 'minFeeB': pp['txFeeFixed'], 'coinsPerUtxoByte': pp['utxoCostPerByte'], 'maxTxSize': pp['maxTxSize'],
            'priceMem': ratio(prices['priceMemory']), 'priceStep': ratio(prices['priceSteps']), 'collateralPercent': pp['collateralPercentage'],
            'maxCollateralInputs': pp['maxCollateralInputs'], 'maxTxExMem': pp['maxTxExecutionUnits']['memory'], 'maxTxExSteps': pp['maxTxExecutionUnits']['steps'],
            'costModelV3': models, 'systemStart': self.profile.system_start, 'slot': self.profile.tip_slot(), **self.params_overrides,
        }

    def wallet_utxos(self, name):
        actor = self.profile.actors[name]
        return [{'ref': u['outref'], 'address': actor['address'], 'lovelace': u['lovelace'], 'assets': u['assets']} for u in self.profile.utxos(actor['address'])]

    def tip_unix(self):
        return self.profile.system_start + self.profile.tip_slot()

    # ------------------------------------------------------------------ the page's flow
    def run_page(self, op, name, terms, preimage=None, budget=None, collateral=None, extra=None, now_seconds=None):
        actor = self.profile.actors[name]
        utxos = self.wallet_utxos(name)
        request = {
            'op': op, 'terms': terms, 'preimage': preimage, 'budget': budget or {'memory': SCRIPT['executionUnits']['memory'], 'steps': SCRIPT['executionUnits']['steps']},
            'params': self.params(), 'utxos': utxos, 'collateral': collateral or [], 'changeAddress': actor['address'], 'signingKeyFile': str(actor['skey']),
            'nowSeconds': now_seconds or self.tip_unix(), **(extra or {}),
        }
        result = subprocess.run([node_binary(), str(BRIDGE)], input=json.dumps(request), capture_output=True, text=True, timeout=120)
        try:
            out = json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            raise RuntimeError('bridge failed: ' + result.stderr[-1500:] + result.stdout[-500:])
        if 'error' in out:
            raise PageRefused(out['error'], out.get('code'))
        return out

    # ------------------------------------------------------------------ submission
    def submit_hex(self, tx_hex, wait=True):
        self.serial += 1
        path = self.work / f'page-{self.serial}.signed'
        path.write_text(json.dumps({'type': 'Tx ConwayEra', 'description': '', 'cborHex': tx_hex}))
        txid = self.profile._run('transaction', 'txid', '--tx-file', path, '--output-text').strip()
        import cbor2
        body = cbor2.loads(bytes.fromhex(tx_hex))[0]
        self.profile.sent[txid] = {'inputs': [f'{bytes(i[0]).hex()}#{i[1]}' for i in body[0]], 'cbor': tx_hex, 'outputs': [f'{txid}#{i}' for i in range(len(body[1]))]}
        self.profile._run('transaction', 'submit', '--tx-file', path, *self.profile.testnet_args, '--socket-path', self.profile.socket)
        if wait:
            self.wait_confirmed(txid)
        return txid

    def wait_confirmed(self, txid, depth=2, seconds=90):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.profile.confirmations(txid) >= depth:
                return
            time.sleep(0.5)
        raise RuntimeError('transaction not confirmed: ' + txid)

    def script_cost(self, tx_hex):
        """Ask the node to evaluate the script in a transaction. Returns {'memory': .., 'steps': ..}."""
        path = self.work / 'cost.signed'
        path.write_text(json.dumps({'type': 'Tx ConwayEra', 'description': '', 'cborHex': tx_hex}))
        rows = json.loads(self.profile._run('transaction', 'calculate-plutus-script-cost', 'online', '--tx-file', path, *self.profile.testnet_args,
                                            '--socket-path', self.profile.socket))
        row = rows[0]
        units = row.get('executionUnits') or row
        return {'memory': units['memory'], 'steps': units['steps'], 'raw': row}

    # ------------------------------------------------------------------ native assets
    def mint(self, name, asset_hex, quantity):
        """Mint `quantity` of a token to `name`, under a single-signature policy of that actor. Returns 'policy.asset'."""
        actor = self.profile.actors[name]
        policy_file = self.work / f'policy-{name}.script'
        policy_file.write_text(json.dumps({'type': 'sig', 'keyHash': actor['keyhash']}))
        policy = self.profile._run('transaction', 'policyid', '--script-file', policy_file).strip()
        available = self.profile._query('utxo', '--address', actor['address'])
        key = max(available, key=lambda k: available[k]['value'].get('lovelace', 0))
        token = f'{policy}.{asset_hex}'
        self.serial += 1
        body, signed = self.work / f'mint-{self.serial}.body', self.work / f'mint-{self.serial}.signed'
        self.profile._run('transaction', 'build', *self.profile.testnet_args, '--socket-path', self.profile.socket, '--tx-in', key,
                          '--tx-out', f"{actor['address']}+2000000+{quantity} {token}", '--mint', f'{quantity} {token}', '--mint-script-file', policy_file,
                          '--change-address', actor['address'], '--out-file', body)
        self.profile._run('transaction', 'sign', '--tx-body-file', body, '--signing-key-file', actor['skey'], *self.profile.testnet_args, '--out-file', signed)
        txid = self.profile._run('transaction', 'txid', '--tx-file', signed, '--output-text').strip()
        self.profile._run('transaction', 'submit', '--tx-file', signed, *self.profile.testnet_args, '--socket-path', self.profile.socket)
        self.wait_confirmed(txid)
        return token

    def balance(self, name):
        total, assets = 0, {}
        for u in self.wallet_utxos(name):
            total += u['lovelace']
            for k, v in u['assets'].items():
                assets[k] = assets.get(k, 0) + v
        return total, assets

    # ------------------------------------------------------------------ terms
    def terms(self, funder='alice', claimant='bob', preimage=None, seconds=25, lovelace=10_000_000, assets=''):
        preimage = preimage or hashlib.sha256(os.urandom(32)).hexdigest()
        expiry = self.tip_unix() + seconds
        return {'hashlock': hashlib.sha256(bytes.fromhex(preimage)).hexdigest(), 'claimant': self.profile.actors[claimant]['keyhash'],
                'refundee': self.profile.actors[funder]['keyhash'], 'expiry_ms': str(expiry * 1000), 'lovelace': str(lovelace), 'assets': assets}, preimage

    def escrow_utxo(self, txid):
        for u in self.profile.utxos(SCRIPT['address']):
            if u['outref'].startswith(txid + '#'):
                return u
        return None


class PageRefused(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code
