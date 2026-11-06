"""Cardano (preview or a local cluster) HTLC adapter over contracts/cardano/validators/htlc.ak.

An escrow reference is {'txid': <lock transaction id>, 'vout': 0}: the lock transaction's first
output pays the script address with an inline datum (hashlock, claimant key hash, refundee key
hash, expiry in milliseconds). Terms carry `expiry` in whole seconds since the Unix epoch, which
the datum multiplies by 1000; the chain slot is `expiry - SYSTEM_START` on preview.

A `profile` supplies the network (reads, protocol parameters, signed submission). `PreviewProfile`
wraps the tested public drivers and Koios; scripts/swap_engine/adapters/local_cardano.py supplies a
local-cluster profile. Everything else here is shared. Fee and collateral inputs must be ADA-only,
because build_balanced preserves tokens only through the change output.
"""
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

try:
    from swap_engine.adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure
    from swap_engine.store import _write_new
    from swap_engine.tools import tool
except ImportError:
    from adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure
    from store import _write_new
    from tools import tool

ROOT = Path(__file__).resolve().parents[3]
SYSTEM_START = 1666656000
HEX64 = re.compile('[0-9a-f]{64}')
EXECUTION_UNITS = (10_000_000, 10_000_000_000)
MIN_FEE_INPUT = 5_000_000
CONFIRMATIONS_FOR_INPUTS = 2


class PreviewProfile:
    """Public preview through the existing drivers and the Koios indexer."""

    name = 'cardano'
    journal_chain = 'cardano-preview'
    system_start = SYSTEM_START
    testnet_args = ['--testnet-magic', '2']
    # A Plutus transaction's upper bound must lie inside the ledger's time horizon (3k/f slots past the tip, about 7 h on
    # preview). A claim for an escrow that expires later than that is bounded one hour ahead instead; the validator only
    # requires the interval to end before the expiry.
    validity_slots = 3600

    def __init__(self):
        import public_cardano_driver as driver
        import public_testnet_probe as probe
        import public_testnet_submit as submit
        import public_testnet_utxos as utxos
        self._driver, self._probe, self._submit, self._utxos = driver, probe, submit, utxos
        self.koios = probe.CARDANO

    def _post(self, path, body):
        return json.loads(self._probe.request(self.koios + path, body))

    def now(self):
        return int(time.time())

    def verify_network(self):
        self._submit.verify_network('cardano-preview')

    def tip_slot(self):
        rows = json.loads(self._probe.request(self.koios + '/tip'))
        if len(rows) != 1 or type(rows[0].get('abs_slot')) is not int:
            raise ValueError('Cardano preview tip unavailable')
        return rows[0]['abs_slot']

    def utxos(self, address):
        return self._utxos.cardano_utxos(address)

    def confirmations(self, txid):
        rows = self._post('/tx_status', {'_tx_hashes': [txid]})
        if not rows:
            return 0
        if len(rows) != 1 or rows[0].get('tx_hash') != txid:
            raise ValueError('Cardano transaction status mismatch')
        value = rows[0].get('num_confirmations')
        return 0 if value is None else value

    def utxo_info(self, outref):
        rows = self._post('/utxo_info', {'_utxo_refs': [outref], '_extended': True})
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError('Unexpected utxo_info response')
        return rows[0]

    def spender(self, script_address, outref, created_height):
        """Transaction id that spent `outref`, or None. Scans the script address history."""
        txid = outref.split('#')[0]
        rows = self._post('/address_txs', {'_addresses': [script_address], '_after_block_height': max(0, created_height - 1)})
        candidates = [row['tx_hash'] for row in rows if row.get('tx_hash') != txid]
        if not candidates:
            return None
        for attempt in range(4):
            info = self._post('/tx_info', {'_tx_hashes': candidates, '_inputs': True, '_metadata': False, '_assets': False,
                                           '_withdrawals': False, '_certs': False, '_scripts': False, '_bytecode': False})
            if {item.get('tx_hash') for item in info} == set(candidates):
                break
            # Koios answers with fewer rows than asked while a backend lags; never skip a transaction.
            time.sleep(1 + attempt)
        else:
            raise ValueError('transactions at the script address are not indexed yet')
        for item in info:
            if any(f"{i['tx_hash']}#{i['tx_index']}" == outref for i in item.get('inputs', [])):
                return item['tx_hash']
        return None

    def claim_preimage(self, spend_txid, outref, hashlock):
        """The preimage in the spending transaction, None if it was a refund. Raises while unindexed."""
        from cardano_preimage_observer import claim_preimage
        from public_testnet_observers import IndexerDataPending
        rows = self._post('/tx_cbor', {'_tx_hashes': [spend_txid]})
        if rows == []:
            raise IndexerDataPending('spending transaction bytes are not indexed yet')
        if len(rows) != 1 or rows[0].get('tx_hash') != spend_txid or rows[0].get('valid_contract') is not True:
            raise ValueError('spending transaction invalid')
        return claim_preimage(spend_txid, rows[0].get('cbor'), outref, hashlock)

    def protocol_parameters(self):
        return self._driver.preview_protocol_parameters()

    def submit(self, journal, body, signing_key):
        return self._driver.sign_and_submit(journal, body, signing_key, cli=tool('cardano-cli'))


class CardanoAdapter(JournaledWrites, ChainAdapter):
    chain = 'cardano'

    def __init__(self, profile, wallet):
        """`wallet` = {'skey': path, 'keyhash': 56 hex, 'address': bech32}."""
        self.profile = profile
        self.wallet = {'skey': Path(wallet['skey']), 'keyhash': wallet['keyhash'], 'address': wallet['address']}
        if not re.fullmatch('[0-9a-f]{56}', self.wallet['keyhash']):
            raise ValueError('Invalid Cardano key hash')
        self.journal_chain = profile.journal_chain
        self._validator = None
        self._script_address = None

    # ---- script identity
    def _compile(self):
        if self._validator is None:
            self._validator = subprocess.check_output([str(tool('aiken')), 'blueprint', 'convert', str(ROOT / 'contracts/cardano')], text=True, timeout=60)
            with tempfile.TemporaryDirectory(prefix='ada-script-') as directory:
                path = Path(directory) / 'validator.plutus'
                path.write_text(self._validator)
                self._script_address = subprocess.check_output(
                    [str(tool('cardano-cli')), 'conway', 'address', 'build', '--payment-script-file', str(path), *self.profile.testnet_args],
                    text=True, timeout=60).strip()
        return self._validator, self._script_address

    def script_address(self):
        return self._compile()[1]

    @staticmethod
    def _datum(leg):
        return {'constructor': 0, 'fields': [{'bytes': leg['hashlock']}, {'bytes': leg['claimant']}, {'bytes': leg['refundee']}, {'int': leg['expiry'] * 1000}]}

    def _slot(self, leg):
        slot = leg['expiry'] - self.profile.system_start
        if slot <= 0:
            raise ActionRefused('the expiry is before the chain started')
        return slot

    # ---- reads
    def _read(self, call, *args):
        try:
            return call(*args)
        except Exception as error:
            raise read_failure(error) from error

    def identity(self):
        return self.wallet['keyhash']

    def head(self):
        slot = self._read(self.profile.tip_slot)
        return {'observedAt': self.profile.now(), 'timestamp': self.profile.system_start + slot}

    def escrow_ref(self, leg, txid):
        if not isinstance(txid, str) or not HEX64.fullmatch(txid):
            raise ValueError('Invalid Cardano transaction id')
        return {'txid': txid, 'vout': 0}

    def transaction_seen(self, txid):
        return self._read(self.profile.confirmations, txid) > 0

    def inspect(self, leg, escrow):
        observation = empty_observation()
        outref = f"{escrow['txid']}#{escrow['vout']}"
        if not HEX64.fullmatch(escrow['txid']):
            raise ValueError('Invalid Cardano escrow reference')
        depth = self._read(self.profile.confirmations, escrow['txid'])
        if depth == 0:
            return observation
        row = self._read(self.profile.utxo_info, outref)
        if row is None:
            raise ChainUnavailable('the transaction is confirmed but its outputs are not indexed yet')
        try:
            script_address = self.script_address()
            observation['found'] = True
            observation['confirmations'] = depth
            mismatch = []
            if row.get('address') != script_address:
                mismatch.append('script address')
            if str(row.get('value')) != str(leg['amount']) or row.get('asset_list'):
                mismatch.append('value')
            datum = row.get('inline_datum')
            if not isinstance(datum, dict) or datum.get('value') != self._datum(leg):
                mismatch.append('datum terms')
            if mismatch:
                observation['problem'] = 'escrow differs from the terms in ' + ', '.join(mismatch)
                return observation
            observation['verified'] = True
            if row.get('is_spent') is not True:
                return observation
            spender = self._read(self.profile.spender, script_address, outref, row.get('block_height') or 0)
            if spender is None:
                raise ChainUnavailable('the escrow is spent but the spending transaction is not visible yet')
            secret = self._read(self.profile.claim_preimage, spender, outref, leg['hashlock'])
            observation['spend_txid'] = spender
            observation['spend_confirmations'] = self._read(self.profile.confirmations, spender)
            if secret is None:
                observation['spent'] = 'refunded'
            else:
                observation['spent'] = 'claimed'
                observation['preimage'] = bytes(secret).hex()
                secret[:] = b'\0' * len(secret)
            return observation
        except (KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
            raise read_failure(error) from error

    # ---- writes
    def _inputs(self, count, minimum):
        rows = self._read(self.profile.utxos, self.wallet['address'])
        usable = [x for x in rows if not x['assets'] and x['lovelace'] >= minimum
                  and self._read(self.profile.confirmations, x['outref'].split('#')[0]) >= CONFIRMATIONS_FOR_INPUTS]
        usable.sort(key=lambda x: x['lovelace'])
        if len(usable) < count:
            raise ActionRefused(f'need {count} confirmed ADA-only output(s) of at least {minimum} lovelace')
        return usable[:count]

    def _build_and_submit(self, journal, name, inputs, outputs, extra=None, files=None):
        from public_cardano_transactions import build_balanced
        validator, _ = self._compile()
        with tempfile.TemporaryDirectory(prefix='ada-work-', dir=journal) as directory:
            work = Path(directory)
            params = work / 'params.json'
            _write_new(params, (json.dumps(self.profile.protocol_parameters()) + '\n').encode())
            validator_file = work / 'validator.plutus'
            _write_new(validator_file, validator.encode())
            written = {}
            for key, value in (files or {}).items():
                path = work / key
                _write_new(path, (json.dumps(value) + '\n').encode())
                written[key] = path
            built_inputs, built_outputs = inputs(validator_file, written), outputs(written)
            body = work / (name + '.body')
            build_balanced(inputs=built_inputs, outputs=built_outputs, change_address=self.wallet['address'], params=params, body=body,
                           cli=tool('cardano-cli'), **(extra or {}))
            return self.profile.submit(journal, body, self.wallet['skey'])

    @staticmethod
    def _plain(item):
        return {key: item[key] for key in ('outref', 'lovelace', 'assets')}

    def fund(self, leg, journal):
        if leg['refundee'] != self.wallet['keyhash']:
            raise ActionRefused('the wallet is not the refundee of this leg')
        self._slot(leg)
        coin = self._inputs(1, leg['amount'] + 3_000_000)[0]
        script_address = self.script_address()
        result = self._journaled(journal, lambda: self._build_and_submit(
            journal, 'fund', lambda v, f: [self._plain(coin)],
            lambda f: [{'address': script_address, 'lovelace': leg['amount'], 'assets': {}, 'datum': f['datum.json']}],
            files={'datum.json': self._datum(leg)}))
        return {'txid': result['txid']}

    def _script_spend(self, leg, escrow, journal, name, redeemer, role, window):
        if leg[role] != self.wallet['keyhash']:
            raise ActionRefused(f'the wallet is not the {role} of this leg')
        slot = self._slot(leg)
        tip = self._read(self.profile.tip_slot)
        if window == 'before' and tip + getattr(self.profile, 'claim_margin_slots', 30) >= slot:
            raise ActionRefused('the claim window has closed on chain')
        if window == 'after' and tip < slot:
            raise ActionRefused('the refund is not yet due on chain')
        fee, collateral = self._inputs(2, MIN_FEE_INPUT)
        outref = f"{escrow['txid']}#{escrow['vout']}"
        bound = slot
        reach = getattr(self.profile, 'validity_slots', None)
        if window == 'before' and reach:
            # The ledger can only translate slots within its stability window of the tip. An earlier upper
            # bound than the expiry is always acceptable to the validator, which requires only "not after".
            bound = min(slot, tip + reach)
        extra = {'collateral': collateral['outref'], 'required_signer': self.wallet['keyhash'],
                 ('invalid_hereafter' if window == 'before' else 'invalid_before'): bound}

        def inputs(validator_file, files):
            return [{'outref': outref, 'lovelace': leg['amount'], 'assets': {}, 'script': validator_file, 'redeemer': files['redeemer.json'],
                     'execution_units': EXECUTION_UNITS}, self._plain(fee)]

        result = self._journaled(journal, lambda: self._build_and_submit(
            journal, name, inputs, lambda f: [{'address': self.wallet['address'], 'lovelace': leg['amount'], 'assets': {}}],
            extra=extra, files={'redeemer.json': redeemer}))
        return {'txid': result['txid']}

    def claim(self, leg, escrow, preimage, journal):
        redeemer = {'constructor': 0, 'fields': [{'bytes': bytes(preimage).hex()}]}
        return self._script_spend(leg, escrow, journal, 'claim', redeemer, 'claimant', 'before')

    def refund(self, leg, escrow, journal):
        return self._script_spend(leg, escrow, journal, 'refund', {'constructor': 1, 'fields': []}, 'refundee', 'after')
