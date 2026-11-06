"""Bitcoin HTLC adapter: wsh(or_i(and_v(v:sha256(h),pk(claimant)),and_v(v:after(height),pk(refundee)))).

An escrow reference is {'txid', 'vout': 0}. Terms carry the claimant and refundee as compressed
public keys (hex) and `expiry` as the refund block height. The adapter builds and signs with
public_bitcoin_transactions (shared with the public driver) and applies the same guards the driver
does: canonical block check, exact output script and amount, and an unspent output.

A `profile` supplies the Esplora-style reads and the broadcast. `Testnet4Profile` wraps the existing
public helpers; a regtest profile (adapters/local_bitcoin.py) talks to bitcoind. A spend that sits in
the mempool is visible through `outspend` with spend_confirmations 0, and its witness reveals the
preimage; the engine checks the preimage against the hashlock before using it.
"""
import hashlib
import re
import time

from embit import ec, networks, script

try:
    from swap_engine.adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure
except ImportError:
    from adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure

HEX64 = re.compile('[0-9a-f]{64}')
SPEND_VBYTES = 250


class Testnet4Profile:
    name = 'bitcoin'
    journal_chain = 'bitcoin-testnet4'
    network = 'test'

    def __init__(self):
        import json
        import public_bitcoin_driver as driver
        import public_testnet_probe as probe
        import public_testnet_submit as submit
        import public_testnet_utxos as utxos
        self._json, self._driver, self._probe, self._submit, self._utxos = json, driver, probe, submit, utxos
        self.api = probe.BITCOIN

    def now(self):
        return int(time.time())

    def verify_network(self):
        self._submit.verify_network('bitcoin-testnet4')

    def load_key(self, path):
        return self._driver.load_test_key(path)

    def tip_height(self):
        return int(self._probe.request(self.api + '/blocks/tip/height'))

    def block_hash(self, height):
        return self._probe.request(self.api + '/block-height/' + str(height)).decode().strip()

    def tx(self, txid):
        import urllib.error
        try:
            return self._json.loads(self._probe.request(self.api + '/tx/' + txid))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def outspend(self, txid, vout):
        return self._json.loads(self._probe.request(self.api + '/tx/' + txid + '/outspend/' + str(vout)))

    def utxos(self, address):
        return self._utxos.bitcoin_utxos(address)

    def fee(self):
        return self._driver._fee()

    def submit(self, journal, raw):
        return self._submit.submit(journal, 'bitcoin-testnet4', raw)


class BitcoinAdapter(JournaledWrites, ChainAdapter):
    chain = 'bitcoin'

    def __init__(self, profile, key_file):
        self.profile = profile
        self.journal_chain = profile.journal_chain
        self._key_file = key_file
        key = profile.load_key(key_file)
        self._public = key.get_public_key().sec().hex()
        del key

    def _key(self):
        return self.profile.load_key(self._key_file)

    @staticmethod
    def _contract(leg):
        from public_bitcoin_transactions import contract
        return contract(leg['hashlock'], leg['claimant'], leg['refundee'], leg['expiry'])

    def _read(self, call, *args):
        try:
            return call(*args)
        except Exception as error:
            raise read_failure(error) from error

    def identity(self):
        return self._public

    def head(self):
        return {'observedAt': self.profile.now(), 'height': self._read(self.profile.tip_height)}

    def escrow_ref(self, leg, txid):
        if not isinstance(txid, str) or not HEX64.fullmatch(txid):
            raise ValueError('Invalid Bitcoin transaction id')
        return {'txid': txid, 'vout': 0}

    def transaction_seen(self, txid):
        return self._read(self.profile.tx, txid) is not None

    def _status(self, tx, tip):
        status = tx.get('status', {})
        if status.get('confirmed') is not True:
            return 0
        height, block = status.get('block_height'), status.get('block_hash')
        if type(height) is not int or not isinstance(block, str):
            raise ValueError('Invalid Bitcoin transaction status')
        if self.profile.block_hash(height) != block:
            return 0
        return tip - height + 1

    def inspect(self, leg, escrow):
        observation = empty_observation()
        txid, vout = escrow['txid'], escrow['vout']
        if not HEX64.fullmatch(txid) or type(vout) is not int:
            raise ValueError('Invalid Bitcoin escrow reference')
        try:
            tx = self._read(self.profile.tx, txid)
            if tx is None:
                return observation
            tip = self._read(self.profile.tip_height)
            depth = self._read(self._status, tx, tip)
            _, output = self._contract(leg)
            outputs = tx.get('vout')
            if tx.get('txid') != txid or not isinstance(outputs, list):
                raise ValueError('Bitcoin transaction mismatch')
            observation['found'] = True
            observation['confirmations'] = depth
            if vout >= len(outputs):
                observation['problem'] = 'the escrow output does not exist'
                return observation
            mismatch = []
            if outputs[vout].get('scriptpubkey') != output.data.hex():
                mismatch.append('script')
            if outputs[vout].get('value') != leg['amount']:
                mismatch.append('amount')
            if mismatch:
                observation['problem'] = 'escrow differs from the terms in ' + ', '.join(mismatch)
                return observation
            observation['verified'] = True
            spend = self._read(self.profile.outspend, txid, vout)
            if spend.get('spent') is not True:
                return observation
            spender = spend.get('txid')
            if not isinstance(spender, str) or not HEX64.fullmatch(spender):
                raise ValueError('Invalid Bitcoin spend record')
            spending = self._read(self.profile.tx, spender)
            if spending is None:
                raise ChainUnavailable('the spending transaction is not visible yet')
            observation['spend_txid'] = spender
            observation['spend_confirmations'] = self._read(self._status, spending, tip)
            found = []
            for entry in spending.get('vin', []):
                if entry.get('txid') == txid and entry.get('vout') == vout:
                    for item in entry.get('witness', []):
                        if isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item) and hashlib.sha256(bytes.fromhex(item)).hexdigest() == leg['hashlock']:
                            found.append(item)
            if len(found) > 1:
                raise ValueError('more than one candidate preimage in the spend')
            observation['spent'] = 'claimed' if found else 'refunded'
            observation['preimage'] = found[0] if found else None
            return observation
        except (KeyError, TypeError, ValueError) as error:
            raise read_failure(error) from error

    # ---- writes
    def _address(self, key):
        return script.p2wpkh(key.get_public_key()).address(networks.NETWORKS[self.profile.network])

    def _fee(self):
        return self._read(self.profile.fee)

    def fund(self, leg, journal):
        from public_bitcoin_transactions import funding
        if leg['refundee'] != self._public:
            raise ActionRefused('the wallet is not the refundee of this leg')
        _, output = self._contract(leg)
        tip = self._read(self.profile.tip_height)
        if leg['expiry'] <= tip:
            raise ActionRefused('the refund height has already passed')
        fee = self._fee()
        amount = leg['amount']
        if amount - fee < 546:
            raise ActionRefused('the escrow would be dust after the spend fee')
        key = self._key()
        coins = self._read(self.profile.utxos, self._address(key))
        eligible = [x for x in coins if x['amount_sats'] >= amount + fee and (x['amount_sats'] == amount + fee or x['amount_sats'] >= amount + fee + 546)]
        if not eligible:
            raise ActionRefused('no confirmed Bitcoin output can fund this escrow')
        coin = min(eligible, key=lambda x: x['amount_sats'])
        try:
            tx = funding(coin['txid'], coin['vout'], coin['amount_sats'], key, output, amount, fee)
        except ValueError as error:
            raise ActionRefused(str(error)[:300]) from error
        result = self._journaled(journal, lambda: self.profile.submit(journal, tx.serialize()))
        return {'txid': result['txid']}

    def _spend(self, leg, escrow, journal, preimage):
        from public_bitcoin_transactions import spend
        role = 'claimant' if preimage is not None else 'refundee'
        if leg[role] != self._public:
            raise ActionRefused(f'the wallet is not the {role} of this leg')
        tip = self._read(self.profile.tip_height)
        if preimage is None and tip < leg['expiry']:
            raise ActionRefused('the refund is not yet due on chain')
        if preimage is not None and tip >= leg['expiry']:
            raise ActionRefused('the escrow is already refundable; refusing to claim')
        observation = self.inspect(leg, escrow)
        if not observation['verified'] or observation['spent'] is not None:
            raise ActionRefused('the escrow is not a verified unspent output')
        witness, _ = self._contract(leg)
        fee = self._fee()
        key = self._key()
        destination = script.p2wpkh(key.get_public_key())
        try:
            signed = spend(escrow['txid'], escrow['vout'], leg['amount'], key, witness, destination, fee, hashlock=leg['hashlock'],
                           claimant=leg['claimant'], refund=leg['refundee'], contract_refund_height=leg['expiry'], preimage=preimage)
        except ValueError as error:
            raise ActionRefused(str(error)[:300]) from error
        result = self._journaled(journal, lambda: self.profile.submit(journal, signed.serialize()))
        return {'txid': result['txid']}

    def claim(self, leg, escrow, preimage, journal):
        return self._spend(leg, escrow, journal, bytes(preimage))

    def refund(self, leg, escrow, journal):
        return self._spend(leg, escrow, journal, None)
