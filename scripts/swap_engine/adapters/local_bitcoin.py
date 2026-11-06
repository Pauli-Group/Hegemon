"""A private bitcoind regtest node and the BitcoinAdapter profile that reads and writes it.

bitcoind answers the questions the adapter asks an Esplora service: transaction status and witness,
whether an output is spent and by whom, confirmed UTxOs of an address. Transactions are built, signed
and journaled by the same code as on testnet4 and only the final broadcast differs. Blocks are mined
by `mine()`; the world runner calls it on a timer so depth and expiry behave like a real chain.
"""
import json
import os
import subprocess
import time
import urllib.request
import base64
from pathlib import Path

try:
    from swap_engine.tools import tool
except ImportError:
    from tools import tool

COIN = 100_000_000


def _port():
    import socket
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class LocalBitcoinProfile:
    name = 'bitcoin'
    journal_chain = 'bitcoin-testnet4'  # selects the transaction-id rule in the shared journal code
    network = 'regtest'

    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, exist_ok=True)
        data = self.dir / 'data'
        data.mkdir(mode=0o700, exist_ok=True)
        self.port = _port()
        self.log = (self.dir / 'bitcoind.log').open('wb')
        self.proc = subprocess.Popen(
            [str(tool('bitcoind')), '-regtest', f'-datadir={data}', '-server=1', f'-rpcport={self.port}', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
             '-txindex=1', '-fallbackfee=0.0002', '-listen=0', '-dnsseed=0', '-discover=0', '-printtoconsole=0', f'-port={_port()}'],
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        self.cookie = data / 'regtest' / '.cookie'
        try:
            end = time.monotonic() + 60
            while True:
                try:
                    if self._call('getblockcount') is not None:
                        break
                except (OSError, ValueError, KeyError):
                    pass
                if time.monotonic() > end:
                    raise RuntimeError('bitcoind did not start')
                time.sleep(0.3)
            self._call('createwallet', 'miner')
            self.miner = self._call('getnewaddress', wallet='miner')
            self.mine(101)
        except BaseException:
            self.close()
            raise

    def close(self):
        import signal
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=30)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.log.close()

    def _call(self, method, *params, wallet=None, allow=()):
        user, password = self.cookie.read_text().strip().split(':', 1)
        url = f'http://127.0.0.1:{self.port}/' + (f'wallet/{wallet}' if wallet else '')
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        request = urllib.request.Request(url, data=body, headers={'Authorization': 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode(), 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                answer = json.loads(response.read())
        except urllib.error.HTTPError as error:
            answer = json.loads(error.read())
        if answer.get('error'):
            if answer['error'].get('code') in allow:
                return None
            raise ValueError(f"bitcoind {method}: {answer['error']}")
        return answer['result']

    def mine(self, count=1):
        return self._call('generatetoaddress', count, self.miner)

    def now(self):
        return int(time.time())

    def new_key_file(self, name, sats=1_000_000, coins=3):
        """A funded 0600 hex key file; returns (path, address)."""
        from embit import ec, networks, script
        key = ec.PrivateKey(os.urandom(32))
        path = self.dir / (name + '.key')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(path, flags, 0o600), 'w') as handle:
            handle.write(key.secret.hex() + '\n')
        address = script.p2wpkh(key.get_public_key()).address(networks.NETWORKS['regtest'])
        for _ in range(coins):
            self._call('sendtoaddress', address, sats / COIN, wallet='miner')
        self.mine(3)
        return path, address

    # ---- the profile surface (Esplora-shaped)
    def load_key(self, path):
        import public_bitcoin_driver
        return public_bitcoin_driver.load_test_key(path)

    def tip_height(self):
        return self._call('getblockcount')

    def block_hash(self, height):
        return self._call('getblockhash', height)

    def _shape(self, raw):
        status = {'confirmed': False}
        if raw.get('blockhash'):
            header = self._call('getblockheader', raw['blockhash'])
            status = {'confirmed': True, 'block_height': header['height'], 'block_hash': raw['blockhash']}
        return {'txid': raw['txid'], 'status': status,
                'vin': [{'txid': i.get('txid'), 'vout': i.get('vout'), 'witness': i.get('txinwitness', [])} for i in raw['vin']],
                'vout': [{'value': round(o['value'] * COIN), 'scriptpubkey': o['scriptPubKey']['hex']} for o in raw['vout']]}

    def tx(self, txid):
        raw = self._call('getrawtransaction', txid, True, allow=(-5,))
        return None if raw is None else self._shape(raw)

    def outspend(self, txid, vout):
        if self._call('gettxout', txid, vout, True) is not None:
            return {'spent': False}
        candidates = list(self._call('getrawmempool'))
        raw = self._call('getrawtransaction', txid, True)
        if raw.get('blockhash'):
            start = self._call('getblockheader', raw['blockhash'])['height']
            for height in range(start, self.tip_height() + 1):
                block = self._call('getblock', self._call('getblockhash', height), 1)
                candidates += block['tx']
        for candidate in candidates:
            item = self._call('getrawtransaction', candidate, True, allow=(-5,))
            if item and any(i.get('txid') == txid and i.get('vout') == vout for i in item['vin']):
                return {'spent': True, 'txid': candidate}
        return {'spent': False}

    def utxos(self, address):
        tip = self.tip_height()
        found = self._call('scantxoutset', 'start', [f'addr({address})'])
        result = []
        for item in found['unspents']:
            depth = tip - item['height'] + 1
            if depth >= 2:
                result.append({'txid': item['txid'], 'vout': item['vout'], 'amount_sats': round(item['amount'] * COIN), 'confirmations': depth,
                               'block_hash': self.block_hash(item['height'])})
        return result

    def fee(self):
        return 300

    def submit(self, journal, raw):
        import public_swap_journal
        record = public_swap_journal.prepare(journal, 'bitcoin-testnet4', raw)
        returned = self._call('sendrawtransaction', raw.hex())
        if returned != record['txid']:
            raise RuntimeError('Submission returned an unexpected transaction ID; inspect journal')
        return {'chain': 'bitcoin-testnet4', 'txid': returned, 'confirmed': False, 'state': 'submitted'}
