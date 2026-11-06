"""A private one-node Cardano cluster and the CardanoAdapter profile that reads and writes it.

The cluster uses 1-second slots so a slot number is `expiry - system_start`, exactly the mapping the
public adapter uses. cardano-node has no transaction index, and Ogmios is not installed on this host,
so every transaction goes through this profile, which records what it submitted. That gives the
spender and preimage lookups an indexer would give on preview. This is a documented difference from
the public profile: the adapter's own verification, datum, fee-input, collateral and spend code is
shared and runs against a real node and the real Plutus validator.

Cluster layout and start-up follow scripts/htlc_counterpart.py (cardano-testnet create-env).
"""
import datetime
import json
import os
import subprocess
import time
from pathlib import Path

try:
    from swap_engine.tools import tool
    from swap_engine.store import _write_new
except ImportError:
    from tools import tool
    from store import _write_new

MAGIC = '424242'
ROOT = Path(__file__).resolve().parents[3]


def _port():
    import socket
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait(fn, label, seconds=90):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, KeyError):
            pass
        time.sleep(0.25)
    raise RuntimeError('timed out: ' + label)


class LocalCardanoProfile:
    name = 'cardano'
    journal_chain = 'cardano-preview'  # the journal format is shared; the chain name selects the transaction-id rule
    testnet_args = ['--testnet-magic', MAGIC]
    claim_margin_slots = 4
    validity_slots = 20  # k=5, f=0.5: the ledger translates slots only ~30 ahead of the tip

    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, exist_ok=True)
        self.cli = str(tool('cardano-cli'))
        self.node = str(tool('cardano-node'))
        self.testnet = str(Path(self.cli).with_name('cardano-testnet'))
        self.proc = None
        self.log = (self.dir / 'node.log').open('wb')
        self.included = {}      # txid -> tip block when first seen on chain
        self.sent = {}          # txid -> {'inputs': [outrefs], 'cbor': hex}
        self.rows = {}          # outref -> last UTxO row seen (Koios-like), kept after it is spent
        self.serial = 0
        try:
            self._start()
        except BaseException:
            self.close()
            raise

    # ---- cluster
    def _start(self):
        net = self.dir / 'net'
        self.net = net
        env = dict(os.environ, CARDANO_CLI=self.cli, CARDANO_NODE=self.node)
        subprocess.run([self.testnet, 'create-env', '--num-pool-nodes', '1', '--num-dreps', '0', '--slot-length', '1',
                        '--active-slots-coeff', '0.5', '--epoch-length', '600', '--testnet-magic', MAGIC, '--output', str(net)],
                       env=env, check=True, stdout=self.log, stderr=self.log)
        start = int(time.time()) + 3
        for era in ('shelley', 'byron'):
            path = net / (era + '-genesis.json')
            genesis = json.loads(path.read_text())
            if era == 'shelley':
                genesis['systemStart'] = datetime.datetime.fromtimestamp(start, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                genesis['startTime'] = start
            path.write_text(json.dumps(genesis, indent=2))
        self.system_start = start
        self.socket = net / 'node.socket'
        if len(str(self.socket).encode()) >= 100:
            raise RuntimeError('Cardano socket path too long; use a shorter directory')
        keys = net / 'pools-keys/pool1'
        self.proc = subprocess.Popen(
            [self.node, 'run', '--config', str(net / 'configuration.yaml'), '--topology', str(net / 'node-data/node1/topology.json'),
             '--database-path', str(net / 'db'), '--shelley-kes-key', str(keys / 'kes.skey'), '--shelley-vrf-key', str(keys / 'vrf.skey'),
             '--shelley-operational-certificate', str(keys / 'opcert.cert'), '--byron-delegation-certificate', str(keys / 'byron-delegation.cert'),
             '--byron-signing-key', str(keys / 'byron-delegate.key'), '--socket-path', str(self.socket), '--host-addr', '127.0.0.1', '--port', str(_port())],
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, cwd=net)
        _wait(lambda: self._tip().get('block', 0) > 0, 'Cardano blocks', 120)
        self.actors = {}
        for index, name in enumerate(('alice', 'bob', 'outsider'), 1):
            key = net / f'utxo-keys/utxo{index}/utxo'
            address = self._run('address', 'build', '--payment-verification-key-file', key.with_suffix('.vkey'), *self.testnet_args).strip()
            keyhash = self._run('address', 'key-hash', '--payment-verification-key-file', key.with_suffix('.vkey')).strip()
            self.actors[name] = {'address': address, 'skey': key.with_suffix('.skey'), 'keyhash': keyhash}

    def close(self):
        import signal
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=20)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.log.close()

    def _run(self, *args, check=True):
        result = subprocess.run([self.cli, 'conway', *map(str, args)], capture_output=True, text=True, timeout=60)
        if check and result.returncode:
            raise RuntimeError('cardano-cli failed: ' + result.stderr[-1500:])
        return result.stdout if check else result

    def _query(self, *args):
        return json.loads(self._run('query', *args, *self.testnet_args, '--socket-path', self.socket, '--output-json'))

    def _tip(self):
        return self._query('tip')

    # ---- funding the actors with several ADA-only outputs
    def prepare_wallets(self, count=4, lovelace=100_000_000):
        for name, actor in self.actors.items():
            available = self._query('utxo', '--address', actor['address'])
            key = max(available, key=lambda k: available[k]['value'].get('lovelace', 0))
            self.serial += 1
            body = self.dir / f'split-{name}-{self.serial}.body'
            signed = self.dir / f'split-{name}-{self.serial}.signed'
            outputs = []
            for _ in range(count):
                outputs += ['--tx-out', f"{actor['address']}+{lovelace}"]
            self._run('transaction', 'build', *self.testnet_args, '--socket-path', self.socket, '--tx-in', key, *outputs,
                      '--change-address', actor['address'], '--out-file', body)
            self._run('transaction', 'sign', '--tx-body-file', body, '--signing-key-file', actor['skey'], *self.testnet_args, '--out-file', signed)
            txid = self._run('transaction', 'txid', '--tx-file', signed, '--output-text').strip()
            self._run('transaction', 'submit', '--tx-file', signed, *self.testnet_args, '--socket-path', self.socket)
            _wait(lambda: self.confirmations(txid) >= 3, 'wallet split confirmation', 120)

    def wallet(self, name):
        actor = self.actors[name]
        return {'skey': actor['skey'], 'keyhash': actor['keyhash'], 'address': actor['address']}

    # ---- profile interface used by CardanoAdapter
    def now(self):
        return int(time.time())

    def tip_slot(self):
        return self._tip()['slot']

    def tip_block(self):
        return self._tip()['block']

    def _record(self, outputs):
        for ref, row in outputs.items():
            value = dict(row.get('value', {}))
            lovelace = value.pop('lovelace', 0)
            assets = [{'policy_id': p, 'asset_name': n, 'quantity': str(q)} for p, names in value.items() for n, q in names.items()]
            datum = row.get('inlineDatum')
            self.rows[ref] = {'address': row['address'], 'value': str(lovelace), 'asset_list': assets, 'is_spent': False,
                              'block_height': self.included.get(ref.split('#')[0]),
                              'inline_datum': {'bytes': row.get('inlineDatumRaw', ''), 'value': datum} if datum is not None else None}

    def _scan(self):
        """Refresh the view of the whole (tiny) UTxO set at most once a second and note new inclusions."""
        if time.monotonic() - getattr(self, '_scanned', -10) < 1.0:
            return self._scan_block
        block = self.tip_block()
        outputs = self._query('utxo', '--whole-utxo')
        addresses = {a['address'] for a in self.actors.values()} | set(self._script_addresses)
        outputs = {ref: row for ref, row in outputs.items() if row['address'] in addresses}
        for ref in outputs:
            self.included.setdefault(ref.split('#')[0], block)
        self._record(outputs)
        for ref, row in self.rows.items():
            if ref not in outputs and ref.split('#')[0] in self.included and row['address'] in addresses:
                row['is_spent'] = True
        for txid, item in self.sent.items():
            if txid not in self.included and any(i in outputs or self.rows.get(i, {}).get('is_spent') for i in item['outputs']):
                self.included[txid] = block
        self._scanned, self._scan_block = time.monotonic(), block
        return block

    _script_addresses = ()

    def watch_script(self, address):
        self._script_addresses = (*self._script_addresses, address)

    def utxos(self, address):
        self._scan()
        result = []
        for ref, row in self.rows.items():
            if row['address'] == address and not row['is_spent']:
                result.append({'outref': ref, 'lovelace': int(row['value']), 'assets': {f"{a['policy_id']}.{a['asset_name']}": int(a['quantity']) for a in row['asset_list']},
                               'inline_datum': row['inline_datum'], 'block_height': row['block_height']})
        return result

    def confirmations(self, txid):
        block = self._scan()
        if txid not in self.included:
            return 0
        return max(1, block - self.included[txid] + 1)

    def utxo_info(self, outref):
        self._scan()
        row = self.rows.get(outref)
        return dict(row, tx_hash=outref.split('#')[0]) if row else None

    def spender(self, script_address, outref, created_height):
        self._scan()
        for txid, item in self.sent.items():
            if outref in item['inputs'] and txid in self.included:
                return txid
        return None

    def claim_preimage(self, spend_txid, outref, hashlock):
        from cardano_preimage_observer import claim_preimage
        return claim_preimage(spend_txid, self.sent[spend_txid]['cbor'], outref, hashlock)

    def protocol_parameters(self):
        return self._query('protocol-parameters')

    def submit(self, journal, body, signing_key):
        import public_swap_journal
        work = Path(journal) / f'ada-sign-{self.serial}'
        self.serial += 1
        work.mkdir(mode=0o700)
        try:
            signed = work / 'signed.json'
            self._run('transaction', 'sign', '--tx-body-file', body, '--signing-key-file', signing_key, *self.testnet_args, '--out-file', signed)
            os.chmod(signed, 0o600)
            envelope = json.loads(signed.read_text())
            raw = bytes.fromhex(envelope['cborHex'])
            record = public_swap_journal.prepare(journal, 'cardano-preview', raw)
            import cbor2
            body_map = cbor2.loads(raw)[0]
            txid = record['txid']
            inputs = [f'{bytes(item[0]).hex()}#{item[1]}' for item in body_map[0]]
            self.sent[txid] = {'inputs': inputs, 'cbor': envelope['cborHex'], 'outputs': [f'{txid}#{i}' for i in range(len(body_map[1]))]}
            self._run('transaction', 'submit', '--tx-file', signed, *self.testnet_args, '--socket-path', self.socket)
            return {'txid': txid}
        finally:
            for path in work.glob('*'):
                path.unlink()
            work.rmdir()
