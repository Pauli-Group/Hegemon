"""A private Anvil node and the EthereumAdapter profile that talks to it.

Anvil runs with Sepolia's chain id so the public signing and journal code (which refuses any other
chain id) is used unchanged: the same signed EIP-1559 transactions, the same journal records, the
same contract creation calldata and the same log parsing as the public run. Only the endpoint and
the funding differ. Blocks are produced on a timer so confirmation depth behaves like a real chain.
"""
import fcntl
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

from eth_account import Account

try:
    from swap_engine.tools import tool
except ImportError:
    from tools import tool

SEPOLIA_CHAIN_ID = 11155111


def _port():
    import socket
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class LocalAnvilProfile:
    name = 'ethereum'
    journal_chain = 'ethereum-sepolia'

    def __init__(self, directory, block_seconds=2):
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, exist_ok=True)
        self.url = f'http://127.0.0.1:{_port()}'
        self.log = (self.dir / 'anvil.log').open('wb')
        self.proc = subprocess.Popen(
            [str(tool('anvil')), '--host', '127.0.0.1', '--port', self.url.rsplit(':', 1)[1], '--chain-id', str(SEPOLIA_CHAIN_ID),
             '--hardfork', 'cancun', '--block-time', str(block_seconds), '--silent'],
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            end = time.monotonic() + 30
            while True:
                try:
                    if self.rpc('eth_chainId', []) == hex(SEPOLIA_CHAIN_ID):
                        break
                except OSError:
                    pass
                if time.monotonic() > end:
                    raise RuntimeError('Anvil did not start')
                time.sleep(0.2)
        except BaseException:
            self.close()
            raise

    def close(self):
        import signal
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=20)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.log.close()

    def rpc(self, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        request = urllib.request.Request(self.url, data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=15) as response:
            answer = json.loads(response.read())
        if 'error' in answer:
            raise ValueError('Ethereum RPC failed: ' + str(answer['error'])[:200])
        return answer['result']

    def now(self):
        return int(time.time())

    def new_wallet(self, name, ether=10):
        """A funded 0600 wallet file in the test-wallet format: `<address> <key>`."""
        account = Account.create()
        path = self.dir / (name + '.wallet')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(path, flags, 0o600), 'w') as handle:
            handle.write(f'{account.address} 0x{account.key.hex().removeprefix("0x")}\n')
        self.rpc('anvil_setBalance', [account.address, hex(ether * 10**18)])
        return path

    def load_wallet(self, path):
        import public_sepolia_driver
        return public_sepolia_driver.load_test_wallet(path)

    def logs(self, address, from_block):
        return self.rpc('eth_getLogs', [{'address': address, 'fromBlock': hex(from_block), 'toBlock': 'latest'}])

    def send(self, journal, wallet, to, value, data):
        import public_swap_journal
        from public_ethereum_transactions import sign_transaction
        path = Path(journal)
        key, address = self.load_wallet(wallet)
        fd = os.open(path / ('ethereum-' + address[2:].lower() + '.lock'), os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            nonce = int(self.rpc('eth_getTransactionCount', [address, 'pending']), 16)
            head = self.rpc('eth_getBlockByNumber', ['latest', False])
            base = int(head['baseFeePerGas'], 16)
            priority = int(self.rpc('eth_maxPriorityFeePerGas', []), 16)
            max_fee = 2 * base + priority
            call = {'from': address, 'value': hex(value), 'data': '0x' + data.hex()}
            if to is not None:
                call['to'] = to
            gas = max(21000, (int(self.rpc('eth_estimateGas', [call]), 16) * 12 + 9) // 10)
            if int(self.rpc('eth_getBalance', [address, 'pending']), 16) < value + gas * max_fee:
                raise ValueError('Insufficient ETH for value and maximum gas cost')
            raw, _ = sign_transaction(key, address, nonce=nonce, to=to, value=value, data=data, gas=gas, max_fee=max_fee, priority_fee=priority)
            record = public_swap_journal.prepare(path, 'ethereum-sepolia', raw)
            returned = self.rpc('eth_sendRawTransaction', ['0x' + raw.hex()])
            if str(returned).removeprefix('0x') != record['txid']:
                raise RuntimeError('Submission returned an unexpected transaction ID; inspect journal')
            return {'chain': 'ethereum-sepolia', 'txid': record['txid'], 'confirmed': False, 'state': 'submitted'}
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
