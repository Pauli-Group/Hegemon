"""Ethereum (Sepolia or a local Anvil) HTLC adapter over the repository's native-ETH escrow.

The contract is contracts/ethereum/HegemonHTLC.sol, deployed from swap-ui/ether-escrow-template.json.
An escrow reference is {'txid': <creation transaction id, 64 hex without 0x>}; the contract address
comes from that transaction's receipt, so it is known only once the creation is mined.

A `profile` supplies the network: journal chain name, rpc, a signed-send function, logs, clock.
`SepoliaProfile` wraps the tested public drivers; scripts/swap_engine/adapters/local_ethereum.py
provides an Anvil profile for local fixtures. Everything else here is shared, so local fixture runs
exercise the same verification, calldata and log-parsing code as the public run.
"""
import json
import re
import time
from pathlib import Path

from eth_abi import encode
from eth_utils import keccak

try:
    from swap_engine.adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure
except ImportError:
    from adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure

ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / 'swap-ui' / 'ether-escrow-template.json'
CLAIMED = '0x' + keccak(text='Claimed(bytes32,address,uint256)').hex()
REFUNDED = '0x' + keccak(text='Refunded(address,uint256)').hex()
SPENT_SELECTOR = '0x' + keccak(text='spent()')[:4].hex()
CLAIM_SELECTOR = keccak(text='claim(bytes32)')[:4]
REFUND_SELECTOR = keccak(text='refund()')[:4]
HEX64 = re.compile('[0-9a-f]{64}')
ADDRESS = re.compile('0x[0-9a-f]{40}')


class SepoliaProfile:
    """Public Sepolia through the existing drivers. Reads come from public_testnet_probe.rpc."""

    name = 'ethereum'
    journal_chain = 'ethereum-sepolia'
    BLOCKSCOUT = 'https://eth-sepolia.blockscout.com/api/v2'

    def __init__(self):
        import public_testnet_probe as probe
        import public_sepolia_driver as driver
        import public_testnet_submit as submit
        self._probe, self._driver, self._submit = probe, driver, submit

    def rpc(self, method, params):
        return self._probe.rpc(method, params)

    def verify_network(self):
        self._submit.verify_network('ethereum-sepolia')

    def load_wallet(self, path):
        return self._driver.load_test_wallet(path)

    def send(self, journal, wallet, to, value, data):
        return self._driver.send(journal, wallet, to, value, data)

    def now(self):
        return int(time.time())

    def logs(self, address, from_block):
        """Events of one contract. Falls back to Blockscout when the RPC has pruned them."""
        try:
            rows = self.rpc('eth_getLogs', [{'address': address, 'fromBlock': hex(from_block), 'toBlock': 'latest'}])
            if isinstance(rows, list):
                return rows
        except Exception:
            pass
        page = json.loads(self._probe.request(f'{self.BLOCKSCOUT}/addresses/{address}/logs'))
        out = []
        for item in page.get('items', []):
            out.append({'topics': item.get('topics') or [], 'data': item.get('data') or '0x',
                        'transactionHash': item.get('transaction_hash'), 'blockNumber': hex(int(item.get('block_number')))})
        return out


class EthereumAdapter(JournaledWrites, ChainAdapter):
    chain = 'ethereum'

    def __init__(self, profile, wallet_file):
        self.profile = profile
        self.wallet_file = Path(wallet_file)
        self.journal_chain = profile.journal_chain
        _, address = profile.load_wallet(self.wallet_file)
        self._address = address.lower()

    # ---- reads
    def _rpc(self, method, params):
        try:
            return self.profile.rpc(method, params)
        except Exception as error:
            raise read_failure(error) from error

    def identity(self):
        return self._address

    def head(self):
        block = self._rpc('eth_getBlockByNumber', ['latest', False])
        try:
            return {'observedAt': self.profile.now(), 'timestamp': int(block['timestamp'], 16)}
        except (KeyError, TypeError, ValueError) as error:
            raise read_failure(error) from error

    def escrow_ref(self, leg, txid):
        if not isinstance(txid, str) or not HEX64.fullmatch(txid):
            raise ValueError('Invalid Ethereum transaction id')
        return {'txid': txid}

    def transaction_seen(self, txid):
        if not HEX64.fullmatch(txid):
            raise ValueError('Invalid Ethereum transaction id')
        return bool(self._rpc('eth_getTransactionByHash', ['0x' + txid]))

    @staticmethod
    def _terms_data(leg):
        template = json.loads(TEMPLATE.read_text())
        return bytes.fromhex(template['creation']) + encode(['bytes32', 'address', 'uint256'], [bytes.fromhex(leg['hashlock']), leg['claimant'], leg['expiry']])

    def _contract(self, escrow):
        receipt = self._rpc('eth_getTransactionReceipt', ['0x' + escrow['txid']])
        if not receipt or receipt.get('status') != '0x1' or not receipt.get('contractAddress'):
            return None, receipt
        return receipt['contractAddress'].lower(), receipt

    def inspect(self, leg, escrow):
        observation = empty_observation()
        txid = escrow['txid']
        if not isinstance(txid, str) or not HEX64.fullmatch(txid):
            raise ValueError('Invalid Ethereum escrow reference')
        receipt = self._rpc('eth_getTransactionReceipt', ['0x' + txid])
        if not receipt:
            # Public RPC backends disagree: a mined transaction can briefly have no receipt. Absent
            # means the node knows the transaction but has not mined it, or does not know it at all.
            known = self._rpc('eth_getTransactionByHash', ['0x' + txid])
            if known and known.get('blockNumber'):
                raise ChainUnavailable('the transaction is mined but its receipt is not visible yet')
            return observation
        if receipt.get('status') != '0x1' or not receipt.get('contractAddress'):
            observation['problem'] = 'the creation transaction failed or did not create a contract'
            return observation
        try:
            number = int(receipt['blockNumber'], 16)
            tip = int(self._rpc('eth_blockNumber', []), 16)
            block = self._rpc('eth_getBlockByNumber', [hex(number), False])
            if not block or str(block.get('hash', '')).lower() != str(receipt.get('blockHash', '')).lower():
                raise ChainUnavailable('snapshot or chain changed')
            tx = self._rpc('eth_getTransactionByHash', ['0x' + txid])
            if not tx or str(tx.get('blockHash', '')).lower() != str(receipt['blockHash']).lower():
                raise ChainUnavailable('snapshot or chain changed')
            contract = receipt['contractAddress'].lower()
            observation['found'] = True
            observation['confirmations'] = max(0, tip - number + 1)
            mismatch = []
            if tx.get('to') is not None:
                mismatch.append('creation')
            if str(tx.get('from', '')).lower() != leg['refundee']:
                mismatch.append('funder')
            if int(tx.get('value', '0x0'), 16) != leg['amount']:
                mismatch.append('amount')
            if str(tx.get('input', '')).lower() != '0x' + self._terms_data(leg).hex():
                mismatch.append('constructor terms')
            runtime = self._expected_runtime(leg)
            if str(self._rpc('eth_getCode', [contract, 'latest'])).lower() != runtime:
                mismatch.append('runtime code')
            if mismatch:
                observation['problem'] = 'escrow differs from the terms in ' + ', '.join(mismatch)
                return observation
            observation['verified'] = True
            if int(self._rpc('eth_call', [{'to': contract, 'data': SPENT_SELECTOR}, 'latest']), 16) == 0:
                return observation
            return self._spent(observation, contract, number, tip)
        except (KeyError, TypeError, ValueError) as error:
            raise read_failure(error) from error

    def _expected_runtime(self, leg):
        import public_ethereum_verify as verify
        return verify.expected_runtime(leg['hashlock'], leg['claimant'], leg['refundee'], leg['expiry'])

    def _spent(self, observation, contract, created_block, tip):
        try:
            rows = self.profile.logs(contract, created_block)
        except Exception as error:
            raise read_failure(error) from error
        for row in rows:
            topics = [str(t).lower() for t in row.get('topics', [])]
            if not topics or topics[0] not in (CLAIMED, REFUNDED):
                continue
            observation['spent'] = 'claimed' if topics[0] == CLAIMED else 'refunded'
            observation['spend_txid'] = str(row.get('transactionHash', '')).removeprefix('0x').lower() or None
            observation['spend_confirmations'] = max(0, tip - int(row['blockNumber'], 16) + 1)
            if observation['spent'] == 'claimed':
                data = str(row.get('data', '0x'))
                observation['preimage'] = data[2:66].lower() if len(data) >= 66 else None
            return observation
        raise ChainUnavailable('the contract is spent but its event is not visible yet')

    # ---- writes
    def _check_actor(self, leg, role):
        if leg[role] != self._address:
            raise ActionRefused(f'the wallet is not the {role} of this leg')

    def fund(self, leg, journal):
        self._check_actor(leg, 'refundee')
        data = self._terms_data(leg)
        return self._journaled(journal, lambda: {'txid': self.profile.send(journal, self.wallet_file, None, leg['amount'], data)['txid']})

    def _call(self, leg, escrow, journal, selector_data, role):
        self._check_actor(leg, role)
        contract, _ = self._contract(escrow)
        if contract is None:
            raise ActionRefused('the escrow contract is not mined yet')
        return self._journaled(journal, lambda: {'txid': self.profile.send(journal, self.wallet_file, contract, 0, selector_data)['txid']})

    def claim(self, leg, escrow, preimage, journal):
        # The RPC provider sees the preimage during gas estimation (documented in the driver).
        return self._call(leg, escrow, journal, CLAIM_SELECTOR + encode(['bytes32'], [bytes(preimage)]), 'claimant')

    def refund(self, leg, escrow, journal):
        return self._call(leg, escrow, journal, REFUND_SELECTOR, 'refundee')
