"""Run the two-party engine over real local chains: Anvil, bitcoind regtest and a one-node Cardano cluster.

The chains are real software with real contracts and scripts; only their clocks are fast, so this module
carries a scaled timing configuration (`local_timing`) in the same schema as config/swap/chain-timing.json.
Nothing here relaxes an engine rule: the planner, the policy checks, the journal and the adapters are the
production ones. Two parties (initiator and responder) each have their own store and wallets and exchange
escrow references the way two people would.

Run directly for a smoke swap:  python3 -m swap_engine.local_world ethereum cardano
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

from swap_engine import engine, planner
from swap_engine import timelock_policy as policy
from swap_engine.store import Store

AMOUNTS = {'bitcoin': 50_000, 'ethereum': 10**17, 'cardano': 20_000_000}
FEE_TOLERANCE = {'bitcoin': 2_000, 'ethereum': 5 * 10**15, 'cardano': 3_000_000}
BLOCK_SECONDS = {'bitcoin': 3, 'ethereum': 2}


def local_timing():
    windows = {str(n): {'min': max(0, n * 3 - 3), 'max': n * 3 + 8} for n in (1, 2, 3, 6, 12, 24, 48, 96)}
    config = {
        'version': 1, 'status': 'local fixture timing; scaled to regtest, Anvil and a 1-second-slot private Cardano cluster',
        'policy': {'reactionSeconds': 15, 'gapFactor': 1.5, 'gapFloorSeconds': 15, 'maxHorizonSeconds': 1200,
                   'maxObservationAgeSeconds': 30, 'minShortWindowSeconds': 60},
        'chains': {
            'bitcoin': {'kind': 'height', 'network': 'regtest', 'confirmations': 2, 'clockSkewSeconds': 0, 'slowFactor': 1.5, 'fastFactor': 0.5,
                        'outageAllowanceSeconds': 10, 'providerLagBlocks': 0, 'refundOffsetBlocks': 1, 'windows': windows},
            'ethereum': {'kind': 'time', 'network': 'anvil', 'confirmations': 2, 'clockSkewSeconds': 3, 'inclusionSeconds': 10,
                         'slowBlockSeconds': 4, 'maxHeadAgeSeconds': 30},
            'cardano': {'kind': 'time', 'network': 'local-cluster', 'confirmations': 2, 'clockSkewSeconds': 3, 'inclusionSeconds': 12,
                        'slowBlockSeconds': 8, 'maxHeadAgeSeconds': 30},
        }}
    return policy.validate_timing(config)


class LocalWorld:
    def __init__(self, chains=('bitcoin', 'ethereum', 'cardano')):
        # Cardano needs a short socket path; /dev/shm is also fast.
        self.tmp = Path(tempfile.mkdtemp(prefix='swl', dir='/dev/shm'))
        os.chmod(self.tmp, 0o700)
        self.profiles = {}
        self.wallets = {}
        self.adapter_cache = {}
        self._stop = threading.Event()
        self._miner = None
        try:
            for name in chains:
                self._start(name)
            if 'bitcoin' in self.profiles:
                self._miner = threading.Thread(target=self._mine_loop, daemon=True)
                self._miner.start()
        except BaseException:
            self.close()
            raise

    def _start(self, name):
        if name == 'bitcoin':
            from swap_engine.adapters.local_bitcoin import LocalBitcoinProfile
            self.profiles[name] = LocalBitcoinProfile(self.tmp / 'btc')
        elif name == 'ethereum':
            from swap_engine.adapters.local_ethereum import LocalAnvilProfile
            self.profiles[name] = LocalAnvilProfile(self.tmp / 'eth', BLOCK_SECONDS['ethereum'])
        elif name == 'cardano':
            from swap_engine.adapters.local_cardano import LocalCardanoProfile
            profile = LocalCardanoProfile(self.tmp / 'ada')
            profile.prepare_wallets(count=6)
            self.profiles[name] = profile
        else:
            raise ValueError('Unknown local chain ' + name)

    def _mine_loop(self):
        profile = self.profiles['bitcoin']
        while not self._stop.wait(BLOCK_SECONDS['bitcoin']):
            try:
                profile.mine(1)
            except Exception:
                pass

    def close(self):
        self._stop.set()
        if self._miner:
            self._miner.join(timeout=10)
        for profile in self.profiles.values():
            profile.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- wallets and adapters
    def adapter(self, chain, person, tag):
        key = (chain, person, tag)
        if key in self.adapter_cache:
            return self.adapter_cache[key]
        profile = self.profiles[chain]
        label = f'{person}-{tag}'
        if chain == 'bitcoin':
            from swap_engine.adapters.bitcoin import BitcoinAdapter
            path, _ = profile.new_key_file(label)
            adapter = BitcoinAdapter(profile, path)
        elif chain == 'ethereum':
            from swap_engine.adapters.ethereum import EthereumAdapter
            adapter = EthereumAdapter(profile, profile.new_wallet(label))
        else:
            from swap_engine.adapters.cardano import CardanoAdapter
            adapter = CardanoAdapter(profile, profile.wallet(person))
            profile.watch_script(adapter.script_address())
        self.adapter_cache[key] = adapter
        return adapter


class LocalSwap:
    """One swap between `alice` (initiator, funds the long leg) and `bob` over the world's chains."""

    TERMINAL = ('done', 'refunded', 'aborted', 'failed')

    def __init__(self, world, long_chain, short_chain, tag, config=None, preimage=None, margin_seconds=None):
        self.world, self.config = world, config or local_timing()
        self.tag = tag
        self.preimage = preimage or os.urandom(32)
        self.chains = {'long': long_chain, 'short': short_chain}
        self.alice = {'long': world.adapter(long_chain, 'alice', tag), 'short': world.adapter(short_chain, 'alice', tag)}
        self.bob = {'long': world.adapter(long_chain, 'bob', tag), 'short': world.adapter(short_chain, 'bob', tag)}
        heads = {leg: self.alice[leg].head() for leg in ('long', 'short')}
        now = world.profiles[long_chain].now()
        plan = planner.plan_with_margin(self.config, long_chain, short_chain, heads, now, margin_seconds)
        if not plan['verdict']['ok']:
            raise ValueError('No compliant plan: ' + json.dumps(plan['verdict']['reasons']))
        self.plan = plan
        self.terms = {'version': 1, 'hashlock': hashlib.sha256(self.preimage).hexdigest(), 'legs': {
            'long': {'chain': long_chain, 'amount': AMOUNTS[long_chain], 'refundee': self.alice['long'].identity(),
                     'claimant': self.bob['long'].identity(), 'expiry': plan['long']['expiry']},
            'short': {'chain': short_chain, 'amount': AMOUNTS[short_chain], 'refundee': self.bob['short'].identity(),
                      'claimant': self.alice['short'].identity(), 'expiry': plan['short']['expiry']}}}
        self.swap_id = hashlib.sha256(json.dumps(self.terms, sort_keys=True).encode()).hexdigest()[:16]
        self.stores = {'initiator': Store(world.tmp / f'stores-{tag}' / 'alice'), 'responder': Store(world.tmp / f'stores-{tag}' / 'bob')}
        self.adapters = {'initiator': self.alice, 'responder': self.bob}
        self.stores['initiator'].create(self.swap_id, 'initiator', self.terms, now, self.preimage)
        self.stores['responder'].create(self.swap_id, 'responder', self.terms, now)
        self.log = []

    def now(self):
        return self.world.profiles[self.chains['long']].now()

    def step(self, role):
        with self.stores[role].locked(self.swap_id) as swap:
            result = engine.advance(swap, self.adapters[role], self.config, self.now())
        entry = (round(time.time() - self.started, 1), role, result['status'], result.get('state'))
        if getattr(self, 'verbose', False) and (not self.log or self.log[-1][1:] != entry[1:]):
            print(*entry, str({k: v for k, v in result.items() if k not in ('status', 'state')})[:160], flush=True)
        self.log.append(entry)
        return result

    def exchange(self):
        for sender, receiver, leg in (('initiator', 'responder', 'long'), ('responder', 'initiator', 'short')):
            with self.stores[sender].locked(self.swap_id) as source:
                ref = source.record['escrows'][leg]
            if ref is not None:
                with self.stores[receiver].locked(self.swap_id) as target:
                    engine.receive(target, leg, ref, self.now())

    def states(self):
        out = {}
        for role, store in self.stores.items():
            with store.locked(self.swap_id) as swap:
                out[role] = (swap.record['state'], swap.record['inflight'] is not None, swap.record['needs_human'])
        return out

    def run(self, timeout=600, roles=('initiator', 'responder'), pause=0.5, before_step=None, until=None):
        self.started = time.time()
        while time.time() - self.started < timeout:
            if before_step:
                before_step(self)
            self.exchange()
            for role in roles:
                self.step(role)
            states = self.states()
            if until is not None and until(self):
                return states
            if all(s in self.TERMINAL or human for s, _, human in (states[r] for r in roles)):
                return states
            time.sleep(pause)
        return self.states()

    # ---- end-state checks
    def balances(self):
        """Native balance of each person on each chain they use, for before/after comparison."""
        out = {}
        for person, adapters in (('alice', self.alice), ('bob', self.bob)):
            for leg in ('long', 'short'):
                chain, adapter = self.chains[leg], adapters[leg]
                out[(person, chain)] = self._balance(chain, adapter)
        return out

    def expected_after(self, before, outcome):
        """Balances after the swap: 'swapped', or 'unchanged' when both sides refunded. Returns problems found."""
        after = self.balances()
        long_chain, short_chain = self.chains['long'], self.chains['short']
        expect = {key: 0 for key in before}
        if outcome == 'swapped':
            expect[('alice', long_chain)] -= AMOUNTS[long_chain]
            expect[('bob', long_chain)] += AMOUNTS[long_chain]
            expect[('bob', short_chain)] -= AMOUNTS[short_chain]
            expect[('alice', short_chain)] += AMOUNTS[short_chain]
        problems = []
        if long_chain == short_chain:
            pass  # one wallet per person per chain: the two legs net out through the same keys
        for key, want in expect.items():
            got = after[key] - before[key]
            if abs(got - want) > FEE_TOLERANCE[key[1]] * (2 if long_chain == short_chain else 1):
                problems.append(f'{key}: balance moved {got}, expected {want} within fees')
        return problems

    def _balance(self, chain, adapter):
        profile = self.world.profiles[chain]
        if chain == 'ethereum':
            return int(profile.rpc('eth_getBalance', [adapter.identity(), 'latest']), 16)
        if chain == 'bitcoin':
            from embit import networks, script
            key = profile.load_key(adapter._key_file)
            address = script.p2wpkh(key.get_public_key()).address(networks.NETWORKS['regtest'])
            unspents = profile._call('scantxoutset', 'start', [f'addr({address})'])['unspents']
            return sum(round(u['amount'] * 100_000_000) for u in unspents)
        outputs = profile._query('utxo', '--address', adapter.wallet['address'])
        return sum(row['value'].get('lovelace', 0) for row in outputs.values())


def main(argv):
    long_chain, short_chain = argv[1], argv[2]
    world = LocalWorld(tuple(dict.fromkeys((long_chain, short_chain))))
    try:
        swap = LocalSwap(world, long_chain, short_chain, 'smoke')
        swap.verbose = True
        print('plan', json.dumps(swap.plan['long']), json.dumps(swap.plan['short']), flush=True)
        print(swap.run(timeout=900))
        for entry in swap.log[-12:]:
            print(entry)
    finally:
        world.close()


if __name__ == '__main__':
    main(sys.argv)
