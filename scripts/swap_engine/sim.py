"""Deterministic simulated chains, a simulated adapter, a crash hook and a two-party harness.

The simulated chains implement the same HTLC rules as the real contracts:

  height chains (Bitcoin, Hegemon): a claim is valid until a refund lands; a
    refund is valid in a block whose height is greater than the expiry.
  time chains (Ethereum, Cardano): a claim is valid only in a block whose
    timestamp is before the expiry; a refund only at or after it.

State is derived by replaying the included transactions in block order, so a
reorg is just removing a transaction and replaying. Fault switches model
provider failures (read errors, lag), lost write responses, broadcasts that
never leave the machine, and reorgs. A CrashHook raises SimulatedCrash (a
BaseException, so no `except Exception` swallows it) at a chosen numbered point.
"""
import hashlib
import json
from pathlib import Path

try:
    from swap_engine import engine, planner
    from swap_engine.adapter import ActionRefused, ChainAdapter, ChainUnavailable, empty_observation
    from swap_engine.store import Store, _write_new, journal_ids, terms_digest
except ImportError:
    import engine
    import planner
    from adapter import ActionRefused, ChainAdapter, ChainUnavailable, empty_observation
    from store import Store, _write_new, journal_ids, terms_digest


class SimulatedCrash(BaseException):
    pass


class CrashHook:
    """Counts every named crash point; raises at the numbered one (1-based)."""

    def __init__(self, crash_at=()):
        self.crash_at = set([crash_at] if isinstance(crash_at, int) else crash_at)
        self.count = 0
        self.names = []

    def point(self, name):
        self.count += 1
        self.names.append(name)
        if self.count in self.crash_at:
            self.crash_at.discard(self.count)
            raise SimulatedCrash(name)


class SimChain:
    def __init__(self, name, kind, interval, start_time=1_800_000_000, start_height=1000):
        self.name = name
        self.kind = kind
        self.interval = interval
        self.blocks = [{'height': start_height, 'timestamp': start_time, 'txs': []}]
        self.mempool = []
        self.balances = {}
        self.nonces = {}
        self.state = {'escrows': {}, 'balances': {}, 'rejected': []}
        self.lag = 0
        self.fail_reads = 0
        self.lose_next_response = False
        self.drop_next_broadcast = False
        self.initial_total = 0
        self.credits = {}
        self.fund_count = 0
        self.broadcasts = []
        self._replay()

    # ---- ledger
    def credit(self, identity, amount):
        self.balances[identity] = self.balances.get(identity, 0) + amount
        self.initial_total += amount
        self.credits[identity] = self.credits.get(identity, 0) + amount
        self._replay()

    @property
    def height(self):
        return self.blocks[-1]['height']

    def _valid(self, tx, escrows, state, height, timestamp):
        kind = tx['kind']
        if kind == 'fund':
            return state['balances'].get(tx['sender'], 0) >= tx['amount']
        escrow = escrows.get(tx['escrow'])
        if escrow is None or escrow['spent'] is not None:
            return False
        if kind == 'claim':
            if hashlib.sha256(bytes.fromhex(tx['preimage'])).hexdigest() != escrow['hashlock']:
                return False
            if tx['sender'] != escrow['claimant']:
                return False
            return self.kind == 'height' or timestamp < escrow['expiry']
        if kind == 'refund':
            if tx['sender'] != escrow['refundee']:
                return False
            return height > escrow['expiry'] if self.kind == 'height' else timestamp >= escrow['expiry']
        return False

    def _apply_block(self, state, block):
        kept = []
        for tx in block['txs']:
            if not self._valid(tx, state['escrows'], state, block['height'], block['timestamp']):
                state['rejected'].append(tx['id'])
                continue
            kept.append(tx)
            if tx['kind'] == 'fund':
                state['balances'][tx['sender']] -= tx['amount']
                state['escrows'][tx['id']] = {**{k: tx[k] for k in ('amount', 'hashlock', 'claimant', 'refundee', 'expiry')},
                                              'funded_height': block['height'], 'spent': None, 'spend_tx': None,
                                              'spend_height': None, 'preimage': None}
            else:
                escrow = state['escrows'][tx['escrow']]
                to = escrow['claimant'] if tx['kind'] == 'claim' else escrow['refundee']
                state['balances'][to] = state['balances'].get(to, 0) + escrow['amount']
                escrow.update(spent='claimed' if tx['kind'] == 'claim' else 'refunded', spend_tx=tx['id'],
                              spend_height=block['height'], preimage=tx.get('preimage'))
        block['txs'] = kept

    def _replay(self):
        state = {'escrows': {}, 'balances': dict(self.balances), 'rejected': []}
        for block in self.blocks:
            self._apply_block(state, block)
        self.state = state

    def mine(self, count=1):
        for _ in range(count):
            last = self.blocks[-1]
            block = {'height': last['height'] + 1, 'timestamp': last['timestamp'] + self.interval, 'txs': list(self.mempool)}
            self.mempool = []
            self.blocks.append(block)
            self._apply_block(self.state, block)

    def advance_to(self, timestamp):
        while self.blocks[-1]['timestamp'] + self.interval <= timestamp:
            self.mine(1)

    def submit(self, tx):
        self.broadcasts.append((tx['kind'], tx['sender'], tx.get('escrow')))
        if any(item['id'] == tx['id'] for item in self.mempool) or self.included_height(tx['id']) is not None:
            return
        self.mempool.append(tx)

    def included_height(self, txid):
        for block in self.blocks:
            if any(tx['id'] == txid for tx in block['txs']):
                return block['height']
        return None

    def seen(self, txid):
        return any(tx['id'] == txid for tx in self.mempool) or self.included_height(txid) is not None

    def pending_debit(self, identity):
        return sum(tx['amount'] for tx in self.mempool if tx['kind'] == 'fund' and tx['sender'] == identity)

    def drop(self, txid):
        """Reorg: remove a transaction from its block and from the mempool."""
        self.mempool = [tx for tx in self.mempool if tx['id'] != txid]
        for block in self.blocks:
            block['txs'] = [tx for tx in block['txs'] if tx['id'] != txid]
        self._replay()

    def unconfirm(self, txid):
        """Reorg that returns the transaction to the mempool."""
        found = None
        for block in self.blocks:
            for tx in block['txs']:
                if tx['id'] == txid:
                    found = tx
            block['txs'] = [tx for tx in block['txs'] if tx['id'] != txid]
        if found:
            self.mempool.append(found)
        self._replay()

    def total_value(self):
        escrowed = sum(e['amount'] for e in self.state['escrows'].values() if e['spent'] is None)
        return sum(self.state['balances'].values()) + escrowed


class SimWorld:
    def __init__(self, chains, now=1_800_000_000):
        self.chains = {chain.name: chain for chain in chains}
        self.now = now

    def tick(self, seconds):
        self.now += seconds
        for chain in self.chains.values():
            chain.advance_to(self.now)


DEFAULT_INTERVALS = {'bitcoin': ('height', 600), 'hegemon': ('height', 75), 'ethereum': ('time', 12), 'cardano': ('time', 20)}


def make_world(names, now=1_800_000_000):
    """Chains whose clocks start at `now` and whose heights count up from a fixed base."""
    chains = []
    for name in names:
        kind, interval = DEFAULT_INTERVALS[name]
        chains.append(SimChain(name, kind, interval, start_time=now, start_height=1000))
    return SimWorld(chains, now)


class SimAdapter(ChainAdapter):
    def __init__(self, world, chain, identity, hook=None):
        self.world, self.sim, self._identity, self.hook = world, world.chains[chain], identity, hook
        self.chain = chain

    def identity(self):
        return self._identity

    def _point(self, name):
        if self.hook is not None:
            self.hook.point(name)

    def _read(self):
        if self.sim.fail_reads > 0:
            self.sim.fail_reads -= 1
            raise ChainUnavailable('simulated HTTP 429')

    def _view_index(self):
        return max(0, len(self.sim.blocks) - 1 - self.sim.lag)

    def head(self):
        self._read()
        block = self.sim.blocks[self._view_index()]
        if self.sim.kind == 'height':
            return {'observedAt': self.world.now, 'height': block['height']}
        return {'observedAt': self.world.now, 'timestamp': block['timestamp']}

    def _view_state(self):
        # Replay the lagged view of the chain: blocks up to the view height.
        view = SimChain.__new__(SimChain)
        view.__dict__.update(self.sim.__dict__)
        view.blocks = [dict(b, txs=list(b['txs'])) for b in self.sim.blocks[:self._view_index() + 1]]
        view._replay()
        return view

    def inspect(self, leg, escrow):
        self._read()
        view = self._view_state() if self.sim.lag else self.sim
        view_height = view.blocks[-1]['height']
        txid = escrow['txid']
        observation = empty_observation()
        record = view.state['escrows'].get(txid)
        if record is None:
            return observation
        observation['found'] = True
        observation['confirmations'] = view_height - record['funded_height'] + 1
        mismatch = [key for key in ('amount', 'hashlock', 'claimant', 'refundee', 'expiry') if record[key] != leg[key]]
        if mismatch:
            observation['problem'] = 'escrow differs from the terms in ' + ', '.join(mismatch)
        else:
            observation['verified'] = True
        if record['spent']:
            observation['spent'] = record['spent']
            observation['spend_txid'] = record['spend_tx']
            observation['spend_confirmations'] = view_height - record['spend_height'] + 1
            observation['preimage'] = record['preimage']
        else:
            # An unconfirmed claim or refund in the mempool is visible with zero confirmations.
            for tx in self.sim.mempool:
                if tx.get('escrow') == txid and tx['kind'] in ('claim', 'refund') and self._plausible(tx, record):
                    observation['spent'] = 'claimed' if tx['kind'] == 'claim' else 'refunded'
                    observation['spend_txid'] = tx['id']
                    observation['preimage'] = tx.get('preimage')
        return observation

    def _plausible(self, tx, record):
        if tx['kind'] == 'claim':
            return hashlib.sha256(bytes.fromhex(tx['preimage'])).hexdigest() == record['hashlock']
        return True

    def escrow_ref(self, leg, txid):
        return {'txid': txid}

    def journal_ids(self, journal):
        return journal_ids(journal, self.chain)

    def transaction_seen(self, txid):
        self._read()
        return self.sim.seen(txid)

    def _send(self, journal, tx):
        self._point('adapter:before-journal')
        record = {'version': 1, 'chain': self.chain, 'txid': tx['id'], 'state': 'prepared_or_submitted'}
        _write_new(Path(journal) / f'{self.chain}-{tx["id"]}.json', (json.dumps(record) + '\n').encode())
        self._point('adapter:after-journal')
        if self.sim.drop_next_broadcast:
            self.sim.drop_next_broadcast = False
            raise TimeoutError('simulated: broadcast never left the machine')
        self.sim.submit(tx)
        self._point('adapter:after-broadcast')
        if self.sim.lose_next_response:
            self.sim.lose_next_response = False
            raise TimeoutError('simulated: response lost after broadcast')
        return {'txid': tx['id']}

    def _tx_id(self, kind, extra=''):
        nonce = self.sim.nonces.get((self._identity, kind, extra), 0)
        self.sim.nonces[(self._identity, kind, extra)] = nonce + 1
        return hashlib.sha256(f'{self.chain}:{self._identity}:{kind}:{extra}:{nonce}'.encode()).hexdigest()

    def fund(self, leg, journal):
        if self.sim.balances.get(self._identity, 0) - self.sim.pending_debit(self._identity) < leg['amount']:
            raise ActionRefused('insufficient funds')
        tx = {'id': self._tx_id('fund'), 'kind': 'fund', 'sender': self._identity, 'amount': leg['amount'], 'hashlock': leg['hashlock'],
              'claimant': leg['claimant'], 'refundee': leg['refundee'], 'expiry': leg['expiry']}
        self.sim.fund_count += 1
        return self._send(journal, tx)

    def claim(self, leg, escrow, preimage, journal):
        tx = {'id': self._tx_id('claim', escrow['txid']), 'kind': 'claim', 'sender': self._identity, 'escrow': escrow['txid'], 'preimage': bytes(preimage).hex()}
        return self._send(journal, tx)

    def refund(self, leg, escrow, journal):
        tx = {'id': self._tx_id('refund', escrow['txid']), 'kind': 'refund', 'sender': self._identity, 'escrow': escrow['txid']}
        return self._send(journal, tx)


class Party:
    """One participant: a store, a role and adapters on the shared simulated world."""

    def __init__(self, root, world, role, identities, hook=None):
        self.world, self.role, self.hook = world, role, hook
        self.store = Store(root, hook)
        self.identities = identities
        self.swap_id = None

    def adapters(self, terms):
        return {name: SimAdapter(self.world, terms['legs'][name]['chain'], self.identities[name], self.hook) for name in ('long', 'short')}


class Harness:
    """Runs an initiator and a responder against one SimWorld, exchanging escrow refs like a messenger."""

    def __init__(self, tmp, world, terms, config, preimage, hook=None):
        self.world, self.terms, self.config, self.hook = world, terms, config, hook
        long_leg, short_leg = terms['legs']['long'], terms['legs']['short']
        self.alice = Party(Path(tmp) / 'alice', world, 'initiator', {'long': long_leg['refundee'], 'short': short_leg['claimant']}, hook)
        self.bob = Party(Path(tmp) / 'bob', world, 'responder', {'long': long_leg['claimant'], 'short': short_leg['refundee']}, hook)
        self.swap_id = hashlib.sha256(json.dumps(terms, sort_keys=True).encode()).hexdigest()[:16]
        self.alice.store.create(self.swap_id, 'initiator', terms, world.now, preimage)
        self.bob.store.create(self.swap_id, 'responder', terms, world.now)
        self.crashes = 0
        self.log = []

    def step(self, party, now=None):
        now = self.world.now if now is None else now
        try:
            with party.store.locked(self.swap_id) as swap:
                result = engine.advance(swap, party.adapters(self.terms), self.config, now)
        except SimulatedCrash as crash:
            self.crashes += 1
            self.log.append((party.role, 'crash', str(crash)))
            return {'status': 'crashed', 'point': str(crash)}
        self.log.append((party.role, result['status'], result.get('state')))
        return result

    def exchange(self):
        """Pass each side's escrow reference to the other (what the people would send each other)."""
        for sender, receiver, leg in ((self.alice, self.bob, 'long'), (self.bob, self.alice, 'short')):
            with sender.store.locked(self.swap_id) as source:
                ref = source.record['escrows'][leg]
            if ref is not None:
                try:
                    with receiver.store.locked(self.swap_id) as target:
                        engine.receive(target, leg, ref, self.world.now)
                except SimulatedCrash as crash:
                    self.crashes += 1
                    self.log.append((receiver.role, 'crash', str(crash)))

    def states(self):
        out = {}
        for party in (self.alice, self.bob):
            with party.store.locked(self.swap_id) as swap:
                out[party.role] = (swap.record['state'], swap.record['inflight'] is not None, swap.record['needs_human'])
        return out

    def settle_inflight(self, roles=None):
        """Play the human: look at the chain and resolve any ambiguous inflight action."""
        resolved = []
        for party in (self.alice, self.bob):
            if roles is not None and party.role not in roles:
                continue
            try:
                with party.store.locked(self.swap_id) as swap:
                    inflight = swap.record['inflight']
                    if inflight is None:
                        continue
                    adapters = party.adapters(self.terms)
                    adapter = adapters[inflight['leg']]
                    unknown = [t for t in adapter.journal_ids(swap.journal_dir) if t not in set(inflight['known'])]
                    how = 'adopt' if len(unknown) == 1 and adapter.transaction_seen(unknown[0]) else 'abandon'
                    engine.resolve(swap, adapters, self.world.now, how)
                    resolved.append((party.role, how))
            except SimulatedCrash as crash:
                self.crashes += 1
                self.log.append((party.role, 'crash', str(crash)))
        return resolved

    def run(self, seconds_per_step=60, max_steps=2000, before_step=None, active=None, human=False, until=None):
        """Tick the world and advance each active party until both are terminal.

        `active(index, harness)` may return the roles allowed to act this step;
        `human=True` resolves any inflight action that automatic recovery cannot.
        """
        terminal = ('done', 'refunded', 'aborted', 'failed')
        for index in range(max_steps):
            if before_step:
                before_step(index, self)
            self.world.tick(seconds_per_step)
            self.exchange()
            roles = ('initiator', 'responder') if active is None else active(index, self)
            waiting = {role for role, (_, inflight, _) in self.states().items() if inflight}
            for party in (self.alice, self.bob):
                if party.role in roles:
                    self.step(party)
            if human and waiting:
                # The engine had a full step to recover on its own; only what it could not resolve reaches a human.
                self.settle_inflight(waiting)
            states = self.states()
            if until is not None and until(self):
                return states
            if all(state in terminal or needs_human for state, _, needs_human in states.values()):
                return states
        return self.states()

    def check_safety(self):
        """Invariants that must hold at every end state."""
        problems = []
        for chain in self.world.chains.values():
            if chain.total_value() != chain.initial_total:
                problems.append(f'value not conserved on {chain.name}')
            funds = {}
            claims = {}
            refunds = {}
            for kind, sender, escrow in chain.broadcasts:
                bucket = {'fund': funds, 'claim': claims, 'refund': refunds}[kind]
                key = sender if kind == 'fund' else (sender, escrow)
                bucket[key] = bucket.get(key, 0) + 1
            # a human abandon may re-fund after a broadcast that never left; those never reach the chain
            if len(chain.state['escrows']) > sum(1 for leg in self.terms['legs'].values() if leg['chain'] == chain.name):
                problems.append(f'more escrows than legs on {chain.name}')
            if any(count > 1 for count in claims.values()):
                problems.append(f'a claim was broadcast twice on {chain.name}')
            if any(count > 1 for count in refunds.values()):
                problems.append(f'a refund was broadcast twice on {chain.name}')
        states = self.states()
        if states['initiator'][0] == 'done' and states['responder'][0] == 'failed':
            problems.append('initiator claimed the short leg and the responder lost the long leg')
        problems += self.check_fairness(states)
        return problems

    def net(self, chain_name, identity):
        chain = self.world.chains[chain_name]
        return chain.state['balances'].get(identity, 0) - chain.credits.get(identity, 0)

    def check_fairness(self, states):
        """When both sides are finished, either the swap happened for both or neither lost or gained anything."""
        terminal = ('done', 'refunded', 'aborted', 'failed')
        if not all(state[0] in terminal for state in states.values()):
            return []
        long_leg, short_leg = self.terms['legs']['long'], self.terms['legs']['short']
        alice = {(long_leg['chain'], long_leg['refundee']): 0, (short_leg['chain'], short_leg['claimant']): 0}
        bob = {(long_leg['chain'], long_leg['claimant']): 0, (short_leg['chain'], short_leg['refundee']): 0}
        deltas = {}
        for name, keys in (('alice', alice), ('bob', bob)):
            for key in keys:
                deltas[(name, key)] = self.net(*key)
        def total(name, chain):
            return sum(v for (who, (c, _)), v in deltas.items() if who == name and c == chain)
        swapped = all(total('alice', c) == (-long_leg['amount'] if c == long_leg['chain'] else 0) + (short_leg['amount'] if c == short_leg['chain'] else 0)
                      for c in {long_leg['chain'], short_leg['chain']}) and all(
            total('bob', c) == (long_leg['amount'] if c == long_leg['chain'] else 0) + (-short_leg['amount'] if c == short_leg['chain'] else 0)
            for c in {long_leg['chain'], short_leg['chain']})
        unchanged = all(value == 0 for value in deltas.values())
        if not (swapped or unchanged):
            return ['unfair end state: ' + str({f'{who}:{key[0]}': v for (who, key), v in deltas.items()})]
        return []


def sim_heads(world, long_chain, short_chain):
    heads = {}
    for key, name in (('long', long_chain), ('short', short_chain)):
        chain = world.chains[name]
        block = chain.blocks[-1]
        heads[key] = {'observedAt': world.now, 'height': block['height']} if chain.kind == 'height' else {'observedAt': world.now, 'timestamp': block['timestamp']}
    return heads


def plan_terms(world, config, long_chain, short_chain, preimage, amounts=(1000, 2000), names=('alice', 'bob')):
    """Terms with compliant expiries from the P1 policy, funding both parties on their own chains."""
    heads = sim_heads(world, long_chain, short_chain)
    plan = planner.plan_with_margin(config, long_chain, short_chain, heads, world.now)
    if not plan['verdict']['ok']:
        raise ValueError('No compliant plan: ' + json.dumps(plan['verdict']['reasons']))
    alice, bob = names
    terms = {'version': 1, 'hashlock': hashlib.sha256(bytes(preimage)).hexdigest(), 'legs': {
        'long': {'chain': long_chain, 'amount': amounts[0], 'refundee': f'{alice}@{long_chain}', 'claimant': f'{bob}@{long_chain}', 'expiry': plan['long']['expiry']},
        'short': {'chain': short_chain, 'amount': amounts[1], 'refundee': f'{bob}@{short_chain}', 'claimant': f'{alice}@{short_chain}', 'expiry': plan['short']['expiry']}}}
    return terms
