"""Two-party HTLC swap engine: a pure decision function and a one-write executor.

`decide(...)` maps (record, terms, observations, timing config, now) to the next
step with no I/O. `advance(swap, adapters, config, now)` gathers observations
through the chain adapters, applies state-only transitions, and performs at most
one signed write per call. See .agent/SWAP_ENGINE_EXECPLAN.md for the design.

Legs. The initiator funds the long leg, refundable later, and claims the short
leg. The responder funds the short leg and claims the long leg after reading the
preimage from the initiator's claim. `adapters` maps 'long' and 'short' to the
local participant's adapter for that leg's chain.
"""
import hashlib
import secrets

try:
    from swap_engine import timelock_policy as policy
    from swap_engine.adapter import ActionRefused, ChainUnavailable, check_escrow_ref, check_observation
    from swap_engine.store import leg_terms
except ImportError:  # run as a plain module from the package directory
    import timelock_policy as policy
    from adapter import ActionRefused, ChainUnavailable, check_escrow_ref, check_observation
    from store import leg_terms

LONG, SHORT = 'long', 'short'
TERMINAL = ('done', 'refunded', 'aborted', 'failed')
TRANSIENT_CODES = ('head-stale', 'clock-drift')
MAX_STEPS = 8

# (role, from_state, to_state, trigger). The decision function implements exactly these.
TRANSITIONS = [
    ('initiator', 'terms_saved', 'long_fund_submitted', 'policy ok on fresh heads: fund the long leg'),
    ('initiator', 'terms_saved', 'aborted', 'policy deterministically fails; nothing is funded'),
    ('initiator', 'long_fund_submitted', 'long_funded', 'long escrow confirmed and matches terms'),
    ('initiator', 'long_funded', 'long_fund_submitted', 'long escrow disappears (reorg); wait, never fund twice'),
    ('initiator', 'long_funded', 'short_verified', 'short escrow confirmed, matches terms, unspent, policy and claim cutoff ok'),
    ('initiator', 'long_funded', 'refund_submitted', 'long leg refund is due'),
    ('initiator', 'short_verified', 'short_claim_submitted', 'claim the short leg with the preimage'),
    ('initiator', 'short_verified', 'long_funded', 'short leg no longer safe to claim'),
    ('initiator', 'short_claim_submitted', 'done', 'claim confirmed'),
    ('initiator', 'short_claim_submitted', 'long_funded', 'short leg refunded before the claim landed'),
    ('initiator', 'refund_submitted', 'refunded', 'refund confirmed'),
    ('responder', 'terms_saved', 'long_verified', 'long escrow confirmed, matches terms, unspent, policy ok'),
    ('responder', 'terms_saved', 'aborted', 'policy fails or long escrow contradicts terms; nothing is funded'),
    ('responder', 'long_verified', 'short_fund_submitted', 'long still verified and policy ok: fund the short leg'),
    ('responder', 'long_verified', 'aborted', 'policy or long escrow no longer acceptable; nothing is funded'),
    ('responder', 'short_fund_submitted', 'short_funded', 'short escrow confirmed and matches terms'),
    ('responder', 'short_funded', 'short_fund_submitted', 'short escrow disappears (reorg); wait, never fund twice'),
    ('responder', 'short_funded', 'preimage_known', 'initiator claim observed; preimage stored'),
    ('responder', 'short_funded', 'refund_submitted', 'short leg refund is due'),
    ('responder', 'preimage_known', 'long_claim_submitted', 'claim the long leg with the learned preimage'),
    ('responder', 'preimage_known', 'failed', 'long leg was refunded before the claim'),
    ('responder', 'long_claim_submitted', 'done', 'claim confirmed'),
    ('responder', 'long_claim_submitted', 'failed', 'long leg refunded before the claim landed'),
    ('responder', 'refund_submitted', 'refunded', 'refund confirmed'),
]


def own_leg(role):
    return LONG if role == 'initiator' else SHORT


def other_leg(role):
    return SHORT if role == 'initiator' else LONG


def confirmations_needed(config, chain):
    return config['chains'][chain]['confirmations']


def refund_due(config, leg, head):
    """True when the contract lets the refundee take the money back (by chain head, not wall clock)."""
    chain = config['chains'][leg['chain']]
    if chain['kind'] == 'height':
        return head['height'] >= leg['expiry'] + chain['refundOffsetBlocks']
    return head['timestamp'] >= leg['expiry']


def claim_blocked_by_chain(config, leg, head):
    """Time chains (Ethereum, Cardano) refuse a claim at or after the deadline: do not try."""
    chain = config['chains'][leg['chain']]
    if chain['kind'] == 'height':
        return False
    return head['timestamp'] >= leg['expiry']


def _wait(why, **detail):
    return {'kind': 'wait', 'why': why, 'detail': detail}


def _move(to, why, **extra):
    return {'kind': 'move', 'to': to, 'why': why, **extra}


def _act(action, leg, to, why):
    return {'kind': 'act', 'action': action, 'leg': leg, 'to': to, 'why': why}


def _halt(why, state=None, **detail):
    return {'kind': 'halt', 'why': why, 'state': state, 'detail': detail}


def _verdict(terms, obs, config, now):
    legs = {name: {'chain': terms['legs'][name]['chain'], 'expiry': terms['legs'][name]['expiry']} for name in (LONG, SHORT)}
    heads = obs['heads']
    if heads[LONG] is None or heads[SHORT] is None:
        return None
    return policy.check_ordered(config, legs[LONG], legs[SHORT], {'long': heads[LONG], 'short': heads[SHORT]}, now)


def _policy_gate(terms, obs, config, now):
    """None when policy allows acting; otherwise a wait or abort decision for a not-yet-funded party."""
    verdict = _verdict(terms, obs, config, now)
    if verdict is None:
        return _wait('chain head unavailable', errors=obs['errors'])
    if verdict['ok']:
        return None
    codes = [item['code'] for item in verdict['reasons']]
    if all(code in TRANSIENT_CODES for code in codes):
        return _wait('policy needs a fresher observation: ' + ', '.join(codes), codes=codes)
    return {'kind': 'abort', 'why': 'timelock policy rejects these terms: ' + ', '.join(codes), 'codes': codes, 'reasons': verdict['reasons']}


def _leg_ready(observation, need):
    return observation is not None and observation['found'] and observation['verified'] and observation['confirmations'] >= need


def _stalled(record, config, terms, key, leg, now):
    """A submitted claim, refund or fund that no read has shown for far longer than inclusion needs."""
    entry = record['submitted'].get(key)
    if entry is None:
        return False
    chain = config['chains'][terms['legs'][leg]['chain']]
    limit = policy.confirm_seconds(chain) + policy.action_seconds(chain) + config['policy']['reactionSeconds']
    return now - entry['at'] > limit


def decide(record, terms, obs, config, now):
    """Return the next step. Pure: no I/O, no mutation."""
    role, state = record['role'], record['state']
    if state in TERMINAL:
        return {'kind': 'terminal', 'why': state}
    if record.get('needs_human'):
        return _halt('needs a human: ' + record['needs_human'])
    own, other = own_leg(role), other_leg(role)
    legs = terms['legs']
    heads, observed = obs['heads'], obs['legs']
    own_obs, other_obs = observed[own], observed[other]
    need_own = confirmations_needed(config, legs[own]['chain'])
    need_other = confirmations_needed(config, legs[other]['chain'])

    def own_refund_step(from_state):
        head = heads[own]
        if head is not None and refund_due(config, legs[own], head):
            return _act('refund', own, 'refund_submitted', 'the refund deadline has passed')
        return None

    def own_funding_confirmed(waiting_state, confirmed_state):
        if own_obs is None:
            return _wait('own leg unreadable', errors=obs['errors'])
        if own_obs['problem']:
            return _halt('the escrow we funded does not match the terms: ' + own_obs['problem'])
        if _leg_ready(own_obs, need_own):
            return _move(confirmed_state, 'own escrow confirmed')
        if not own_obs['found'] and heads[own] is not None and refund_due(config, legs[own], heads[own]):
            return _halt('funding transaction not seen by the deadline; check the chain, then resolve')
        if not own_obs['found'] and _stalled(record, config, terms, 'fund', own, now):
            return _halt('funding transaction not visible long after submission; check the chain, then resolve')
        return _wait('waiting for own escrow confirmations', have=own_obs['confirmations'], need=need_own)

    def own_refund_progress():
        if own_obs is None:
            return _wait('own leg unreadable', errors=obs['errors'])
        if own_obs['spent'] == 'refunded' and own_obs['spend_confirmations'] >= need_own:
            return _move('refunded', 'refund confirmed')
        if own_obs['spent'] == 'claimed':
            return _halt('our escrow was claimed while we were refunding it; inspect the chain')
        if own_obs['spent'] is None and _stalled(record, config, terms, 'refund', own, now):
            return _halt('refund not visible long after submission; check the chain, then resolve')
        return _wait('waiting for refund confirmations')

    if role == 'initiator':
        if state == 'terms_saved':
            gate = _policy_gate(terms, obs, config, now)
            if gate is None:
                return _act('fund', LONG, 'long_fund_submitted', 'policy allows funding the long leg')
            return gate
        if state == 'long_fund_submitted':
            return own_funding_confirmed('long_fund_submitted', 'long_funded')
        if state in ('long_funded', 'short_verified'):
            if own_obs is None:
                return _wait('own leg unreadable', errors=obs['errors'])
            if not own_obs['found']:
                return _move('long_fund_submitted', 'long escrow no longer visible; waiting, never funding twice')
            if own_obs['spent'] == 'refunded':
                return _move('refunded', 'long leg already refunded')
            if own_obs['spent'] == 'claimed':
                return _halt('long leg was claimed before we claimed the short leg; the preimage may have leaked')
            if state == 'long_funded':
                refund = own_refund_step(state)
                if refund:
                    return refund
                if other_obs is None or record['escrows'][SHORT] is None:
                    return _wait('waiting for the responder to fund the short leg' if record['escrows'][SHORT] is None else 'short leg unreadable', errors=obs['errors'])
                if other_obs['problem']:
                    return _wait('short leg contradicts the terms: ' + other_obs['problem'])
                if not _leg_ready(other_obs, need_other):
                    return _wait('short leg not yet confirmed and verified', have=other_obs['confirmations'], need=need_other)
                if other_obs['spent'] is not None:
                    return _wait('short leg already spent')
                if not _claim_ok(terms, obs, config, now):
                    return _wait('policy or claim cutoff does not allow claiming the short leg')
                return _move('short_verified', 'short leg verified; policy and claim cutoff ok')
            # short_verified: re-check everything immediately before revealing the preimage
            if heads[own] is not None and refund_due(config, legs[own], heads[own]):
                return _move('long_funded', 'long leg refund due; not claiming')
            if other_obs is None:
                return _wait('short leg unreadable', errors=obs['errors'])
            if not _leg_ready(other_obs, need_other) or other_obs['spent'] is not None or not _claim_ok(terms, obs, config, now):
                return _move('long_funded', 'short leg no longer safe to claim')
            if not obs['preimage_available']:
                return _halt('the preimage file is missing or does not match the hashlock')
            return _act('claim', SHORT, 'short_claim_submitted', 'claiming the short leg reveals the preimage')
        if state == 'short_claim_submitted':
            if other_obs is None:
                return _wait('short leg unreadable', errors=obs['errors'])
            if other_obs['spent'] == 'claimed' and other_obs['spend_confirmations'] >= need_other:
                return _move('done', 'short claim confirmed')
            if other_obs['spent'] == 'refunded':
                return _move('long_funded', 'short leg was refunded before our claim landed')
            if other_obs['spent'] is None and _stalled(record, config, terms, 'claim', other, now):
                return _halt('claim not visible long after submission; check the chain, then resolve')
            return _wait('waiting for the claim to confirm')
        if state == 'refund_submitted':
            return own_refund_progress()
    else:
        if state in ('terms_saved', 'long_verified'):
            if other_obs is None or record['escrows'][LONG] is None:
                return _wait('waiting for the initiator long leg' if record['escrows'][LONG] is None else 'long leg unreadable', errors=obs['errors'])
            if other_obs['problem']:
                return {'kind': 'abort', 'why': 'long escrow contradicts the terms: ' + other_obs['problem'], 'codes': ['escrow-mismatch']}
            gate = _policy_gate(terms, obs, config, now)
            if gate is not None:
                return gate
            if not _leg_ready(other_obs, need_other) or other_obs['spent'] is not None:
                return _wait('long leg not yet confirmed, verified and unspent', have=other_obs['confirmations'], need=need_other)
            if state == 'terms_saved':
                return _move('long_verified', 'long leg verified; policy ok')
            return _act('fund', SHORT, 'short_fund_submitted', 'long leg verified and policy ok: fund the short leg')
        if state == 'short_fund_submitted':
            return own_funding_confirmed('short_fund_submitted', 'short_funded')
        if state == 'short_funded':
            if own_obs is None:
                return _wait('own leg unreadable', errors=obs['errors'])
            if not own_obs['found']:
                return _move('short_fund_submitted', 'short escrow no longer visible; waiting, never funding twice')
            if own_obs['spent'] == 'claimed':
                if own_obs['preimage'] is None:
                    return _wait('short leg claimed but the preimage is not readable yet')
                return _move('preimage_known', 'initiator claim observed', learn_preimage=own_obs['preimage'])
            if own_obs['spent'] == 'refunded':
                return _move('refunded', 'short leg already refunded')
            refund = own_refund_step(state)
            if refund:
                return refund
            return _wait('waiting for the initiator to claim or the deadline')
        if state in ('preimage_known', 'long_claim_submitted'):
            if other_obs is None:
                return _wait('long leg unreadable', errors=obs['errors'])
            if state == 'long_claim_submitted':
                if other_obs['spent'] == 'claimed' and other_obs['spend_confirmations'] >= need_other:
                    return _move('done', 'long claim confirmed')
                if other_obs['spent'] == 'refunded':
                    return _move('failed', 'long leg was refunded before our claim landed')
                if other_obs['spent'] is None and _stalled(record, config, terms, 'claim', other, now):
                    return _halt('claim not visible long after submission; check the chain, then resolve')
                return _wait('waiting for the claim to confirm')
            if other_obs['spent'] == 'refunded':
                return _move('failed', 'long leg was refunded before we could claim it')
            if other_obs['spent'] == 'claimed':
                return _move('done', 'long leg already claimed')
            if heads[other] is not None and claim_blocked_by_chain(config, legs[other], heads[other]):
                return _move('failed', 'long leg deadline passed on a chain that refuses late claims')
            if heads[other] is None:
                return _wait('long chain head unavailable', errors=obs['errors'])
            if not obs['preimage_available']:
                return _halt('the learned preimage file is missing or does not match the hashlock')
            return _act('claim', LONG, 'long_claim_submitted', 'preimage is public: claim the long leg')
        if state == 'refund_submitted':
            return own_refund_progress()
    return _halt('unknown state ' + state)


def _claim_ok(terms, obs, config, now):
    """Initiator gate before revealing the preimage: policy ok and the short leg far enough from refund."""
    verdict = _verdict(terms, obs, config, now)
    if verdict is None or not verdict['ok']:
        return False
    short = {'chain': terms['legs'][SHORT]['chain'], 'expiry': terms['legs'][SHORT]['expiry']}
    window = policy.leg_window(config, short, obs['heads'][SHORT], now)
    return window['firstRefund'] >= policy.action_seconds(config['chains'][short['chain']])


def claim_gate(role, terms, heads, config, now):
    """May a hosted page submit this participant's claim now? Pure; the page has its own copy (swap-flow.mjs).

    The claimed leg is the other leg (the initiator claims short, the responder claims long). A claim is
    refused when the chain would refuse it or the refund is due, and when fewer than one action time (build
    plus inclusion) remains before the last safe claim (`submitBySeconds` < 0). The initiator's claim
    additionally needs the engine's own gate: policy ok on both legs and the short leg not too close to its
    refund, because a claim that misses its deadline still reveals the preimage.
    """
    name = other_leg(role)
    leg, head = terms['legs'][name], heads.get(name)
    if head is None:
        return {'ok': False, 'reasons': ['chain-head-unavailable'], 'submitBySeconds': None}
    chain = config['chains'][leg['chain']]
    window = policy.leg_window(config, {'chain': leg['chain'], 'expiry': leg['expiry']}, head, now)
    reasons = []
    if window['expired'] or refund_due(config, leg, head) or claim_blocked_by_chain(config, leg, head):
        reasons.append('claim-closed')
    submit_by = window['lastClaim'] - policy.action_seconds(chain)
    if submit_by < 0:
        reasons.append('inside-claim-cutoff')
    if role == 'initiator' and not _claim_ok(terms, {'heads': heads}, config, now):
        reasons.append('policy-rejects-claim')
    return {'ok': not reasons, 'reasons': reasons, 'submitBySeconds': submit_by}


def explain(role):
    return [(a, b, c) for (r, a, b, c) in TRANSITIONS if r == role]


# ---------------------------------------------------------------- executor

class IdentityMismatch(Exception):
    pass


def _check_identities(swap, adapters):
    terms, role = swap.terms, swap.record['role']
    own, other = own_leg(role), other_leg(role)
    for name in (LONG, SHORT):
        adapter = adapters.get(name)
        if adapter is None or adapter.chain != terms['legs'][name]['chain']:
            raise IdentityMismatch(f'The {name} adapter does not serve chain {terms["legs"][name]["chain"]}')
    if adapters[own].identity() != terms['legs'][own]['refundee']:
        raise IdentityMismatch('The wallet for our leg is not the refundee named in the terms')
    if adapters[other].identity() != terms['legs'][other]['claimant']:
        raise IdentityMismatch('The wallet for the counterparty leg is not the claimant named in the terms')


def observe(swap, adapters, now):
    """Read heads and both legs. Failures become None plus an error string, never a guess."""
    terms = swap.terms
    obs = {'now': now, 'heads': {LONG: None, SHORT: None}, 'legs': {LONG: None, SHORT: None}, 'errors': {}, 'preimage_available': False}
    for name in (LONG, SHORT):
        try:
            head = adapters[name].head()
            if not isinstance(head, dict) or not isinstance(head.get('observedAt'), int):
                raise ValueError('Malformed head')
            obs['heads'][name] = head
        except ChainUnavailable as error:
            obs['errors'][name] = f'head: {error}'
    for name in (LONG, SHORT):
        escrow = swap.record['escrows'][name]
        if escrow is None:
            continue
        try:
            value = check_observation(adapters[name].inspect(leg_terms(terms, name), escrow))
        except ChainUnavailable as error:
            obs['errors'][name] = f'inspect: {error}'
            continue
        if value['preimage'] is not None and hashlib.sha256(bytes.fromhex(value['preimage'])).hexdigest() != terms['hashlock']:
            obs['errors'][name] = 'inspect: provider returned a preimage that does not match the hashlock'
            value = {**value, 'preimage': None}
        obs['legs'][name] = value
    secret_name = 'secret' if swap.record['role'] == 'initiator' else 'learned-preimage'
    try:
        secret = swap.read_secret(secret_name)
    except ValueError:
        secret = None
    obs['preimage_available'] = secret is not None
    if secret is not None:
        secret[:] = b'\0' * len(secret)
    return obs


def _recover(swap, adapters, now):
    """Resolve an inflight action from the journal. Never signs or broadcasts."""
    record = swap.record
    inflight = record['inflight']
    adapter = adapters[inflight['leg']]
    known = set(inflight['known'])
    new = [txid for txid in adapter.journal_ids(swap.journal_dir) if txid not in known]
    if not new:
        record['inflight'] = None
        swap.log(now, 'inflight-cleared', action=inflight['action'], why='nothing was signed')
        swap.save()
        return {'status': 'recovered', 'detail': 'nothing was signed; the inflight marker is cleared'}
    if len(new) > 1:
        return {'status': 'inflight', 'detail': 'several unknown journal records; resolve by hand', 'txids': new}
    txid = new[0]
    try:
        seen = adapter.transaction_seen(txid)
    except ChainUnavailable as error:
        return {'status': 'inflight', 'detail': f'cannot read the chain yet: {error}', 'txid': txid}
    if not seen:
        return {'status': 'inflight', 'detail': 'a transaction was signed but the chain does not show it; inspect it, then run resolve --adopt or --abandon', 'txid': txid}
    _adopt(swap, adapter, txid, now, 'chain shows the journaled transaction')
    return {'status': 'recovered', 'detail': 'adopted journaled transaction', 'txid': txid}


def _adopt(swap, adapter, txid, now, why):
    record = swap.record
    inflight = record['inflight']
    leg = inflight['leg']
    if inflight['action'] == 'fund':
        record['escrows'][leg] = check_escrow_ref(adapter.escrow_ref(leg_terms(swap.terms, leg), txid))
    record['txids'][inflight['action'] + ':' + leg] = txid
    record['submitted'][inflight['action']] = {'txid': txid, 'at': now}
    record['state'] = inflight['to']
    record['inflight'] = None
    swap.log(now, 'adopted', action=inflight['action'], txid=txid, why=why)
    swap.save()


def resolve(swap, adapters, now, how):
    """Human resolution of an ambiguous inflight action after checking the chain by hand."""
    record = swap.record
    inflight = record['inflight']
    if inflight is None:
        raise ValueError('Nothing is inflight')
    adapter = adapters[inflight['leg']]
    if how == 'adopt':
        new = [t for t in adapter.journal_ids(swap.journal_dir) if t not in set(inflight['known'])]
        if len(new) != 1:
            raise ValueError('Adopt needs exactly one unknown journal record')
        _adopt(swap, adapter, new[0], now, 'resolved by a human: adopt')
    elif how == 'abandon':
        record['inflight'] = None
        swap.log(now, 'abandoned', action=inflight['action'], why='resolved by a human: transaction declared not broadcast')
        swap.save()
    else:
        raise ValueError('how must be adopt or abandon')
    return {'status': 'resolved', 'how': how, 'state': record['state']}


def abort(swap, now, reason):
    """Abort a swap in which we have funded nothing."""
    record = swap.record
    if record['state'] not in ('terms_saved', 'long_verified') or record['inflight'] or record['txids'].get('fund:' + own_leg(record['role'])):
        raise ValueError('Only a swap that has funded nothing can be aborted')
    record['state'] = 'aborted'
    swap.log(now, 'aborted', why=reason)
    swap.save()
    return {'status': 'aborted'}


def receive(swap, leg, escrow, now):
    """Record the counterparty's escrow reference. Untrusted until inspect() verifies it."""
    record = swap.record
    if leg != other_leg(record['role']):
        raise ValueError('Only the counterparty leg can be received')
    check_escrow_ref(escrow)
    if record['escrows'][leg] is not None and record['escrows'][leg] != escrow:
        raise ValueError('A different escrow reference is already recorded for this leg')
    if record['escrows'][leg] is None:
        record['escrows'][leg] = escrow
        swap.log(now, 'received', leg=leg)
        swap.save()
    return {'status': 'received', 'leg': leg}


def _write_action(swap, adapters, decision, now):
    record, terms = swap.record, swap.terms
    action, leg = decision['action'], decision['leg']
    adapter = adapters[leg]
    known = list(adapter.journal_ids(swap.journal_dir))
    record['inflight'] = {'action': action, 'leg': leg, 'to': decision['to'], 'intent': secrets.token_hex(8), 'known': known, 'at': now}
    swap.log(now, 'inflight', action=action, leg=leg)
    swap.save()
    swap.point('engine:before-write')
    secret = None
    try:
        lt = leg_terms(terms, leg)
        if action == 'fund':
            result = adapter.fund(lt, swap.journal_dir)
        elif action == 'claim':
            secret = swap.read_secret('secret' if record['role'] == 'initiator' else 'learned-preimage')
            if secret is None:
                raise ActionRefused('preimage missing')
            result = adapter.claim(lt, record['escrows'][leg], secret, swap.journal_dir)
        elif action == 'refund':
            result = adapter.refund(lt, record['escrows'][leg], swap.journal_dir)
        else:
            raise ValueError('Unknown action')
    except ActionRefused as error:
        new = [t for t in adapter.journal_ids(swap.journal_dir) if t not in set(known)]
        if not new:
            record['inflight'] = None
            swap.log(now, 'refused', action=action, why=str(error)[:200])
            swap.save()
            return {'status': 'refused', 'action': action, 'detail': str(error)[:200]}
        return {'status': 'inflight', 'action': action, 'detail': 'refused after journaling; resolve by hand'}
    except Exception as error:
        outcome = _recover(swap, adapters, now)
        outcome['error'] = type(error).__name__
        return outcome
    finally:
        if secret is not None:
            secret[:] = b'\0' * len(secret)
    swap.point('engine:after-write')
    txid = result['txid']
    if action == 'fund':
        record['escrows'][leg] = check_escrow_ref(adapter.escrow_ref(leg_terms(terms, leg), txid))
    record['txids'][action + ':' + leg] = txid
    record['submitted'][action] = {'txid': txid, 'at': now}
    record['state'] = decision['to']
    record['inflight'] = None
    swap.log(now, 'submitted', action=action, leg=leg, txid=txid)
    swap.save()
    return {'status': 'submitted', 'action': action, 'txid': txid}


def advance(swap, adapters, config, now):
    """Do the next safe thing. At most one signed write per call."""
    record = swap.record
    _check_identities(swap, adapters)
    if record['inflight'] is not None:
        return {**_recover(swap, adapters, now), 'state': record['state']}
    if record['state'] in TERMINAL:
        return {'status': 'terminal', 'state': record['state']}
    if record.get('needs_human'):
        return {'status': 'needs-human', 'state': record['state'], 'detail': record['needs_human']}
    obs = observe(swap, adapters, now)
    last = None
    for _ in range(MAX_STEPS):
        decision = decide(record, swap.terms, obs, config, now)
        kind = decision['kind']
        if kind == 'move':
            if decision.get('learn_preimage'):
                secret = bytes.fromhex(decision['learn_preimage'])
                if swap.read_secret('learned-preimage') is None:
                    swap.write_secret('learned-preimage', secret)
                obs['preimage_available'] = True
            record['state'] = decision['to']
            swap.log(now, 'moved', to=decision['to'], why=decision['why'])
            swap.save()
            last = decision
            continue
        if kind == 'act':
            return {**_write_action(swap, adapters, decision, now), 'state': record['state']}
        if kind == 'abort':
            record['state'] = 'aborted'
            swap.log(now, 'aborted', why=decision['why'][:300], codes=decision.get('codes'))
            swap.save()
            return {'status': 'aborted', 'state': 'aborted', 'detail': decision['why']}
        if kind == 'halt':
            record['needs_human'] = decision['why'][:300]
            swap.log(now, 'needs-human', why=decision['why'][:300])
            swap.save()
            return {'status': 'needs-human', 'state': record['state'], 'detail': decision['why']}
        if kind == 'terminal':
            return {'status': 'terminal', 'state': record['state'], 'detail': last['why'] if last else None}
        return {'status': 'waiting', 'state': record['state'], 'detail': decision['why'], 'info': decision.get('detail')}
    return {'status': 'waiting', 'state': record['state'], 'detail': 'step limit reached'}


def clear_needs_human(swap, now, note):
    """A human has inspected the chain and wants the engine to re-evaluate."""
    if not swap.record.get('needs_human'):
        raise ValueError('Nothing to clear')
    swap.record['needs_human'] = None
    swap.log(now, 'needs-human-cleared', note=note[:200])
    swap.save()
