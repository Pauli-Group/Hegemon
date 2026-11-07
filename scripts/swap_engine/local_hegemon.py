"""Engine swaps that involve a real local Hegemon chain, in fresh worlds.

Hegemon's block time is a protocol constant of about 60 seconds, so these runs take real minutes (a happy swap) to hours
(anything that waits for a refund deadline, which the timelock policy places well over an hour away). Each scenario runs in
its own `LocalWorld` so several can run side by side; every world copies the Hegemon template into a fresh directory and
stops every process it started. Run one:

    python3 -m swap_engine.local_hegemon --scenario happy --long hegemon --short ethereum --output /tmp/out.json

Scenarios: happy; no_counterparty (the responder never funds, the initiator refunds the Hegemon long leg); both_refund
(the initiator vanishes after the responder funded the Hegemon short leg, both refund); late_claim (the initiator is offline
past the Hegemon short leg's deadline, the responder refunds, and a claim attempted afterwards is refused by the chain).
Fixture timing is `local_world.hegemon_timing`; each run ends by checking that the blocks it saw stayed inside its windows.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from swap_engine.local_world import LocalSwap, LocalWorld, local_timing
from swap_engine.adapter import ActionRefused

SCENARIOS = ('happy', 'no_counterparty', 'both_refund', 'late_claim')


def _swap(world, long_chain, short_chain, tag):
    swap = LocalSwap(world, long_chain, short_chain, tag)
    swap.verbose = os.environ.get('HEGEMON_LOCAL_VERBOSE', '1') == '1'
    if swap.verbose:
        print('plan', json.dumps(swap.plan['long']), json.dumps(swap.plan['short']), flush=True)
    return swap


def _chains(*names):
    return tuple(dict.fromkeys(names))


def _result(swap, started, before, outcome, states, extra=None):
    problems = swap.expected_after(before, outcome) if before is not None else []
    return {'states': {role: value[0] for role, value in states.items()}, 'balance_problems': problems,
            'seconds': round(time.time() - started), 'plan': {'long': swap.plan['long'], 'short': swap.plan['short']},
            'log_tail': [list(entry) for entry in swap.log[-6:]], **(extra or {})}


def happy(world, long_chain, short_chain, tag, timeout=3600):
    swap = _swap(world, long_chain, short_chain, tag)
    started, before = time.time(), swap.balances()
    states = swap.run(timeout=timeout)
    result = _result(swap, started, before, 'swapped', states)
    result['ok'] = {k: v[0] for k, v in states.items()} == {'initiator': 'done', 'responder': 'done'} and not result['balance_problems']
    return result


def no_counterparty(world, long_chain, short_chain, tag, timeout=6 * 3600):
    swap = _swap(world, long_chain, short_chain, tag)
    started, before = time.time(), swap.balances()
    states = swap.run(timeout=timeout, roles=('initiator',))
    result = _result(swap, started, before, 'unchanged', states)
    result['ok'] = states['initiator'][0] == 'refunded' and states['responder'][0] == 'terms_saved' and not result['balance_problems']
    return result


def both_refund(world, long_chain, short_chain, tag, timeout=6 * 3600):
    swap = _swap(world, long_chain, short_chain, tag)
    started, before = time.time(), swap.balances()
    swap.run(timeout=3600, until=lambda s: s.states()['responder'][0] == 'short_fund_submitted')
    states = swap.run(timeout=timeout, roles=('responder',))  # the initiator is gone
    responder = states['responder'][0]
    states = swap.run(timeout=timeout, roles=('initiator',))  # and returns after both deadlines
    result = _result(swap, started, before, 'unchanged', states, {'responder_before_initiator_returned': responder})
    result['ok'] = responder == 'refunded' and states['initiator'][0] == 'refunded' and not result['balance_problems']
    return result


def late_claim(world, long_chain, short_chain, tag, timeout=6 * 3600):
    """The initiator misses the short leg's deadline; the responder refunds; the late claim must be refused."""
    swap = _swap(world, long_chain, short_chain, tag)
    started, before = time.time(), swap.balances()
    swap.run(timeout=3600, until=lambda s: s.states()['responder'][0] == 'short_fund_submitted')  # then the initiator goes offline
    states = swap.run(timeout=timeout, roles=('responder',))
    responder = states['responder'][0]
    refused = None
    with swap.stores['initiator'].locked(swap.swap_id) as source:
        escrow = source.record['escrows']['short']
    with swap.stores['responder'].locked(swap.swap_id) as source:
        escrow = escrow or source.record['escrows']['short']
    journal = swap.world.tmp / 'late-claim-journal'
    journal.mkdir(mode=0o700, exist_ok=True)
    try:
        swap.alice['short'].claim({**swap.terms['legs']['short'], 'hashlock': swap.terms['hashlock']}, escrow, swap.preimage, str(journal))
        refused = False
    except ActionRefused:
        refused = True
    states = swap.run(timeout=timeout, roles=('initiator',))
    result = _result(swap, started, before, 'unchanged', states, {'responder_before_late_claim': responder, 'late_claim_refused': refused})
    result['ok'] = responder == 'refunded' and refused is True and states['initiator'][0] == 'refunded' and not result['balance_problems']
    return result


RUNNERS = {'happy': happy, 'no_counterparty': no_counterparty, 'both_refund': both_refund, 'late_claim': late_claim}


def run_scenario(scenario, long_chain, short_chain, tag=None):
    world = LocalWorld(_chains(long_chain, short_chain))
    try:
        started = time.time()
        result = RUNNERS[scenario](world, long_chain, short_chain, tag or f'{scenario[:3]}-{long_chain[:3]}-{short_chain[:3]}')
        profile = world.profiles['hegemon']
        windows = local_timing(('hegemon',))['chains']['hegemon']
        result.update(scenario=scenario, long=long_chain, short=short_chain, started=int(started),
                      hegemon_blocks=len(profile.block_times()) - profile.start_height,
                      hegemon_peers=profile.rpc('system_health')['peers'],
                      window_problems=profile.spans_within_windows(windows))
        # `swap_ok` is the swap's own outcome; `ok` also needs the fixture to have stayed inside its modelled windows. A window
        # holds with probability 1 - 1e-3 per span, and a run checks hundreds of overlapping spans, so an excursion is expected
        # in a noticeable fraction of runs: it means this run did not test the timing claim, not that the engine failed.
        result['swap_ok'] = bool(result['ok']) and result['hegemon_peers'] == 0
        result['ok'] = result['swap_ok'] and not result['window_problems']
        return result
    finally:
        world.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--scenario', choices=SCENARIOS, required=True)
    parser.add_argument('--long', required=True)
    parser.add_argument('--short', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if 'hegemon' not in (args.long, args.short):
        parser.error('one leg must be hegemon')
    if args.output.exists():
        parser.error('the output file must not exist; every run is fresh')
    result = run_scenario(args.scenario, args.long, args.short)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
