#!/usr/bin/env python3
"""Command line for the two-party swap engine (scripts/swap_engine).

Nothing secret is accepted on the command line or printed. Wallets are named by file path in a JSON
config; the initiator's preimage is generated here, stored 0600 in the swap directory and never shown.
Every command prints one JSON document so scripts and people can both read it.

  plan     print compliant expiries for a chain pair from live chain heads
  init     create a swap from terms (initiator: --new-preimage fills in the hashlock)
  status   one swap or all swaps
  advance  take the next safe step once, or --watch SECONDS to keep going until finished
  explain  the transitions the engine allows for a role
  export   print this side's escrow reference to give to the counterparty
  receive  record the counterparty's escrow reference
  resolve  settle an ambiguous in-flight action after checking the chain (--adopt or --abandon)
  clear    clear a needs-human flag after inspecting the chain
  abort    abort a swap in which nothing is funded

Wallet config (default ~/.config/hegemon/swap-wallets.json, or --wallets / HEGEMON_SWAP_WALLETS):
  {"bitcoin":  {"key_file": "/path/bitcoin-testnet4.key"},
   "ethereum": {"wallet_file": "/path/ethereum-sepolia.key"},
   "cardano":  {"skey": "/path/cardano.skey", "keyhash": "<56 hex>", "address": "addr_test1..."}}
Run `make setup` first; operators of shared Hegemon mining hosts must also set HEGEMON_SEEDS and keep NTP/chrony on.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from swap_engine import engine, planner  # noqa: E402
from swap_engine import timelock_policy as policy  # noqa: E402
from swap_engine.store import Store, terms_digest  # noqa: E402

DEFAULT_STORE = Path.home() / '.hegemon-swaps'
DEFAULT_WALLETS = Path.home() / '.config/hegemon/swap-wallets.json'
TERMINAL = ('done', 'refunded', 'aborted', 'failed')


def fail(message, code=2):
    print(json.dumps({'error': message}), file=sys.stderr)
    sys.exit(code)


def load_wallets(path):
    path = Path(path)
    if not path.is_file():
        fail(f'Wallet config not found: {path}')
    config = json.loads(path.read_text())
    for chain, item in config.items():
        for key, value in item.items():
            if key in ('key_file', 'wallet_file', 'skey') and not Path(value).is_file():
                fail(f'{chain}: {key} does not exist')
    return config


def build_adapter(chain, wallets):
    """The local participant's adapter for one public testnet chain."""
    if chain == 'bitcoin':
        from swap_engine.adapters.bitcoin import BitcoinAdapter, Testnet4Profile
        return BitcoinAdapter(Testnet4Profile(), wallets['bitcoin']['key_file'])
    if chain == 'ethereum':
        from swap_engine.adapters.ethereum import EthereumAdapter, SepoliaProfile
        return EthereumAdapter(SepoliaProfile(), wallets['ethereum']['wallet_file'])
    if chain == 'cardano':
        from swap_engine.adapters.cardano import CardanoAdapter, PreviewProfile
        return CardanoAdapter(PreviewProfile(), wallets['cardano'])
    if chain == 'hegemon':
        from swap_engine.adapters.hegemon_stub import HegemonStubAdapter
        return HegemonStubAdapter()
    fail(f'Unknown chain {chain}')


def adapters_for(terms, wallets):
    return {name: build_adapter(terms['legs'][name]['chain'], wallets) for name in ('long', 'short')}


def open_store(args):
    root = Path(args.store)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return Store(root)


def summary(swap):
    record = swap.record
    return {'swap_id': record['swap_id'], 'role': record['role'], 'state': record['state'], 'inflight': record['inflight'],
            'needs_human': record['needs_human'], 'escrows': record['escrows'], 'txids': record['txids'],
            'terms_digest': record['terms_digest'], 'last': record['history'][-1] if record['history'] else None}


def cmd_plan(args):
    wallets = load_wallets(args.wallets)
    adapters = {name: build_adapter(chain, wallets) for name, chain in (('long', args.long), ('short', args.short))}
    config = policy.load_timing()
    heads = {name: adapter.head() for name, adapter in adapters.items()}
    now = int(time.time())
    plan = planner.plan_with_margin(config, args.long, args.short, heads, now, args.margin)
    print(json.dumps({'heads': heads, 'now': now, 'long': plan['long'], 'short': plan['short'], 'verdict': plan['verdict']}, indent=1))


def cmd_init(args):
    store = open_store(args)
    terms = json.loads(Path(args.terms).read_text())
    preimage = None
    if args.role == 'initiator':
        if not args.new_preimage:
            fail('The initiator creates the preimage: pass --new-preimage')
        preimage = os.urandom(32)
        terms['hashlock'] = hashlib.sha256(preimage).hexdigest()
    elif args.new_preimage:
        fail('Only the initiator creates a preimage')
    swap_id = args.swap_id or terms_digest(terms)[:16]
    store.create(swap_id, args.role, terms, int(time.time()), preimage)
    print(json.dumps({'swap_id': swap_id, 'role': args.role, 'terms': terms, 'terms_digest': terms_digest(terms),
                      'note': 'Send the terms to the counterparty, who runs init --role responder with them.' if args.role == 'initiator' else 'Created.'}, indent=1))


def cmd_identities(args):
    store = open_store(args)
    context = {'offer': args.offer, 'reservation': args.reservation, 'owner_inbox': args.owner_inbox, 'taker_inbox': args.taker_inbox}
    with store.locked(args.swap_id) as swap:
        value = swap.attach_identities(Path(args.owner).read_text(), Path(args.taker).read_text(), context, args.give_leg, int(time.time()))
    print(json.dumps(value, indent=1))


def cmd_status(args):
    store = open_store(args)
    ids = [args.swap_id] if args.swap_id else store.list()
    out = []
    for swap_id in ids:
        with store.locked(swap_id) as swap:
            out.append(summary(swap))
    print(json.dumps(out if not args.swap_id else out[0], indent=1))


def cmd_advance(args):
    store = open_store(args)
    wallets = load_wallets(args.wallets)
    config = policy.load_timing()
    last = None
    while True:
        with store.locked(args.swap_id) as swap:
            adapters = adapters_for(swap.terms, wallets)
            result = engine.advance(swap, adapters, config, int(time.time()))
            state = swap.record['state']
        if result != last:
            print(json.dumps({'at': int(time.time()), **result}), flush=True)
            last = result
        if not args.watch or state in TERMINAL or result['status'] in ('needs-human', 'inflight'):
            return
        time.sleep(args.watch)


def cmd_explain(args):
    print(json.dumps([{'from': a, 'to': b, 'when': c} for a, b, c in engine.explain(args.role)], indent=1))


def cmd_export(args):
    store = open_store(args)
    with store.locked(args.swap_id) as swap:
        leg = engine.own_leg(swap.record['role'])
        print(json.dumps({'leg': leg, 'escrow': swap.record['escrows'][leg]}))


def cmd_receive(args):
    store = open_store(args)
    ref = json.loads(Path(args.ref_file).read_text() if args.ref_file else args.ref)
    ref = ref.get('escrow', ref)
    with store.locked(args.swap_id) as swap:
        print(json.dumps(engine.receive(swap, args.leg or engine.other_leg(swap.record['role']), ref, int(time.time()))))


def cmd_resolve(args):
    store = open_store(args)
    wallets = load_wallets(args.wallets)
    with store.locked(args.swap_id) as swap:
        adapters = adapters_for(swap.terms, wallets)
        print(json.dumps(engine.resolve(swap, adapters, int(time.time()), 'adopt' if args.adopt else 'abandon'), default=str))


def cmd_clear(args):
    store = open_store(args)
    with store.locked(args.swap_id) as swap:
        engine.clear_needs_human(swap, int(time.time()), args.note)
        print(json.dumps(summary(swap)))


def cmd_abort(args):
    store = open_store(args)
    with store.locked(args.swap_id) as swap:
        print(json.dumps(engine.abort(swap, int(time.time()), args.reason), default=str))


def parser():
    top = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    top.add_argument('--store', default=os.environ.get('HEGEMON_SWAP_STORE', str(DEFAULT_STORE)))
    top.add_argument('--wallets', default=os.environ.get('HEGEMON_SWAP_WALLETS', str(DEFAULT_WALLETS)))
    sub = top.add_subparsers(dest='command', required=True)
    p = sub.add_parser('plan')
    p.add_argument('--long', required=True)
    p.add_argument('--short', required=True)
    p.add_argument('--margin', type=int, default=None, help='seconds of staleness the plan must survive')
    p.set_defaults(run=cmd_plan)
    p = sub.add_parser('init')
    p.add_argument('--role', choices=('initiator', 'responder'), required=True)
    p.add_argument('--terms', required=True, help='terms JSON file (initiator: without hashlock when --new-preimage)')
    p.add_argument('--new-preimage', action='store_true')
    p.add_argument('--swap-id')
    p.set_defaults(run=cmd_init)
    p = sub.add_parser('identities', help='verify both signed relay identity statements against the swap terms and record them')
    p.add_argument('swap_id')
    p.add_argument('--owner', required=True, help='file with the owner identity blob from the relay')
    p.add_argument('--taker', required=True, help='file with the taker identity blob from the relay')
    p.add_argument('--offer', required=True)
    p.add_argument('--reservation', required=True)
    p.add_argument('--owner-inbox', required=True, help='inbox fingerprint (sha256 of the raw public key) the owner statement must name')
    p.add_argument('--taker-inbox', required=True)
    p.add_argument('--give-leg', choices=('long', 'short'), required=True, help="the engine leg that is the offer owner's give leg")
    p.set_defaults(run=cmd_identities)
    p = sub.add_parser('status')
    p.add_argument('swap_id', nargs='?')
    p.set_defaults(run=cmd_status)
    p = sub.add_parser('advance')
    p.add_argument('swap_id')
    p.add_argument('--watch', type=float, default=0, metavar='SECONDS')
    p.set_defaults(run=cmd_advance)
    p = sub.add_parser('explain')
    p.add_argument('role', choices=('initiator', 'responder'))
    p.set_defaults(run=cmd_explain)
    p = sub.add_parser('export')
    p.add_argument('swap_id')
    p.set_defaults(run=cmd_export)
    p = sub.add_parser('receive')
    p.add_argument('swap_id')
    p.add_argument('--leg', choices=('long', 'short'))
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--ref')
    group.add_argument('--ref-file')
    p.set_defaults(run=cmd_receive)
    p = sub.add_parser('resolve')
    p.add_argument('swap_id')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--adopt', action='store_true')
    group.add_argument('--abandon', action='store_true')
    p.set_defaults(run=cmd_resolve)
    p = sub.add_parser('clear')
    p.add_argument('swap_id')
    p.add_argument('--note', required=True)
    p.set_defaults(run=cmd_clear)
    p = sub.add_parser('abort')
    p.add_argument('swap_id')
    p.add_argument('--reason', default='aborted by operator')
    p.set_defaults(run=cmd_abort)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.run(args)
    except (ValueError, RuntimeError, KeyError, engine.IdentityMismatch) as error:
        fail(f'{type(error).__name__}: {str(error)[:300]}', 1)


if __name__ == '__main__':
    main()
