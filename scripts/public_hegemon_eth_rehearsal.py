#!/usr/bin/env python3
"""Stage one disposable Hegemon/Sepolia swap with Ethereum disclosure first.

Run init once, then advance one step at a time on the machine with the wallets
and the trusted loopback Hegemon relay. A *_inflight phase is uncertain and
must be inspected locally; never automatically retry a proof or submission.
This is a public-testnet experiment, not a production swap coordinator.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from eth_abi import encode
from eth_utils import keccak

import public_hegemon_wallet as hgn
from check_native_asset_lifecycle import pending_action_public_args
from hegemon_preimage_observer import IDENTITY
from probe_hegemon_testnet import RELATION
from public_btc_eth_rehearsal import _directory, _locked, _receipt, _write
from public_ethereum_verify import verify_native
from public_sepolia_driver import load_test_wallet, send as ethereum_send
from public_testnet_observers import ethereum_claim
from public_testnet_probe import rpc as ethereum_rpc
from public_testnet_submit import verify_network
from release_private_spend_lifecycle_io import public_v8_address_keys


ROOT = Path(__file__).resolve().parents[1]
HGN_AMOUNT = 100_000
HGN_FEE = 1_000
ETH_AMOUNT = 10**14
HGN_WINDOW = 1440
HGN_BEFORE_ETH = 720
HGN_BEFORE_REVEAL = 360
ETH_WINDOW = 7200
ETH_BEFORE_REVEAL = 900
HANDOFF_PROMPT = b'Encrypted refund handoff passphrase: '
SECRET_PROMPT = b'Private 32-byte preimage (hex): '


def _actors(root):
    hgn_addresses = json.loads(hgn._private_read(root / 'hegemon-pre-mainnet/addresses.json', 32_000))
    public = json.loads(hgn._private_read(root / 'addresses.json', 32_000))
    if not isinstance(hgn_addresses, dict) or set(hgn_addresses) != {'alice', 'bob'}:
        raise ValueError('Invalid Hegemon test address record')
    for value in hgn_addresses.values():
        public_v8_address_keys(value)
    if hgn_addresses['alice'] == hgn_addresses['bob']:
        raise ValueError('Hegemon participants must differ')
    actors = {'hgn_alice': hgn_addresses['alice'], 'hgn_bob': hgn_addresses['bob']}
    for name in ('alice', 'bob'):
        _, address = load_test_wallet(root / name / 'ethereum-sepolia.key')
        if not isinstance(public, dict) or not isinstance(public.get(name), dict):
            raise ValueError('Invalid public test address record')
        expected = public[name].get('ethereum_sepolia')
        if not isinstance(expected, str) or address.lower() != expected.lower():
            raise ValueError('Ethereum test wallet does not match its public address')
        actors['eth_' + name] = address
    if actors['eth_alice'].lower() == actors['eth_bob'].lower():
        raise ValueError('Ethereum participants must differ')
    return actors


def _wallet(root, binary, url, name, command, *, extra_prompts=()):
    if name not in ('alice', 'bob'):
        raise ValueError('Invalid Hegemon participant')
    folder = root / 'hegemon-pre-mainnet'
    return hgn.wallet(binary, folder / (name + '.wallet'), folder / (name + '.pass'),
                      url, command, extra_prompts=extra_prompts)


def _state(work):
    state = json.loads(hgn._private_read(work / 'state.json', 64_000))
    if (not isinstance(state, dict) or state.get('version') != 1
            or state.get('scenario') != 'hegemon-eth-ethereum-first'
            or not re.fullmatch(r'[0-9a-f]{64}', state.get('hashlock', ''))):
        raise ValueError('Invalid Hegemon/Ethereum rehearsal state')
    return state


def _save(work, state, exclusive=False):
    _write(work / 'state.json', (json.dumps(state, sort_keys=True, indent=2) + '\n').encode(), exclusive)


def _begin(work, state, action):
    state['phase'] = action + '_inflight'
    _save(work, state)


def _single_note(output, minimum):
    summary = hgn.balance(output)
    if summary['watch_only'] or summary['reserved_notes'] != 0:
        raise ValueError('Wallet has no signing authority or has reserved notes')
    candidates = [(position, value) for position, value in hgn.notes(output, 'ordinary')
                  if value >= minimum]
    if not candidates or summary['available_atoms'] < minimum:
        raise ValueError('A sufficiently funded ordinary Hegemon note is required')
    return min(candidates, key=lambda item: item[1])[0]


def _candidate(output):
    rows = [match[1] for line in output.splitlines()
            if (match := re.fullmatch(r'candidate ([0-9a-f]{64})', line))]
    if len(rows) != 1:
        raise ValueError('Wallet did not return one preparation attempt')
    return rows[0]


def _submitted(output, expected):
    rows = [match[1] for line in output.splitlines()
            if (match := re.fullmatch(r'submitted ([0-9a-f]{96})', line))]
    if rows != [expected]:
        raise ValueError('Wallet submission acknowledgement differs from exported action')


def _json_line(output):
    values = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict):
            values.append(value)
    if len(values) != 1:
        raise ValueError('Wallet did not return one verification result')
    return values[0]


def _check_hgn_identity(root, binary, url, actors):
    for name in ('alice', 'bob'):
        text, _ = _wallet(root, binary, url, name, ['address', '--index', '0'])
        if actors['hgn_' + name] not in text.splitlines():
            raise ValueError('Hegemon test wallet does not match its public address')


def _ethereum_funds(actors):
    verify_network('ethereum-sepolia')
    head = ethereum_rpc('eth_getBlockByNumber', ['latest', False])
    base = int(head['baseFeePerGas'], 16)
    priority = int(ethereum_rpc('eth_maxPriorityFeePerGas', []), 16)
    fee = 2 * base + priority
    # Conservative preflight only; the real sender estimates gas again.
    if int(ethereum_rpc('eth_getBalance', [actors['eth_bob'], 'pending']), 16) < ETH_AMOUNT + 600_000 * fee:
        raise ValueError('Bob needs more Sepolia ETH for escrow and gas')
    if int(ethereum_rpc('eth_getBalance', [actors['eth_alice'], 'pending']), 16) < 200_000 * fee:
        raise ValueError('Alice needs more Sepolia ETH for claim gas')
    return int(head['timestamp'], 16)


def _initialize(root, binary, url):
    root = _directory(root)
    binary = hgn.check_binary(binary)
    node, _ = hgn.ready(url)
    actors = _actors(root)
    _check_hgn_identity(root, binary, url, actors)
    alice, _ = _wallet(root, binary, url, 'alice', ['status'])
    bob, _ = _wallet(root, binary, url, 'bob', ['status'])
    # Preserve at least one fee's worth of change if Alice must refund later.
    alice_input = _single_note(alice, HGN_AMOUNT + 2 * HGN_FEE)
    bob_fee = _single_note(bob, HGN_FEE)
    _ethereum_funds(actors)
    work = root / 'hegemon-eth'
    work.mkdir(mode=0o700)
    secret = bytearray(secrets.token_bytes(32))
    handoff = bytearray(secrets.token_hex(32).encode())
    try:
        digest = hashlib.sha256(secret).hexdigest()
        _write(work / 'secret', secret, True)
        _write(work / 'refund.pass', handoff + b'\n', True)
        state = {'version': 1, 'scenario': 'hegemon-eth-ethereum-first',
                 'phase': 'created', 'hashlock': digest, 'actors': actors,
                 'alice_input': alice_input, 'bob_fee_input': bob_fee,
                 'alice_initial_htlc_positions': [p for p, _ in hgn.notes(alice, 'htlc')],
                 'hgn_amount_atoms': HGN_AMOUNT, 'hgn_fee_atoms': HGN_FEE,
                 'eth_amount_wei': str(ETH_AMOUNT), 'initial_hgn_height': node['height'],
                 'wallet_binary_sha256': binary.sha256,
                 'proofs': {}}
        _save(work, state, True)
    finally:
        secret[:] = b'\0' * len(secret)
        handoff[:] = b'\0' * len(handoff)
    return {'phase': 'created', 'hashlock': digest}


def _handoff(work):
    return hgn._password(work / 'refund.pass')


def _verify_hgn_note(root, binary, url, state, name, position, min_remaining):
    actors = state['actors']
    args = ['verify-htlc', '--locked', str(position), '--claim', actors['hgn_bob'],
            '--refund', actors['hgn_alice'], '--hashlock', state['hashlock'],
            '--timeout', str(state['hgn_timeout']), '--amount', str(HGN_AMOUNT),
            '--min-confirmations', '2', '--min-remaining-blocks', str(min_remaining)]
    output, _ = _wallet(root, binary, url, name, args)
    result = _json_line(output)
    if (result.get('verified') is not True or result.get('position') != position
            or result.get('created_height') != state['hgn_lock_block_height']
            or type(result.get('confirmations')) is not int or result['confirmations'] < 2):
        raise ValueError('Hegemon HTLC verification does not match the locked note')
    return result


def _validate_export(work, filename, state, *, releasing):
    raw = hgn._private_read(work / filename, hgn.MAX_ACTION)
    if len(raw) < 56:
        raise ValueError('Invalid exported Hegemon action')
    if tuple(int.from_bytes(raw[i:i + 2], 'little') for i in (48, 50, 52, 54)) != (12, 7, 1, 15):
        raise ValueError('Unexpected Hegemon action family')
    carrier, outer = pending_action_public_args(raw)
    chain = bytes.fromhex(state['chain_id'][2:])
    if (outer['vector_counts'] != [0, 0, 2, 2] or not 5788 <= len(carrier) <= 177632
            or carrier[:8] != b'HGPSLC02' or carrier[8:24] != IDENTITY
            or carrier[24:72] != bytes.fromhex(RELATION[:96]) or carrier[72:104] != chain
            or carrier[5784:5788] != b'SMZL'):
        raise ValueError('Unexpected Hegemon action carrier')
    flag = int.from_bytes(carrier[528:536], 'little')
    secret = bytearray(carrier[536:568])
    try:
        if ((releasing and (flag != 1 or hashlib.sha256(secret).hexdigest() != state['hashlock']))
                or (not releasing and (flag != 0 or any(secret)))):
            raise ValueError('Unexpected Hegemon secret release')
    finally:
        secret[:] = b'\0' * len(secret)
    return raw[:48].hex(), hashlib.sha256(raw).hexdigest()


def _check_export(work, filename, expected):
    raw = hgn._private_read(work / filename, hgn.MAX_ACTION)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Exported Hegemon action changed')


def _confirmed_lock_action(root, binary, url, work, state):
    _check_export(work, 'lock.action', state['hgn_lock_action_sha256'])
    alice, _ = _wallet(root, binary, url, 'alice', ['status'])
    inclusion = hgn.confirmed_action(url, alice, state['hgn_lock_attempt'], work / 'lock.action')
    if (inclusion is None or inclusion['action_id'] != state['hgn_lock_action_id']
            or inclusion['block_height'] != state['hgn_lock_block_height']
            or inclusion['block_hash'] != state['hgn_lock_block_hash']):
        raise ValueError('Hegemon lock lost its confirmed canonical inclusion')
    return inclusion


def _confirmed_lock(root, binary, url, work, state, min_remaining, *, check_refund):
    inclusion = _confirmed_lock_action(root, binary, url, work, state)
    _verify_hgn_note(root, binary, url, state, 'bob', state['hgn_locked_position'], min_remaining)
    if check_refund:
        _verify_hgn_note(root, binary, url, state, 'alice', state['hgn_locked_position'], min_remaining)
    return inclusion


def _refund_pass(work, root, binary, url, name, args):
    phrase = _handoff(work)
    try:
        return _wallet(root, binary, url, name, args, extra_prompts=[(HANDOFF_PROMPT, phrase)])
    finally:
        phrase[:] = b'\0' * len(phrase)


def _advance(root, binary, url):
    root = _directory(root)
    work = _directory(root / 'hegemon-eth')
    state = _state(work)
    expected_binary = state.get('wallet_binary_sha256')
    if not isinstance(expected_binary, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_binary):
        raise ValueError('Saved wallet executable digest is absent or invalid')
    binary = hgn.check_binary(binary, expected_binary)
    if state.get('actors') != _actors(root):
        raise ValueError('Rehearsal participant identities changed')
    phase = state.get('phase')
    if not isinstance(phase, str) or phase.endswith('_inflight'):
        raise ValueError('Uncertain action: inspect the wallet, private journal and chains before recovery')
    actors = state['actors']
    if phase == 'created':
        node, _ = hgn.ready(url)
        _ethereum_funds(actors)
        alice, _ = _wallet(root, binary, url, 'alice', ['status'])
        bob, _ = _wallet(root, binary, url, 'bob', ['status'])
        if _single_note(alice, HGN_AMOUNT + 2 * HGN_FEE) != state['alice_input']:
            raise ValueError('Alice Hegemon input changed before preparation')
        if _single_note(bob, HGN_FEE) != state['bob_fee_input']:
            raise ValueError('Bob Hegemon fee input changed before preparation')
        state.update(hgn_timeout=node['height'] + HGN_WINDOW, chain_id=node['chain_id'])
        _begin(work, state, 'hgn_lock_prepare')
        args = ['lock', '--inputs', str(state['alice_input']), '--claim', actors['hgn_bob'],
                '--refund', actors['hgn_alice'], '--hashlock', state['hashlock'],
                '--timeout', str(state['hgn_timeout']), '--amount', str(HGN_AMOUNT),
                '--fee', str(HGN_FEE), '--release-secret', '--refund-handoff', str(work / 'refund.bin')]
        output, metrics = _refund_pass(work, root, binary, url, 'alice', args)
        hgn._private_read(work / 'refund.bin', 1024 * 1024)
        state.update(phase='hgn_lock_prepared', hgn_lock_attempt=_candidate(output))
        state['proofs']['hgn_lock'] = metrics
        _save(work, state)
    elif phase == 'hgn_lock_prepared':
        _begin(work, state, 'hgn_lock_export')
        _wallet(root, binary, url, 'alice', ['export', state['hgn_lock_attempt'], str(work / 'lock.action')])
        action_id, digest = _validate_export(work, 'lock.action', state, releasing=False)
        state.update(phase='hgn_lock_exported', hgn_lock_action_id=action_id,
                     hgn_lock_action_sha256=digest)
        _save(work, state)
    elif phase == 'hgn_lock_exported':
        node, _ = hgn.ready(url)
        if state['hgn_timeout'] - node['height'] < HGN_BEFORE_ETH:
            raise ValueError('Hegemon refund deadline is too close')
        _check_export(work, 'lock.action', state['hgn_lock_action_sha256'])
        _begin(work, state, 'hgn_lock_submit')
        output, _ = _wallet(root, binary, url, 'alice', ['submit', state['hgn_lock_attempt']])
        _submitted(output, state['hgn_lock_action_id'])
        state['phase'] = 'hgn_lock_submitted'
        _save(work, state)
    elif phase == 'hgn_lock_submitted':
        _check_export(work, 'lock.action', state['hgn_lock_action_sha256'])
        alice, _ = _wallet(root, binary, url, 'alice', ['status'])
        inclusion = hgn.confirmed_action(url, alice, state['hgn_lock_attempt'], work / 'lock.action')
        if inclusion is None:
            return {'phase': phase, 'pending': True}
        if inclusion['action_id'] != state['hgn_lock_action_id']:
            raise ValueError('Confirmed Hegemon lock is not the exported action')
        state.update(phase='hgn_lock_confirmed', hgn_lock_block_height=inclusion['block_height'],
                     hgn_lock_block_hash=inclusion['block_hash'])
        _save(work, state)
    elif phase == 'hgn_lock_confirmed':
        _confirmed_lock_action(root, binary, url, work, state)
        _begin(work, state, 'refund_import')
        _refund_pass(work, root, binary, url, 'alice', ['import-refund-handoff', str(work / 'refund.bin'),
                     '--block-height', str(state['hgn_lock_block_height']), '--refund-index', '0'])
        alice, _ = _wallet(root, binary, url, 'alice', ['status'])
        prior = set(state['alice_initial_htlc_positions'])
        candidates = [position for position, value in hgn.notes(alice, 'htlc')
                      if position not in prior and value == HGN_AMOUNT]
        if len(candidates) != 1:
            raise ValueError('Alice does not have exactly one new expected refund note')
        state['hgn_locked_position'] = candidates[0]
        _verify_hgn_note(root, binary, url, state, 'alice', candidates[0], HGN_BEFORE_ETH)
        state['phase'] = 'refund_ready'
        _save(work, state)
    elif phase == 'refund_ready':
        _confirmed_lock(root, binary, url, work, state, HGN_BEFORE_ETH, check_refund=True)
        timestamp = _ethereum_funds(actors)
        state['eth_expiry'] = timestamp + ETH_WINDOW
        template = json.loads((ROOT / 'swap-ui/ether-escrow-template.json').read_text())
        data = bytes.fromhex(template['creation']) + encode(
            ['bytes32', 'address', 'uint256'],
            [bytes.fromhex(state['hashlock']), actors['eth_alice'], state['eth_expiry']])
        _begin(work, state, 'eth_lock')
        result = ethereum_send(work, root / 'bob/ethereum-sepolia.key', None, ETH_AMOUNT, data)
        state.update(phase='eth_lock_submitted', eth_lock=result['txid'])
        _save(work, state)
    elif phase == 'eth_lock_submitted':
        receipt = _receipt(state['eth_lock'])
        if receipt is None:
            return {'phase': phase, 'pending': True}
        contract = receipt.get('contractAddress')
        verify_native(contract, state['hashlock'], actors['eth_alice'], actors['eth_bob'],
                      state['eth_expiry'], ETH_AMOUNT)
        state.update(phase='both_verified', eth_contract=contract)
        _save(work, state)
    elif phase == 'both_verified':
        _confirmed_lock(root, binary, url, work, state, HGN_BEFORE_REVEAL, check_refund=True)
        verify_native(state['eth_contract'], state['hashlock'], actors['eth_alice'],
                      actors['eth_bob'], state['eth_expiry'], ETH_AMOUNT)
        timestamp = int(ethereum_rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if state['eth_expiry'] - timestamp < ETH_BEFORE_REVEAL:
            raise ValueError('Ethereum refund deadline is too close')
        secret = bytearray(hgn._private_read(work / 'secret', 32))
        try:
            if len(secret) != 32 or hashlib.sha256(secret).hexdigest() != state['hashlock']:
                raise ValueError('Local preimage backup does not match the hashlock')
            data = keccak(text='claim(bytes32)')[:4] + encode(['bytes32'], [bytes(secret)])
            _begin(work, state, 'eth_claim')
            result = ethereum_send(work, root / 'alice/ethereum-sepolia.key',
                                   state['eth_contract'], 0, data)
            state.update(phase='eth_claim_submitted', eth_claim=result['txid'])
            _save(work, state)
        finally:
            secret[:] = b'\0' * len(secret)
    elif phase == 'eth_claim_submitted':
        if _receipt(state['eth_claim']) is None:
            return {'phase': phase, 'pending': True}
        _confirmed_lock(root, binary, url, work, state, 2, check_refund=True)
        observed, _ = ethereum_claim(state['eth_claim'], state['eth_contract'], state['hashlock'])
        secret_hex = bytearray(observed.hex().encode())
        try:
            bob, _ = _wallet(root, binary, url, 'bob', ['status'])
            if state['bob_fee_input'] not in [p for p, value in hgn.notes(bob, 'ordinary') if value >= HGN_FEE]:
                raise ValueError('Bob Hegemon fee note is no longer available')
            state['bob_ordinary_before_claim'] = [p for p, _ in hgn.notes(bob, 'ordinary')]
            _begin(work, state, 'hgn_claim_prepare')
            output, metrics = _wallet(root, binary, url, 'bob',
                ['claim', '--locked', str(state['hgn_locked_position']),
                 '--fee-input', str(state['bob_fee_input']), '--recipient', actors['hgn_bob'],
                 '--fee', str(HGN_FEE)], extra_prompts=[(SECRET_PROMPT, secret_hex)])
            state.update(phase='hgn_claim_prepared', hgn_claim_attempt=_candidate(output))
            state['proofs']['hgn_claim'] = metrics
            _save(work, state)
        finally:
            observed[:] = b'\0' * len(observed)
            secret_hex[:] = b'\0' * len(secret_hex)
    elif phase == 'hgn_claim_prepared':
        _begin(work, state, 'hgn_claim_export')
        _wallet(root, binary, url, 'bob', ['export', state['hgn_claim_attempt'], str(work / 'claim.action')])
        action_id, digest = _validate_export(work, 'claim.action', state, releasing=True)
        state.update(phase='hgn_claim_exported', hgn_claim_action_id=action_id,
                     hgn_claim_action_sha256=digest)
        _save(work, state)
    elif phase == 'hgn_claim_exported':
        _check_export(work, 'claim.action', state['hgn_claim_action_sha256'])
        _begin(work, state, 'hgn_claim_submit')
        output, _ = _wallet(root, binary, url, 'bob', ['submit', state['hgn_claim_attempt']])
        _submitted(output, state['hgn_claim_action_id'])
        state['phase'] = 'hgn_claim_submitted'
        _save(work, state)
    elif phase == 'hgn_claim_submitted':
        _check_export(work, 'claim.action', state['hgn_claim_action_sha256'])
        bob, _ = _wallet(root, binary, url, 'bob', ['status'])
        inclusion = hgn.confirmed_action(url, bob, state['hgn_claim_attempt'], work / 'claim.action')
        if inclusion is None:
            return {'phase': phase, 'pending': True}
        if inclusion['action_id'] != state['hgn_claim_action_id']:
            raise ValueError('Confirmed Hegemon claim is not the exported action')
        old = set(state['bob_ordinary_before_claim'])
        if not any(p not in old and value == HGN_AMOUNT for p, value in hgn.notes(bob, 'ordinary')):
            raise ValueError('Expected Hegemon payout was not recovered by Bob')
        if _receipt(state['eth_claim']) is None:
            raise ValueError('Ethereum claim no longer has the required confirmations')
        observed, _ = ethereum_claim(state['eth_claim'], state['eth_contract'], state['hashlock'])
        observed[:] = b'\0' * len(observed)
        state.update(phase='complete', hgn_claim_block_height=inclusion['block_height'],
                     hgn_claim_block_hash=inclusion['block_hash'])
        _save(work, state)
    elif phase != 'complete':
        raise ValueError('Unknown Hegemon/Ethereum rehearsal phase')
    return {'phase': state['phase'], 'pending': state['phase'].endswith('_submitted')}


def initialize(root, binary, url):
    with _locked(root) as directory:
        return _initialize(directory, binary, url)


def advance(root, binary, url):
    with _locked(root) as directory:
        return _advance(directory, binary, url)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('init', 'advance', 'status'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--wallet-binary', type=Path, required=True)
    parser.add_argument('--hegemon-rpc', default='http://127.0.0.1:9944')
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == 'init':
        result = initialize(args.directory, args.wallet_binary, args.hegemon_rpc)
    elif args.operation == 'advance':
        result = advance(args.directory, args.wallet_binary, args.hegemon_rpc)
    else:
        with _locked(args.directory) as root:
            state = _state(_directory(root / 'hegemon-eth'))
            allowed = ('phase', 'hashlock', 'hgn_lock_action_id', 'hgn_lock_block_height',
                       'hgn_claim_action_id', 'hgn_claim_block_height', 'eth_lock', 'eth_claim',
                       'wallet_binary_sha256', 'proofs')
            result = {key: state[key] for key in allowed if key in state}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
