"""Read a confirmed hash-bound preimage from trusted v0.11 pre-mainnet data.

The local full node and public explorer are trusted observations. This parser
does not prove that the specified action spent a particular HTLC, verify proofs
or consensus independently, or establish finality. It never submits a
transaction or prints the returned secret.
"""

import math
import re
import time

from check_native_asset_lifecycle import canonical_body, pending_action_public_args
from hegemon_preimage_observer import released_preimage
from probe_hegemon_testnet import RELATION, compare_public_tip, endpoint, hegemon_policy_confirmations, probe, rpc


READ_METHODS = frozenset(('chain_getBlockHash', 'chain_getBlockActionsChunk',
                          'hegemon_latestBlock', 'hegemon_nodeConfig',
                          'hegemon_privateSpendParameters'))
MAX_SCAN_BLOCKS = 512
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SCAN_ACTIONS = 20_000
HASH32 = re.compile(r'0x[0-9a-fA-F]{64}\Z')


def _snapshot(url):
    node = probe(url)
    missing = node.get('missing_wallet_methods')
    if (not isinstance(missing, list) or any(not isinstance(x, str) for x in missing)
            or READ_METHODS.intersection(missing)
            or node.get('private_spend_parameters_match') is not True
            or node.get('syncing') is not False or type(node.get('peers')) is not int
            or node['peers'] < 1 or type(node.get('height')) is not int or node['height'] < 1):
        raise ValueError('Hegemon node is not ready for public observation')
    reference = compare_public_tip(url, node)
    if not isinstance(reference, dict) or reference.get('matches') is not True:
        raise ValueError('Hegemon public reference did not match')
    return node, reference


def _block_hash(url, height):
    value = rpc(url, 'chain_getBlockHash', [height])
    if not isinstance(value, str) or not HASH32.fullmatch(value):
        raise ValueError('Invalid Hegemon block hash')
    return value.lower()


def observe_public_hegemon_preimage(url, *, action_id, hashlock, start_height,
                                    confirmations=None, timeout=600, _clock=None, _sleep=None):
    """Return (mutable preimage, public snapshot); caller must clear the preimage."""
    url = endpoint(url)
    if confirmations is None:
        confirmations = hegemon_policy_confirmations()
    if (not isinstance(action_id, str) or not re.fullmatch(r'[0-9a-f]{96}', action_id)
            or not isinstance(hashlock, str) or not re.fullmatch(r'[0-9a-f]{64}', hashlock)):
        raise ValueError('Invalid Hegemon action ID or hashlock')
    if (type(start_height) is not int or not 1 <= start_height < 2**48
            or type(confirmations) is not int or not 2 <= confirmations <= 100
            or type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 3600):
        raise ValueError('Invalid public observation limits')
    clock = time.monotonic if _clock is None else _clock
    sleep = time.sleep if _sleep is None else _sleep
    deadline = clock() + timeout
    next_height = start_height
    checkpoint = None
    scanned_bytes = 0
    scanned_actions = 0
    relation_prefix = bytes.fromhex(RELATION[:96])
    while True:
        if clock() >= deadline:
            raise TimeoutError('Hegemon public observation timed out')
        node, _reference = _snapshot(url)
        if clock() >= deadline:
            raise TimeoutError('Hegemon public observation timed out')
        height = node['height']
        if start_height > height or height - start_height > MAX_SCAN_BLOCKS:
            raise ValueError('Invalid or excessive Hegemon observation range')
        chain_id = node.get('chain_id')
        if not isinstance(chain_id, str) or not HASH32.fullmatch(chain_id):
            raise ValueError('Invalid Hegemon chain identity')
        chain_id = bytes.fromhex(chain_id[2:])
        anchor = _block_hash(url, height)
        if checkpoint is not None and _block_hash(url, checkpoint[0]) != checkpoint[1]:
            raise ValueError('Hegemon chain reorganized during observation')
        confirmed_end = height - confirmations + 1
        for number in range(next_height, confirmed_end + 1):
            if clock() >= deadline:
                raise TimeoutError('Hegemon public observation timed out')
            block_hash = _block_hash(url, number)
            actions, meta, body = canonical_body(url, block_hash)
            if (not isinstance(actions, list) or not isinstance(body, bytes)
                    or not isinstance(meta, dict) or meta.get('height') != number):
                raise ValueError('Hegemon block height mismatch')
            scanned_bytes += len(body)
            scanned_actions += len(actions)
            if scanned_bytes > MAX_SCAN_BYTES or scanned_actions > MAX_SCAN_ACTIONS:
                raise ValueError('Hegemon observation resource bound exceeded')
            for action in actions:
                if not isinstance(action, (bytes, bytearray)):
                    raise ValueError('Invalid Hegemon action bytes')
                if len(action) < 48 or action[:48].hex() != action_id:
                    continue
                if (len(action) < 56 or tuple(int.from_bytes(action[i:i + 2], 'little')
                                             for i in (48, 50, 52, 54)) != (12, 7, 1, 15)):
                    raise ValueError('Expected Hegemon action is not a private spend')
                carrier, outer = pending_action_public_args(action)
                if outer['vector_counts'] != [0, 0, 2, 2]:
                    raise ValueError('Unexpected private-spend action framing')
                secret = released_preimage(carrier, chain_id=chain_id,
                                           relation_prefix=relation_prefix, hashlock=hashlock)
                if secret is None:
                    raise ValueError('Specified Hegemon action did not release the expected preimage')
                try:
                    if _block_hash(url, number) != block_hash or _block_hash(url, height) != anchor:
                        raise ValueError('Hegemon chain changed during observation')
                    fresh, fresh_reference = _snapshot(url)
                    if clock() >= deadline:
                        raise TimeoutError('Hegemon public observation timed out')
                    depth = fresh['height'] - number + 1
                    if (depth < confirmations or _block_hash(url, number) != block_hash
                            or _block_hash(url, height) != anchor):
                        raise ValueError('Hegemon claim lost confirmations or changed')
                    if clock() >= deadline:
                        raise TimeoutError('Hegemon public observation timed out')
                    snapshot = {'chain': 'hegemon-v0.11-pre-mainnet',
                                'action_id': action_id,
                                'block_height': number, 'block_hash': block_hash,
                                'confirmations': depth, 'node_height': fresh['height'],
                                'reference_height': fresh_reference['reference_height']}
                    result = secret
                    secret = None
                    return result, snapshot
                finally:
                    if secret is not None:
                        secret[:] = b'\0' * len(secret)
            checkpoint = (number, block_hash)
            next_height = number + 1
        if _block_hash(url, height) != anchor:
            raise ValueError('Hegemon chain changed during observation')
        if checkpoint is not None and _block_hash(url, checkpoint[0]) != checkpoint[1]:
            raise ValueError('Hegemon chain reorganized during observation')
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError('Hegemon public observation timed out')
        sleep(min(5, remaining))


def scan_public_hegemon_preimage(url, *, hashlock, start_height, confirmations=None,
                                 timeout=0.05, _clock=None, _sleep=None):
    """Poll canonical public blocks for a disclosed preimage matching `hashlock`.

    Returns (secret, snapshot) or None when nothing confirmed is visible yet. A short timeout
    is the adapter's poll; the caller must zero the secret. Confirmation depth defaults to the
    P1 Hegemon entry in config/swap/chain-timing.json.
    """
    url = endpoint(url)
    if confirmations is None:
        confirmations = hegemon_policy_confirmations()
    if (not isinstance(hashlock, str) or not re.fullmatch(r'[0-9a-f]{64}', hashlock)
            or type(start_height) is not int or not 1 <= start_height < 2**48
            or type(confirmations) is not int or not 2 <= confirmations <= 100
            or type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 3600):
        raise ValueError('Invalid public observation limits')
    clock = time.monotonic if _clock is None else _clock
    sleep = time.sleep if _sleep is None else _sleep
    deadline = clock() + timeout
    next_height = start_height
    relation_prefix = bytes.fromhex(RELATION[:96])
    while True:
        if clock() >= deadline:
            return None
        node, reference = _snapshot(url)
        height = node['height']
        if start_height > height or height - start_height > MAX_SCAN_BLOCKS:
            raise ValueError('Invalid or excessive Hegemon observation range')
        chain_id = node.get('chain_id')
        if not isinstance(chain_id, str) or not HASH32.fullmatch(chain_id):
            raise ValueError('Invalid Hegemon chain identity')
        chain_id = bytes.fromhex(chain_id[2:])
        anchor = _block_hash(url, height)
        confirmed_end = height - confirmations + 1
        for number in range(next_height, confirmed_end + 1):
            if clock() >= deadline:
                return None
            block_hash = _block_hash(url, number)
            actions, meta, body = canonical_body(url, block_hash)
            if (not isinstance(actions, list) or not isinstance(meta, dict)
                    or meta.get('height') != number):
                raise ValueError('Hegemon block height mismatch')
            for action in actions:
                if not isinstance(action, (bytes, bytearray)) or len(action) < 56:
                    continue
                if tuple(int.from_bytes(action[i:i + 2], 'little') for i in (48, 50, 52, 54)) != (12, 7, 1, 15):
                    continue
                carrier, outer = pending_action_public_args(action)
                if outer['vector_counts'] != [0, 0, 2, 2]:
                    raise ValueError('Unexpected private-spend action framing')
                secret = released_preimage(carrier, chain_id=chain_id,
                                           relation_prefix=relation_prefix, hashlock=hashlock)
                if secret is None:
                    continue
                try:
                    if _block_hash(url, number) != block_hash or _block_hash(url, height) != anchor:
                        raise ValueError('Hegemon chain changed during observation')
                    fresh, fresh_reference = _snapshot(url)
                    depth = fresh['height'] - number + 1
                    if (depth < confirmations or _block_hash(url, number) != block_hash
                            or _block_hash(url, height) != anchor):
                        raise ValueError('Hegemon claim lost confirmations or changed')
                    snapshot = {'chain': 'hegemon-v0.11-pre-mainnet',
                                'action_id': action[:48].hex(),
                                'block_height': number, 'block_hash': block_hash,
                                'confirmations': depth, 'node_height': fresh['height'],
                                'reference_height': fresh_reference['reference_height']}
                    result = secret
                    secret = None
                    return result, snapshot
                finally:
                    if secret is not None:
                        secret[:] = b'\0' * len(secret)
            next_height = number + 1
        remaining = deadline - clock()
        if remaining <= 0:
            return None
        sleep(min(5, remaining))
