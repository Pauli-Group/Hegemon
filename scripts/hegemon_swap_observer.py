"""Bounded public-pre-mainnet claim observation for a local swap companion.

The underlying observer checks the pinned network, a matching public tip,
canonical action framing and confirmation depth. A result is evidence of a
publicly released preimage, not a substitute for checking the other escrow.
"""
import hashlib
import re

from probe_hegemon_testnet import hegemon_policy_confirmations
from public_hegemon_preimage_observer import scan_public_hegemon_preimage
from probe_hegemon_testnet import RELATION
from hegemon_preimage_observer import IDENTITY
from check_native_asset_lifecycle import canonical_body, pending_action_public_args, rpc

_HASH = re.compile(r'[0-9a-f]{64}\Z')
_ACTION = re.compile(r'[0-9a-f]{96}\Z')
_DECIMAL = re.compile(r'0|[1-9][0-9]{0,19}\Z')
_COMMITMENT = re.compile(r'[0-9a-f]{112}\Z')
_GOLDILOCKS = 0xffffffff00000001


def verify_lock_action_output(url, *, block_height, block_hash, action_id, commitment, chain_id,
                              read=rpc, body=canonical_body, parse=pending_action_public_args):
    """Bind the wallet-verified note commitment to one canonical action.

    A Hegemon candidate ID, 48-byte action ID and private note position are
    distinct. The public carrier's two 56-byte commitments are checked in the
    node-accepted action; the wallet separately verifies membership and terms.
    This framing check is not a proof or consensus verifier.
    """
    if (type(block_height) is not int or not 1 <= block_height < 2**48
            or not isinstance(block_hash, str) or not re.fullmatch(r'0x[0-9a-f]{64}', block_hash)
            or not isinstance(action_id, str) or not _ACTION.fullmatch(action_id)
            or not isinstance(commitment, str) or not _COMMITMENT.fullmatch(commitment)
            or not isinstance(chain_id, str) or not re.fullmatch(r'0x[0-9a-f]{64}', chain_id)):
        raise ValueError('Invalid Hegemon lock action reference')
    def current():
        value = read(url, 'chain_getBlockHash', [block_height])
        return isinstance(value, str) and value.lower() == block_hash
    if not current():
        raise ValueError('Hegemon lock block is no longer canonical')
    actions, meta, _ = body(url, block_hash)
    if not isinstance(actions, list) or not isinstance(meta, dict) or meta.get('height') != block_height:
        raise ValueError('Invalid Hegemon lock block')
    matches = [a for a in actions if isinstance(a, (bytes, bytearray)) and len(a) >= 56 and a[:48].hex() == action_id]
    if len(matches) != 1 or tuple(int.from_bytes(matches[0][i:i+2], 'little') for i in (48, 50, 52, 54)) != (12, 7, 1, 15):
        raise ValueError('Hegemon lock action is absent or has the wrong family')
    carrier, outer = parse(matches[0])
    if (not isinstance(carrier, (bytes, bytearray)) or not 5788 <= len(carrier) <= 177632
            or carrier[:8] != b'HGPSLC02' or carrier[8:24] != IDENTITY
            or carrier[24:72] != bytes.fromhex(RELATION[:96]) or carrier[72:104] != bytes.fromhex(chain_id[2:])
            or carrier[5784:5788] != b'SMZL' or not isinstance(outer, dict)
            or outer.get('vector_counts') != [0, 0, 2, 2]):
        raise ValueError('Invalid Hegemon lock carrier')
    commitments = [bytes(carrier[320:376]), bytes(carrier[376:432])]
    if any(int.from_bytes(c[i:i+8], 'little') >= _GOLDILOCKS for c in commitments for i in range(0, 56, 8)):
        raise ValueError('Invalid Hegemon output commitment')
    if sum(c.hex() == commitment for c in commitments) != 1:
        raise ValueError('The Hegemon action does not contain the verified note')
    if not current():
        raise ValueError('Hegemon lock block changed during verification')
    return True


def observe_claim_request(request, rpc, *, scan=scan_public_hegemon_preimage,
                          confirmations=hegemon_policy_confirmations, timeout=20):
    """Return a confirmed public preimage or a pending state; never log it.

    The caller supplies a trusted loopback RPC and must restrict access to the
    paired local client. Absence of a result means only that no confirmed
    matching release was observed in the bounded scan.
    """
    if (not isinstance(request, dict) or set(request) != {'hashlock', 'start_height'}
            or not isinstance(request['hashlock'], str) or not _HASH.fullmatch(request['hashlock'])
            or not isinstance(request['start_height'], str) or not _DECIMAL.fullmatch(request['start_height'])
            or not 1 <= int(request['start_height']) < 2**48):
        raise ValueError('Invalid Hegemon claim observation request')
    depth = confirmations()
    if type(depth) is not int or not 2 <= depth <= 100:
        raise ValueError('Invalid Hegemon confirmation policy')
    found = scan(rpc, hashlock=request['hashlock'], start_height=int(request['start_height']),
                 confirmations=depth, timeout=timeout)
    if found is None:
        return {'state': 'pending'}
    secret, snapshot = found
    try:
        if (not isinstance(secret, bytearray) or len(secret) != 32
                or hashlib.sha256(secret).hexdigest() != request['hashlock']
                or not isinstance(snapshot, dict) or snapshot.get('chain') != 'hegemon-v0.11-pre-mainnet'
                or not isinstance(snapshot.get('action_id'), str) or not _ACTION.fullmatch(snapshot['action_id'])
                or not isinstance(snapshot.get('block_hash'), str)
                or not re.fullmatch(r'0x[0-9a-f]{64}', snapshot['block_hash'])
                or type(snapshot.get('block_height')) is not int
                or snapshot['block_height'] < int(request['start_height'])
                or type(snapshot.get('confirmations')) is not int or snapshot['confirmations'] < depth
                or type(snapshot.get('node_height')) is not int
                or snapshot['node_height'] - snapshot['block_height'] + 1 != snapshot['confirmations']
                or type(snapshot.get('reference_height')) is not int or snapshot['reference_height'] < 1):
            raise ValueError('Invalid Hegemon claim observation')
        # A matching released preimage does not by itself prove which private
        # HTLC was spent. The caller must verify its saved escrow separately.
        return {'state': 'secret-revealed', 'preimage': secret.hex(),
                'action_id': snapshot['action_id'], 'block_hash': snapshot['block_hash'],
                'block_height': str(snapshot['block_height']),
                'confirmations': snapshot['confirmations']}
    finally:
        if isinstance(secret, bytearray):
            secret[:] = b'\0' * len(secret)
