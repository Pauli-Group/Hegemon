"""Verify signed identity statements (the Python twin of swap-ui/identity.mjs).

The statement format, signature schemes and rules are specified in `.agent/SWAP_RELAY_IDENTITY_EXECPLAN.md`. Both
implementations verify the shared vectors in `config/swap/identity-vectors.json`, which are signed by code that is
independent of either verifier. Everything here fails closed: any doubt raises `IdentityError`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

IDENTITY_KIND = 'hegemon.swap.identity'
TEXT_PREFIX = 'hegemon.swap.identity.v1\n'
MAX_LIFETIME_SECONDS = 7 * 86400
CLOCK_SKEW_SECONDS = 300
MAX_BLOB = 8192
FIELDS = {'owner': {'give': 'refund', 'receive': 'claim'}, 'taker': {'give': 'claim', 'receive': 'refund'}}


class IdentityError(ValueError):
    pass


def _hex(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def _bitcoin_key(value):
    if not isinstance(value, str) or not re.fullmatch('0[23][0-9a-f]{64}', value):
        return False
    try:
        from embit import ec
        ec.PublicKey.parse(bytes.fromhex(value))
        return True
    except Exception:
        return False


ADDRESS = {
    'ethereum': lambda v: isinstance(v, str) and re.fullmatch('0x[0-9a-f]{40}', v) is not None,
    'cardano': lambda v: _hex(v, 56),
    'bitcoin': _bitcoin_key,
    'hegemon': lambda v: v == 'pending',
}


def canonical(value) -> str:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(k, ensure_ascii=True) + ':' + canonical(value[k]) for k in sorted(value)) + '}'
    raise IdentityError('Unsupported value in a statement.')


def statement_text(statement) -> str:
    return TEXT_PREFIX + canonical(statement)


def identity_code(statement) -> str:
    return hashlib.sha256(canonical(statement).encode()).hexdigest()[:16]


def _check_shape(statement):
    if not isinstance(statement, dict) or set(statement) != {'expires', 'inbox', 'issued', 'kind', 'legs', 'nonce', 'offer', 'reservation', 'role', 'version'}:
        raise IdentityError('Invalid identity statement.')
    if statement['version'] != 1 or isinstance(statement['version'], bool) or statement['kind'] != IDENTITY_KIND:
        raise IdentityError('Unsupported identity statement version.')
    role = statement['role']
    if role not in FIELDS:
        raise IdentityError('Unknown identity role.')
    if not (_hex(statement['offer'], 64) and _hex(statement['inbox'], 64) and _hex(statement['nonce'], 32)):
        raise IdentityError('Invalid identity statement fields.')
    reservation = statement['reservation']
    if (reservation != '') if role == 'owner' else not _hex(reservation, 64):
        raise IdentityError('Invalid reservation in the identity statement.')
    issued, expires = statement['issued'], statement['expires']
    if any(not isinstance(v, int) or isinstance(v, bool) for v in (issued, expires)) or expires <= issued or expires - issued > MAX_LIFETIME_SECONDS:
        raise IdentityError('Invalid identity statement lifetime.')
    legs = statement['legs']
    if not isinstance(legs, dict) or set(legs) != {'give', 'receive'}:
        raise IdentityError('Invalid identity statement legs.')
    for side in ('give', 'receive'):
        leg, field = legs[side], FIELDS[role][side]
        if not isinstance(leg, dict) or set(leg) != {'chain', field} or leg['chain'] not in ADDRESS or not ADDRESS[leg['chain']](leg[field]):
            raise IdentityError(f'Invalid {side} leg in the identity statement.')


def leg_address(statement, side):
    return statement['legs'][side][FIELDS[statement['role']][side]]


# ---------------------------------------------------------------- signature schemes

def _verify_ethereum(proof, text):
    from eth_account import Account
    from eth_account.messages import encode_defunct
    signature = proof.get('signature')
    if not isinstance(signature, str) or not re.fullmatch('0x[0-9a-f]{130}', signature):
        raise IdentityError('Invalid Ethereum signature.')
    v = int(signature[-2:], 16)
    if v not in (0, 1, 27, 28):
        raise IdentityError('Invalid Ethereum signature recovery value.')
    try:
        return Account.recover_message(encode_defunct(text=text), signature=signature).lower()
    except Exception as error:
        raise IdentityError('The Ethereum signature does not recover an address.') from error


def _verify_cardano(proof, text):
    import cbor2
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    try:
        sign1 = cbor2.loads(bytes.fromhex(proof['signature']))
        cose = cbor2.loads(bytes.fromhex(proof['key']))
    except Exception as error:
        raise IdentityError('Invalid Cardano signature.') from error
    if not isinstance(sign1, list) or len(sign1) != 4:
        raise IdentityError('Invalid COSE_Sign1.')
    protected, unprotected, payload, signature = sign1
    if not (isinstance(protected, bytes) and isinstance(unprotected, dict) and isinstance(payload, bytes) and isinstance(signature, bytes) and len(signature) == 64):
        raise IdentityError('Invalid COSE_Sign1.')
    if unprotected.get('hashed') is True:
        raise IdentityError('Hashed payloads are not accepted; sign the statement text itself.')
    if payload != text.encode():
        raise IdentityError('The signed payload is not the identity statement.')
    header = cbor2.loads(protected)
    if not isinstance(header, dict) or header.get(1) != -8:
        raise IdentityError('Unsupported COSE algorithm.')
    if not isinstance(cose, dict) or cose.get(1) != 1 or cose.get(-1) != 6 or not isinstance(cose.get(-2), bytes) or len(cose[-2]) != 32:
        raise IdentityError('Invalid COSE_Key.')
    key = cose[-2]
    try:
        VerifyKey(key).verify(cbor2.dumps(['Signature1', protected, b'', payload]), signature)
    except BadSignatureError as error:
        raise IdentityError('The Cardano signature does not verify.') from error
    key_hash = hashlib.blake2b(key, digest_size=28).digest()
    address = header.get('address')
    if not isinstance(address, bytes) or len(address) < 29:
        raise IdentityError('The signature does not name an address.')
    if address[0] >> 4 not in (0, 2, 4, 6):
        raise IdentityError('The signing address does not use a payment key.')
    if address[1:29] != key_hash:
        raise IdentityError('The signing address does not belong to the signing key.')
    return key_hash.hex()


def _varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b'\xfd' + n.to_bytes(2, 'little')
    raise IdentityError('Value too large.')


def _dsha(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _b64(value, what):
    if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch('[A-Za-z0-9+/]+={0,2}', value) or len(value) % 4:
        raise IdentityError(f'Invalid {what}.')
    return base64.b64decode(value)


def _verify_bip137(proof, text):
    import ecdsa
    raw = _b64(proof.get('signature'), 'Bitcoin signature')
    if len(raw) != 65:
        raise IdentityError('Invalid Bitcoin message signature.')
    header = raw[0]
    if not 31 <= header <= 42:
        raise IdentityError('Only compressed-key message signatures are accepted.')
    magic, message = b'Bitcoin Signed Message:\n', text.encode()
    digest = _dsha(_varint(len(magic)) + magic + _varint(len(message)) + message)
    try:
        candidates = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(raw[1:], digest, ecdsa.SECP256k1, sigdecode=ecdsa.util.sigdecode_string)
    except Exception as error:
        raise IdentityError('The signature does not recover a public key.') from error
    index = (header - 27) & 3
    if index >= len(candidates):
        raise IdentityError('The signature does not recover a public key.')
    return candidates[index].to_string('compressed').hex()


def _verify_bip322(proof, text):
    from embit import ec, script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    raw = _b64(proof.get('signature'), 'Bitcoin signature')
    if len(raw) < 4 or raw[0] != 2:
        raise IdentityError('Only a two-item P2WPKH witness is supported.')
    offset = 1

    def item():
        nonlocal offset
        if offset >= len(raw):
            raise IdentityError('Truncated BIP-322 signature.')
        length = raw[offset]
        offset += 1
        if length >= 0xFD or offset + length > len(raw):
            raise IdentityError('Invalid BIP-322 signature.')
        part = raw[offset:offset + length]
        offset += length
        return part

    signature, public_key = item(), item()
    if offset != len(raw):
        raise IdentityError('Trailing data after the BIP-322 witness.')
    try:
        pub = ec.PublicKey.parse(public_key)
    except Exception as error:
        raise IdentityError('Invalid BIP-322 public key.') from error
    if len(public_key) != 33 or len(signature) < 9 or signature[-1] != 1:
        raise IdentityError('The BIP-322 signature must use SIGHASH_ALL.')
    tag = hashlib.sha256(b'BIP0322-signed-message').digest()
    message_hash = hashlib.sha256(tag + tag + text.encode()).digest()
    spk = script.p2wpkh(pub)
    to_spend = Transaction(version=0, vin=[TransactionInput(bytes(32), 0xFFFFFFFF, script.Script(b'\x00\x20' + message_hash), 0)],
                           vout=[TransactionOutput(0, spk)], locktime=0)
    to_sign = Transaction(version=0, vin=[TransactionInput(to_spend.txid(), 0, script.Script(b''), 0)],
                          vout=[TransactionOutput(0, script.Script(b'\x6a'))], locktime=0)
    sighash = to_sign.sighash_segwit(0, script.p2pkh_from_p2wpkh(spk), 0)
    try:
        ok = pub.verify(ec.Signature.parse(signature[:-1]), sighash)
    except Exception:
        ok = False
    if not ok:
        raise IdentityError('The BIP-322 signature does not verify.')
    return public_key.hex()


SCHEMES = {'ethereum': {'eip191': _verify_ethereum}, 'cardano': {'cip8': _verify_cardano},
           'bitcoin': {'bip322-simple': _verify_bip322, 'bip137': _verify_bip137}}


def verify_proof(proof, text):
    if not isinstance(proof, dict):
        raise IdentityError('Invalid identity proof.')
    verify = SCHEMES.get(proof.get('chain'), {}).get(proof.get('scheme'))
    if verify is None:
        raise IdentityError('Unsupported identity proof scheme.')
    signer = verify(proof, text)
    if proof.get('signer') != signer:
        raise IdentityError('The proof signer is not the key that signed.')
    return {'chain': proof['chain'], 'scheme': proof['scheme'], 'signer': signer}


def parse_identity(blob):
    if not isinstance(blob, str) or len(blob) > MAX_BLOB:
        raise IdentityError('Invalid identity statement.')
    try:
        value = json.loads(blob)
    except ValueError as error:
        raise IdentityError('Invalid identity statement.') from error
    if not isinstance(value, dict) or set(value) != {'proofs', 'statement'} or not isinstance(value['proofs'], list) or len(value['proofs']) > 4:
        raise IdentityError('Invalid identity statement.')
    _check_shape(value['statement'])
    return value


def verify_identity(blob, expected, now):
    """Verify a stored identity blob against what this process independently knows.

    `expected` is `{offer, role, reservation, inbox, give:{chain}, receive:{chain}}`; `now` is whole seconds. Returns
    `{statement, code, role, addresses, proven, unverified, proofs}` exactly as the JavaScript verifier does."""
    if not isinstance(now, int) or isinstance(now, bool):
        raise IdentityError('The current time is required.')
    parsed = parse_identity(blob)
    statement, proofs = parsed['statement'], parsed['proofs']
    if statement['role'] != expected['role']:
        raise IdentityError('The identity statement is for a different role.')
    if statement['offer'] != expected['offer']:
        raise IdentityError('The identity statement is for a different offer.')
    if statement['reservation'] != expected.get('reservation', ''):
        raise IdentityError('The identity statement is for a different reservation.')
    if statement['inbox'] != expected['inbox']:
        raise IdentityError('The identity statement names a different inbox key.')
    for side in ('give', 'receive'):
        if statement['legs'][side]['chain'] != expected[side]['chain']:
            raise IdentityError(f'The identity statement is for a different {side} chain.')
    if statement['expires'] <= now:
        raise IdentityError('The identity statement has expired.')
    if statement['issued'] > now + CLOCK_SKEW_SECONDS:
        raise IdentityError('The identity statement is dated in the future.')
    if not proofs:
        raise IdentityError('The identity statement has no signature.')
    text, seen, verified = statement_text(statement), set(), []
    for proof in proofs:
        result = verify_proof(proof, text)
        key = (result['chain'], result['signer'])
        if key in seen:
            raise IdentityError('Duplicate identity proof.')
        seen.add(key)
        if not any(statement['legs'][s]['chain'] == result['chain'] and leg_address(statement, s) == result['signer'] for s in ('give', 'receive')):
            raise IdentityError('A proof signer is not an address named in the statement.')
        verified.append(result)
    addresses = {side: leg_address(statement, side) for side in ('give', 'receive')}
    proven = {side: any(p['chain'] == statement['legs'][side]['chain'] and p['signer'] == addresses[side] for p in verified) for side in ('give', 'receive')}
    unverified = [side for side in ('give', 'receive') if statement['legs'][side]['chain'] == 'hegemon']
    return {'statement': statement, 'code': identity_code(statement), 'role': statement['role'], 'addresses': addresses,
            'proven': proven, 'unverified': unverified, 'proofs': verified}


def _same(chain, a, b):
    return a.lower() == b.lower() if chain == 'ethereum' else a == b


def check_terms(terms, owner, taker, give_leg):
    """Raise unless every leg of the engine `terms` names exactly the two verified identities.

    `give_leg` is `'long'` or `'short'`: the engine leg that is the offer owner's give leg. A Hegemon leg has no identity
    scheme yet; its addresses are not compared and the leg is reported as unverified, never as matching."""
    if give_leg not in ('long', 'short'):
        raise IdentityError('give_leg must be long or short.')
    receive_leg = 'short' if give_leg == 'long' else 'long'
    plan = {give_leg: ('give', taker['addresses']['give'], owner['addresses']['give']),
            receive_leg: ('receive', owner['addresses']['receive'], taker['addresses']['receive'])}
    unverified = []
    for name, (side, claimant, refundee) in plan.items():
        leg = terms['legs'][name]
        chain = owner['statement']['legs'][side]['chain']
        if taker['statement']['legs'][side]['chain'] != chain or leg['chain'] != chain:
            raise IdentityError(f'The {name} leg is on a different chain than the identities.')
        if chain == 'hegemon':
            unverified.append(name)
            continue
        if not _same(chain, leg['claimant'], claimant):
            raise IdentityError(f'The {name} leg claimant is not the signed identity.')
        if not _same(chain, leg['refundee'], refundee):
            raise IdentityError(f'The {name} leg refundee is not the signed identity.')
    return {'unverified': unverified}
