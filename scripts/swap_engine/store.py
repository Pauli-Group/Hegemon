"""Durable per-swap storage for the two-party swap engine.

Same discipline as scripts/public_swap_journal.py: a private (0700, user-owned)
directory, no symlinks, files created with O_EXCL|O_NOFOLLOW at 0600, fsync of
file and directory. The mutable record is replaced atomically (write a fresh
temporary file, fsync, rename, fsync the directory). The preimage lives in its
own 0600 file and is never part of the record, history, logs or arguments.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path

ID = re.compile('[0-9a-f]{16}')
HEX64 = re.compile('[0-9a-f]{64}')
ROLES = ('initiator', 'responder')
MAX_HISTORY = 200
SECRET_NAMES = ('secret', 'learned-preimage')


def private_directory(path, create=False):
    path = Path(path)
    if create and not path.exists():
        path.mkdir(mode=0o700, parents=True)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError('Swap storage must be a private, user-owned directory without symlinks: ' + str(path))
    return path


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_directory(Path(path).parent)


def _private_file(path, limit=2_000_000):
    st = Path(path).lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077 or st.st_size > limit:
        raise ValueError('File must be a private, user-owned regular file: ' + str(path))
    return Path(path)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def terms_digest(terms):
    return hashlib.sha256(canonical(terms)).hexdigest()


def validate_terms(terms):
    """Terms are fixed at init. Legs carry everything an adapter needs to verify and act."""
    if not isinstance(terms, dict) or terms.get('version') != 1 or not HEX64.fullmatch(str(terms.get('hashlock', ''))):
        raise ValueError('Terms need version 1 and a 64-hex hashlock')
    legs = terms.get('legs')
    if not isinstance(legs, dict) or set(legs) != {'long', 'short'}:
        raise ValueError('Terms need a long and a short leg')
    for name, leg in legs.items():
        if not isinstance(leg, dict) or set(leg) != {'chain', 'amount', 'refundee', 'claimant', 'expiry'}:
            raise ValueError(f'The {name} leg needs chain, amount, refundee, claimant and expiry')
        if not isinstance(leg['chain'], str) or not isinstance(leg['refundee'], str) or not isinstance(leg['claimant'], str):
            raise ValueError(f'The {name} leg has a malformed field')
        if not isinstance(leg['amount'], int) or isinstance(leg['amount'], bool) or leg['amount'] <= 0:
            raise ValueError(f'The {name} leg amount must be a positive integer in the chain base unit')
        if not isinstance(leg['expiry'], int) or isinstance(leg['expiry'], bool) or leg['expiry'] <= 0:
            raise ValueError(f'The {name} leg expiry must be a positive integer')
    for name, leg in legs.items():
        if leg['refundee'] == leg['claimant']:
            raise ValueError(f'The {name} leg must name different refundee and claimant')
    if legs['long']['chain'] == legs['short']['chain'] and (
            legs['long']['refundee'] != legs['short']['claimant'] or legs['short']['refundee'] != legs['long']['claimant']):
        # On one chain the same two identities must cross: the initiator refunds long and claims short.
        raise ValueError('Same-chain legs must cross identities: long refundee = short claimant and short refundee = long claimant')
    return terms


def leg_terms(terms, name):
    """Terms for one leg as an adapter sees it (hashlock included)."""
    return {**terms['legs'][name], 'hashlock': terms['hashlock']}


class Swap:
    """One locked, open swap directory. Obtain via Store.locked()."""

    def __init__(self, directory, hook=None):
        self.directory = Path(directory)
        self.hook = hook
        self.journal_dir = self.directory / 'journal'
        self.terms = json.loads(_private_file(self.directory / 'terms.json').read_text())
        self.record = json.loads(_private_file(self.directory / 'record.json').read_text())
        self._validate()

    def _validate(self):
        record = self.record
        if record.get('version') != 1 or record.get('role') not in ROLES or not ID.fullmatch(str(record.get('swap_id', ''))):
            raise ValueError('Invalid swap record')
        if record.get('terms_digest') != terms_digest(self.terms) or record['swap_id'] != self.directory.name:
            raise ValueError('Swap terms changed or record does not match its directory')
        validate_terms(self.terms)

    def point(self, name):
        if self.hook is not None:
            self.hook.point(name)

    def save(self):
        self.record['seq'] += 1
        if len(self.record['history']) > MAX_HISTORY:
            del self.record['history'][:len(self.record['history']) - MAX_HISTORY]
        data = (json.dumps(self.record, sort_keys=True, indent=1) + '\n').encode()
        self.point('store:save:before')
        temp = self.directory / f'.record.{os.getpid()}.tmp'
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()
        _write_new(temp, data)
        os.replace(temp, self.directory / 'record.json')
        _sync_directory(self.directory)
        self.point('store:save:after')

    def log(self, at, event, **detail):
        self.record['history'].append({'at': at, 'seq': self.record['seq'], 'event': event, **detail})

    def attach_identities(self, owner_blob, taker_blob, context, give_leg, now):
        """Verify both signed identity statements and record them, only if every leg of the terms names them.

        `context` is `{offer, reservation, owner_inbox, taker_inbox}` as this process knows them. Nothing is stored unless
        both statements verify (signatures, bindings, expiry) and the terms' claimants and refundees equal the signed
        addresses. A Hegemon leg has no identity scheme yet and is recorded as unverified. Attaching again is allowed only
        with identical statements."""
        from . import identity
        receive_leg = 'short' if give_leg == 'long' else 'long'
        chains = {'give': {'chain': self.terms['legs'][give_leg]['chain']}, 'receive': {'chain': self.terms['legs'][receive_leg]['chain']}}
        owner = identity.verify_identity(owner_blob, {'offer': context['offer'], 'role': 'owner', 'reservation': '', 'inbox': context['owner_inbox'], **chains}, now)
        taker = identity.verify_identity(taker_blob, {'offer': context['offer'], 'role': 'taker', 'reservation': context['reservation'], 'inbox': context['taker_inbox'], **chains}, now)
        checked = identity.check_terms(self.terms, owner, taker, give_leg)

        def summary(item):
            return {'code': item['code'], 'statement_digest': hashlib.sha256(identity.canonical(item['statement']).encode()).hexdigest(),
                    'addresses': item['addresses'], 'proven': item['proven'], 'unverified': item['unverified'], 'proofs': item['proofs'],
                    'expires': item['statement']['expires']}

        value = {'offer': context['offer'], 'reservation': context['reservation'], 'give_leg': give_leg, 'owner': summary(owner),
                 'taker': summary(taker), 'unverified_legs': checked['unverified']}
        existing = self.record.get('identities')
        if existing is not None:
            if existing != value:
                raise ValueError('Different identities are already recorded for this swap')
            return existing
        self.record['identities'] = value
        self.log(now, 'identities_verified', owner=value['owner']['code'], taker=value['taker']['code'], unverified=checked['unverified'])
        self.save()
        return value

    def write_secret(self, name, data):
        if name not in SECRET_NAMES or len(data) != 32:
            raise ValueError('Secrets are 32 bytes under a fixed name')
        self.point('store:secret:before')
        _write_new(self.directory / name, bytes(data))
        self.point('store:secret:after')

    def read_secret(self, name):
        """Return the secret as a bytearray the caller must zero, or None when absent."""
        if name not in SECRET_NAMES:
            raise ValueError('Unknown secret name')
        path = self.directory / name
        if not os.path.lexists(path):
            return None
        data = bytearray(_private_file(path, 64).read_bytes())
        if len(data) != 32 or hashlib.sha256(bytes(data)).hexdigest() != self.terms['hashlock']:
            data[:] = b'\0' * len(data)
            raise ValueError('Stored secret does not match the hashlock')
        return data


class Store:
    def __init__(self, root, hook=None):
        self.root = private_directory(root, create=True)
        self.hook = hook

    def _swap_dir(self, swap_id):
        if not ID.fullmatch(swap_id):
            raise ValueError('Invalid swap id')
        return self.root / swap_id

    def create(self, swap_id, role, terms, now, preimage=None):
        """Create a swap exclusively. The preimage (initiator only) is hashed against terms."""
        if role not in ROLES:
            raise ValueError('Role must be initiator or responder')
        validate_terms(terms)
        if (role == 'initiator') != (preimage is not None):
            raise ValueError('Only the initiator holds a preimage at init')
        if preimage is not None and hashlib.sha256(bytes(preimage)).hexdigest() != terms['hashlock']:
            raise ValueError('Preimage does not match the hashlock')
        directory = self._swap_dir(swap_id)
        directory.mkdir(mode=0o700)
        _sync_directory(self.root)
        private_directory(directory)
        (directory / 'journal').mkdir(mode=0o700)
        _write_new(directory / 'terms.json', (json.dumps(terms, sort_keys=True, indent=1) + '\n').encode())
        if preimage is not None:
            _write_new(directory / 'secret', bytes(preimage))
        record = {'version': 1, 'swap_id': swap_id, 'role': role, 'state': 'terms_saved', 'terms_digest': terms_digest(terms),
                  'escrows': {'long': None, 'short': None}, 'txids': {}, 'submitted': {}, 'inflight': None,
                  'needs_human': None, 'seq': 0, 'history': [{'at': now, 'seq': 0, 'event': 'created', 'role': role}]}
        _write_new(directory / 'record.json', (json.dumps(record, sort_keys=True, indent=1) + '\n').encode())
        return swap_id

    def list(self):
        return sorted(p.name for p in self.root.iterdir() if ID.fullmatch(p.name) and p.is_dir())

    @contextlib.contextmanager
    def locked(self, swap_id):
        directory = private_directory(self._swap_dir(swap_id))
        fd = os.open(directory / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError('Another process is advancing this swap') from error
            yield Swap(directory, self.hook)
        finally:
            os.close(fd)


def journal_ids(directory, chain=None):
    """Transaction ids of every `prepared_or_submitted` journal record in `directory`.

    Reads the JSON records written by scripts/public_swap_journal.py (or its
    simulated twin) and returns ids in a stable order. `chain` filters by chain.
    """
    ids = []
    for path in sorted(Path(directory).glob('*.json')):
        try:
            item = json.loads(path.read_text())
        except (OSError, ValueError):
            raise ValueError('Unreadable journal record: ' + path.name)
        if isinstance(item, dict) and isinstance(item.get('txid'), str) and (chain is None or item.get('chain') == chain):
            ids.append(item['txid'])
    return ids
