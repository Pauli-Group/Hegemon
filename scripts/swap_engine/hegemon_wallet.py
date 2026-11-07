"""Typed parsers for the private-spend wallet CLI (`private-spend`) and the profile contract.

The CLI is the only component that holds spending keys and proves the HTLC relation, so the adapter
drives it as a subprocess and reads its text output. Every parser here is strict: an unexpected or
ambiguous output raises ValueError instead of guessing, because a wrong guess about an attempt id,
a note position or a spent note leads straight to a wrong signed action.

A *profile* (see LocalHegemonProfile in adapters/hegemon_local.py and FakeHegemonProfile in
hegemon_fake.py) is what the adapter needs from the outside world:

    journal_chain          journal record chain name
    fee                    atoms of fee per action (the wallet needs it explicitly)
    prove_timeout          hard ceiling in seconds for one proving wallet command
    now()                  integer unix seconds
    height()               canonical tip height of the guarded node (raises on any guard failure)
    block_hash(height)     canonical block hash as 64 hex
    address(person)        the person's shielded address (`shca1...`)
    private_dir(person)    0700 directory for adapter state and refund handoffs
    handoff_secret(person) bytes: the passphrase of encrypted refund handoffs
    wallet(person, command, secrets=(), label=None, expected=True, timeout=None) -> (text, metrics)
                           runs `private-spend` with the wallet passphrase typed at its prompt and the
                           given extra (prompt, secret) pairs; `expected=None` returns the text of a
                           failing run instead of raising
    observe_release(hashlock, start_height) -> None | (preimage_hex, {'block_height', 'confirmations'})
"""
import json
import re

HEX64 = re.compile('[0-9a-f]{64}')
HEX96 = re.compile('[0-9a-f]{96}')
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

# Prompts that the wallet writes before it reads a secret without echo.
PASS_PROMPT = b'Encrypted wallet passphrase: '
HANDOFF_PROMPT = b'Encrypted refund handoff passphrase: '
SECRET_PROMPT = b'Private 32-byte preimage (hex): '

ATTEMPT_LINE = re.compile(r'^([0-9a-f]{64}) ([A-Za-z]+) mined=(None|Some\(\((\d+), \[([0-9, ]+)\]\)\))\s*$', re.M)
NOTE_LINE = re.compile(r'^(ordinary|htlc|policy) position=(\d+) value=(\d+)\s*$', re.M)
SYNCED_LINE = re.compile(r'^synced (\d+)\s*$', re.M)
ATTEMPT_STATUSES = ('Prepared', 'Candidate', 'SubmissionUncertain', 'Submitted')


def clean(text):
    return ANSI.sub('', text).replace('\r', '')


def parse_status(text):
    """`status` output: {'height', 'notes': [{kind, position, value}], 'attempts': [{id, status, mined}]}."""
    text = clean(text)
    heights = SYNCED_LINE.findall(text)
    if len(heights) != 1:
        raise ValueError('status output does not name one synced height')
    notes = [{'kind': kind, 'position': int(position), 'value': int(value)} for kind, position, value in NOTE_LINE.findall(text)]
    if len({(n['kind'], n['position']) for n in notes}) != len(notes):
        raise ValueError('status output repeats a note position')
    attempts = []
    for attempt_id, status, mined, height, raw in ATTEMPT_LINE.findall(text):
        if status not in ATTEMPT_STATUSES:
            raise ValueError('unknown attempt status')
        record = {'id': attempt_id, 'status': status, 'mined': None}
        if mined != 'None':
            digits = [int(part) for part in raw.split(',')]
            if len(digits) != 32 or any(not 0 <= d <= 255 for d in digits):
                raise ValueError('malformed mined block hash')
            record['mined'] = {'height': int(height), 'hash': bytes(digits).hex()}
        attempts.append(record)
    if len({a['id'] for a in attempts}) != len(attempts):
        raise ValueError('status output repeats an attempt')
    return {'height': int(heights[0]), 'notes': notes, 'attempts': attempts}


def parse_candidate(text):
    found = set(re.findall(r'^candidate ([0-9a-f]{64})\s*$', clean(text), re.M))
    if len(found) != 1:
        raise ValueError('the wallet did not report exactly one candidate attempt')
    return found.pop()


def parse_submitted(text):
    found = set(re.findall(r'^submitted ([0-9a-f]{96})\s*$', clean(text), re.M))
    if len(found) != 1:
        raise ValueError('the wallet did not acknowledge exactly one submitted action')
    return found.pop()


def parse_verified(text):
    """The `verify-htlc` JSON line: {'position', 'created_height', 'confirmations', 'reference_height'}."""
    for line in clean(text).splitlines():
        line = line.strip()
        if line.startswith('{') and '"verified"' in line:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if value.get('verified') is True and all(isinstance(value.get(k), int) and not isinstance(value.get(k), bool)
                                                      for k in ('position', 'created_height', 'reference_height', 'confirmations')):
                return value
    raise ValueError('the wallet did not verify the escrow')


def last_error(text):
    """One short line describing why a wallet command failed. Never the whole log."""
    lines = [line.strip() for line in clean(text).splitlines()
             if line.strip() and not line.startswith('wallet-progress') and not line.startswith('Syncing blocks')]
    return (lines[-1] if lines else 'no output')[:200]
