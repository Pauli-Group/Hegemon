"""A simulated Hegemon chain and private-spend wallet CLI, for adapter and crash-resume tests.

It speaks the profile contract of swap_engine/hegemon_wallet.py and prints the same text formats as the real
`private-spend` binary (status lines, `candidate <id>`, `submitted <96 hex>`, `verify-htlc` JSON, and the same
error sentences the real wallet raises), so the adapter's parsers and decisions are exercised against the real
shapes. The rules it enforces are the ones the local runs measured:

  * a lock needs an ordinary input and a timeout of at least tip + 14;
  * the claimant sees a locked note by syncing; the funder sees it only after importing the refund handoff;
  * a claim is valid while the note is unspent and publishes its preimage; a refund needs height above the timeout;
  * `export` marks an attempt SubmissionUncertain before it writes bytes; `submit` marks it Submitted;
  * `verify-htlc` refuses a deadline closer than its floor and a spent or unknown note.

Chain height is a function of the shared simulated clock (one block per `interval` seconds), so the chain moves
exactly as fast as the other simulated chains. A crash hook raises at the start and end of every mutating wallet
command to model a process kill between any two steps.
"""
import hashlib
import json
import os
import re
from pathlib import Path

try:
    from swap_engine import hegemon_wallet as hw
except ImportError:
    import hegemon_wallet as hw

MUTATING = ('lock', 'claim', 'refund', 'export', 'submit', 'import-refund-handoff', 'cancel')


def _flag(args, name):
    return args[args.index(name) + 1]


class FakeHegemonProfile:
    name = 'hegemon'
    journal_chain = 'hegemon-local'
    fee = 1
    prove_timeout = 600

    def __init__(self, directory, clock, people=('alice', 'bob'), interval=75, base_height=1000, hook=None):
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, exist_ok=True)
        self.clock, self.interval, self.hook = clock, interval, hook
        self.start_time, self.base = clock(), base_height
        self.height_now = base_height
        self.addresses = {p: f'shca1{p}{"0" * 40}' for p in people}
        self.notes = {}
        self.next_position = 1
        self.attempts = {p: {} for p in people}
        self.imported = {p: set() for p in people}
        self.mempool = []
        self.blocks = {}
        self.releases = []
        self.calls = []
        self.fail_reads = 0
        self.fail_commands = {}
        self.secrets_seen = []

    # ---- chain
    def _advance(self):
        target = self.base + max(0, self.clock() - self.start_time) // self.interval
        while self.height_now < target:
            self.height_now += 1
            actions, self.mempool = self.mempool, []
            self.blocks[self.height_now] = [a for a in actions if self._include(a, self.height_now)]

    def _block_hash(self, height):
        return hashlib.sha256(f'hegemon-fake-{height}'.encode()).hexdigest()

    def _add_note(self, kind, owner, value, **extra):
        position = self.next_position
        self.next_position += 1
        self.notes[position] = {'kind': kind, 'owner': owner, 'value': value, 'spent': False, 'position': position, **extra}
        return position

    def credit(self, person, value):
        return self._add_note('ordinary', person, value)

    def _include(self, action, height):
        kind, attempt = action['kind'], action['attempt']
        if kind == 'lock':
            source = self.notes.get(action['input'])
            if source is None or source['spent'] or source['owner'] != action['owner'] or source['value'] < action['amount'] + self.fee:
                return False
            source['spent'] = True
            position = self._add_note('htlc', action['owner'], action['amount'], terms=action['terms'], created=height, attempt=attempt)
            self._add_note('ordinary', action['owner'], source['value'] - action['amount'] - self.fee)
            action['position'] = position
            return True
        note = self.notes.get(action['locked'])
        if note is None or note['spent'] or note['kind'] != 'htlc':
            return False
        fee_note = self.notes.get(action['fee_input'])
        if fee_note is None or fee_note['spent']:
            return False
        if kind == 'refund' and height <= note['terms']['expiry']:
            return False
        note['spent'] = fee_note['spent'] = True
        if kind == 'claim':
            self.releases.append({'hashlock': note['terms']['hashlock'], 'preimage': action['preimage'], 'height': height})
        self._add_note('ordinary', action['owner'], note['value'])
        self._add_note('ordinary', action['owner'], fee_note['value'] - self.fee)
        return True

    # ---- profile contract
    def now(self):
        return self.clock()

    def height(self):
        if self.fail_reads:
            self.fail_reads -= 1
            raise OSError('simulated: Hegemon node unreachable')
        self._advance()
        return self.height_now

    def block_hash(self, height):
        self._advance()
        return self._block_hash(height)

    def address(self, person):
        return self.addresses[person]

    def private_dir(self, person):
        path = self.dir / 'adapter' / person
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        return path

    def handoff_secret(self, person):
        return b'handoff-passphrase'

    def observe_release(self, hashlock, start_height):
        self._advance()
        if self.fail_reads:
            self.fail_reads -= 1
            raise OSError('simulated: Hegemon node unreachable')
        for row in self.releases:
            if row['hashlock'] == hashlock and row['height'] >= start_height:
                return row['preimage'], {'block_height': row['height'], 'confirmations': self.height_now - row['height'] + 1}
        return None

    # ---- wallet
    def _visible(self, person):
        out = []
        for note in self.notes.values():
            if note['spent']:
                continue
            if note['kind'] == 'ordinary' and note['owner'] == person:
                out.append(note)
            elif note['kind'] == 'htlc' and (note['terms']['claimant'] == self.addresses[person]
                                              or (note['owner'] == person and note['attempt'] in self.imported[person])):
                out.append(note)
        return sorted(out, key=lambda n: n['position'])

    def _scan(self, person):
        for attempt in self.attempts[person].values():
            action = attempt.get('action')
            if action is None or attempt['status'] != 'Submitted' or attempt.get('mined'):
                continue
            for height, actions in self.blocks.items():
                if any(a is action for a in actions):
                    attempt['mined'] = (height, self._block_hash(height))

    def _point(self, command, when):
        if self.hook is not None and command in MUTATING:
            self.hook.point(f'wallet:{command}:{when}')

    def wallet(self, person, command, secrets=(), label=None, expected=True, timeout=None):
        name = command[0]
        self.calls.append((person, name))
        self._advance()
        self._point(name, 'before')
        try:
            text = self._run(person, name, [str(c) for c in command[1:]], list(secrets))
            code = 0
        except _Refused as error:
            text, code = f'Error: {error}\n', 1
        if code == 0:
            self._point(name, 'after')
        if expected is not None and code != 0:
            raise RuntimeError(f'{name} failed: ' + hw.last_error(text))
        return text, {'seconds': 0.0, 'peak_rss_kib': 0, 'exit_code': code}

    def _run(self, person, name, args, secrets):
        if self.fail_commands.get(name):
            self.fail_commands[name] -= 1
            raise _Refused('simulated wallet failure')
        self._scan(person)
        if name == 'sync':
            return f'synced {self.height_now}\n'
        if name == 'status':
            return self._status(person)
        if name in ('lock', 'claim', 'refund'):
            return self._prepare(person, name, args, secrets)
        if name == 'export':
            attempt = self._attempt(person, args[0])
            if attempt['status'] not in ('Candidate', 'SubmissionUncertain'):
                raise _Refused('attempt cannot be exported')
            attempt['status'] = 'SubmissionUncertain'
            with open(args[1], 'xb') as handle:
                handle.write(b'FAKE-ACTION-' + attempt['id'].encode())
            return ''
        if name == 'submit':
            attempt = self._attempt(person, args[0])
            if attempt['status'] not in ('SubmissionUncertain', 'Submitted'):
                raise _Refused('attempt was not exported')
            if attempt['status'] != 'Submitted':
                attempt['status'] = 'Submitted'
                self.mempool.append(attempt['action'])
            return 'submitted ' + hashlib.sha256(attempt['id'].encode()).hexdigest() + hashlib.sha256(b'x' + attempt['id'].encode()).hexdigest()[:32] + '\n'
        if name == 'cancel':
            attempt = self._attempt(person, args[0])
            if attempt['status'] not in ('Candidate', 'Prepared'):
                raise _Refused('only an unexported attempt can be cancelled')
            del self.attempts[person][attempt['id']]
            return ''
        if name == 'import-refund-handoff':
            return self._import(person, args, secrets)
        if name == 'verify-htlc':
            return self._verify(person, args)
        raise _Refused('unknown command ' + name)

    def _attempt(self, person, attempt_id):
        if attempt_id not in self.attempts[person]:
            raise _Refused('unknown attempt')
        return self.attempts[person][attempt_id]

    def _status(self, person):
        lines = [f'synced {self.height_now}']
        for note in self._visible(person):
            lines.append(f"{'ordinary' if note['kind'] == 'ordinary' else 'htlc'} position={note['position']} value={note['value']}")
        for attempt in self.attempts[person].values():
            if attempt.get('mined'):
                height, block = attempt['mined']
                mined = f"Some(({height}, [{', '.join(str(b) for b in bytes.fromhex(block))}]))"
            else:
                mined = 'None'
            lines.append(f"{attempt['id']} {attempt['status']} mined={mined}")
        return '\n'.join(lines) + '\n'

    def _need_prompt(self, secrets, prompt):
        found = [s for p, s in secrets if p == prompt]
        if not found:
            raise _Refused('missing secret prompt')
        self.secrets_seen.append(prompt)
        return found[0]

    def _prepare(self, person, name, args, secrets):
        height = self.height_now
        action = {'kind': name, 'owner': person}
        if name == 'lock':
            position = int(_flag(args, '--inputs'))
            note = self.notes.get(position)
            amount = int(_flag(args, '--amount'))
            if note is None or note['spent'] or note['owner'] != person or note['kind'] != 'ordinary':
                raise _Refused('unspent private note absent at position')
            if note['value'] < amount + int(_flag(args, '--fee')):
                raise _Refused('insufficient value')
            timeout = int(_flag(args, '--timeout'))
            if timeout < height + 14:
                raise _Refused('HTLC timeout must satisfy the native lock window')
            self._need_prompt(secrets, hw.HANDOFF_PROMPT)
            if '--release-secret' not in args:
                raise _Refused('release secret required')
            terms = {'chain': 'hegemon', 'amount': amount, 'claimant': _flag(args, '--claim'), 'refundee': _flag(args, '--refund'),
                     'hashlock': _flag(args, '--hashlock'), 'expiry': timeout}
            action.update(input=position, amount=amount, terms=terms)
        else:
            locked = int(_flag(args, '--locked'))
            note = next((n for n in self._visible(person) if n['position'] == locked and n['kind'] == 'htlc'), None)
            if note is None:
                raise _Refused('unspent private note absent at position')
            fee_input = int(_flag(args, '--fee-input'))
            fee_note = self.notes.get(fee_input)
            if fee_note is None or fee_note['spent'] or fee_note['owner'] != person or fee_note['kind'] != 'ordinary':
                raise _Refused('unspent fee note absent')
            action.update(locked=locked, fee_input=fee_input)
            if name == 'claim':
                secret = bytes.fromhex(self._need_prompt(secrets, hw.SECRET_PROMPT).decode())
                if hashlib.sha256(secret).hexdigest() != note['terms']['hashlock']:
                    raise _Refused('preimage does not match the hashlock')
                action['preimage'] = secret.hex()
            elif height <= note['terms']['expiry'] - 1:
                raise _Refused('refund timeout has not passed')
        attempt_id = hashlib.sha256(os.urandom(16)).hexdigest()
        action['attempt'] = attempt_id
        if name == 'lock':
            with open(_flag(args, '--refund-handoff'), 'xb') as handle:
                handle.write(json.dumps({'attempt': attempt_id, 'owner': person}).encode())
        self.attempts[person][attempt_id] = {'id': attempt_id, 'status': 'Candidate', 'mined': None, 'action': action}
        return f'proving...\ncandidate {attempt_id}\n'

    def _import(self, person, args, secrets):
        self._need_prompt(secrets, hw.HANDOFF_PROMPT)
        record = json.loads(Path(args[0]).read_text())
        height = int(_flag(args, '--block-height'))
        attempt = self.attempts[person].get(record['attempt'])
        if record['owner'] != person or attempt is None or not attempt.get('mined') or attempt['mined'][0] != height:
            raise _Refused('refund handoff does not match the canonical lock block')
        if record['attempt'] in self.imported[person]:
            raise _Refused('refund handoff already imported')
        self.imported[person].add(record['attempt'])
        return 'imported HTLC commitment ' + '00' * 48 + '\n'

    def _verify(self, person, args):
        position = int(_flag(args, '--locked'))
        note = next((n for n in self._visible(person) if n['position'] == position and n['kind'] == 'htlc'), None)
        if note is None:
            raise _Refused('unspent private note absent at position')
        confirmations = self.height_now - note['created'] + 1
        if confirmations < int(_flag(args, '--min-confirmations')):
            raise _Refused('insufficient confirmations')
        timeout = int(_flag(args, '--timeout'))
        if timeout - self.height_now < int(_flag(args, '--min-remaining-blocks')):
            raise _Refused('HTLC deadline too close')
        terms = note['terms']
        if not (terms['amount'] == int(_flag(args, '--amount')) and terms['hashlock'] == _flag(args, '--hashlock') and terms['expiry'] == timeout
                and terms['claimant'] == _flag(args, '--claim') and terms['refundee'] == _flag(args, '--refund')):
            raise _Refused('HTLC terms mismatch')
        return json.dumps({'verified': True, 'position': position, 'created_height': note['created'], 'reference_height': self.height_now,
                           'confirmations': confirmations}) + '\n'


class _Refused(Exception):
    pass
