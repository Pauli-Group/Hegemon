"""Hegemon adapter for the two-party swap engine, over the private-spend wallet (`private-spend`).

The wallet is the only component that holds keys and proves the HTLC relation, so the adapter drives it as
a subprocess through a *profile* (see swap_engine/hegemon_wallet.py for the contract). This module also
holds LocalHegemonProfile and AttachedHegemonProfile (peerless Development chains) and
PublicHegemonProfile (the pinned v0.11 public pre-mainnet). The public class is a separate
guard set: it never relaxes `peers == 0` on the local profiles.

How a swap leg maps onto the wallet
  fund    `lock` proves the HTLC (about a minute), `export` writes the exact signed action, the journal
          records those bytes, then `submit` broadcasts them. Nothing is journaled before the proof exists
          and nothing is broadcast before the journal write, as the adapter contract requires.
  claim   `claim --locked N` with the preimage typed at the wallet's no-echo prompt; same sequence.
  refund  `refund --locked N`; the funder first imports the encrypted refund handoff written by the lock.
  inspect the claimant finds the locked note by syncing and checks it with `verify-htlc` against the agreed
          terms; the funder checks its own journaled lock record against the mined attempt. A claim is seen
          from canonical block bytes (the preimage is public once it is released), never from wallet state.

An escrow reference is {'txid': <lock attempt id, 64 hex>}. It is chosen when the lock is submitted, before the
lock is mined, so it cannot name the note position; positions are resolved by the wallets. The attempt id is
also the journal transaction id; the 96-hex action id the node acknowledges is not used as an identity.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

try:
    from swap_engine.adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure
    from swap_engine import hegemon_wallet as hw
    from swap_engine.store import _write_new, canonical
except ImportError:  # plain-module use
    from adapter import ActionRefused, ChainAdapter, ChainUnavailable, JournaledWrites, empty_observation, read_failure
    import hegemon_wallet as hw
    from store import _write_new, canonical

ROOT = Path(__file__).resolve().parents[3]
LEG_FIELDS = ('chain', 'amount', 'refundee', 'claimant', 'expiry', 'hashlock')


def terms_digest(leg):
    return hashlib.sha256(canonical({key: leg[key] for key in LEG_FIELDS})).hexdigest()


def _atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(temporary, flags, 0o600), 'wb') as handle:
        handle.write(canonical(value) + b'\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return None


class HegemonAdapter(JournaledWrites, ChainAdapter):
    chain = 'hegemon'

    def __init__(self, profile, person, floor_confirmations=1, floor_remaining_blocks=1):
        self.profile = profile
        self.person = person
        self.journal_chain = profile.journal_chain
        self.floor_confirmations = floor_confirmations
        self.floor_remaining_blocks = floor_remaining_blocks
        self.state = Path(profile.private_dir(person))
        for name in ('locks', 'verified', 'imported', 'spends', 'exports', 'handoffs', 'scans'):
            (self.state / name).mkdir(mode=0o700, exist_ok=True)
        self._address = profile.address(person)

    # ---- wallet access
    def _wallet(self, command, secrets=(), label=None, expected=True, timeout=None):
        return self.profile.wallet(self.person, command, secrets, label or f'{self.person}-{command[0]}', expected, timeout)

    def _read(self, command, label=None):
        """A read-only wallet call; any failure means the chain could not be read, never that nothing exists."""
        try:
            return self._wallet(command, label=label)[0]
        except (RuntimeError, OSError, ValueError) as error:
            raise read_failure(error) from error

    def _status(self):
        try:
            return hw.parse_status(self._read(['status'], f'{self.person}-status'))
        except ValueError as error:
            raise read_failure(error) from error

    @contextlib.contextmanager
    def _write_lock(self):
        descriptor = os.open(self.state / 'write.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    # ---- reads
    def identity(self):
        return self._address

    def head(self):
        try:
            return {'observedAt': self.profile.now(), 'height': int(self.profile.height())}
        except Exception as error:
            raise read_failure(error) from error

    def escrow_ref(self, leg, txid):
        if not isinstance(txid, str) or not hw.HEX64.fullmatch(txid):
            raise ValueError('Invalid Hegemon lock attempt id')
        return {'txid': txid}

    def transaction_seen(self, txid):
        if not isinstance(txid, str) or not hw.HEX64.fullmatch(txid):
            raise ValueError('Invalid Hegemon attempt id')
        for attempt in self._status()['attempts']:
            if attempt['id'] == txid:
                return attempt['status'] == 'Submitted' or attempt['mined'] is not None
        return False

    def _role(self, leg):
        if leg['chain'] != 'hegemon':
            raise ValueError('Not a Hegemon leg')
        if leg['claimant'] == self._address and leg['refundee'] != self._address:
            return 'claimant'
        if leg['refundee'] == self._address and leg['claimant'] != self._address:
            return 'refundee'
        raise ValueError('The wallet is neither the claimant nor the refundee of this leg')

    def _terms_args(self, leg, position):
        return ['verify-htlc', '--locked', str(position), '--claim', leg['claimant'], '--refund', leg['refundee'],
                '--hashlock', leg['hashlock'], '--timeout', str(leg['expiry']), '--amount', str(leg['amount']),
                '--min-confirmations', str(self.floor_confirmations), '--min-remaining-blocks', str(self.floor_remaining_blocks)]

    def _verify(self, leg, position):
        """('verified', info) | ('mismatch', None) | ('unverifiable', reason). Anything else is unreadable."""
        try:
            text, metrics = self._wallet(self._terms_args(leg, position), label=f'{self.person}-verify', expected=None)
        except (RuntimeError, OSError) as error:
            raise read_failure(error) from error
        if metrics['exit_code'] == 0:
            try:
                return 'verified', hw.parse_verified(text)
            except ValueError as error:
                raise read_failure(error) from error
        reason = hw.last_error(text)
        if 'HTLC terms mismatch' in reason or 'not an HTLC note' in reason:
            return 'mismatch', None
        if 'HTLC deadline too close' in reason:
            return 'unverifiable', reason
        raise ChainUnavailable('wallet could not verify the escrow: ' + reason)

    def _cache_path(self, leg):
        return self.state / 'verified' / (terms_digest(leg) + '.json')

    def _find_claimant_note(self, leg, status):
        """(position, created_height) of the note that matches every agreed term, or (None, None)."""
        cached = _load_json(self._cache_path(leg))
        if cached is not None:
            return cached['position'], cached['created_height']
        for note in status['notes']:
            if note['kind'] != 'htlc' or note['value'] != leg['amount']:
                continue
            verdict, info = self._verify(leg, note['position'])
            if verdict == 'verified':
                _atomic_json(self._cache_path(leg), {'position': info['position'], 'created_height': info['created_height']})
                return info['position'], info['created_height']
        return None, None

    def _lock_record(self, leg, escrow):
        txid = escrow.get('txid') if isinstance(escrow, dict) else None
        if not isinstance(txid, str) or not hw.HEX64.fullmatch(txid):
            raise ValueError('Invalid Hegemon escrow reference')
        record = _load_json(self.state / 'locks' / (txid + '.json'))
        if record is None or record.get('digest') != terms_digest(leg):
            raise ValueError('This wallet did not make a lock with these terms')
        return txid, record

    def _import_handoff(self, txid, record, mined_height):
        marker = self.state / 'imported' / (txid + '.json')
        if marker.exists():
            return
        handoff = self.state / 'handoffs' / (record['token'] + '.bin')
        self._wallet(['import-refund-handoff', handoff, '--block-height', str(mined_height), '--refund-index', '0'],
                     [(hw.HANDOFF_PROMPT, self.profile.handoff_secret(self.person))], f'{self.person}-import')
        _atomic_json(marker, {'imported': True, 'height': mined_height})

    def _find_refund_note(self, leg, txid, record, status, mined):
        cached = _load_json(self._cache_path(leg))
        if cached is not None:
            return cached['position']
        marker = self.state / 'imported' / (txid + '.json')

        def candidates(current):
            return [n for n in current['notes'] if n['kind'] == 'htlc' and n['value'] == leg['amount']]

        def verified(notes):
            for note in notes:
                verdict, info = self._verify(leg, note['position'])
                if verdict == 'verified':
                    _atomic_json(self._cache_path(leg), {'position': info['position'], 'created_height': info['created_height']})
                    return info['position']
            return None

        notes = candidates(status)
        if notes and not marker.exists():
            # The funder sees a locked note only after importing its handoff, so a visible note means a crash left
            # the marker unwritten. Importing again would fail; record what is already true.
            _atomic_json(marker, {'imported': True, 'height': mined['height']})
        position = verified(notes)
        if position is None and not marker.exists():
            try:
                self._import_handoff(txid, record, mined['height'])
            except (RuntimeError, OSError) as error:
                raise read_failure(error) from error
            notes = candidates(self._status())
            position = verified(notes)
        if position is not None:
            return position
        # Our own lock, imported from our own handoff, whose window is too close for the wallet to verify:
        # accept the only note of the right size.
        if len(notes) == 1 and marker.exists():
            return notes[0]['position']
        return None

    SCAN_MARGIN = 12  # blocks re-read behind the last scan, so a short reorg cannot hide a release

    def _release(self, hashlock, created):
        """(preimage_hex, meta) of a claim that released `hashlock` at or after `created`, else None.

        Only canonical block bytes are read. The scan resumes near where the last empty scan stopped.
        """
        cursor_path = self.state / 'scans' / (hashlock + '.json')
        cursor = _load_json(cursor_path)
        start = max(created, cursor['tip'] - self.SCAN_MARGIN) if cursor else created
        try:
            tip = int(self.profile.height())
            found = self.profile.observe_release(hashlock, max(1, start))
        except Exception as error:
            raise read_failure(error) from error
        if found is None:
            # Only advance past blocks the scan could have confirmed. A sub-second
            # timeout used to return None without reading, which skipped the claim.
            _atomic_json(cursor_path, {'tip': max(created, start)})
        return found

    def inspect(self, leg, escrow):
        role = self._role(leg)
        observation = empty_observation()
        status = self._status()
        tip = status['height']
        if role == 'refundee':
            return self._inspect_refundee(leg, escrow, status, tip, observation)
        return self._inspect_claimant(leg, status, tip, observation)

    def _canonical_mined(self, mined):
        try:
            same = self.profile.block_hash(mined['height']) == mined['hash']
        except Exception as error:
            raise read_failure(error) from error
        if not same:
            raise ChainUnavailable('snapshot or chain changed')

    def _inspect_refundee(self, leg, escrow, status, tip, observation):
        try:
            txid, record = self._lock_record(leg, escrow)
        except ValueError as error:
            raise ChainUnavailable('this wallet has no record of that lock (' + str(error) + '); its adapter state may be missing') from error
        attempt = next((a for a in status['attempts'] if a['id'] == txid), None)
        if attempt is None or attempt['mined'] is None:
            return observation
        self._canonical_mined(attempt['mined'])
        created = attempt['mined']['height']
        observation['found'] = True
        observation['verified'] = True  # our own wallet built this lock from exactly these terms
        observation['confirmations'] = max(0, tip - created + 1)
        release = self._release(leg['hashlock'], created)
        if release is not None:
            preimage, meta = release
            observation.update(spent='claimed', spend_confirmations=meta['confirmations'], preimage=preimage)
            return observation
        spend = _load_json(self.state / 'spends' / (txid + '.json'))
        if spend is not None and spend.get('action') == 'refund':
            mined = next((a['mined'] for a in status['attempts'] if a['id'] == spend['attempt']), None)
            if mined is not None:
                self._canonical_mined(mined)
                observation.update(spent='refunded', spend_txid=spend['attempt'], spend_confirmations=max(0, tip - mined['height'] + 1))
        return observation

    def _inspect_claimant(self, leg, status, tip, observation):
        position, created = self._find_claimant_note(leg, status)
        if position is None:
            return observation
        observation['found'] = True
        observation['verified'] = True
        observation['confirmations'] = max(0, tip - created + 1)
        if any(n['kind'] == 'htlc' and n['position'] == position for n in status['notes']):
            return observation
        # The note is no longer unspent: a claim leaves its preimage in public bytes, a refund does not.
        release = self._release(leg['hashlock'], created)
        if release is not None:
            preimage, meta = release
            observation.update(spent='claimed', spend_confirmations=meta['confirmations'], preimage=preimage)
            return observation
        if tip < leg['expiry']:
            raise ChainUnavailable('the locked note is spent but no release is visible before its deadline')
        observation['spent'] = 'refunded'
        return observation

    # ---- writes
    def _check_actor(self, leg, role):
        try:
            actual = self._role(leg)
        except ValueError as error:
            raise ActionRefused(str(error)) from error
        if actual != role:
            raise ActionRefused(f'the wallet is not the {role} of this leg')

    def _cancel_stale(self, journal, status):
        """Cancel proved-but-never-journaled attempts left by a crash before the journal write."""
        journaled = set(self.journal_ids(journal))
        for attempt in status['attempts']:
            if attempt['id'] in journaled or attempt['mined'] is not None or attempt['status'] in ('Submitted', 'SubmissionUncertain'):
                continue
            try:
                self._wallet(['cancel', attempt['id']], label=f'{self.person}-cancel')
            except (RuntimeError, OSError):
                pass  # best effort: a retained attempt only reserves notes

    def _wallet_status_for_write(self):
        try:
            return hw.parse_status(self._wallet(['status'], label=f'{self.person}-status')[0])
        except (RuntimeError, OSError, ValueError) as error:
            raise ValueError('the wallet could not report its notes: ' + str(error)[:160]) from error

    @staticmethod
    def _smallest(notes, kind, at_least, exclude=()):
        pool = sorted((n for n in notes if n['kind'] == kind and n['value'] >= at_least and n['position'] not in exclude),
                      key=lambda n: (n['value'], n['position']))
        return pool[0]['position'] if pool else None

    def _prepare(self, command, secrets, label):
        try:
            text, metrics = self._wallet(command, secrets, label, timeout=self.profile.prove_timeout)
        except RuntimeError as error:
            raise ValueError('the wallet did not prepare the action: ' + str(error)[:200]) from error
        try:
            return hw.parse_candidate(text), metrics
        except ValueError as error:
            raise ValueError(str(error)) from error

    def _journal_and_submit(self, attempt, journal, before_submit=None):
        export = self.state / 'exports' / (attempt + '.action')
        try:
            self._wallet(['export', attempt, export], label=f'{self.person}-export')
        except RuntimeError as error:
            raise ValueError('the wallet did not export the prepared action: ' + str(error)[:200]) from error
        raw = export.read_bytes()
        if not 1 <= len(raw) <= 1_000_000:
            raise ValueError('the exported action has an invalid size')
        base = Path(journal) / f'{self.journal_chain}-{attempt}'
        _write_new(str(base) + '.signed', raw)
        _write_new(str(base) + '.json', (json.dumps({'version': 1, 'chain': self.journal_chain, 'txid': attempt, 'state': 'prepared_or_submitted'}, sort_keys=True) + '\n').encode())
        with contextlib.suppress(OSError):
            export.unlink()
        if before_submit is not None:
            before_submit()
        # From here the transaction may be on the network: errors propagate so the engine recovers from the journal.
        text, _ = self._wallet(['submit', attempt], label=f'{self.person}-submit')
        hw.parse_submitted(text)
        return {'txid': attempt}

    def fund(self, leg, journal):
        self._check_actor(leg, 'refundee')
        if not isinstance(leg['amount'], int) or leg['amount'] <= 0 or not hw.HEX64.fullmatch(leg['hashlock']):
            raise ActionRefused('invalid amount or hashlock')
        return self._journaled(journal, lambda: self._fund(leg, journal))

    def _fund(self, leg, journal):
        with self._write_lock():
            status = self._wallet_status_for_write()
            self._cancel_stale(journal, status)
            fee = self.profile.fee
            position = self._smallest(status['notes'], 'ordinary', leg['amount'] + fee)
            if position is None:
                raise ValueError('no spendable note is large enough for the amount and fee')
            token = os.urandom(16).hex()
            handoff = self.state / 'handoffs' / (token + '.bin')
            try:
                attempt, _ = self._prepare(
                    ['lock', '--inputs', str(position), '--claim', leg['claimant'], '--refund', self._address, '--hashlock', leg['hashlock'],
                     '--timeout', str(leg['expiry']), '--amount', str(leg['amount']), '--fee', str(fee), '--release-secret', '--refund-handoff', handoff],
                    [(hw.HANDOFF_PROMPT, self.profile.handoff_secret(self.person))], f'{self.person}-lock')
            except ValueError:
                with contextlib.suppress(OSError):
                    handoff.unlink()
                raise
            _atomic_json(self.state / 'locks' / (attempt + '.json'), {'digest': terms_digest(leg), 'token': token, 'expiry': leg['expiry']})
            return self._journal_and_submit(attempt, journal)

    def claim(self, leg, escrow, preimage, journal):
        self._check_actor(leg, 'claimant')
        secret = bytes(preimage)
        if len(secret) != 32 or hashlib.sha256(secret).hexdigest() != leg['hashlock']:
            raise ActionRefused('the preimage does not match the hashlock')
        return self._journaled(journal, lambda: self._spend('claim', leg, escrow, journal, secret))

    def refund(self, leg, escrow, journal):
        self._check_actor(leg, 'refundee')
        return self._journaled(journal, lambda: self._spend('refund', leg, escrow, journal, None))

    def _spend(self, action, leg, escrow, journal, secret):
        with self._write_lock():
            status = self._wallet_status_for_write()
            self._cancel_stale(journal, status)
            if action == 'claim':
                position, _ = self._find_claimant_note(leg, status)
                if position is None or not any(n['kind'] == 'htlc' and n['position'] == position for n in status['notes']):
                    raise ValueError('the verified escrow is not an unspent note of this wallet')
                spend_id = None
            else:
                txid, record = self._lock_record(leg, escrow)
                attempt = next((a for a in status['attempts'] if a['id'] == txid), None)
                if attempt is None or attempt['mined'] is None:
                    raise ValueError('the lock is not mined yet')
                position = self._find_refund_note(leg, txid, record, status, attempt['mined'])
                if position is None or not any(n['kind'] == 'htlc' and n['position'] == position for n in self._status()['notes']):
                    raise ValueError('the refund note is not available to this wallet')
                spend_id = txid
            fee = self.profile.fee
            fee_input = self._smallest(status['notes'], 'ordinary', fee)
            if fee_input is None:
                raise ValueError('no spendable note to pay the fee')
            command = [action, '--locked', str(position), '--fee-input', str(fee_input), '--recipient', self._address, '--fee', str(fee)]
            secrets = [(hw.SECRET_PROMPT, secret.hex().encode())] if secret is not None else []
            attempt_id, _ = self._prepare(command, secrets, f'{self.person}-{action}')

            def remember():
                if spend_id is not None:
                    _atomic_json(self.state / 'spends' / (spend_id + '.json'), {'action': 'refund', 'attempt': attempt_id})
            return self._journal_and_submit(attempt_id, journal, remember)


# ---------------------------------------------------------------------------------------------------------
# A private, peerless Development chain with real wallets, for local fixture swaps and tests.

def find_binaries():
    """(node, wallet) built with `development-candidate` and `wallet/private-spend-dev-artifacts`."""
    candidates = []
    if os.environ.get('HEGEMON_DEV_NODE') and os.environ.get('HEGEMON_PRIVATE_SPEND'):
        candidates.append((Path(os.environ['HEGEMON_DEV_NODE']), Path(os.environ['HEGEMON_PRIVATE_SPEND'])))
    candidates.append((Path.home() / '.local/opt/hegemon-p6/hegemon-node', Path.home() / '.local/opt/hegemon-p6/private-spend'))
    candidates.append((ROOT / 'target/release/hegemon-node', ROOT / 'target/release/private-spend'))
    for node, wallet in candidates:
        if node.is_file() and wallet.is_file():
            helped = subprocess.run([str(node), '--help'], capture_output=True, text=True, timeout=30).stdout
            if '--development-candidate' in helped:
                return node, wallet
    raise FileNotFoundError('Build the development binaries first: cargo build --locked --release -p hegemon-node --bin hegemon-node '
                            '--features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend '
                            '(or set HEGEMON_DEV_NODE and HEGEMON_PRIVATE_SPEND)')


def _loopback(url):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname != '127.0.0.1' or not parts.port or parts.username or parts.path not in ('', '/') or parts.query or parts.fragment:
        raise ValueError('The local Hegemon profile only talks to an explicit http://127.0.0.1:PORT endpoint')
    return f'http://127.0.0.1:{parts.port}'


def _private_secret(path):
    """A passphrase file: private, user-owned, one line."""
    path = Path(path)
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Passphrase files must be private, user-owned regular files: ' + str(path))
    return path.read_bytes().strip()


class LoopbackProfile:
    """Wallet, node RPC and release observation for a peerless Development chain on this machine.

    Every read first checks that the node has zero peers and the expected genesis, so a wallet command or an
    observation can never silently run against a public network. It holds no secret on disk beyond what the
    operator's passphrase files already hold, and it never logs one.
    """
    name = 'hegemon'
    journal_chain = 'hegemon-local'
    fee = 1
    prove_timeout = 600

    def __init__(self, directory, wallet_binary, url, manifest, stores, addresses, wallet_pass, handoff_pass, helper=None):
        if helper is None:
            import local_private_spend_swap as helper
        import release_private_spend_lifecycle_io as io
        self._helper, self._io = helper, io
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.wallet_binary = Path(wallet_binary)
        self.url = _loopback(url)
        self.manifest = Path(manifest)
        self._stores = {name: Path(path) for name, path in stores.items()}
        self._addresses = dict(addresses)
        self._wallet_pass, self._handoff_pass = wallet_pass, handoff_pass
        self.genesis = None
        self.metrics = []

    # ---- profile contract
    def now(self):
        return int(time.time())

    def address(self, person):
        return self._addresses[person]

    def private_dir(self, person):
        path = self.dir / 'adapter' / person
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o700)
        return path

    def handoff_secret(self, person):
        return self._handoff_pass

    def rpc(self, method, params=None):
        return self._io.rpc(self.url, method, params if params is not None else [])

    def pin_genesis(self, expected=None):
        found = self.rpc('chain_getBlockHash', [0])
        if expected is not None and found != expected:
            raise RuntimeError('Hegemon genesis is not the expected one')
        self.genesis = found
        self._guard()

    def _guard(self):
        if self.rpc('system_health')['peers'] != 0:
            raise RuntimeError('Hegemon has peers; the local profile refuses to continue')
        if self.rpc('chain_getBlockHash', [0]) != self.genesis:
            raise RuntimeError('Hegemon genesis changed')

    def height(self):
        self._guard()
        return self._io.height(self.url)

    def block_hash(self, height):
        return str(self.rpc('chain_getBlockHash', [height])).removeprefix('0x')

    def wallet(self, person, command, secrets=(), label=None, expected=True, timeout=None):
        argv = ['--wallet', self._stores[person], '--manifest', self.manifest, '--genesis', self.genesis,
                '--rpc', self.url, '--development-local-candidate', *command]
        text, metrics = self._helper.wallet(self.wallet_binary, argv, [(hw.PASS_PROMPT, self._wallet_pass), *secrets], self.dir,
                                            label or f'{person}-{command[0]}', expected=None, timeout=timeout or 600)
        self.metrics.append({'label': label, 'command': command[0], **metrics})
        if expected is not None and metrics['exit_code'] != 0:
            raise RuntimeError(f'{command[0]} failed: ' + hw.last_error(text))
        return text, metrics

    def observe_release(self, hashlock, start_height):
        import hegemon_preimage_observer as observer
        try:
            secret, meta = observer.observe_hegemon_preimage(self.url, manifest=self.manifest, genesis=self.genesis, hashlock=hashlock,
                                                             start_height=start_height, confirmations=1, timeout=0.05)
        except ValueError as error:
            if 'timed out' in str(error):
                return None
            raise
        try:
            return bytes(secret).hex(), {'block_height': meta['block_height'], 'confirmations': meta['confirmations']}
        finally:
            secret[:] = b'\0' * len(secret)


class AttachedHegemonProfile(LoopbackProfile):
    """One person's wallet on a Development chain that is already running (the engine CLI's `hegemon` entry).

    Config keys: rpc, manifest, wallet (the wallet store), wallet_binary, address, passphrase_file,
    handoff_passphrase_file, and optionally state_dir. The wallet's `private-spend` binary must be the
    development build; the production build refuses Development mode.
    """

    def __init__(self, config):
        for key in ('rpc', 'manifest', 'wallet', 'wallet_binary', 'address', 'passphrase_file', 'handoff_passphrase_file'):
            if not isinstance(config.get(key), str) or not config[key]:
                raise ValueError(f'hegemon wallet config needs {key}')
        state = Path(config.get('state_dir') or (Path(config['wallet']).parent / 'hegemon-swap-state'))
        super().__init__(state, config['wallet_binary'], config['rpc'], config['manifest'], {'self': config['wallet']}, {'self': config['address']},
                         _private_secret(config['passphrase_file']), _private_secret(config['handoff_passphrase_file']))
        self.pin_genesis()


class PublicHegemonProfile:
    """One person's wallet on the pinned v0.11 public pre-mainnet, loopback RPC only.

    Separate from LoopbackProfile: this class requires peers, a tip within two blocks of the public
    explorer, the pinned manifest and genesis, and NTP. It never adds `--development-local-candidate`.
    Config keys match AttachedHegemonProfile plus `"profile": "public"`.
    """
    name = 'hegemon'
    journal_chain = 'hegemon-pre-mainnet'
    # Public rehearsal and smoke use 1000 atoms; the local Development profile keeps fee = 1.
    fee = 1_000
    prove_timeout = 1800

    def __init__(self, config, *, ntp=None, probe_node=None, compare=None):
        for key in ('rpc', 'manifest', 'wallet', 'wallet_binary', 'address', 'passphrase_file', 'handoff_passphrase_file'):
            if not isinstance(config.get(key), str) or not config[key]:
                raise ValueError(f'hegemon wallet config needs {key}')
        import local_private_spend_swap as helper
        import release_private_spend_lifecycle_io as io
        import probe_hegemon_testnet as probe
        self._helper, self._io, self._probe = helper, io, probe
        self._ntp = ntp
        self._probe_node = probe_node
        self._compare = compare
        release = json.loads(probe.RELEASE.read_text())
        self._expected_genesis = release['genesis_hash']
        self.dir = Path(config.get('state_dir') or (Path(config['wallet']).parent / 'hegemon-public-swap-state'))
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.wallet_binary = Path(config['wallet_binary'])
        self.url = _loopback(config['rpc'])
        self.manifest = Path(config['manifest'])
        self._stores = {'self': Path(config['wallet'])}
        self._addresses = {'self': config['address']}
        self._wallet_pass = _private_secret(config['passphrase_file'])
        self._handoff_pass = _private_secret(config['handoff_passphrase_file'])
        self.genesis = None
        self.metrics = []
        self.pin_genesis()

    def now(self):
        return int(time.time())

    def address(self, person):
        return self._addresses[person]

    def private_dir(self, person):
        path = self.dir / 'adapter' / person
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o700)
        return path

    def handoff_secret(self, person):
        return self._handoff_pass

    def rpc(self, method, params=None):
        return self._io.rpc(self.url, method, params if params is not None else [])

    def pin_genesis(self, expected=None):
        node, _ = self._guard()
        found = node['genesis']
        if expected is not None and found != expected:
            raise RuntimeError('Hegemon genesis is not the expected one')
        self.genesis = found

    def _guard(self):
        return self._probe.assert_public_profile(
            self.url, genesis=self._expected_genesis, manifest=self.manifest,
            ntp=self._ntp, probe_node=self._probe_node, compare=self._compare)

    def height(self):
        self._guard()
        return self._io.height(self.url)

    def block_hash(self, height):
        return str(self.rpc('chain_getBlockHash', [height])).removeprefix('0x')

    def wallet(self, person, command, secrets=(), label=None, expected=True, timeout=None):
        if '--development-local-candidate' in command:
            raise RuntimeError('the public Hegemon profile refuses Development-only wallet flags')
        self._guard()
        argv = ['--wallet', self._stores[person], '--manifest', self.manifest, '--genesis', self.genesis,
                '--rpc', self.url, *command]
        text, metrics = self._helper.wallet(self.wallet_binary, argv, [(hw.PASS_PROMPT, self._wallet_pass), *secrets], self.dir,
                                            label or f'{person}-{command[0]}', expected=None, timeout=timeout or self.prove_timeout)
        self.metrics.append({'label': label, 'command': command[0], **metrics})
        if expected is not None and metrics['exit_code'] != 0:
            raise RuntimeError(f'{command[0]} failed: ' + hw.last_error(text))
        return text, metrics

    def observe_release(self, hashlock, start_height):
        self._guard()
        import public_hegemon_preimage_observer as observer
        confirmations = self._probe.hegemon_policy_confirmations()
        try:
            found = observer.scan_public_hegemon_preimage(
                self.url, hashlock=hashlock, start_height=start_height,
                confirmations=confirmations, timeout=15)
        except TimeoutError:
            return None
        except ValueError as error:
            if 'timed out' in str(error).lower():
                return None
            raise
        if found is None:
            return None
        secret, meta = found
        try:
            return bytes(secret).hex(), {'block_height': meta['block_height'], 'confirmations': meta['confirmations']}
        finally:
            secret[:] = b'\0' * len(secret)


TEMPLATE_DIR = Path.home() / '.local/opt/hegemon-p6/template'


class LocalHegemonProfile(LoopbackProfile):
    """A private Development chain with two funded wallets, for local fixture swaps and tests.

    A chain cannot be produced faster than the protocol allows: the difficulty retargets every 10 blocks toward a
    60 second block time (a 4x change at most per window), so a freshly mined chain that outruns that is quickly
    too hard to mine. The expensive part, mining about 136 blocks so that the reward notes of Alice and Bob have
    matured, is therefore done once into a *template* (`build_template`); every run copies the template into a
    fresh directory and mines on from it at the chain's natural pace, with `miner` rewarding the third wallet so
    Alice's and Bob's balances do not move by themselves.
    """
    ALICE_BLOCKS = 8
    BOB_BLOCKS = 8
    MATURE_HEIGHT = 136
    SETTLE_HEIGHT = 152

    def __init__(self, directory, template=None, node=None, wallet=None, mine=True, miner_threads=1):
        import local_private_spend_swap as helper
        self.node_binary, wallet_binary = (Path(node), Path(wallet)) if node and wallet else find_binaries()
        directory = Path(directory)
        self.people = ('alice', 'bob', 'treasury')
        self.miner_threads = miner_threads
        self._proc = None
        self._log = None
        self._lock = threading.Lock()
        self._mining = False
        template_dir = Path(template) if template else TEMPLATE_DIR
        if template is False:
            secrets = {'wallet_pass': os.urandom(24).hex(), 'handoff_pass': os.urandom(24).hex()}
            addresses = {}
        else:
            secrets = json.loads(_private_file(template_dir / 'secrets.json').read_text())
            addresses = secrets['addresses']
            if directory.exists():
                raise FileExistsError(f'{directory} already exists; every local run uses a fresh directory')
            shutil.copytree(template_dir / 'state', directory, symlinks=False)
            os.chmod(directory, 0o700)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        super().__init__(directory, wallet_binary, 'http://127.0.0.1:1', directory / 'manifest.json',
                         {name: directory / (name + '.store') for name in self.people}, addresses,
                         secrets['wallet_pass'].encode(), secrets['handoff_pass'].encode(), helper)
        try:
            if template is not False:
                self._attach(mine)
        except BaseException:
            self.close()
            raise

    # ---- chain control
    def _bootstrap(self):
        for person in self.people:
            argv = ['--wallet', self._stores[person], 'bootstrap-new']
            text, _ = self._helper.wallet(self.wallet_binary, argv, [(hw.PASS_PROMPT, self._wallet_pass),
                                          (b'Confirm encrypted wallet passphrase: ', self._wallet_pass)], self.dir, f'{person}-bootstrap', expected=True)
            self._addresses[person] = json.loads(text.splitlines()[-1].strip())['address']
        manifest = json.loads(subprocess.check_output([str(self.node_binary), '--print-development-candidate-manifest',
                                                       '--development-funding-address', self._addresses['treasury']]))
        manifest['pow_bits'] = 0x207fffff
        self.manifest.write_text(json.dumps(manifest, indent=2))

    def _start_node(self, miner):
        self._stop_node()
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEGEMON_')}
        env.update(HEGEMON_MINER_ADDRESS=self._addresses[miner], HEGEMON_SEEDS='', HEGEMON_MINE='0', HEGEMON_BOOTSTRAP_AUTHORING='1',
                   RAYON_NUM_THREADS='2', RUST_LOG='warn')
        self.rpc_port, self.p2p_port = self._helper.port(), self._helper.port()
        self.url = f'http://127.0.0.1:{self.rpc_port}'
        self._log = (self.dir / f'node-{miner}.log').open('ab')
        self._proc = subprocess.Popen(
            [str(self.node_binary), '--dev', '--network', 'development', '--network-manifest', str(self.manifest), '--development-candidate',
             '--base-path', str(self.dir / 'chain'), '--rpc-port', str(self.rpc_port), '--rpc-methods', 'unsafe', '--listen-addr',
             f'127.0.0.1:{self.p2p_port}', '--port', str(self.p2p_port)],
            env=env, stdout=self._log, stderr=subprocess.STDOUT, start_new_session=True)
        end = time.monotonic() + 180
        while True:
            if self._proc.poll() is not None:
                raise RuntimeError('Hegemon node exited; see ' + str(self._log.name))
            try:
                found = self.rpc('chain_getBlockHash', [0])
                break
            except (OSError, RuntimeError):
                if time.monotonic() > end:
                    raise RuntimeError('Hegemon node RPC did not start')
                time.sleep(0.2)
        if self.genesis is None:
            self.pin_genesis()
        elif found != self.genesis:
            raise RuntimeError('Hegemon genesis changed across a restart')

    def _stop_node(self):
        self._mining = False
        if self._proc is not None:
            self._helper.stop(self._proc)
            self._proc = None
        if self._log is not None:
            self._log.close()
            self._log = None

    def mine(self, target):
        """Mine until the canonical height reaches `target` (peerless chain)."""
        with self._lock:
            self._helper.mine(self.url, target)

    def start_mining(self):
        """Mine continuously at the chain's own pace until `stop_mining` or `close`."""
        self._guard()
        self.rpc('hegemon_startMining', [{'threads': self.miner_threads}])
        self._mining = True

    def stop_mining(self):
        if self._mining and self._proc is not None:
            self.rpc('hegemon_stopMining')
        self._mining = False

    def _attach(self, mine):
        self._start_node('treasury')
        self.start_height = self._io.height(self.url)
        for person in ('alice', 'bob'):
            self.wallet(person, ['sync'], label=f'{person}-sync')
        if mine:
            self.start_mining()

    def build_template(self, destination):
        """Mine the reward notes of Alice and Bob and save the chain, wallets and secrets as a template."""
        destination = Path(destination)
        if destination.exists():
            raise FileExistsError(str(destination))
        self.dir.joinpath('chain').mkdir(exist_ok=True)
        self._bootstrap()
        for person, count in (('alice', self.ALICE_BLOCKS), ('bob', self.BOB_BLOCKS)):
            self._start_node(person)
            self.mine(self._io.height(self.url) + count)
        self._start_node('treasury')
        self.mine(self.MATURE_HEIGHT)
        for person in ('alice', 'bob'):
            self.wallet(person, ['sync'], label=f'{person}-template-sync')
            status = hw.parse_status(self.wallet(person, ['status'], label=f'{person}-template-status')[0])
            usable = [n for n in status['notes'] if n['kind'] == 'ordinary']
            if len(usable) < 6:
                raise RuntimeError(f'{person} has only {len(usable)} mature notes; mine further before saving the template')
        height = self.settle()
        self._stop_node()
        destination.mkdir(mode=0o700, parents=True)
        state = destination / 'state'
        shutil.copytree(self.dir, state, ignore=shutil.ignore_patterns('*.log', 'adapter'), symlinks=False)
        os.chmod(state, 0o700)
        secrets = destination / 'secrets.json'
        fd = os.open(secrets, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump({'wallet_pass': self._wallet_pass.decode(), 'handoff_pass': self._handoff_pass.decode(), 'addresses': self._addresses,
                       'height': height, 'note': 'Development fixture chain with no value; kept private anyway.'}, handle)
        return height

    def settle(self, height=SETTLE_HEIGHT, timeout=4 * 3600):
        """Mine on at the runtime thread count until the retarget has caught up with this machine's hash rate.

        The fast bootstrap leaves the difficulty far above what one thread can mine in a minute. The retarget cannot
        fall faster than 4x per 10-block window, so the first slow window brings it down; saving the template after
        that makes every run start at an honest pace."""
        self.start_mining()
        started = time.monotonic()
        try:
            while self._io.height(self.url) < height:
                if time.monotonic() - started > timeout:
                    raise RuntimeError('the chain did not settle in time')
                time.sleep(5)
        finally:
            self.stop_mining()
        return self._io.height(self.url)

    def block_times(self):
        """{height: timestamp seconds} of every mined block on the chain."""
        return {int(row['height']): row['timestamp_ms'] / 1000 for row in self.rpc('hegemon_minedBlockTimestamps')}

    def spans_within_windows(self, chain_timing, first_height=None):
        """Problems found when the blocks mined during this run left the windows the timing entry promised.

        `first_height` defaults to the run's first block after the template; that block's own interval includes the
        time the template sat idle on disk, so spans start after it."""
        times = self.block_times()
        first = (first_height if first_height is not None else self.start_height) + 1
        heights = sorted(h for h in times if h >= first)
        problems = []
        for n, window in chain_timing['windows'].items():
            n = int(n)
            for index in range(len(heights) - n):
                a, b = heights[index], heights[index + n]
                if b - a != n:
                    continue
                span = times[b] - times[a]
                if not window['min'] <= span <= window['max']:
                    problems.append(f'{n} blocks from {a} took {span:.0f}s, outside [{window["min"]}, {window["max"]}]')
        return problems

    def pause_blocks(self):
        self.stop_mining()

    def resume_blocks(self):
        self.start_mining()

    def balance(self, person):
        status = hw.parse_status(self.wallet(person, ['status'], label=f'{person}-balance')[0])
        return sum(n['value'] for n in status['notes'] if n['kind'] == 'ordinary')

    def close(self):
        self.stop_mining_quietly()
        self._stop_node()

    def stop_mining_quietly(self):
        try:
            self.stop_mining()
        except Exception:
            pass


def _private_file(path):
    info = Path(path).lstat()
    if not Path(path).is_file() or Path(path).is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('File must be private and user-owned: ' + str(path))
    return Path(path)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description='Build the local Hegemon fixture chain template (about 20 to 40 minutes once).')
    parser.add_argument('command', choices=['build-template'])
    parser.add_argument('--destination', default=str(TEMPLATE_DIR))
    args = parser.parse_args(argv)
    work = Path(tempfile.mkdtemp(prefix='hgn-template-'))
    os.chmod(work, 0o700)
    profile = LocalHegemonProfile(work / 'chain', template=False)
    try:
        print('template height', profile.build_template(args.destination), 'at', args.destination)
    finally:
        profile.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, str(ROOT / 'scripts'))
    main(sys.argv[1:])
