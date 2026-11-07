"""Bounded local wallet I/O for a v0.11 pre-mainnet testnet rehearsal.

The operator's trusted node validates consensus and proofs. This adapter never
starts a node or miner and does not decide whether a cross-chain action is safe.
Wallet output can contain private note metadata and must stay on the machine.
"""

import fcntl
import hashlib
import os
import pty
import re
import select
import signal
import stat
import subprocess
import termios
import time
from dataclasses import dataclass
from pathlib import Path

from check_native_asset_lifecycle import canonical_body
from probe_hegemon_testnet import MANIFEST, compare_public_tip, endpoint, probe, rpc


# The official release lacks the branch's verify-htlc subcommand.
OFFICIAL_PRIVATE_SPEND_SHA256 = '389eb1a09e943f7b56b68cce6da5806b8566bd54e248162f19bb38f6da15243e'
PASS_PROMPT = b'Encrypted wallet passphrase: '
MAX_OUTPUT = 2 * 1024 * 1024
MAX_ACTION = 10 * 1024 * 1024
ATTEMPT_ID = re.compile(r'[0-9a-f]{64}\Z')
HASH32 = re.compile(r'0x[0-9a-fA-F]{64}\Z')
COMMANDS = frozenset(('status', 'address', 'verify-htlc', 'lock', 'import-refund-handoff',
                      'export', 'submit', 'claim', 'refund', 'ordinary'))


class WalletCommandError(RuntimeError):
    """A local wallet operation failed; its private output is not exposed."""


@dataclass(frozen=True)
class CheckedBinary:
    path: Path
    sha256: str


def _private_read(path, limit):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(Path(path), flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > limit):
            raise ValueError('Expected a bounded private user-owned file')
        with os.fdopen(fd, 'rb') as source:
            fd = None
            data = source.read(limit + 1)
        if len(data) != info.st_size:
            raise ValueError('Private file changed while reading')
        return data
    finally:
        if fd is not None:
            os.close(fd)


def _check_private_wallet(path):
    fd = os.open(Path(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError('Wallet must be a private user-owned file')
    finally:
        os.close(fd)


def _password(path):
    secret = bytearray(_private_read(path, 4096).rstrip(b'\r\n'))
    if not secret or any(c in secret for c in (0, 10, 13)):
        secret[:] = b'\0' * len(secret)
        raise ValueError('Invalid private wallet passphrase file')
    return secret


def check_binary(path, expected_sha256=None):
    """Pin an operator-trusted branch build and check required CLI support.

    The digest prevents accidental changes between steps; it does not prove
    where a binary came from. The operator must build it from reviewed source.
    """
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Wallet executable cannot be a symlink')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError('Wallet executable is not a regular executable')
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual == OFFICIAL_PRIVATE_SPEND_SHA256:
        raise ValueError('Official v0.11.2 wallet lacks verify-htlc; build private-spend from this branch')
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
            raise ValueError('Invalid saved wallet executable digest')
        if actual != expected_sha256:
            raise ValueError('Wallet executable changed since rehearsal initialization')
    else:
        try:
            version = subprocess.run([str(path), '--version'], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     check=True, timeout=15).stdout
            help_text = subprocess.run([str(path), '--help'], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       check=True, timeout=15).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError('Could not inspect the source-built wallet executable') from error
        if (len(version) > 4096 or version.strip() != b'private-spend 0.11.2'
                or len(help_text) > 65536
                or not re.search(rb'(?m)^\s+verify-htlc\s', help_text)):
            raise ValueError('Wallet must be a v0.11.2 branch build with verify-htlc')
    return CheckedBinary(path, actual)


def ready(url):
    """Check the local node and a trusted public reference; never submit."""
    url = endpoint(url)
    node = probe(url)
    if node.get('basic_wallet_checks_passed') is not True:
        raise ValueError('Hegemon node is not ready for wallet operations')
    reference = compare_public_tip(url, node)
    if reference.get('matches') is not True:
        raise ValueError('Hegemon node and public reference do not match')
    return node, reference


def _execute(binary, argv, prompt_values, *, timeout=1800):
    """Return bounded private output and child metrics; do not log diagnostics."""
    if type(timeout) not in (int, float) or not 0 < timeout <= 3600:
        raise ValueError('Invalid wallet command timeout')
    prompts = []
    for prompt, value in prompt_values:
        if (not isinstance(prompt, bytes) or not prompt or not isinstance(value, bytearray)
                or not value or any(c in value for c in (0, 10, 13))):
            raise ValueError('Invalid private wallet prompt')
        prompts.append((prompt, value))
    master, slave = pty.openpty()
    process = None
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def controlling_tty():
            os.setsid()
            os.umask(0o077)
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        env = {k: v for k, v in os.environ.items() if not k.startswith('HEGEMON_')}
        env['RAYON_NUM_THREADS'] = '2'
        started = time.monotonic()
        process = subprocess.Popen([str(binary), *map(str, argv)], stdin=slave,
                                   stdout=slave, stderr=slave, close_fds=True,
                                   preexec_fn=controlling_tty, env=env)
        os.close(slave)
        slave = None
        output = bytearray()
        sent = 0
        prompt_cursor = 0
        usage = None
        status = None
        while True:
            if time.monotonic() - started >= timeout:
                raise TimeoutError('Wallet command timed out; inspect the wallet before retrying')
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b''
                output.extend(data)
                if len(output) > MAX_OUTPUT:
                    raise WalletCommandError('Wallet output exceeded its limit')
            if sent < len(prompts):
                position = output.find(prompts[sent][0], prompt_cursor)
                if position >= 0:
                    prompt_cursor = position + len(prompts[sent][0])
                    os.write(master, prompts[sent][1] + b'\n')
                    sent += 1
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                while select.select([master], [], [], 0)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output.extend(data)
                    if len(output) > MAX_OUTPUT:
                        raise WalletCommandError('Wallet output exceeded its limit')
                break
        if any(value in output for _, value in prompts):
            raise WalletCommandError('Wallet output unexpectedly contained private input')
        if process.returncode != 0 or sent != len(prompts):
            raise WalletCommandError('Wallet command failed; inspect the wallet before retrying')
        return output.decode('utf-8', 'strict'), {
            'seconds': round(time.monotonic() - started, 3),
            'peak_rss_kib': usage.ru_maxrss,
        }
    finally:
        if slave is not None:
            os.close(slave)
        os.close(master)
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                _, status, _ = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                pass


def wallet(binary, wallet_path, passphrase_path, url, command, *, extra_prompts=(), timeout=1800):
    """Run one wallet command after validating the release and local node.

    Callers must durably record an uncertain phase before any mutating command.
    Returned text is private and must not be sent to public logs or chat.
    """
    if (not isinstance(command, (tuple, list)) or not command
            or command[0] not in COMMANDS
            or any(not isinstance(x, (str, Path)) for x in command)
            or '--development-local-candidate' in command):
        raise ValueError('Unsupported public Hegemon wallet command')
    if isinstance(binary, CheckedBinary):
        binary = check_binary(binary.path, binary.sha256)
    else:
        binary = check_binary(binary)
    _check_private_wallet(wallet_path)
    node, _ = ready(url)
    secret = _password(passphrase_path)
    try:
        args = ['--wallet', str(wallet_path), '--manifest', str(MANIFEST),
                '--genesis', node['genesis'], '--rpc', endpoint(url), *command]
        return _execute(binary.path, args, [(PASS_PROMPT, secret), *extra_prompts], timeout=timeout)
    finally:
        secret[:] = b'\0' * len(secret)


def notes(output, kind):
    if kind not in ('ordinary', 'htlc') or not isinstance(output, str):
        raise ValueError('Invalid wallet note query')
    found = []
    for line in output.splitlines():
        match = re.fullmatch(r'(ordinary|htlc) position=([0-9]+) value=([0-9]+)', line)
        if match and match[1] == kind:
            position, value = int(match[2]), int(match[3])
            if position >= 2**64 or value >= 2**64 or any(p == position for p, _ in found):
                raise ValueError('Invalid or duplicate wallet note position')
            found.append((position, value))
    return found


def balance(output):
    """Read the wallet's machine-readable balance without publishing it."""
    if not isinstance(output, str):
        raise ValueError('Invalid wallet balance')
    rows = [line for line in output.splitlines() if line.startswith('balance synced_height=')]
    if len(rows) != 1:
        raise ValueError('Wallet balance is absent or ambiguous')
    entries = rows[0].split()[1:]
    if any('=' not in item for item in entries):
        raise ValueError('Invalid wallet balance fields')
    fields = dict(item.split('=', 1) for item in entries)
    if len(fields) != len(entries):
        raise ValueError('Duplicate wallet balance field')
    names = ('synced_height', 'available_atoms', 'available_notes',
             'reserved_atoms', 'reserved_notes', 'htlc_atoms', 'htlc_notes')
    if any(not re.fullmatch(r'[0-9]{1,39}', fields.get(name, '')) for name in names):
        raise ValueError('Invalid wallet balance fields')
    if fields.get('watch_only') not in ('true', 'false'):
        raise ValueError('Invalid wallet authority')
    result = {name: int(fields[name]) for name in names}
    result['watch_only'] = fields['watch_only'] == 'true'
    return result


def attempt_inclusion(output, attempt_id):
    """Parse one wallet attempt's local mined position without exposing notes."""
    if not isinstance(output, str) or not isinstance(attempt_id, str) or not ATTEMPT_ID.fullmatch(attempt_id):
        raise ValueError('Invalid Hegemon attempt')
    rows = [line for line in output.splitlines() if line.startswith(attempt_id + ' ')]
    if len(rows) != 1:
        raise ValueError('Wallet attempt is absent or ambiguous')
    if rows[0].endswith(' mined=None'):
        return None
    match = re.search(r' mined=Some\(\(([0-9]+), \[([0-9, ]+)\]\)\)$', rows[0])
    if not match:
        raise ValueError('Unrecognized wallet attempt inclusion')
    height = int(match[1])
    try:
        block = bytes(int(x.strip()) for x in match[2].split(','))
    except (ValueError, OverflowError):
        raise ValueError('Invalid wallet attempt block hash') from None
    if height < 1 or height >= 2**48 or len(block) != 32:
        raise ValueError('Invalid wallet attempt inclusion')
    return height, '0x' + block.hex()


def confirmed_action(url, output, attempt_id, action_path, confirmations=2):
    """Require exact exported bytes in a sufficiently deep local canonical block."""
    if type(confirmations) is not int or not 2 <= confirmations <= 100:
        raise ValueError('Invalid Hegemon confirmation threshold')
    raw = _private_read(action_path, MAX_ACTION)
    if len(raw) < 56:
        raise ValueError('Invalid exported Hegemon action')
    inclusion = attempt_inclusion(output, attempt_id)
    if inclusion is None:
        return None
    height, expected_hash = inclusion
    node, _ = ready(url)
    tip = node['height']
    if tip - height + 1 < confirmations:
        return None
    anchor = rpc(url, 'chain_getBlockHash', [tip])
    block_hash = rpc(url, 'chain_getBlockHash', [height])
    if (not isinstance(anchor, str) or not HASH32.fullmatch(anchor)
            or not isinstance(block_hash, str) or block_hash.lower() != expected_hash):
        raise ValueError('Wallet action block is no longer canonical')
    actions, meta, _ = canonical_body(url, block_hash)
    if meta.get('height') != height or sum(action == raw for action in actions) != 1:
        raise ValueError('Exact wallet action is absent or duplicated in the block')
    fresh, _ = ready(url)
    if (fresh['height'] - height + 1 < confirmations
            or rpc(url, 'chain_getBlockHash', [height]).lower() != expected_hash
            or rpc(url, 'chain_getBlockHash', [tip]).lower() != anchor.lower()):
        raise ValueError('Hegemon chain changed during action verification')
    return {'action_id': raw[:48].hex(), 'block_height': height, 'block_hash': expected_hash,
            'confirmations': fresh['height'] - height + 1}
