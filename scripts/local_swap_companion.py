#!/usr/bin/env python3
"""Loopback-only local escrow companion.

By default it only verifies escrows. Optional Hegemon Development actions
require `--enable-hegemon-actions`. Public v0.11 pre-mainnet verify/actions use
`--hegemon-public` (mutually exclusive with Development actions). Both need
local terminal approval. The bearer token is stored in a user-private file
and is not a wallet passphrase.
"""
import argparse
import datetime
import getpass
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import signal
import stat
import sys
import subprocess
import tempfile
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from bitcoin_escrow_verifier import verify_bitcoin_htlc
from cardano_escrow_verifier import verify_cardano_htlc
from development_atomic_swap_rehearsal import BitcoinRPC
from htlc_counterpart import ROOT, TOOLS
from hegemon_action_runner import run_hegemon_action
from hegemon_local_actions import private_handoff_directory
from ethereum_local_anchor import ethereum_local_head
from bitcoin_local_actions import run_bitcoin_action
from cardano_local_actions import run_cardano_action,local_node_identity,private_key,private_journal_directory
from local_private_spend_swap import PASS, wallet
from release_private_spend_lifecycle_io import rpc, json_line, public_v8_address_keys, height

HOSTED_ORIGIN = 'https://hegemon-swap-testnet.willdoyle422.workers.dev'
active_server = None


def confirm_unlock():
    return input('Type UNLOCK to read the local Hegemon wallet: ').strip()


def read_passphrase():
    return getpass.getpass('Hegemon encrypted wallet passphrase (local terminal only): ')


class KeyringUnavailable(RuntimeError):
    pass


class DesktopKeyring:
    """Remember a wallet passphrase in the desktop Secret Service via secret-tool.

    The passphrase is written on stdin. It is never a command argument and never a file.
    """

    def __init__(self, run=None):
        self._run = run or subprocess.run

    def attributes(self, wallet_path):
        return ['service', 'hegemon-swap-companion', 'wallet', str(Path(wallet_path).resolve())]

    def _call(self, argv, input_bytes=None):
        try:
            return self._run(argv, input=input_bytes, capture_output=True, timeout=10)
        except FileNotFoundError as error:
            raise KeyringUnavailable('The desktop keyring is unavailable. Install secret-tool from the libsecret-tools package. The passphrase was not saved.') from error

    def load(self, wallet_path):
        result = self._call(['secret-tool', 'lookup', *self.attributes(wallet_path)])
        if result.returncode != 0 or not result.stdout:
            return None
        text = result.stdout.decode('utf-8', 'replace')
        if text.endswith('\n'):
            text = text[:-1]
        return text or None

    def save(self, wallet_path, passphrase):
        if not isinstance(passphrase, str) or passphrase == '' or '\n' in passphrase or '\x00' in passphrase:
            raise ValueError('passphrase required')
        argv = ['secret-tool', 'store', '--label', 'Hegemon companion wallet', *self.attributes(wallet_path)]
        if passphrase in argv:
            raise ValueError('passphrase required')
        result = self._call(argv, passphrase.encode() + b'\n')
        if result.returncode != 0:
            raise KeyringUnavailable('The desktop keyring is unavailable. Install secret-tool from the libsecret-tools package. The passphrase was not saved.')

    def delete(self, wallet_path):
        result = self._call(['secret-tool', 'clear', *self.attributes(wallet_path)])
        if result.returncode not in (0, 1):
            raise KeyringUnavailable('The desktop keyring is unavailable. Install secret-tool from the libsecret-tools package. The passphrase was not saved.')


class GuiApproval:
    """One local click that replaces typing UNLOCK and the terminal passphrase prompt."""

    def __init__(self):
        self._lock = threading.Lock()
        self._waiting = threading.Event()
        self._answered = threading.Event()
        self._answer = None
        self.notice = ''

    def ask(self):
        with self._lock:
            self._answer = None
            self.notice = ''
        self._answered.clear()
        self._waiting.set()
        self._answered.wait()
        self._waiting.clear()
        with self._lock:
            return self._answer

    def waiting(self):
        return self._waiting.is_set() and not self._answered.is_set()

    def submit(self, passphrase, remember):
        if not self.waiting():
            return False
        with self._lock:
            self._answer = ('ok', passphrase, bool(remember))
        self._answered.set()
        return True

    def decline(self):
        if not self.waiting():
            return False
        with self._lock:
            self._answer = ('decline',)
        self._answered.set()
        return True

    def report(self, text):
        with self._lock:
            self.notice = text

    def read_notice(self):
        with self._lock:
            return self.notice


def describe_companion_status(snapshot, notice=''):
    if notice:
        return notice
    if not isinstance(snapshot, dict):
        return 'Companion is listening on this computer.'
    phase = snapshot.get('phase')
    if phase == 'awaiting_approval':
        return 'The browser is waiting. Click Unlock. The passphrase stays on this computer.'
    if phase == 'awaiting_passphrase':
        return 'Enter the wallet passphrase in this window. It is not sent to the page.'
    if phase == 'syncing':
        current, target = snapshot.get('current_height'), snapshot.get('target_height')
        height = re.compile(r'^(0|[1-9][0-9]{0,19})$')
        if isinstance(current, str) and isinstance(target, str) and height.fullmatch(current) and height.fullmatch(target):
            if snapshot.get('kind') == 'history':
                return f'Checking saved notes: {current} of {target}.'
            if snapshot.get('resumed') is True:
                return f'Resuming from the saved wallet: block {current} of {target}.'
            return f'Syncing the wallet: block {current} of {target}.'
        return 'Passphrase accepted. Syncing the wallet with the local node. This can take several minutes.'
    return 'Companion is listening on this computer.'


NODE_ACTIVITY_PHASES = {
    'opening_database': 'Opening the chain database',
    'loading_rows': 'Loading saved blocks',
    'rebuilding_state': 'Rebuilding chain state',
    'rechecking_proofs': 'Rechecking private proofs',
    'saving_verified_state': 'Saving the checked chain',
    'checking_indexes': 'Checking chain indexes',
    'ready': 'Starting the network',
}
NODE_ACTIVITY_FRACTIONS = {'rebuilding_state', 'rechecking_proofs', 'saving_verified_state'}
NODE_ACTIVITY_QUIET_MS = 120_000


def format_node_eta(remaining_seconds, slowed, network_target):
    """Plain time left. Estimates of 90 seconds or less stay under a minute."""
    if remaining_seconds is None or remaining_seconds <= 0:
        return ''
    slowed = bool(slowed)
    if remaining_seconds <= 90:
        if slowed:
            body = 'Under a minute at this pace.'
        elif network_target:
            body = 'Under a minute to the current target.'
        else:
            body = 'Under a minute left'
    else:
        minutes = max(2, int((remaining_seconds + 30) // 60))
        if slowed:
            body = f'About {minutes} minutes at this pace.'
        elif network_target:
            body = f'About {minutes} minutes to the current target.'
        else:
            body = f'About {minutes} minutes left'
    if slowed:
        return f'This stretch slowed down. {body}'
    return body


def estimate_node_remaining(samples, total):
    """Return (seconds left, slowed) from the last few (time, current) samples.

    A stretch is slowed when the newest interval is at most half the speed of
    the earlier samples in that window. The estimate then follows the newer pace.
    """
    if type(total) is not int or total < 0 or len(samples) < 2:
        return None, False
    window = list(samples[-4:])
    times, currents = [], []
    for item in window:
        if not isinstance(item, tuple) or len(item) != 2:
            return None, False
        stamp, current = item
        if type(stamp) not in (int, float) or type(current) is not int:
            return None, False
        times.append(stamp)
        currents.append(current)
    if currents[-1] > total:
        return None, False
    if currents[-1] >= total:
        return 0, False
    span_time = times[-1] - times[0]
    span_blocks = currents[-1] - currents[0]
    if span_time <= 0 or span_blocks <= 0:
        return None, False
    rate = span_blocks / span_time
    slowed = False
    if len(window) >= 3:
        earlier_time = times[-2] - times[0]
        earlier_blocks = currents[-2] - currents[0]
        last_time = times[-1] - times[-2]
        last_blocks = currents[-1] - currents[-2]
        if earlier_time <= 0 or earlier_blocks <= 0 or last_time <= 0 or last_blocks <= 0:
            return None, False
        earlier_rate = earlier_blocks / earlier_time
        last_rate = last_blocks / last_time
        if last_rate * 2 <= earlier_rate:
            slowed = True
            rate = last_rate
    return (total - currents[-1]) / rate, slowed


def _node_fraction(current, total):
    if type(current) is not int or type(total) is not int or total <= 0 or current < 0 or current > total:
        return '', None
    return f'Block {current:,} of {total:,}', current / total


def _node_endpoint(url):
    if not url:
        return '127.0.0.1:9944'
    parts = urlsplit(url)
    if not parts.hostname:
        return '127.0.0.1:9944'
    return f'{parts.hostname}:{parts.port or 80}'


def describe_node_activity(observation):
    """Turn one node observation into the words and fraction the window draws."""
    if not isinstance(observation, dict):
        observation = {}
    source = observation.get('source')
    endpoint = observation.get('endpoint') or '127.0.0.1:9944'
    if source == 'rpc':
        return _describe_node_rpc(observation, endpoint)
    if source == 'file':
        return _describe_node_file(observation, endpoint)
    return {
        'title': 'Not running',
        'fraction': '',
        'progress': None,
        'time_line': '',
        'consequence': f'Nothing is listening on {endpoint}.',
        'tone': 'stopped',
    }


def _describe_node_rpc(observation, endpoint):
    height, target, peers = observation.get('height'), observation.get('target'), observation.get('peers')
    if type(height) is not int or type(target) is not int or type(peers) is not int or peers < 0:
        return describe_node_activity({'source': 'none', 'endpoint': endpoint})
    if target > height or observation.get('syncing') is True:
        fraction, progress = _node_fraction(height, target) if target > height else ('', None)
        return {
            'title': 'Catching up with the network',
            'fraction': fraction,
            'progress': progress,
            'time_line': format_node_eta(observation.get('remaining_seconds'), observation.get('slowed') is True, True),
            'consequence': 'The node is connected and still catching up.',
            'tone': 'working',
        }
    if peers >= 1:
        peer_word = 'peer' if peers == 1 else 'peers'
        return {
            'title': 'Caught up',
            'fraction': '',
            'progress': 1.0,
            'time_line': '',
            'consequence': f'Ready. Height {height:,}, {peers} {peer_word}.',
            'tone': 'caught_up',
        }
    return {
        'title': 'Waiting for peers',
        'fraction': '',
        'progress': None,
        'time_line': '',
        'consequence': 'The node is up and has not found a peer yet.',
        'tone': 'working',
    }


def _describe_node_file(observation, endpoint):
    phase = observation.get('phase')
    title = NODE_ACTIVITY_PHASES.get(phase)
    if title is None:
        return describe_node_activity({'source': 'none', 'endpoint': endpoint})
    fraction, progress = ('', None)
    current, total = observation.get('current'), observation.get('total')
    if phase in NODE_ACTIVITY_FRACTIONS:
        fraction, progress = _node_fraction(current, total)
    if observation.get('pid_alive') is not True:
        detail = title[0].lower() + title[1:]
        if fraction:
            consequence = f'The node stopped during {detail} at block {current:,} of {total:,}.'
        else:
            consequence = f'The node stopped during {detail}.'
        return {
            'title': 'Not running',
            'fraction': fraction,
            'progress': progress,
            'time_line': '',
            'consequence': consequence,
            'tone': 'stopped',
        }
    if observation.get('quiet') is True:
        minutes = observation.get('quiet_minutes')
        if type(minutes) is not int or minutes < 2:
            minutes = 2
        unit = 'minute' if minutes == 1 else 'minutes'
        time_line = f'Still on this step. Last update was {minutes} {unit} ago.'
    else:
        time_line = format_node_eta(observation.get('remaining_seconds'), observation.get('slowed') is True, False)
    if phase == 'ready':
        consequence = 'The node is not accepting connections yet.'
    else:
        consequence = 'The node is not accepting connections until this finishes.'
    return {
        'title': title,
        'fraction': fraction,
        'progress': progress,
        'time_line': time_line,
        'consequence': consequence,
        'tone': 'working',
    }


def read_node_activity(path):
    """Read one local progress file. Unknown or oversized contents are ignored."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return None
        raw = os.read(descriptor, 4096)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    phase = value.get('phase')
    if type(phase) is not str or phase not in NODE_ACTIVITY_PHASES:
        return None
    current, total = value.get('current'), value.get('total')
    if current is None and total is None:
        parsed_current, parsed_total = None, None
    elif type(current) is int and type(total) is int and 0 <= current <= total < 2**64:
        parsed_current, parsed_total = current, total
    else:
        return None
    updated = value.get('updated_at_ms')
    pid = value.get('pid')
    if type(updated) is not int or not 0 <= updated < 2**64:
        return None
    if type(pid) is not int or not 1 <= pid <= 2**32 - 1:
        return None
    return {'phase': phase, 'current': parsed_current, 'total': parsed_total, 'updated_at_ms': updated, 'pid': pid}


def read_node_rpc(url):
    """Ask only health and consensus status, with a one-second timeout."""
    parts = urlsplit(url)
    if (parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', 'localhost', '::1')
            or parts.path not in ('', '/') or parts.query or parts.fragment or parts.username):
        raise ValueError('RPC must use loopback HTTP')
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=1)

    def call(method):
        connection.request(
            'POST', '/',
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': []}),
            {'Content-Type': 'application/json'})
        raw = connection.getresponse().read(65536)
        if len(raw) >= 65536:
            raise ValueError('RPC response exceeded bound')
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get('error') or 'result' not in payload:
            raise ValueError('RPC failed')
        return payload['result']

    try:
        health = call('system_health')
        status = call('hegemon_consensusStatus')
    finally:
        connection.close()
    if (not isinstance(health, dict) or type(health.get('isSyncing')) is not bool
            or type(health.get('peers')) is not int or health['peers'] < 0):
        raise ValueError('Invalid node health response')
    if not isinstance(status, dict):
        raise ValueError('Invalid consensus status')
    height, target = status.get('height'), status.get('sync_target_height')
    syncing, peers = status.get('syncing'), status.get('peers')
    if (type(height) is not int or type(target) is not int or type(syncing) is not bool or type(peers) is not int
            or height < 0 or target < 0 or peers < 0 or height >= 2**64 or target >= 2**64):
        raise ValueError('Invalid consensus status')
    return {'height': height, 'target': target, 'syncing': syncing, 'peers': peers}


def node_pid_alive(pid):
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class NodeActivityMonitor:
    """Poll the node off the window thread and keep the latest card text."""

    def __init__(self, rpc, activity_path, read_rpc=None, read_file=None, pid_alive=None, clock=None):
        self.rpc = rpc
        self.activity_path = activity_path
        self.read_rpc = read_rpc or read_node_rpc
        self.read_file = read_file or read_node_activity
        self.pid_alive = pid_alive or node_pid_alive
        self.clock = clock or time.time
        self.endpoint = _node_endpoint(rpc)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._samples = []
        self._sample_key = None
        self._view = {
            'title': 'Checking the local node',
            'fraction': '',
            'progress': None,
            'time_line': '',
            'consequence': 'Looking for the local node.',
            'tone': 'working',
        }

    def snapshot(self):
        with self._lock:
            return dict(self._view)

    def start(self):
        threading.Thread(target=self._loop, name='node-activity', daemon=True).start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                self._store(describe_node_activity({'source': 'none', 'endpoint': self.endpoint}))
            self._stop.wait(1.0)

    def _store(self, view):
        with self._lock:
            self._view = view

    def _note(self, key, now, current):
        if key != self._sample_key:
            self._samples = []
            self._sample_key = key
        if type(current) is not int:
            return
        if self._samples and current < self._samples[-1][1]:
            self._samples = []
        if not self._samples or self._samples[-1][1] != current:
            self._samples.append((now, current))
        if len(self._samples) > 4:
            del self._samples[:-4]

    def poll_once(self):
        now = self.clock()
        now_ms = int(now * 1000)
        status = None
        if self.rpc:
            try:
                status = self.read_rpc(self.rpc)
            except Exception:
                status = None
        if status is not None:
            self._note(('rpc', status['target'], status['syncing']), now, status['height'])
            total = status['target'] if status['target'] > status['height'] else None
            remaining, slowed = estimate_node_remaining(self._samples, total)
            self._store(describe_node_activity({
                'source': 'rpc', 'endpoint': self.endpoint, 'height': status['height'],
                'target': status['target'], 'syncing': status['syncing'], 'peers': status['peers'],
                'remaining_seconds': remaining, 'slowed': slowed,
            }))
            return
        record = None
        if self.activity_path is not None:
            try:
                record = self.read_file(self.activity_path)
            except Exception:
                record = None
        if record is None:
            self._samples = []
            self._sample_key = None
            self._store(describe_node_activity({'source': 'none', 'endpoint': self.endpoint}))
            return
        alive = self.pid_alive(record['pid'])
        age = now_ms - record['updated_at_ms']
        quiet = alive and age >= NODE_ACTIVITY_QUIET_MS
        if alive and not quiet and record['current'] is not None:
            self._note(('file', record['phase'], record['total']), now, record['current'])
            remaining, slowed = estimate_node_remaining(self._samples, record['total'])
        else:
            if not alive:
                self._samples = []
                self._sample_key = None
            remaining, slowed = None, False
        self._store(describe_node_activity({
            'source': 'file', 'endpoint': self.endpoint, 'phase': record['phase'],
            'current': record['current'], 'total': record['total'], 'pid_alive': alive,
            'quiet': quiet, 'quiet_minutes': max(2, age // 60000) if quiet else None,
            'remaining_seconds': remaining, 'slowed': slowed,
        }))


class CompanionWindow:
    """Local window for the pairing token and, in wallet-status mode, the passphrase."""

    def __init__(self, *, token, wallet_path=None, keyring=None, prompt=None, activity=None, monitor=None):
        self.token = token
        self.wallet_path = wallet_path
        self.keyring = keyring
        self.prompt = prompt
        self.activity = activity
        self.monitor = monitor

    def run(self):
        try:
            import tkinter as tk
            from tkinter import font as tkfont
        except ModuleNotFoundError as error:
            raise SystemExit('The companion window needs Python tkinter. Install the python3-tk package and start again.') from error
        root = tk.Tk()
        root.title('Hegemon companion')
        root.configure(bg='#0E1C36')
        root.minsize(480, 560)
        families = set(tkfont.families(root))
        body = next((name for name in ('Space Grotesk', 'Inter') if name in families), 'TkDefaultFont')
        mono = next((name for name in ('JetBrains Mono', 'DejaVu Sans Mono') if name in families), 'TkFixedFont')
        pad = {'padx': 24, 'pady': 8}
        frame = tk.Frame(root, bg='#0E1C36')
        frame.pack(fill='both', expand=True)
        node_title = node_fraction = node_time = node_consequence = node_dot = node_bar = None
        shimmer = {'step': 0}
        if self.monitor is not None:
            card = tk.Frame(frame, bg='#F4F7FB')
            card.pack(fill='x', padx=24, pady=(24, 8))
            inner = tk.Frame(card, bg='#F4F7FB')
            inner.pack(fill='x', padx=16, pady=16)
            header = tk.Frame(inner, bg='#F4F7FB')
            header.pack(fill='x')
            node_dot = tk.Canvas(header, width=12, height=12, bg='#F4F7FB', highlightthickness=0)
            node_dot.pack(side='left', padx=(0, 8))
            node_title = tk.Label(header, text='Checking the local node', bg='#F4F7FB', fg='#0E1C36', font=(body, 16), anchor='w')
            node_title.pack(side='left', fill='x', expand=True)
            node_fraction = tk.Label(inner, text='', bg='#F4F7FB', fg='#0E1C36', font=(mono, 12), anchor='w')
            node_fraction.pack(fill='x', pady=(8, 0))
            node_bar = tk.Canvas(inner, height=8, bg='#E1E6EE', highlightthickness=0)
            node_bar.pack(fill='x', pady=(8, 0))
            node_time = tk.Label(inner, text='', bg='#F4F7FB', fg='#0E1C36', font=(body, 12), anchor='w', justify='left', wraplength=400)
            node_time.pack(fill='x', pady=(8, 0))
            node_consequence = tk.Label(inner, text='', bg='#F4F7FB', fg='#0E1C36', font=(body, 12), anchor='w', justify='left', wraplength=400)
            node_consequence.pack(fill='x', pady=(4, 0))
            self.monitor.start()
        tk.Label(frame, text='Pairing token', bg='#0E1C36', fg='#F4F7FB', font=(body, 12)).pack(anchor='w', **pad)
        token_row = tk.Frame(frame, bg='#0E1C36')
        token_row.pack(fill='x', padx=24)
        token_value = tk.StringVar(value=self.token)
        token_entry = tk.Entry(token_row, textvariable=token_value, readonlybackground='#F4F7FB', fg='#0E1C36', font=(mono, 12), state='readonly', relief='flat')
        token_entry.pack(side='left', fill='x', expand=True, ipady=6)
        copy_button = tk.Button(token_row, text='Copy token', bg='#1BE7FF', fg='#0E1C36', activebackground='#1BE7FF', font=(body, 12), relief='flat')
        copy_button.pack(side='left', padx=(8, 0))

        def copy_token():
            root.clipboard_clear()
            root.clipboard_append(self.token)
            root.update_idletasks()
            copy_button.configure(text='Copied')
            root.after(2000, lambda: copy_button.configure(text='Copy token'))

        copy_button.configure(command=copy_token)
        passphrase = tk.StringVar()
        remember = tk.BooleanVar(value=False)
        unlock_button = None
        if self.wallet_path is not None:
            tk.Label(frame, text='Wallet passphrase', bg='#0E1C36', fg='#F4F7FB', font=(body, 12)).pack(anchor='w', **pad)
            tk.Entry(frame, textvariable=passphrase, show='*', bg='#F4F7FB', fg='#0E1C36', font=(body, 14), relief='flat').pack(fill='x', padx=24, ipady=6)
            tk.Checkbutton(frame, text='Remember on this computer', variable=remember, bg='#0E1C36', fg='#F4F7FB', selectcolor='#0E1C36', activebackground='#0E1C36', activeforeground='#1BE7FF', font=(body, 12)).pack(anchor='w', padx=24, pady=8)
            if self.keyring is not None:
                try:
                    saved = self.keyring.load(self.wallet_path)
                except KeyringUnavailable as error:
                    if self.prompt is not None:
                        self.prompt.report(str(error))
                else:
                    if saved:
                        passphrase.set(saved)
                        remember.set(True)
            unlock_button = tk.Button(frame, text='Unlock', bg='#1BE7FF', fg='#0E1C36', activebackground='#1BE7FF', font=(body, 14), relief='flat', state='disabled')
            unlock_button.pack(anchor='w', padx=24, pady=8)

            def approve():
                if self.prompt is None or not self.prompt.submit(passphrase.get(), remember.get()):
                    status.configure(text='The page has not asked to read the wallet yet.', fg='#FF4E4E')

            unlock_button.configure(command=approve)
        status = tk.Label(frame, text='Companion is listening on this computer.', bg='#0E1C36', fg='#F4F7FB', font=(body, 12), wraplength=400, justify='left')
        status.pack(anchor='w', padx=24, pady=16)

        def paint_node(view):
            if node_title is None:
                return
            tone = view.get('tone')
            color = '#FF4E4E' if tone == 'stopped' else '#1BE7FF'
            node_dot.delete('all')
            node_dot.create_oval(1, 1, 11, 11, fill=color, outline=color)
            node_title.configure(text=view.get('title') or '')
            node_fraction.configure(text=view.get('fraction') or '')
            node_time.configure(text=view.get('time_line') or '')
            node_consequence.configure(text=view.get('consequence') or '')
            node_bar.delete('all')
            width = max(node_bar.winfo_width(), 1)
            progress = view.get('progress')
            if tone == 'stopped' and progress is None:
                return
            if progress is None:
                shimmer['step'] = (shimmer['step'] + 1) % 8
                span = max(width // 3, 24)
                origin = int((width + span) * shimmer['step'] / 8) - span
                node_bar.create_rectangle(origin, 0, origin + span, 8, fill='#F4F7FB', outline='')
                return
            try:
                fraction = max(0.0, min(1.0, float(progress)))
            except (TypeError, ValueError):
                return
            fill = int(width * fraction)
            if fill > 0:
                node_bar.create_rectangle(0, 0, fill, 8, fill=color, outline='')

        def tick():
            snapshot = self.activity.snapshot() if self.activity is not None else {'phase': 'idle'}
            notice = self.prompt.read_notice() if self.prompt is not None else ''
            text = describe_companion_status(snapshot, notice)
            status.configure(text=text, fg='#FF4E4E' if notice else '#F4F7FB')
            if self.monitor is not None:
                paint_node(self.monitor.snapshot())
            if unlock_button is not None:
                unlock_button.configure(state='normal' if self.prompt is not None and self.prompt.waiting() else 'disabled')
            root.after(400, tick)

        tick()
        root.protocol('WM_DELETE_WINDOW', root.quit)
        root.mainloop()
        if self.monitor is not None:
            self.monitor.stop()
        if self.prompt is not None:
            self.prompt.decline()
        root.destroy()


def wallet_progress_event(line):
    """Return a display event for one private-spend progress line, or None.

    Note rows, passphrase prompts and any other transcript text are ignored.
    """
    line = line.strip()
    if line == 'Unlocking encrypted wallet…':
        return ('unlock', None, None)
    patterns = (
        ('history', r'Checking wallet history: ([0-9]+)/([0-9]+)$'),
        ('saved', r'Saved wallet is already at block ([0-9]+)\.$'),
        ('resume', r'Resuming from saved block ([0-9]+) of ([0-9]+)\.$'),
        ('history', r'wallet-progress stage=unlock current=([0-9]+) target=([0-9]+) notes=[0-9]+ elapsed_ms=[0-9]+$'),
        ('sync', r'Syncing blocks: ([0-9]+)/([0-9]+); new notes [0-9]+$'),
        ('sync', r'wallet-progress stage=sync current=([0-9]+) target=([0-9]+) notes=[0-9]+ elapsed_ms=[0-9]+$'),
    )
    done = re.fullmatch(r'(?:Sync complete at block ([0-9]+)|wallet-progress stage=done current=([0-9]+) target=([0-9]+) notes=[0-9]+ elapsed_ms=[0-9]+)', line)
    if done:
        height = next(group for group in done.groups() if group is not None)
        if done.group(2) is not None and done.group(2) != done.group(3):
            return None
        value = int(height)
        if value >= 2**64:
            return None
        return ('sync', value, value)
    for kind, pattern in patterns:
        match = re.fullmatch(pattern, line)
        if not match:
            continue
        current = int(match.group(1))
        target = current if kind == 'saved' else int(match.group(2))
        if current > target or target >= 2**64:
            return None
        return (kind, current, target)
    return None


class WalletActivity:
    """Unlock phase and block heights. Safe to read while a wallet sync holds the session lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self.phase = 'idle'
        self.current = None
        self.target = None
        self.resumed = False
        self.progress_kind = None
        self._pending = bytearray()

    def set_phase(self, phase):
        with self._lock:
            self.phase = phase
            if phase != 'syncing':
                self.current = None
                self.target = None
                self.resumed = False
                self.progress_kind = None

    def snapshot(self):
        with self._lock:
            body = {'phase': self.phase}
            if self.phase == 'syncing' and self.current is not None and self.target is not None:
                body['current_height'] = str(self.current)
                body['target_height'] = str(self.target)
                body['kind'] = 'history' if self.progress_kind == 'history' else 'blocks'
                if self.resumed:
                    body['resumed'] = True
            return body

    def add_output(self, data):
        if not data:
            return
        self._pending.extend(data)
        if len(self._pending) > 8192:
            del self._pending[:-1024]
        while b'\n' in self._pending:
            raw, _, rest = self._pending.partition(b'\n')
            self._pending = bytearray(rest)
            event = wallet_progress_event(raw.decode('utf-8', 'replace'))
            if event is None:
                continue
            kind, current, target = event
            with self._lock:
                self.phase = 'syncing'
                if kind == 'history':
                    self.progress_kind = 'history'
                elif kind in ('sync', 'resume', 'saved'):
                    self.progress_kind = 'blocks'
                    if kind in ('resume', 'saved'):
                        self.resumed = True
                if current is not None:
                    self.current = current
                    self.target = target
            if current is None:
                print('Unlocking the encrypted wallet.', file=sys.stderr, flush=True)
            elif kind == 'history':
                print(f'Checking saved notes: {current} of {target}.', file=sys.stderr, flush=True)
            elif kind == 'saved':
                print(f'Saved wallet is already at block {current}. No new blocks to scan.', file=sys.stderr, flush=True)
            elif kind == 'resume':
                print(f'Resuming from the saved wallet at block {current} of {target}. Only new blocks are scanned.', file=sys.stderr, flush=True)
            else:
                print(f'Syncing the wallet: block {current} of {target}.', file=sys.stderr, flush=True)


def private_wallet_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Hegemon wallet must be a private mode-0600 file owned by this user')
    finally:
        os.close(fd)


def hosted_balance_view(text, observed_height):
    """Totals only. Note rows in `text` are never copied into the result."""
    from public_hegemon_wallet import balance
    parsed = balance(text)
    rows = [line for line in text.splitlines() if line.startswith('balance synced_height=')]
    fields = dict(item.split('=', 1) for item in rows[0].split()[1:])
    immature = fields.get('immature_atoms', '')
    if not re.fullmatch(r'[0-9]{1,39}', immature):
        raise ValueError('Invalid wallet balance fields')
    names = ('synced_height', 'available_atoms', 'reserved_atoms', 'htlc_atoms')
    if any(parsed[name] >= 2**64 for name in names) or int(immature) >= 2**64:
        raise ValueError('Invalid wallet balance fields')
    height = int(observed_height)
    if height < 0 or height >= 2**64:
        raise ValueError('Invalid wallet balance fields')
    return {'available_atoms': str(parsed['available_atoms']), 'reserved_atoms': str(parsed['reserved_atoms']),
            'htlc_atoms': str(parsed['htlc_atoms']), 'immature_atoms': str(int(immature)),
            'synced_height': str(parsed['synced_height']), 'watch_only': parsed['watch_only'],
            'observed_height': str(height), 'observed_at': str(int(time.time() * 1000))}


def read_hosted_node(rpc):
    """Probe the loopback node and the public explorer. Failure is always the same error."""
    from probe_hegemon_testnet import compare_public_tip, probe
    try:
        node = probe(rpc)
        if not isinstance(node, dict) or node.get('basic_wallet_checks_passed') is not True:
            raise ValueError('node not ready')
        reference = compare_public_tip(rpc, node)
        if not isinstance(reference, dict) or reference.get('matches') is not True:
            raise ValueError('public tip mismatch')
    except LookupError:
        raise
    except Exception as error:
        raise LookupError('hegemon_node_not_ready') from error
    return node


def read_hosted_swap_node(rpc, genesis, manifest):
    """Pin the public profile and the wallet's expected private-spend relation."""
    from probe_hegemon_testnet import assert_public_profile
    node, _reference = assert_public_profile(rpc, genesis=genesis, manifest=manifest)
    if not isinstance(node, dict) or node.get('basic_wallet_checks_passed') is not True:
        raise ValueError('Hegemon wallet RPC or private-spend parameters are unavailable')
    return node


def check_swap_wallet_binary(path):
    """Require the reviewed wallet build with the explicit mature-refund check."""
    from public_hegemon_wallet import check_binary
    checked=check_binary(path)
    try:
        help_text=subprocess.run([str(path),'verify-htlc','--help'],stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=15).stdout
        root_help=subprocess.run([str(path),'--help'],stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=15).stdout
    except (OSError,subprocess.SubprocessError) as error:
        raise ValueError('Could not inspect the Hegemon swap wallet') from error
    if len(help_text)>65536 or len(root_help)>65536 or b'--refund-ready' not in help_text or any(name not in root_help for name in (b'available-notes',b'locate-htlc',b'attempt-reference')):
        raise ValueError('Hegemon swap mode needs the branch wallet with refund verification and note lookup')
    return checked


class HostedWalletSession:
    """One wallet, totals only. The passphrase stays in this process and is wiped on close."""

    def __init__(self, *, rpc, wallet_path, manifest, genesis, binary, scratch, read_node=None, prompt=None, keyring=None):
        self.rpc = rpc
        self.wallet_path = wallet_path
        self.manifest = manifest
        self.genesis = genesis
        self.binary = binary
        self.scratch = scratch
        self.read_node = read_node or (lambda: read_hosted_node(rpc))
        self.prompt = prompt
        self.keyring = keyring
        self._lock = threading.Lock()
        self.activity = WalletActivity()
        self._phrase = None
        self._cached = None
        self._cached_at = 0.0

    def _wipe(self):
        if self._phrase is not None:
            self._phrase[:] = b'\0' * len(self._phrase)
            self._phrase = None

    def close(self):
        with self._lock:
            self._wipe()
            self._cached = None

    def _run(self, secret):
        argv = ['--wallet', self.wallet_path, '--manifest', self.manifest, '--genesis', self.genesis, '--rpc', self.rpc, 'status']
        text, _metrics = wallet(self.binary, argv, [(PASS, bytes(secret))], Path(self.scratch), 'hegemon-hosted-balance', on_output=self.activity.add_output)
        log = Path(self.scratch) / 'hegemon-hosted-balance.log'
        try:
            return text
        finally:
            try:
                log.unlink()
            except FileNotFoundError:
                pass

    def _remember(self, secret, view):
        self._wipe()
        self._phrase = secret
        self._cached = view
        self._cached_at = time.monotonic()
        return dict(view)

    def _status_view(self, secret):
        """Run status, then stamp the node tip. One extra status if still more than two blocks behind."""
        text = self._run(secret)
        node = self.read_node()
        height = int(node['height'])
        view = hosted_balance_view(text, height)
        if height - int(view['synced_height']) > 2:
            text = self._run(secret)
            node = self.read_node()
            height = int(node['height'])
            view = hosted_balance_view(text, height)
        return view

    def unlock(self):
        with self._lock:
            self.activity.set_phase('awaiting_approval')
            if self.prompt is not None:
                print('The browser is waiting. Click Unlock in the companion window. The passphrase stays on this computer.', flush=True)
            else:
                print('The browser is waiting. Type UNLOCK in this terminal, then the wallet passphrase. Sync progress appears here and on the page.', flush=True)
            try:
                remember = False
                if self.prompt is not None:
                    decision = self.prompt.ask()
                    if not decision or decision[0] != 'ok':
                        raise ValueError('wallet unlock declined locally')
                    phrase = decision[1]
                    remember = decision[2]
                else:
                    if confirm_unlock() != 'UNLOCK':
                        raise ValueError('wallet unlock declined locally')
                    self.activity.set_phase('awaiting_passphrase')
                    phrase = read_passphrase()
                if not isinstance(phrase, str) or phrase == '':
                    raise ValueError('passphrase required')
                secret = bytearray(phrase.encode())
                del phrase
                self.activity.set_phase('syncing')
                print('Passphrase accepted. Syncing the wallet with the local node. This can take several minutes.', flush=True)
                try:
                    view = self._status_view(secret)
                except Exception:
                    secret[:] = b'\0' * len(secret)
                    raise
                if self.keyring is not None:
                    try:
                        if remember:
                            self.keyring.save(self.wallet_path, secret.decode())
                        else:
                            self.keyring.delete(self.wallet_path)
                    except KeyringUnavailable as error:
                        if self.prompt is not None:
                            self.prompt.report(str(error))
                        print(str(error), flush=True)
                print('Wallet read finished. Return to the browser to see available HGN. Creating a listing does not lock those funds.', flush=True)
                return self._remember(secret, view)
            except ValueError as error:
                if str(error) == 'wallet unlock declined locally':
                    print('Wallet read was not approved.', flush=True)
                elif str(error) == 'passphrase required':
                    print('A passphrase is required. Nothing was read.', flush=True)
                else:
                    print('Wallet read failed. The browser will show the error.', flush=True)
                raise
            except Exception:
                print('Wallet read failed. The browser will show the error.', flush=True)
                raise
            finally:
                self.activity.set_phase('idle')

    def balance(self):
        with self._lock:
            if self._phrase is None:
                raise PermissionError('wallet_locked')
            node = self.read_node()
            height = int(node['height'])
            saved = int(self._cached['synced_height']) if self._cached is not None else None
            caught_up = saved == height
            fresh = saved is not None and time.monotonic() - self._cached_at <= 60 and 0 <= height - saved <= 2
            if caught_up or fresh:
                if caught_up:
                    print(f'Using the saved wallet read at block {height}. The chain has not moved, so this did not scan again.', flush=True)
                view = dict(self._cached)
                view['observed_height'] = str(height)
                view['observed_at'] = str(int(time.time() * 1000))
                return view
            self.activity.set_phase('syncing')
            try:
                if saved is not None:
                    print(f'The chain moved. Resuming the saved wallet from block {saved} through {height}.', flush=True)
                view = self._status_view(self._phrase)
            finally:
                self.activity.set_phase('idle')
            self._cached = view
            self._cached_at = time.monotonic()
            return dict(view)

    def verify_swap_htlc(self, request, *, check_node=None, verify_action=None, read_block=None):
        """Verify a live private HTLC using the unlocked local wallet.

        This read discloses only the validated public snapshot. It does not
        approve, prepare or submit a transaction. The caller must still check
        the other chain and deadline policy immediately before a wallet action.
        """
        fields = ('locked', 'claim', 'refund', 'hashlock', 'timeout', 'amount',
                  'min_confirmations', 'min_remaining_blocks')
        if not isinstance(request, dict) or set(request) != set(fields)|{'action_id','refund_ready'}:
            raise ValueError('invalid Hegemon verification fields')
        if not isinstance(request['action_id'],str) or not re.fullmatch(r'[0-9a-f]{96}',request['action_id']) or type(request['refund_ready']) is not bool:
            raise ValueError('invalid Hegemon verification mode')
        values = hegemon_wire_terms({field:request[field] for field in fields})
        if check_node is None:
            check_node = lambda: read_hosted_swap_node(self.rpc, self.genesis, self.manifest)
        if not self._lock.acquire(blocking=False):
            raise RuntimeError('wallet busy')
        try:
            if self._phrase is None:
                raise PermissionError('wallet locked')
            node=check_node()
            argv = ['--wallet', self.wallet_path, '--manifest', self.manifest, '--genesis', self.genesis,
                    '--rpc', self.rpc, 'verify-htlc']
            for field in fields:
                argv.extend(['--' + field.replace('_', '-'), values[field]])
            if request['refund_ready']:argv.append('--refund-ready')
            try:
                text, _ = wallet(self.binary, argv, [(PASS, bytes(self._phrase))], Path(self.scratch), 'hegemon-swap-verify')
                result = json_line(text)
            finally:
                try:
                    (Path(self.scratch) / 'hegemon-swap-verify.log').unlink()
                except FileNotFoundError:
                    pass
            node = check_node()
            names = ('position', 'created_height', 'reference_height', 'confirmations')
            if (not isinstance(result, dict) or result.get('verified') is not True
                    or result.get('refund_ready') is not request['refund_ready']
                    or any(type(result.get(name)) is not int or result[name] < 0 for name in names)
                    or result['position'] != int(values['locked'])
                    or result['confirmations'] < int(values['min_confirmations'])
                    or result['reference_height'] - result['created_height'] + 1 != result['confirmations']
                    or not isinstance(node, dict) or type(node.get('height')) is not int or not isinstance(node.get('chain_id'),str)
                    or node['height'] < result['reference_height']
                    or (node['height'] < int(values['timeout']) if request['refund_ready'] else int(values['timeout']) - node['height'] < int(values['min_remaining_blocks']))
                    or not isinstance(result.get('commitment'),str) or not re.fullmatch(r'[0-9a-f]{112}',result['commitment'])
                    or any(not isinstance(result.get(name),str) or not re.fullmatch(r'0x[0-9a-f]{64}',result[name]) for name in ('created_block_hash','reference_block_hash'))):
                raise ValueError('Hegemon verification is stale or inconsistent')
            if verify_action is None:
                from hegemon_swap_observer import verify_lock_action_output
                verify_action=verify_lock_action_output
            if read_block is None:read_block=lambda height:rpc(self.rpc,'chain_getBlockHash',[height])
            if read_block(result['reference_height'])!=result['reference_block_hash']:
                raise ValueError('Hegemon verification reference changed')
            verify_action(self.rpc,block_height=result['created_height'],block_hash=result['created_block_hash'],action_id=request['action_id'],commitment=result['commitment'],chain_id=node['chain_id'])
            node=check_node()
            if (type(node.get('height')) is not int or node['height']<result['reference_height']
                    or read_block(result['reference_height'])!=result['reference_block_hash']
                    or (node['height']<int(values['timeout']) if request['refund_ready'] else int(values['timeout'])-node['height']<int(values['min_remaining_blocks']))):
                raise ValueError('Hegemon chain changed during verification')
            return {'verified': True, **{name: str(result[name]) for name in names},
                    'commitment':result['commitment'],'action_id':request['action_id'],'refund_ready':request['refund_ready']}
        finally:
            self._lock.release()

    def swap_address(self, *, check_node=None):
        """Derive address zero from the unlocked wallet; never return key material."""
        if check_node is None:
            check_node = lambda: read_hosted_swap_node(self.rpc, self.genesis, self.manifest)
        if not self._lock.acquire(blocking=False):
            raise RuntimeError('wallet busy')
        try:
            if self._phrase is None:
                raise PermissionError('wallet locked')
            check_node()
            argv=['--wallet', self.wallet_path, '--manifest', self.manifest, '--genesis', self.genesis,
                  '--rpc', self.rpc, 'address', '--index', '0']
            try:
                text,_=wallet(self.binary,argv,[(PASS,bytes(self._phrase))],Path(self.scratch),'hegemon-swap-address')
            finally:
                try:(Path(self.scratch)/'hegemon-swap-address.log').unlink()
                except FileNotFoundError:pass
            lines=[line.strip() for line in text.splitlines() if line.strip().startswith('shca1')]
            if len(lines)!=1 or len(lines[0])>3000:raise ValueError('Hegemon address unavailable')
            public_v8_address_keys(lines[0]);check_node()
            return {'address':lines[0]}
        finally:
            self._lock.release()

    def available_swap_notes(self, *, check_node=None):
        """Read selector-safe position/value pairs without exposing the inventory."""
        if check_node is None:
            check_node=lambda:read_hosted_swap_node(self.rpc,self.genesis,self.manifest)
        if not self._lock.acquire(blocking=False):raise RuntimeError('wallet busy')
        try:
            if self._phrase is None:raise PermissionError('wallet locked')
            check_node()
            argv=['--wallet',self.wallet_path,'--manifest',self.manifest,'--genesis',self.genesis,
                  '--rpc',self.rpc,'available-notes']
            try:
                text,_=wallet(self.binary,argv,[(PASS,bytes(self._phrase))],Path(self.scratch),'hegemon-swap-notes')
                value=json_line(text)
            finally:
                try:(Path(self.scratch)/'hegemon-swap-notes.log').unlink()
                except FileNotFoundError:pass
            if not isinstance(value,dict) or set(value)!={'synced_height','available'} or not isinstance(value['available'],list) or len(value['available'])>10000:
                raise ValueError('invalid available Hegemon notes')
            synced=int(hegemon_wire_integer(value['synced_height']))
            rows=[];positions=set()
            for row in value['available']:
                if not isinstance(row,dict) or set(row)!={'position','value'}:raise ValueError('invalid available Hegemon note')
                position=hegemon_wire_integer(row['position']);amount=hegemon_wire_integer(row['value'])
                if position in positions:raise ValueError('duplicate Hegemon note')
                positions.add(position);rows.append({'position':position,'value':amount})
            node=check_node()
            if type(node.get('height')) is not int or not 0<=node['height']-synced<=2:
                raise ValueError('Hegemon wallet note list is stale')
            return {'synced_height':str(synced),'available':rows}
        finally:self._lock.release()

    def locate_swap_htlc(self, commitment, *, check_node=None):
        """Find one imported, unspent HTLC by its exact private commitment."""
        if not isinstance(commitment,str) or not re.fullmatch('[0-9a-f]{112}',commitment):raise ValueError('invalid Hegemon commitment')
        if check_node is None:check_node=lambda:read_hosted_swap_node(self.rpc,self.genesis,self.manifest)
        if not self._lock.acquire(blocking=False):raise RuntimeError('wallet busy')
        try:
            if self._phrase is None:raise PermissionError('wallet locked')
            check_node()
            argv=['--wallet',self.wallet_path,'--manifest',self.manifest,'--genesis',self.genesis,
                  '--rpc',self.rpc,'locate-htlc','--commitment',commitment]
            try:
                text,_=wallet(self.binary,argv,[(PASS,bytes(self._phrase))],Path(self.scratch),'hegemon-swap-locate')
                value=json_line(text)
            finally:
                try:(Path(self.scratch)/'hegemon-swap-locate.log').unlink()
                except FileNotFoundError:pass
            if not isinstance(value,dict) or set(value)!={'position','created_height','synced_height'}:raise ValueError('invalid Hegemon HTLC lookup')
            position=hegemon_wire_integer(value['position']);created=int(hegemon_wire_integer(value['created_height']));synced=int(hegemon_wire_integer(value['synced_height']))
            node=check_node()
            if created<1 or created>synced or type(node.get('height')) is not int or not 0<=node['height']-synced<=2:raise ValueError('Hegemon HTLC lookup is stale')
            return {'position':position,'created_height':str(created),'synced_height':str(synced)}
        finally:self._lock.release()

    def swap_attempt_inclusion(self, request, *, check_node=None, read=None, body=None):
        """Find a candidate's canonical inclusion without exposing wallet status."""
        from check_native_asset_lifecycle import rpc,canonical_body
        if (not isinstance(request,dict) or set(request)!={'attempt','action_id'}
                or not isinstance(request['attempt'],str) or not re.fullmatch('[0-9a-f]{64}',request['attempt'])
                or not (request['action_id'] is None or isinstance(request['action_id'],str) and re.fullmatch('[0-9a-f]{96}',request['action_id']))):raise ValueError('invalid Hegemon attempt')
        if check_node is None:check_node=lambda:read_hosted_swap_node(self.rpc,self.genesis,self.manifest)
        read=read or rpc;body=body or canonical_body
        if not self._lock.acquire(blocking=False):raise RuntimeError('wallet busy')
        try:
            if self._phrase is None:raise PermissionError('wallet locked')
            check_node()
            argv=['--wallet',self.wallet_path,'--manifest',self.manifest,'--genesis',self.genesis,'--rpc',self.rpc,'attempt-reference','--attempt',request['attempt']]
            try:
                text,_=wallet(self.binary,argv,[(PASS,bytes(self._phrase))],Path(self.scratch),'hegemon-swap-inclusion')
                result=json_line(text)
            finally:
                try:(Path(self.scratch)/'hegemon-swap-inclusion.log').unlink()
                except FileNotFoundError:pass
            node=check_node()
            if (not isinstance(result,dict) or set(result)!={'attempt','action_id','mined','inputs_consumed','synced_height'}
                    or result['attempt']!=request['attempt'] or type(result['inputs_consumed']) is not bool):raise ValueError('invalid Hegemon wallet attempt')
            tip=node.get('height');synced=int(hegemon_wire_integer(result['synced_height']))
            if type(tip) is not int or not 0<=tip-synced<=2:raise ValueError('stale Hegemon attempt')
            action=result['action_id']
            if action is not None and (not isinstance(action,str) or not re.fullmatch('[0-9a-f]{96}',action)):raise ValueError('invalid Hegemon wallet action')
            if request['action_id'] is not None and action is not None and action!=request['action_id']:raise ValueError('Hegemon action does not match the wallet attempt')
            if result['mined'] is None:return {'state':'pending','action_id':action}
            mined=result['mined']
            if (action is None or result['inputs_consumed'] is not True or not isinstance(mined,dict) or set(mined)!={'height','block_hash'}
                    or not isinstance(mined['block_hash'],str) or not re.fullmatch('0x[0-9a-f]{64}',mined['block_hash'])):raise ValueError('invalid Hegemon attempt inclusion')
            height=int(hegemon_wire_integer(mined['height']));block=mined['block_hash']
            if not 1<=height<2**48 or height>synced:raise ValueError('stale Hegemon attempt')
            if tip-height+1<2:return {'state':'pending','action_id':action}
            anchor=read(self.rpc,'chain_getBlockHash',[tip]);canonical=read(self.rpc,'chain_getBlockHash',[height])
            if not isinstance(anchor,str) or not re.fullmatch('0x[0-9a-fA-F]{64}',anchor) or not isinstance(canonical,str) or canonical.lower()!=block:raise ValueError('Hegemon attempt is no longer canonical')
            actions,metadata,_=body(self.rpc,block)
            if not isinstance(actions,list) or not isinstance(metadata,dict) or metadata.get('height')!=height or sum(isinstance(item,(bytes,bytearray)) and len(item)>=56 and item[:48].hex()==action for item in actions)!=1:raise ValueError('Hegemon attempt action is absent or ambiguous')
            latest=check_node()
            if type(latest.get('height')) is not int or latest['height']<tip or read(self.rpc,'chain_getBlockHash',[height]).lower()!=block or read(self.rpc,'chain_getBlockHash',[tip]).lower()!=anchor.lower():raise ValueError('Hegemon chain changed during attempt lookup')
            return {'state':'confirmed','block_height':str(height),'block_hash':block,'confirmations':latest['height']-height+1,'action_id':action}
        finally:self._lock.release()


def private_token(path):
    parent=path.parent.stat()
    if parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)&0o077:
        raise ValueError('token directory must be owned by this user and mode 0700')
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd,'w') as f:
            f.write(secrets.token_hex(32)+'\n');f.flush();os.fsync(f.fileno())
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>128:
            raise ValueError('token must be a private mode-0600 regular file')
        token=f.read().strip()
    if len(token)!=64 or any(c not in '0123456789abcdef' for c in token):raise ValueError('invalid companion token file')
    return token


def cardano_wire_terms(data):
    """Convert decimal strings exactly; browser numbers cannot represent u64 values."""
    def decimal(value):
        if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,18}',value):raise ValueError('invalid Cardano integer')
        result=int(value)
        if result>=2**63:raise ValueError('Cardano integer out of range')
        return result
    value=data['expected_value']
    if not isinstance(value,dict):raise ValueError('invalid Cardano value')
    converted={}
    for policy,assets in value.items():
        if policy=='lovelace':converted[policy]=decimal(assets)
        else:
            if not isinstance(assets,dict):raise ValueError('invalid Cardano asset map')
            converted[policy]={name:decimal(quantity) for name,quantity in assets.items()}
    return {**data,'expiry_ms':decimal(data['expiry_ms']),'expected_value':converted}


def hegemon_wire_integer(value):
    if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,19}',value) or int(value)>=2**64:raise ValueError('invalid Hegemon integer')
    return value


def select_swap_notes(snapshot, request):
    """Choose at most two available native notes without exposing the inventory."""
    if not isinstance(request,dict) or set(request)!={'amount','fee','exclude'}:raise ValueError('invalid Hegemon selection request')
    amount=int(hegemon_wire_integer(request['amount']));fee=int(hegemon_wire_integer(request['fee']))
    if amount<=0 or amount+fee>=2**64:raise ValueError('invalid Hegemon selection amount')
    exclude=request['exclude']
    if not isinstance(exclude,list) or len(exclude)>2 or any(not isinstance(x,str) for x in exclude):raise ValueError('invalid Hegemon exclusions')
    excluded={hegemon_wire_integer(x) for x in exclude}
    if len(excluded)!=len(exclude):raise ValueError('duplicate Hegemon exclusions')
    if not isinstance(snapshot,dict) or set(snapshot)!={'synced_height','available'} or not isinstance(snapshot['available'],list) or len(snapshot['available'])>10000:raise ValueError('invalid Hegemon note snapshot')
    height=hegemon_wire_integer(snapshot['synced_height']);rows=[];seen=set()
    for row in snapshot['available']:
        if not isinstance(row,dict) or set(row)!={'position','value'}:raise ValueError('invalid Hegemon note')
        position=hegemon_wire_integer(row['position']);value=int(hegemon_wire_integer(row['value']))
        if position in seen:raise ValueError('duplicate Hegemon note')
        seen.add(position)
        if value>0 and position not in excluded:rows.append((value,position))
    rows.sort();need=amount+fee
    one=next((row for row in rows if row[0]>=need),None)
    if one is not None:return {'inputs':[one[1]],'total':str(one[0]),'synced_height':height}
    left,right,best=0,len(rows)-1,None
    while left<right:
        total=rows[left][0]+rows[right][0]
        if total>=2**64:right-=1
        elif total>=need:
            candidate=(total,rows[left][1],rows[right][1])
            if best is None or candidate<best:best=candidate
            right-=1
        else:left+=1
    if best is None:raise ValueError('not enough unreserved Hegemon notes for amount and fee')
    return {'inputs':[best[1],best[2]],'total':str(best[0]),'synced_height':height}


def hegemon_wire_terms(data):
    values={}
    for field in ('locked','timeout','amount','min_confirmations','min_remaining_blocks'):
        value=data[field]
        values[field]=hegemon_wire_integer(value)
    if values['amount']=='0' or values['min_confirmations']=='0' or values['min_remaining_blocks']=='0':raise ValueError('invalid Hegemon verification limits')
    if not isinstance(data['hashlock'],str) or not re.fullmatch('[0-9a-f]{64}',data['hashlock']):raise ValueError('invalid hashlock')
    for field in ('claim','refund'):public_v8_address_keys(data[field])
    return {**data,**values}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bitcoin-rpc',help='Bitcoin Core regtest RPC on loopback')
    p.add_argument('--bitcoin-cookie',type=Path)
    p.add_argument('--enable-bitcoin-actions',action='store_true',help='enable locally approved Bitcoin regtest wallet actions')
    p.add_argument('--bitcoin-wallet',help='preloaded Bitcoin Core descriptor wallet name')
    p.add_argument('--bitcoin-genesis',help='expected regtest genesis hash')
    p.add_argument('--bitcoin-preimage-backup',type=Path,help='optional private exported browser backup for local claims')
    p.add_argument('--cardano-socket',type=Path)
    p.add_argument('--cardano-network-dir',type=Path,help='directory containing the trusted local Shelley genesis')
    p.add_argument('--enable-cardano-actions',action='store_true',help='enable locally approved isolated Cardano actions')
    p.add_argument('--cardano-node-pid',type=int,help='process ID of the local Cardano node owning the socket')
    p.add_argument('--cardano-genesis',help='SHA-256 of the trusted local Shelley genesis')
    p.add_argument('--cardano-signing-key',type=Path,help='private local payment signing key')
    p.add_argument('--cardano-journal-dir',type=Path,help='private directory for durable public transaction records')
    p.add_argument('--cardano-preimage-backup',type=Path,help='optional private exported browser backup for local claims')
    p.add_argument('--ethereum-rpc',help='non-forked Anvil RPC on loopback, chain ID 31337')
    p.add_argument('--cardano-cli',type=Path,default=TOOLS/'cardano/bin/cardano-cli')
    p.add_argument('--aiken',type=Path,default=TOOLS/'aiken/aiken-x86_64-unknown-linux-musl/aiken')
    p.add_argument('--hegemon-wallet',type=Path)
    p.add_argument('--hegemon-manifest',type=Path)
    p.add_argument('--hegemon-genesis')
    p.add_argument('--hegemon-rpc')
    p.add_argument('--private-spend',type=Path,default=ROOT/'target/release/private-spend')
    p.add_argument('--enable-hegemon-actions',action='store_true',help='enable locally approved Development-only wallet actions')
    p.add_argument('--hegemon-public',action='store_true',help='use the pinned v0.11 public pre-mainnet (mutually exclusive with --enable-hegemon-actions)')
    p.add_argument('--hosted-node-status',action='store_true',help='allow the hosted testnet page to read Hegemon node status only; no wallet or transaction operations')
    p.add_argument('--hosted-wallet-status',action='store_true',help='allow the hosted testnet page to read one unlocked wallet\'s HGN totals; no spends')
    p.add_argument('--hosted-hegemon-swap',action='store_true',help='opt in to locally approved Hegemon pre-mainnet swap operations from the pinned hosted page')
    p.add_argument('--hegemon-handoff-dir',type=Path,help='private directory for encrypted refund handoffs')
    p.add_argument('--hegemon-preimage-backup',type=Path,help='optional private exported browser backup for local claims')
    p.add_argument('--token-file',type=Path,required=True,help='0600 file inside a user-owned 0700 directory')
    p.add_argument('--gui',action='store_true',help='open a local window to copy the pairing token and approve the wallet passphrase')
    p.add_argument('--hegemon-node-path',type=Path,help='node base directory containing node-activity.json; default ~/.hegemon-node-v0.11')
    p.add_argument('--origin',default=None)
    p.add_argument('--port',type=int,default=8788)
    args=p.parse_args();os.umask(0o077)
    if sum((args.hosted_node_status,args.hosted_wallet_status,args.hosted_hegemon_swap))>1:p.error('hosted node status, wallet status and swap mode are mutually exclusive')
    if args.hosted_node_status:
        if args.origin not in (None, HOSTED_ORIGIN):p.error('hosted node status accepts only the pinned hosted origin')
        args.origin=HOSTED_ORIGIN
        other=[args.bitcoin_rpc,args.bitcoin_cookie,args.enable_bitcoin_actions,args.bitcoin_wallet,args.bitcoin_genesis,args.bitcoin_preimage_backup,
               args.cardano_socket,args.cardano_network_dir,args.enable_cardano_actions,args.cardano_node_pid,args.cardano_genesis,args.cardano_signing_key,args.cardano_journal_dir,args.cardano_preimage_backup,
               args.ethereum_rpc,args.hegemon_wallet,args.hegemon_manifest,args.hegemon_genesis,args.enable_hegemon_actions,args.hegemon_public,args.hegemon_handoff_dir,args.hegemon_preimage_backup]
        if not args.hegemon_rpc or any(other):p.error('hosted node status requires only a loopback Hegemon RPC and no wallet or other chain options')
        from probe_hegemon_testnet import endpoint
        endpoint(args.hegemon_rpc)
    elif args.hosted_wallet_status or args.hosted_hegemon_swap:
        if args.origin not in (None, HOSTED_ORIGIN):p.error('hosted wallet status accepts only the pinned hosted origin')
        args.origin=HOSTED_ORIGIN
        other=[args.bitcoin_rpc,args.bitcoin_cookie,args.enable_bitcoin_actions,args.bitcoin_wallet,args.bitcoin_genesis,args.bitcoin_preimage_backup,
               args.cardano_socket,args.cardano_network_dir,args.enable_cardano_actions,args.cardano_node_pid,args.cardano_genesis,args.cardano_signing_key,args.cardano_journal_dir,args.cardano_preimage_backup,
               args.ethereum_rpc,args.hegemon_manifest,args.hegemon_genesis,args.enable_hegemon_actions,args.hegemon_public]
        if not args.hosted_hegemon_swap:other.extend([args.hegemon_handoff_dir,args.hegemon_preimage_backup])
        if not args.hegemon_rpc or not args.hegemon_wallet or any(other):p.error('hosted wallet status requires only a loopback Hegemon RPC and one wallet file')
        if args.hosted_hegemon_swap:
            if not args.hegemon_handoff_dir:p.error('hosted Hegemon swap mode requires a private refund handoff directory')
            if not os.isatty(0):p.error('hosted Hegemon swap actions require an interactive local terminal')
            private_handoff_directory(args.hegemon_handoff_dir)
            check_swap_wallet_binary(args.private_spend)
            args.hegemon_public=True
        from probe_hegemon_testnet import endpoint
        endpoint(args.hegemon_rpc)
        release=json.loads((ROOT/'config/testnet/0.11/release.json').read_text())
        args.hegemon_manifest=ROOT/'config/testnet/0.11/network-manifest.json'
        args.hegemon_genesis=release['genesis_hash']
        if hashlib.sha256(args.hegemon_manifest.read_bytes()).hexdigest()!=release['network_manifest_sha256']:
            p.error('pinned v0.11 manifest does not match the release')
        private_wallet_file(args.hegemon_wallet)
        if not os.isatty(0) and not args.gui:p.error('Hegemon wallet status requires an interactive local terminal')
    else:
        args.origin=args.origin or 'http://127.0.0.1:8787'
        origin=urlsplit(args.origin)
        if origin.scheme!='http' or origin.hostname not in ('127.0.0.1','localhost') or not origin.port or origin.path or origin.query or origin.fragment or origin.username:raise ValueError('origin must be an explicit loopback HTTP origin')
    if not 1<=args.port<=65535:raise ValueError('invalid port')
    if bool(args.bitcoin_rpc)!=bool(args.bitcoin_cookie):p.error('Bitcoin RPC and cookie must be supplied together')
    if args.enable_bitcoin_actions:
        if not args.bitcoin_rpc or not args.bitcoin_wallet or not re.fullmatch('[A-Za-z0-9_-]{1,64}',args.bitcoin_wallet) or not re.fullmatch('[0-9a-f]{64}',args.bitcoin_genesis or ''):p.error('Bitcoin actions require a local RPC, cookie, wallet name and genesis')
        if not os.isatty(0):p.error('Bitcoin actions require an interactive local terminal')
    elif args.bitcoin_wallet or args.bitcoin_genesis or args.bitcoin_preimage_backup:p.error('Bitcoin wallet options require Bitcoin actions')
    if bool(args.cardano_socket)!=bool(args.cardano_network_dir):p.error('Cardano socket and network directory must be supplied together')
    if args.enable_cardano_actions:
        if not args.cardano_socket or not args.cardano_node_pid or not args.cardano_genesis or not args.cardano_signing_key or not args.cardano_journal_dir:p.error('Cardano actions require the socket, network directory, node PID, genesis, signing key and journal directory')
        if not os.isatty(0):p.error('Cardano actions require an interactive local terminal')
        local_node_identity(args.cardano_node_pid,args.cardano_socket,args.cardano_network_dir,args.cardano_genesis);private_key(args.cardano_signing_key);private_journal_directory(args.cardano_journal_dir)
    elif args.cardano_node_pid or args.cardano_genesis or args.cardano_signing_key or args.cardano_journal_dir or args.cardano_preimage_backup:p.error('Cardano wallet options require Cardano actions')
    hegemon_options=[args.hegemon_wallet,args.hegemon_manifest,args.hegemon_genesis,args.hegemon_rpc]
    if args.hegemon_public and args.enable_hegemon_actions:
        p.error('--hegemon-public is mutually exclusive with --enable-hegemon-actions')
    if not args.hosted_node_status and not args.hosted_wallet_status and not args.hosted_hegemon_swap and any(hegemon_options) and not all(hegemon_options):p.error('all Hegemon wallet, manifest, genesis and RPC options are required')
    if not args.hosted_node_status and not args.hosted_wallet_status and not args.hosted_hegemon_swap and not args.bitcoin_rpc and not args.cardano_socket and not args.ethereum_rpc and not all(hegemon_options):p.error('configure at least one local node')
    if args.ethereum_rpc:ethereum_local_head(args.ethereum_rpc)
    if all(hegemon_options):
        if not os.isatty(0):p.error('Hegemon verification requires an interactive local terminal')
        endpoint=urlsplit(args.hegemon_rpc)
        if endpoint.scheme!='http' or endpoint.hostname not in ('127.0.0.1','localhost') or endpoint.username or not re.fullmatch('(0x)?[0-9a-f]{64}',args.hegemon_genesis):p.error('Hegemon requires a loopback RPC and canonical genesis hash')
    if args.enable_hegemon_actions:
        if not all(hegemon_options):p.error('Hegemon actions require all Hegemon options')
        private_handoff_directory(args.hegemon_handoff_dir)
    if args.hegemon_public:
        if not all(hegemon_options):p.error('Hegemon public mode requires all Hegemon options')
        release=json.loads((ROOT/'config/testnet/0.11/release.json').read_text())
        if args.hegemon_genesis.removeprefix('0x')!=release['genesis_hash'].removeprefix('0x'):
            p.error('Hegemon public mode requires the pinned v0.11 genesis')
        if hashlib.sha256(args.hegemon_manifest.read_bytes()).hexdigest()!=release['network_manifest_sha256']:
            p.error('Hegemon public mode requires the pinned v0.11 manifest')
        if args.hegemon_handoff_dir:private_handoff_directory(args.hegemon_handoff_dir)
    if args.hegemon_preimage_backup and not args.enable_hegemon_actions and not (args.hegemon_public and args.hegemon_handoff_dir):
        p.error('preimage backup requires Hegemon actions')
    token=private_token(args.token_file)
    btc=BitcoinRPC(args.bitcoin_rpc,args.bitcoin_cookie) if args.bitcoin_rpc else None
    if args.enable_bitcoin_actions:
        if btc.call('getblockchaininfo')['chain']!='regtest' or btc.call('getblockhash',0)!=args.bitcoin_genesis or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin requires the configured isolated regtest chain')
        btc.call('getwalletinfo',wallet=args.bitcoin_wallet)
    scratch=tempfile.TemporaryDirectory(prefix='hegemon-local-companion-')
    session=None
    prompt=GuiApproval() if args.gui and (args.hosted_wallet_status or args.hosted_hegemon_swap) else None
    keyring=DesktopKeyring() if prompt is not None else None
    if args.hosted_wallet_status or args.hosted_hegemon_swap:
        session=HostedWalletSession(rpc=args.hegemon_rpc,wallet_path=args.hegemon_wallet,manifest=args.hegemon_manifest,genesis=args.hegemon_genesis,binary=args.private_spend,scratch=scratch.name,prompt=prompt,keyring=keyring)
    cardano=None
    if args.cardano_socket:
        if not stat.S_ISSOCK(args.cardano_socket.stat().st_mode):raise ValueError('Cardano socket must be a local Unix socket')
        class CardanoView:
            magic='424242'
            net=args.cardano_network_dir
            socket=args.cardano_socket
            aiken=args.aiken
            script=Path(scratch.name)/'validator.plutus'
            script.write_text(subprocess.check_output([str(args.aiken),'blueprint','convert',str(ROOT/'contracts/cardano')],text=True))
            def run(self,*values):
                result=subprocess.run([str(args.cardano_cli),'conway',*map(str,values)],capture_output=True,text=True,timeout=60)
                if result.returncode:raise RuntimeError('local Cardano CLI request failed')
                return result.stdout
            def query(self,*values):
                return json.loads(self.run('query',*values,'--testnet-magic',self.magic,'--socket-path',args.cardano_socket,'--output-json'))
            def tip(self):return self.query('tip')
            def utxos(self,address):return self.query('utxo','--address',address)
        cardano=CardanoView()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def permitted(self):
            return self.headers.get('Host')==f'127.0.0.1:{args.port}' and self.headers.get('Origin')==args.origin
        def reply(self,status,value):
            data=json.dumps(value,separators=(',',':')).encode()
            self.send_response(status)
            if self.permitted():self.send_header('Access-Control-Allow-Origin',args.origin)
            self.send_header('Vary','Origin');self.send_header('Cache-Control','no-store')
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
        def do_OPTIONS(self):
            if not self.permitted():return self.reply(403,{'error':'forbidden'})
            self.send_response(204);self.send_header('Access-Control-Allow-Origin',args.origin)
            self.send_header('Access-Control-Allow-Methods','GET, OPTIONS' if args.hosted_node_status else 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers','authorization, content-type')
            if self.headers.get('Access-Control-Request-Private-Network')=='true':self.send_header('Access-Control-Allow-Private-Network','true')
            self.send_header('Vary','Origin');self.end_headers()
        def authorized(self):
            value=self.headers.get('Authorization','')
            return self.permitted() and value.startswith('Bearer ') and re.fullmatch('[0-9a-f]{64}',value[7:]) is not None and hmac.compare_digest(value[7:],token)
        def do_GET(self):
            if not self.authorized():return self.reply(403,{'error':'forbidden'})
            try:
                if self.path=='/health':
                    if args.hosted_hegemon_swap:return self.reply(200,{'status':'ok','capabilities':['hegemon-public-status','hegemon-public-balance','hegemon-swap-verify','hegemon-swap-actions','hegemon-swap-observe','hegemon-swap-select']})
                    if args.hosted_wallet_status:return self.reply(200,{'status':'ok','capabilities':['hegemon-public-status','hegemon-public-balance']})
                    if args.hosted_node_status:return self.reply(200,{'status':'ok','capabilities':['hegemon-public-status']})
                    capabilities=(['bitcoin-regtest-verify'] if btc else [])+(['bitcoin-regtest-actions'] if args.enable_bitcoin_actions else [])+(['cardano-local-verify'] if cardano else [])+(['cardano-local-actions'] if args.enable_cardano_actions else [])+(['ethereum-local-anchor'] if args.ethereum_rpc else [])+(['hegemon-public-verify'] if args.hegemon_public else ['hegemon-local-verify'] if all(hegemon_options) else [])+(['hegemon-public-actions'] if args.hegemon_public and args.hegemon_handoff_dir else ['hegemon-local-actions'] if args.enable_hegemon_actions else [])
                    return self.reply(200,{'status':'ok','capabilities':capabilities})
                if self.path=='/hegemon/status' and (args.hosted_node_status or args.hosted_wallet_status or args.hosted_hegemon_swap):
                    from probe_hegemon_testnet import probe
                    node=probe(args.hegemon_rpc)
                    return self.reply(200,{'network':node['network'],'height':str(node['height']),'syncing':node['syncing'],
                                           'peers':node['peers'],'wallet_rpc_ready':node['basic_wallet_checks_passed']})
                if self.path=='/hegemon/wallet-activity' and (args.hosted_wallet_status or args.hosted_hegemon_swap):
                    return self.reply(200,session.activity.snapshot())
                if self.path=='/hegemon/swap/address' and args.hosted_hegemon_swap:
                    try:return self.reply(200,session.swap_address())
                    except PermissionError:return self.reply(409,{'error':'wallet_locked'})
                    except RuntimeError:return self.reply(409,{'error':'wallet_busy'})
                    except Exception:return self.reply(502,{'error':'Hegemon address unavailable'})
                if self.path=='/hegemon/swap/head' and args.hosted_hegemon_swap:
                    try:
                        node=read_hosted_swap_node(args.hegemon_rpc,args.hegemon_genesis,args.hegemon_manifest)
                        return self.reply(200,{'network':'pre-mainnet','genesis':node['genesis'],'chain_id':node['chain_id'],'height':str(node['height'])})
                    except Exception:return self.reply(503,{'error':'hegemon_node_not_ready'})
                if self.path=='/hegemon/balance' and (args.hosted_wallet_status or args.hosted_hegemon_swap):
                    try:return self.reply(200,session.balance())
                    except PermissionError:return self.reply(409,{'error':'wallet_locked'})
                    except LookupError:return self.reply(503,{'error':'hegemon_node_not_ready'})
                    except Exception:return self.reply(502,{'error':'wallet balance unavailable'})
                if args.hosted_node_status or args.hosted_wallet_status or args.hosted_hegemon_swap:return self.reply(404,{'error':'not found'})
                if self.path=='/bitcoin/head' and btc:
                    info=btc.call('getblockchaininfo')
                    if info['chain']!='regtest' or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not isolated regtest')
                    return self.reply(200,{'genesis':btc.call('getblockhash',0),'height':str(info['blocks']),'tip_hash':info['bestblockhash']})
                if self.path=='/ethereum/head' and args.ethereum_rpc:
                    return self.reply(200,ethereum_local_head(args.ethereum_rpc))
                if self.path=='/cardano/head' and cardano:
                    raw=(cardano.net/'shelley-genesis.json').read_bytes();genesis=json.loads(raw)
                    if genesis.get('networkId')!='Testnet' or genesis.get('networkMagic')!=424242:raise ValueError('wrong Cardano network')
                    start=int(datetime.datetime.fromisoformat(genesis['systemStart'].replace('Z','+00:00')).timestamp())*1000
                    slot_ms=Decimal(str(genesis['slotLength']))*1000
                    if slot_ms!=slot_ms.to_integral_value():raise ValueError('unsupported slot duration')
                    tip=cardano.tip()
                    return self.reply(200,{'genesis':hashlib.sha256(raw).hexdigest(),'time_ms':str(start+tip['slot']*int(slot_ms)),'tip_hash':tip['hash']})
                if self.path=='/hegemon/head' and all(hegemon_options):
                    if args.hegemon_public:
                        from probe_hegemon_testnet import assert_public_profile
                        node,_=assert_public_profile(args.hegemon_rpc,genesis=args.hegemon_genesis,manifest=args.hegemon_manifest)
                        return self.reply(200,{'genesis':node['genesis'].removeprefix('0x'),'height':str(node['height']),'profile':'public'})
                    genesis=str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or genesis!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon node is not isolated')
                    return self.reply(200,{'genesis':genesis,'height':str(height(args.hegemon_rpc))})
                return self.reply(404,{'error':'not found'})
            except Exception:
                return self.reply(502,{'error':'local node status unavailable'})
        def do_POST(self):
            if not self.authorized():return self.reply(403,{'error':'forbidden'})
            if args.hosted_node_status:return self.reply(403,{'error':'hosted node status is read-only'})
            if args.hosted_hegemon_swap and self.path!='/hegemon/unlock':
                if self.path not in ('/hegemon/swap/verify','/hegemon/swap/observe','/hegemon/swap/action','/hegemon/swap/select','/hegemon/swap/locate','/hegemon/swap/inclusion'):return self.reply(404,{'error':'not found'})
                if self.headers.get_content_type()!='application/json':return self.reply(400,{'error':'JSON required'})
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if not 0<length<=16384:raise ValueError('invalid body size')
                    data=json.loads(self.rfile.read(length))
                    if self.path=='/hegemon/swap/verify':
                        return self.reply(200,{'verified':True,'snapshot':session.verify_swap_htlc(data)})
                    if self.path=='/hegemon/swap/observe':
                        from hegemon_swap_observer import observe_claim_request
                        return self.reply(200,observe_claim_request(data,args.hegemon_rpc))
                    if self.path=='/hegemon/swap/select':
                        return self.reply(200,select_swap_notes(session.available_swap_notes(),data))
                    if self.path=='/hegemon/swap/locate':
                        if not isinstance(data,dict) or set(data)!={'commitment'}:raise ValueError('invalid Hegemon lookup')
                        return self.reply(200,session.locate_swap_htlc(data['commitment']))
                    if self.path=='/hegemon/swap/inclusion':
                        return self.reply(200,session.swap_attempt_inclusion(data))
                    secret_backup=None
                    if isinstance(data,dict) and set(data)=={'action','secret_envelope'}:
                        from unlock_swap_backup import validate_envelope
                        if not isinstance(data['action'],dict) or data['action'].get('operation')!='claim':raise ValueError('encrypted secret is only valid for a claim')
                        validate_envelope(data['secret_envelope'])
                        secret_backup=data['secret_envelope'];data=data['action']
                    if not session._lock.acquire(blocking=False):return self.reply(409,{'error':'wallet_busy'})
                    try:
                        read_hosted_swap_node(args.hegemon_rpc,args.hegemon_genesis,args.hegemon_manifest)
                        base=['--wallet',args.hegemon_wallet,'--manifest',args.hegemon_manifest,'--genesis',args.hegemon_genesis,'--rpc',args.hegemon_rpc]
                        backup_path=None
                        try:
                            if secret_backup is not None:
                                with tempfile.NamedTemporaryFile(mode='w',prefix='encrypted-swap-secret-',dir=scratch.name,delete=False) as backup:
                                    backup_path=Path(backup.name);json.dump({'label':'Swap recovery','envelope':secret_backup},backup);backup.flush();os.fsync(backup.fileno())
                            result=run_hegemon_action(binary=args.private_spend,base_args=base,scratch=scratch.name,request=data,handoff_dir=args.hegemon_handoff_dir,preimage_backup=backup_path or args.hegemon_preimage_backup,banner='Hegemon public pre-mainnet swap wallet action')
                        finally:
                            if backup_path is not None:
                                try:backup_path.unlink()
                                except FileNotFoundError:pass
                        read_hosted_swap_node(args.hegemon_rpc,args.hegemon_genesis,args.hegemon_manifest)
                        return self.reply(200,{'completed':True,'result':result})
                    finally:
                        session._cached=None
                        session._lock.release()
                except PermissionError:return self.reply(409,{'error':'wallet_locked'})
                except RuntimeError:return self.reply(409,{'error':'wallet_busy_or_action_uncertain'})
                except (ValueError,TypeError,json.JSONDecodeError):
                    if self.path=='/hegemon/swap/action':return self.reply(409,{'error':'Action outcome may be uncertain. Check wallet status before retrying.'})
                    return self.reply(400,{'error':'Local Hegemon request declined or invalid.'})
                except Exception:return self.reply(502,{'error':'Local Hegemon operation unavailable; check wallet status before retrying.'})
            if args.hosted_wallet_status or args.hosted_hegemon_swap:
                if self.path!='/hegemon/unlock':return self.reply(404,{'error':'not found'})
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if length<0 or length>2:raise ValueError('invalid unlock request')
                    if length and self.rfile.read(length) not in (b'',b'{}'):raise ValueError('invalid unlock request')
                    view=session.unlock()
                    return self.reply(200,{'unlocked':True,'balance':view})
                except LookupError:return self.reply(503,{'error':'hegemon_node_not_ready'})
                except ValueError as error:
                    allowed={'wallet unlock declined locally','passphrase required','invalid unlock request','Invalid wallet balance','Wallet balance is absent or ambiguous','Invalid wallet balance fields','Duplicate wallet balance field','Invalid wallet authority'}
                    return self.reply(400,{'error':str(error) if str(error) in allowed else 'wallet balance unavailable'})
                except Exception:return self.reply(502,{'error':'wallet balance unavailable'})
            if self.path not in ('/bitcoin/verify','/bitcoin/action','/cardano/verify','/cardano/action','/hegemon/verify','/hegemon/action'):return self.reply(404,{'error':'not found'})
            if self.headers.get_content_type()!='application/json':return self.reply(400,{'error':'JSON required'})
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:raise ValueError('invalid body size')
                data=json.loads(self.rfile.read(length))
                if self.path=='/bitcoin/action':
                    if not args.enable_bitcoin_actions:raise ValueError('Bitcoin actions are not enabled')
                    result=run_bitcoin_action(btc=btc,wallet=args.bitcoin_wallet,genesis=args.bitcoin_genesis,request=data,backup=args.bitcoin_preimage_backup)
                    return self.reply(200,{'completed':True,'result':result})
                if self.path=='/cardano/action':
                    if not args.enable_cardano_actions:raise ValueError('Cardano actions are not enabled')
                    result=run_cardano_action(chain=cardano,pid=args.cardano_node_pid,genesis_hash=args.cardano_genesis,signing_key=args.cardano_signing_key,journal_dir=args.cardano_journal_dir,request=data,backup=args.cardano_preimage_backup)
                    return self.reply(200,{'completed':True,'result':result})
                if self.path=='/hegemon/action':
                    if args.hegemon_public:
                        if not args.hegemon_handoff_dir:raise ValueError('Hegemon public actions need a handoff directory')
                        from probe_hegemon_testnet import assert_public_profile
                        assert_public_profile(args.hegemon_rpc,genesis=args.hegemon_genesis,manifest=args.hegemon_manifest)
                        base=['--wallet',args.hegemon_wallet,'--manifest',args.hegemon_manifest,'--genesis',args.hegemon_genesis,'--rpc',args.hegemon_rpc]
                        result=run_hegemon_action(binary=args.private_spend,base_args=base,scratch=scratch.name,request=data,handoff_dir=args.hegemon_handoff_dir,preimage_backup=args.hegemon_preimage_backup,banner='Hegemon public pre-mainnet action (not an atomic swap)')
                        assert_public_profile(args.hegemon_rpc,genesis=args.hegemon_genesis,manifest=args.hegemon_manifest)
                        return self.reply(200,{'completed':True,'result':result})
                    if not args.enable_hegemon_actions:raise ValueError('Hegemon actions are not enabled')
                    manifest=json.loads(args.hegemon_manifest.read_text())
                    if manifest.get('profile')!='development' or manifest.get('development_candidate',{}).get('private_spend_only') is not True:raise ValueError('actions require a private-spend Development manifest')
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon node is not the configured isolated chain')
                    base=['--wallet',args.hegemon_wallet,'--manifest',args.hegemon_manifest,'--genesis',args.hegemon_genesis,'--rpc',args.hegemon_rpc,'--development-local-candidate']
                    result=run_hegemon_action(binary=args.private_spend,base_args=base,scratch=scratch.name,request=data,handoff_dir=args.hegemon_handoff_dir,preimage_backup=args.hegemon_preimage_backup)
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Node changed; action outcome may be uncertain. Check wallet status.')
                    return self.reply(200,{'completed':True,'result':result})
                expected=({'txid','vout','amount_sats','hashlock','claimant_key','refund_key','refund_height','genesis_hash'} if self.path=='/bitcoin/verify'
                          else {'outref','hashlock','claimant','refundee','expiry_ms','expected_value','genesis_sha256'} if self.path=='/cardano/verify'
                          else {'locked','claim','refund','hashlock','timeout','amount','min_confirmations','min_remaining_blocks'})
                if not isinstance(data,dict) or set(data)!=expected:raise ValueError('invalid request fields')
                if self.path=='/bitcoin/verify':
                    if btc is None:raise ValueError('Bitcoin verifier is not configured')
                    if btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not isolated')
                    result=verify_bitcoin_htlc(btc,**data)
                    if btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not isolated')
                elif self.path=='/cardano/verify':
                    if cardano is None:raise ValueError('Cardano verifier is not configured')
                    result=verify_cardano_htlc(cardano,**cardano_wire_terms(data),aiken=args.aiken)
                else:
                    if not all(hegemon_options):raise ValueError('Hegemon verifier is not configured')
                    values=hegemon_wire_terms(data)
                    if args.hegemon_public:
                        from probe_hegemon_testnet import assert_public_profile
                        assert_public_profile(args.hegemon_rpc,genesis=args.hegemon_genesis,manifest=args.hegemon_manifest)
                    elif rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon node is not the configured isolated chain')
                    print('\nHegemon verification request (no funds will be moved):\n'+json.dumps(values,indent=2),flush=True)
                    if input('Type VERIFY to approve this local wallet read: ').strip()!='VERIFY':raise ValueError('verification declined locally')
                    phrase=getpass.getpass('Hegemon encrypted wallet passphrase (local terminal only): ')
                    if not phrase:raise ValueError('passphrase required')
                    argv=['--wallet',args.hegemon_wallet,'--manifest',args.hegemon_manifest,'--genesis',args.hegemon_genesis,'--rpc',args.hegemon_rpc]
                    if not args.hegemon_public:argv.append('--development-local-candidate')
                    argv.append('verify-htlc')
                    for field in ('locked','claim','refund','hashlock','timeout','amount','min_confirmations','min_remaining_blocks'):
                        argv.extend(['--'+field.replace('_','-'),values[field]])
                    try:
                        text,_=wallet(args.private_spend,argv,[(PASS,phrase.encode())],Path(scratch.name),'hegemon-verify')
                    except RuntimeError as e:
                        raise ValueError('Hegemon wallet did not verify the note') from e
                    finally:del phrase
                    result=json_line(text)
                    if args.hegemon_public:
                        from probe_hegemon_testnet import assert_public_profile
                        assert_public_profile(args.hegemon_rpc,genesis=args.hegemon_genesis,manifest=args.hegemon_manifest)
                        if result.get('verified') is not True:raise ValueError('Hegemon verification unavailable')
                    elif result.get('verified') is not True or rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon verification unavailable')
                    fields=('position','created_height','reference_height','confirmations')
                    if any(type(result.get(field)) is not int or result[field]<0 for field in fields):raise ValueError('invalid Hegemon verifier result')
                    result={'verified':True,**{field:str(result[field]) for field in fields}}
                self.reply(200,{'verified':True,'snapshot':result})
            except (ValueError,TypeError,json.JSONDecodeError) as e:
                self.reply(400,{'error':str(e)})
            except Exception:
                self.reply(502,{'error':'local operation failed; check wallet status before retrying'})
    global active_server
    Server=ThreadingHTTPServer if args.hosted_wallet_status or args.hosted_hegemon_swap else HTTPServer
    server=Server(('127.0.0.1',args.port),Handler)
    if args.hosted_wallet_status or args.hosted_hegemon_swap:server.daemon_threads=True
    active_server=server
    def terminate(_signum,_frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,terminate)
    print(f'Local companion listening on 127.0.0.1:{args.port}; token file: {args.token_file}; hosted node status: {args.hosted_node_status}; hosted wallet status: {args.hosted_wallet_status}; Hegemon actions: {args.enable_hegemon_actions}; Hegemon public: {args.hegemon_public}; gui: {args.gui}',flush=True)
    try:
        if args.gui:
            threading.Thread(target=server.serve_forever,name='companion-http',daemon=True).start()
            activity_path=(args.hegemon_node_path if args.hegemon_node_path is not None else Path.home()/'.hegemon-node-v0.11')/'node-activity.json'
            monitor=NodeActivityMonitor(args.hegemon_rpc,activity_path)
            CompanionWindow(token=token,wallet_path=args.hegemon_wallet if args.hosted_wallet_status or args.hosted_hegemon_swap else None,keyring=keyring,prompt=prompt,activity=session.activity if session is not None else None,monitor=monitor).run()
            monitor.stop()
            server.shutdown()
        else:
            server.serve_forever()
    except KeyboardInterrupt:pass
    finally:
        active_server=None
        server.server_close()
        if session is not None:session.close()
        scratch.cleanup()

if __name__=='__main__':main()
