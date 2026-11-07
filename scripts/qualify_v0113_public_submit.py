#!/usr/bin/env python3
"""Fresh, isolated public-submit candidate lifecycle using production source authority.

Creates only disposable local state. Mines real current-manifest rewards, proves
with the normal client, then submits the exact retained action over loopback HTTP
under public-submit. No proof/manifest/source pins are changed. This is candidate
behavior evidence, not release approval, deployment, or a full network lifecycle.
"""
from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import shutil
import signal
import socket
import subprocess
import termios
import time

MAX_RESPONSE = 10 * 1024 * 1024
MAX_DIAGNOSTICS = 16 * 1024 * 1024
MIN_FREE_BYTES = 4 * 1024 ** 3


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def current_action_carrier(raw):
    """Exact ordinary PendingAction framing; production parsers remain authoritative."""
    def compact(position):
        require(position < len(raw), 'truncated SCALE length')
        mode = raw[position] & 3
        size = (1, 2, 4)[mode] if mode < 3 else (raw[position] >> 2) + 5
        require((mode != 3 or size == 5) and position + size <= len(raw), 'invalid SCALE length')
        value = (int.from_bytes(raw[position:position + size], 'little') >> 2 if mode < 3 else
                 int.from_bytes(raw[position + 1:position + size], 'little'))
        require(mode == 0 or value >= (64, 16384, 1 << 30)[mode - 1], 'noncanonical SCALE length')
        return value, position + size
    require(len(raw) >= 104 and raw[48:56] == bytes.fromhex('0c00070001000f00'), 'wrong current action identity')
    cursor = 104
    for width in (48, 48, 48, 4):
        count, cursor = compact(cursor)
        require(count <= (len(raw) - cursor) // width, 'truncated action vector')
        cursor += count * width
    size, cursor = compact(cursor)
    end = cursor + size
    require(end + 9 == len(raw) and raw[end + 8] == 0, 'action trailing bytes or candidate artifact')
    carrier = raw[cursor:end]
    require(len(carrier) > 5784 and raw[end:end + 8] == carrier[200:208], 'outer/inner fee mismatch')
    require(carrier[:24] == b'HGPSLC02' + bytes.fromhex('01000c00070001000f000800020c0100'), 'carrier identity')
    require(carrier[5784:5788] == b'SMZL', 'proof magic')
    return carrier


def submit_request(carrier):
    return {'binding_circuit': 12, 'binding_crypto': 7, 'family_id': 1, 'action_id': 15,
            'object_refs': [], 'new_nullifiers': [], 'public_args': base64.b64encode(carrier).decode(),
            'authorization_proof': None, 'authorization_signatures': [], 'aux_data': None}


class Qualification:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        require(not self.output.exists(), 'output must be a new disposable directory')
        self.output.mkdir(parents=True, mode=0o700)
        self.started = time.monotonic()
        self.deadline = self.started + args.timeout_seconds
        self.owned = []
        self.node = None
        self.expected_fixture_tip = None
        self.logs = []
        self.passphrase = secrets.token_urlsafe(32)
        # Retained only in the private fixture directory, never argv/log/receipt.
        secret = self.output / 'disposable-wallet.passphrase'
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(self.passphrase + '\n')
        self.wallet_path = self.output / 'disposable-wallet.store'
        self.node_state = self.output / ('mined-fixture/node-state' if args.fixture_builder_bin else 'node-state')
        self.receipt = {'schema': 'hegemon.v0113.public-submit-candidate-lifecycle.v1', 'status': 'RUNNING',
                        'production_authorized': False, 'release_approved': False,
                        'publication_performed': False, 'deployment_performed': False,
                        'test_only_route_activation': False, 'source_authority_pins_modified': False,
                        'operator_wallet_opened': False, 'live_node_touched': False,
                        'full_network_lifecycle_verified': False, 'controls': {}, 'stages': [],
                        'limitations': ['single local host and fresh disposable exact-manifest chain',
                                        'no relay, reorg, fresh-node sync or full release gate coverage',
                                        'no hard verifier CPU-time cutoff or universal DoS claim',
                                        'negative controls record observed responses; a rejection alone does not identify its internal stage',
                                        'build provenance must be joined to the separate candidate build receipt']}
        self.manifest = args.source_root / 'config/testnet/0.11/network-manifest.json'
        release = json.loads((args.source_root / 'config/testnet/0.11/release.json').read_text())
        self.genesis = release['genesis_hash']
        self.chain = release['chain_id']
        require(sha(self.manifest) == release['network_manifest_sha256'], 'manifest does not match release identity')
        self.inputs = {str(path): sha(path) for path in (args.node_bin, args.private_spend_bin, self.manifest,
                       args.source_root / 'protocol/versioning/src/launch_candidate.rs',
                       args.source_root / 'protocol/versioning/src/launch_candidate_identity.rs',
                       args.source_root / 'circuits/transaction/src/private_spend/types.rs',
                       Path(__file__).resolve())}
        if args.fixture_builder_bin:
            self.inputs[str(args.fixture_builder_bin)] = sha(args.fixture_builder_bin)
            self.inputs[str(args.source_root / 'node/src/native/public_submit_fixture_tests.rs')] = sha(
                args.source_root / 'node/src/native/public_submit_fixture_tests.rs')
        self.receipt.update(inputs_before=self.inputs, expected_genesis=self.genesis, expected_chain_id=self.chain,
                            source_root=str(args.source_root), timeout_seconds=args.timeout_seconds,
                            public_submissions_per_minute=args.submissions_per_minute,
                            public_requests_per_minute=6000,
                            resource_limit_qualification=False)
        self.save()

    def save(self):
        self.receipt['elapsed_seconds'] = round(time.monotonic() - self.started, 3)
        atomic_json(self.output / 'receipt.json', self.receipt)

    def mark(self, stage):
        self.receipt['stages'].append(stage)
        self.save()
        print(stage, flush=True)

    def budget(self):
        require(time.monotonic() < self.deadline, 'candidate lifecycle timeout; owned children will be stopped')
        require(shutil.disk_usage(self.output).free >= MIN_FREE_BYTES, '4 GiB free-disk reserve reached')
        for path in self.logs:
            require(not path.exists() or path.stat().st_size <= MAX_DIAGNOSTICS, 'owned diagnostic log exceeds bound')
        if self.node is not None:
            require(self.node.poll() is None, 'owned node exited unexpectedly')

    def isolated_env(self):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith('HEGEMON_') and key not in {'PQ_IDENTITY_SEED', 'PQ_IDENTITY_SEED_PATH'}}
        env.update(HEGEMON_MINE='0', HEGEMON_SEEDS='', HEGEMON_BOOTSTRAP_AUTHORING='1',
                   HEGEMON_MINE_THREADS='1', HEGEMON_MAX_PEERS='1', RAYON_NUM_THREADS='2')
        return env

    def wallet(self, command, network=True, timeout=300):
        self.budget()
        argv = [str(self.args.private_spend_bin), '--wallet', str(self.wallet_path)]
        if network:
            argv += ['--manifest', str(self.manifest), '--genesis', self.genesis, '--rpc', self.url]
        argv += list(map(str, command))
        master, slave = pty.openpty()
        attributes = termios.tcgetattr(slave)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attributes)
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        process = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                   preexec_fn=controlling_terminal, env=self.isolated_env(), close_fds=True)
        os.close(slave)
        self.owned.append(process)
        transcript = bytearray()
        prompts = [b'Encrypted wallet passphrase: ']
        if command == ['bootstrap-new']:
            prompts += [b'Confirm encrypted wallet passphrase: ']
        sent = 0
        end = min(self.deadline, time.monotonic() + timeout)
        try:
            while True:
                self.budget()
                require(time.monotonic() < end, 'owned wallet command timeout; retained attempt may be uncertain')
                ready = select.select([master], [], [], 0.1)[0]
                if ready:
                    try:
                        chunk = os.read(master, 8192)
                    except OSError:
                        chunk = b''
                    transcript.extend(chunk)
                    require(len(transcript) <= MAX_DIAGNOSTICS, 'wallet diagnostic bound reached')
                    if not chunk and process.poll() is not None:
                        break
                while sent < len(prompts) and prompts[sent] in transcript:
                    os.write(master, self.passphrase.encode() + b'\n')
                    sent += 1
                if process.poll() is not None and not ready:
                    break
            require(process.wait(timeout=5) == 0 and sent == len(prompts),
                    'owned wallet command failed; private diagnostic retained')
            return transcript.decode('utf-8', 'replace')
        finally:
            os.close(master)
            # PTY echo is disabled; additionally suppress the private passphrase.
            path = self.output / ('wallet-' + str(process.pid) + '.log')
            path.write_bytes(bytes(transcript).replace(self.passphrase.encode(), b'[redacted]'))
            os.chmod(path, 0o600)
            self.logs.append(path)

    def start_node(self, policy):
        self.budget()
        holders = [socket.socket() for _ in range(2)]
        try:
            for sock in holders:
                sock.bind(('127.0.0.1', 0))
            rpc_port, p2p_port = [sock.getsockname()[1] for sock in holders]
        finally:
            for sock in holders:
                sock.close()
        self.url = f'http://127.0.0.1:{rpc_port}'
        self.rpc_port = rpc_port
        env = self.isolated_env()
        env['HEGEMON_MINER_ADDRESS'] = self.address
        argv = [str(self.args.node_bin), '--network', 'pre-mainnet', '--network-manifest', str(self.manifest),
                '--base-path', str(self.node_state), '--rpc-port', str(rpc_port),
                '--listen-addr', f'127.0.0.1:{p2p_port}', '--port', str(p2p_port), '--rpc-methods', policy,
                '--name', 'v0113-public-submit-disposable']
        if policy == 'public-submit':
            argv += ['--rpc-public-submissions-per-minute', str(self.args.submissions_per_minute),
                     '--rpc-public-requests-per-minute', '6000']
        path = self.output / f'node-{len(self.owned)}-{policy}.log'
        self.logs.append(path)
        with path.open('wb') as log:
            self.node = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        self.owned.append(self.node)
        end = min(self.deadline, time.monotonic() + 90)
        while True:
            self.budget()
            require(time.monotonic() < end, 'owned node startup timeout')
            try:
                cfg = self.rpc('hegemon_nodeConfig')
                require(cfg['chainId'] == self.chain and cfg['rpcMethods'] == policy, 'wrong running identity/policy')
                require(self.rpc('chain_getBlockHash', [0]) == self.genesis, 'wrong running genesis')
                require(self.rpc('system_health')['peers'] == 0, 'isolated node unexpectedly connected to a peer')
                break
            except (ConnectionError, OSError, http.client.HTTPException):
                time.sleep(0.2)
        self.mark('started_' + policy)

    def stop_node(self):
        process = self.node
        self.node = None
        if process is not None:
            process.send_signal(signal.SIGTERM)
            require(process.wait(timeout=30) == 0, 'owned node did not shut down cleanly')

    def raw_rpc(self, method=None, params=None, body=None):
        self.budget()
        if body is None:
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': [] if params is None else params}).encode()
        connection = http.client.HTTPConnection('127.0.0.1', self.rpc_port, timeout=min(60, max(1, self.deadline-time.monotonic())))
        try:
            connection.request('POST', '/', body, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE, 'response byte bound exceeded')
            return response.status, data
        finally:
            connection.close()

    def rpc(self, method, params=None):
        status, raw = self.raw_rpc(method, params)
        require(status == 200, f'HTTP {status} for {method}')
        value = json.loads(raw)
        require(not value.get('error'), f'RPC {method} failed: {value.get("error")}')
        return value['result']

    def fingerprint(self):
        return {'consensus': self.rpc('hegemon_consensusStatus'), 'notes': self.rpc('hegemon_walletNotes'),
                'pending': sorted(self.rpc('author_pendingExtrinsics'))}

    def reject(self, name, request):
        before = self.fingerprint()
        started = time.monotonic()
        status, raw = self.raw_rpc('hegemon_submitAction', [request])
        elapsed = time.monotonic() - started
        require(status == 200, name + ' hit transport/capacity instead of semantic rejection')
        response = json.loads(raw)
        error = response.get('error')
        if error is not None:
            require(error.get('code') == -32602, name + ' hit admission/capacity instead of semantic rejection')
        else:
            require(response.get('result', {}).get('success') is False, name + ' was not rejected')
        text = json.dumps(response).lower()
        require('capacity' not in text and 'rate limit' not in text, name + ' was capacity-rejected')
        require(self.fingerprint() == before, name + ' changed canonical/pending state')
        self.receipt['controls'][name] = {'response': response, 'elapsed_seconds': elapsed,
                                          'canonical_and_pending_unchanged': True}
        self.save()

    def build_matured_fixture(self):
        self.budget()
        env = self.isolated_env()
        fixture = self.output / 'mined-fixture'
        env.update(HEGEMON_PUBLIC_SUBMIT_FIXTURE_DIR=str(fixture),
                   HEGEMON_PUBLIC_SUBMIT_FIXTURE_MINER_ADDRESS=self.address,
                   HEGEMON_PUBLIC_SUBMIT_FIXTURE_TIMEOUT_SECS='600')
        argv = [str(self.args.fixture_builder_bin), '--exact',
                'native::public_submit_fixture_tests::build_current_manifest_public_submit_fixture',
                '--ignored', '--nocapture', '--test-threads=1']
        path = self.output / 'fixture-builder.log'
        self.logs.append(path)
        with path.open('wb') as log:
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                       env=env, start_new_session=True)
        self.owned.append(process)
        end = min(self.deadline, time.monotonic() + 660)
        while process.poll() is None:
            self.budget()
            require(time.monotonic() < end, 'fixture builder exceeded its bounded runtime')
            time.sleep(0.1)
        require(process.returncode == 0, 'fixture builder failed; retained diagnostic log')
        receipt_path = fixture / 'receipt.json'
        require(receipt_path.is_file(), 'fixture builder did not produce its required receipt')
        receipt = json.loads(receipt_path.read_text())
        require(receipt.get('schema') == 'hegemon.v0113.production-path-mined-fixture.v1'
                and receipt.get('status') == 'PASS_PRODUCTION_PATH_MINED_FIXTURE'
                and receipt.get('database_closed') is True,
                'fixture builder did not complete its production path')
        require(receipt.get('manifest_sha256') == sha(self.manifest)
                and receipt.get('genesis_hash') == self.genesis
                and receipt.get('chain_id') == self.chain,
                'fixture builder identity mismatch')
        require([block.get('height') for block in receipt.get('blocks', [])] == list(range(1, 122))
                and all(block.get('normal_import_passed') is True for block in receipt['blocks']),
                'fixture builder import history incomplete')
        for flag in ('test_only_authority_installed', 'development_candidate_enabled',
                     'synthetic_state_rows_inserted', 'proof_validation_bypassed',
                     'scheduled_difficulty_overridden'):
            require(receipt.get(flag) is False, 'fixture builder must preserve ' + flag)
        self.expected_fixture_tip = receipt['blocks'][-1]['hash']
        self.receipt['fixture_builder'] = {'argv': argv, 'receipt': str(receipt_path),
            'receipt_sha256': sha(receipt_path),
            'historical_timestamps_selected': True,
            'real_time_mining_throughput_measured': False,
            'release_binary_replay_required': True}
        self.receipt['limitations'].append(
            'matured fixture selects valid historical block timestamps and solves real PoW; it does not measure real-time mining')
        self.mark('built_real_pow_historical_timestamp_fixture')

    def run(self):
        output = self.wallet(['bootstrap-new'], network=False)
        rows = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
        self.address = rows[-1]['address']
        self.mark('created_disposable_encrypted_wallet')
        if self.args.fixture_builder_bin:
            self.build_matured_fixture()
        else:
            self.start_node('unsafe')
            require(int(self.rpc('chain_getHeader')['number'], 16) == 0, 'fixture did not start at genesis')
            self.rpc('hegemon_startMining', [{'threads': 1}])
            last = -1
            while True:
                self.budget()
                height = int(self.rpc('chain_getHeader')['number'], 16)
                if height != last:
                    self.receipt['mined_height'] = height
                    self.save()
                    last = height
                if height >= 121:
                    break
                time.sleep(0.25)
            self.rpc('hegemon_stopMining')
            time.sleep(0.5)
            self.stop_node()
        self.start_node('public-submit')
        height = int(self.rpc('chain_getHeader')['number'], 16)
        require(height >= 121, 'release binary did not replay the matured reward prefix')
        if self.expected_fixture_tip is not None:
            require(height == 121 and self.rpc('chain_getBlockHash', [121]) == self.expected_fixture_tip,
                    'release binary did not replay the exact constructed fixture prefix')
            self.receipt['release_binary_replayed_fixture_tip'] = self.expected_fixture_tip
        self.receipt['matured_prefix_height'] = height
        self.receipt['release_binary_matured_prefix_replay_verified'] = True
        self.mark('genuine_current_manifest_matured_rewards')
        methods = self.rpc('rpc_methods')['methods']
        require('hegemon_submitAction' in methods, 'public-submit catalog missing submission')
        for method in ('hegemon_startMining', 'hegemon_stopMining', 'da_submitCiphertexts', 'da_submitProofs', 'system_peers'):
            require(method not in methods, 'privileged method in public catalog: ' + method)
        self.receipt['public_method_catalog'] = methods
        self.wallet(['sync'])
        notes = self.wallet(['notes'])
        entries = re.findall(r'^ordinary position=(\d+) value=(\d+)\r?$', notes, re.MULTILINE)
        require(bool(entries), 'wallet did not decrypt a real mined ordinary note')
        position, amount = min((int(p), int(v)) for p, v in entries if int(v) > 101000)
        proof_start = time.monotonic()
        prepared = self.wallet(['ordinary', '--inputs', position, '--recipient', self.address,
                                '--amount', 100000, '--fee', 1000], timeout=self.args.proof_timeout_seconds)
        attempts = re.findall(r'^candidate ([0-9a-f]{64})\r?$', prepared, re.MULTILINE)
        require(len(attempts) == 1, 'wallet did not retain exactly one proved attempt')
        attempt = attempts[0]
        self.receipt['client_proving_elapsed_seconds'] = time.monotonic() - proof_start
        action_path = self.output / 'ordinary.action'
        self.wallet(['export', attempt, action_path])
        action = action_path.read_bytes()
        require(len(action) <= 200000, 'exported ordinary action too large')
        carrier = current_action_carrier(action)
        proof = carrier[5784:]
        self.receipt['action'] = {'attempt': attempt, 'tx_hash': '0x' + action[:48].hex(),
                                  'bytes': len(action), 'sha256': hashlib.sha256(action).hexdigest(),
                                  'carrier_bytes': len(carrier), 'carrier_sha256': hashlib.sha256(carrier).hexdigest(),
                                  'proof_bytes': len(proof), 'proof_sha256': hashlib.sha256(proof).hexdigest()}
        self.mark('retained_one_fresh_client_proof')
        request = submit_request(carrier)
        self.reject('malformed', {})
        wrong = bytearray(carrier); wrong[72] ^= 1
        self.reject('wrong_network', submit_request(wrong))
        bad = bytearray(carrier); bad[-1] ^= 1
        self.reject('mutated_proof_bytes', submit_request(bad))
        # The SMZL wire reads an unconstrained 32-byte salt immediately after its
        # four-byte magic. Changing one salt byte preserves all lengths, field
        # encodings and the canonical suffix, but changes the proof transcript.
        bad_salt = bytearray(carrier); bad_salt[5784 + 4] ^= 1
        self.reject('changed_transcript_salt', submit_request(bad_salt))
        unsupported = copy.deepcopy(request); unsupported['action_id'] = 65535
        self.reject('unsupported_action', unsupported)
        before = self.fingerprint()
        status, _ = self.raw_rpc(body=b' ' * (8 * 1024 * 1024 + 1))
        require(status == 413 and self.fingerprint() == before, 'oversized body did not reject without state changes')
        self.receipt['controls']['oversized_body'] = {'http_status': status, 'canonical_and_pending_unchanged': True}
        # CLI submit checks the RPC acknowledgment against the retained action identity.
        # Any lost response fails this run; the reserved attempt is never canceled/replaced.
        started = time.monotonic()
        accepted = self.wallet(['submit', attempt], timeout=180)
        require(('submitted ' + action[:48].hex()) in accepted, 'client did not validate matching submission acknowledgment')
        self.receipt['public_submission_elapsed_seconds'] = time.monotonic() - started
        require(self.receipt['action']['tx_hash'] in self.rpc('author_pendingExtrinsics'), 'accepted action absent from mempool')
        self.receipt['accepted_through_actual_public_http'] = True
        self.mark('actual_public_submit_accepted')
        self.reject('duplicate', request)
        # No public observation privilege is added. Restart only this owned node
        # under the preexisting trusted loopback policy for exact durable readback.
        self.stop_node()
        self.start_node('unsafe')
        readback = self.rpc('hegemon_pendingActionChunk', [self.receipt['action']['tx_hash'], 0, 1024 * 1024])
        require(readback and readback['total_len'] == len(action) and readback['offset'] == 0,
                'durable pending readback missing after restart')
        exact = bytes.fromhex(readback['chunk'].removeprefix('0x'))
        require(exact == action and current_action_carrier(exact)[5784:] == proof,
                'durable action/proof bytes changed')
        self.receipt.update(unchanged_durable_action_verified=True, unchanged_proof_verified=True,
                            persistent_pending_restart_verified=True, state_admission_verified=True)
        self.stop_node()
        self.mark('durable_restart_exact_action_and_proof_readback')
        self.receipt['inputs_after'] = {path: sha(path) for path in self.inputs}
        require(self.receipt['inputs_after'] == self.inputs, 'binary/authority/manifest inputs changed during run')
        self.receipt['status'] = 'PASS_FRESH_PUBLIC_SUBMIT_CANDIDATE_LIFECYCLE'

    def cleanup(self):
        self.node = None
        for process in reversed(self.owned):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=15)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                        self.receipt['forced_cleanup'] = True
                        self.receipt['status'] = 'NON_PASS'
        self.receipt['owned_processes'] = [{'pid': p.pid, 'exit_code': p.returncode, 'reaped': p.poll() is not None}
                                           for p in self.owned]
        self.receipt['all_owned_reaped'] = all(p.poll() is not None for p in self.owned)
        if not self.receipt['all_owned_reaped']:
            self.receipt['status'] = 'NON_PASS'
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--node-bin', type=Path, required=True)
    parser.add_argument('--private-spend-bin', type=Path, required=True)
    parser.add_argument('--fixture-builder-bin', type=Path,
                        help='optional no-feature node test binary: real PoW/import with valid historical timestamps')
    parser.add_argument('--output', type=Path, required=True, help='new private fixture directory; never reused')
    parser.add_argument('--timeout-seconds', type=int, default=2400)
    parser.add_argument('--proof-timeout-seconds', type=int, default=600)
    parser.add_argument('--submissions-per-minute', type=int, default=30,
                        help='explicit fixture budget; admission limit tests are separate')
    args = parser.parse_args()
    require(60 <= args.timeout_seconds <= 7200 and 30 <= args.proof_timeout_seconds <= 1800, 'invalid bounded runtime')
    require(6 <= args.submissions_per_minute <= 60, 'fixture request budget must be 6..60')
    args.source_root = args.source_root.resolve(strict=True)
    args.node_bin = args.node_bin.resolve(strict=True)
    args.private_spend_bin = args.private_spend_bin.resolve(strict=True)
    if args.fixture_builder_bin:
        args.fixture_builder_bin = args.fixture_builder_bin.resolve(strict=True)
    qualification = Qualification(args)
    def interrupted(signum, frame):
        raise RuntimeError(f'candidate lifecycle interrupted by signal {signum}')
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        qualification.run()
    except Exception as error:
        qualification.receipt.update(status='NON_PASS', failure=str(error)[:1000],
                                     uncertain_attempt_must_remain_reserved=True)
        print('candidate lifecycle failed: ' + str(error), flush=True)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        qualification.cleanup()
    return 0 if qualification.receipt['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
