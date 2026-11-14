#!/usr/bin/env python3
"""Source-bound software candidate checks; never production/activation authority.

--prepare is useful before source freeze. --require-authorized requires a frozen
source inventory and independent scope review. Final artifacts additionally run
unchanged actual proof/H0 executors and source-owned fresh qualification commands.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/ntime-rolling-candidate-v0115.json'
BASE = 'ad77c8d564944972b6ae5e7cab26fcf500972aff'
SCHEMA = 'hegemon.ntime-rolling.candidate.v1'
KIND = 'ntime-rolling-software-candidate'
SCOPE = 'exact-v0115-premainnet-source-proof-h0-and-ntime-lifecycle'
SOFTWARE_VERSION = '0.11.5'
COMBINED_ACTIVATION_HEIGHT = 18_660
RELATION_ID = 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4'
RELATION = 'b9d22c2f0cb49df519b34620c138d7f2d74fa135a76c7b526cd73a60bb5cd6cec2f910dde83b1a848684e123d02ab0bbc8bdb384b1bcaff1b489fd8794c14685'
LOCK = '1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719'
EVIDENCE_ROOT = 'release-evidence/ntime-rolling-v0115/'
GENERATED_ARTIFACT_CONFIG = 'config/v0115-release-artifacts.json'
CHECKS = ('ntime', 'asert', 'treasury', 'adapter', 'sync')
REQUIRED_GATES = {
    'ntime': ('solved_backward_forward', 'fresh_clock_bounds', 'activation_precision', 'restart_reorg_fresh_sync'),
    'asert': ('reference_vectors', 'no_std', 'activation_branch_anchor', 'cold_resumption'),
    'treasury': ('original_activation_maturity', 'formal_supply_vectors'),
    'adapter': ('real_tcp_and_range_regressions',),
    'sync': ('queue_target_preservation', 'retained_asic_gate', 'disconnected_rpc_reservations'),
}
BOUNDARIES = {'production_authorized': False, 'mainnet_authorized': False,
              'activation_authorized': False, 'public_cutover_authorized': False,
              'deployment_verified': False, 'physical_asic_qualified': False}
# These exact files retain their historical authority and execution behavior.
IMMUTABLE = {'scripts/check_v0113_release_successor.py': 'af04798400fd70c11b934a743961b271bd9db16a729210d73641b600737df61c', 'config/v0113-release-successor.json': 'a8ca68b402ef5db13caee27c6e3e4f384549f5286f6fa2798b2d8542854bd76f', 'scripts/check_v011_sync_import_successor.py': 'ceceb9f281343f9c730422684b44819ab8e9c2ed973a551de641992153303f0f', 'config/v011-sync-import-successor-20261106.json': '9cc53dc52975d3f9cd5edd3caaaf11d971a77f773430b637377e64561aecd9d6', 'scripts/check_v011_release_successor.py': '390f5cbc69e877e29302db4af7b7382bbf6db9bdeccada01942ccba384b0fc67', 'config/v011-release-successor.json': '94bd9591a8232292d1928198b3d4778a27f7cc4c8fc560c0ff87ac3bfa22fadb', 'scripts/check_private_spend_launch_authorization.py': '7f5265e5ddc8ec947bbc93df31df276c0fae787bfdcbc7b1e5a2547958ae60ab', 'scripts/private_spend_launch_authorized_registry.json': 'c37455302ad34f631df1938b0ee7980af8bb8a57930ba38c05a6fe86941c145f', 'scripts/check_v011_current_binary_proofs.py': 'd2f0fae819828482093676f831a5d6c621013c02368cdddafcdf491d294eb2f2', 'scripts/release_artifact_manifest.py': '0f41da8be0536335978ed42d2f93f930b2c9ee078f3ecbeb6293e44ce20c42cb', 'scripts/check_release_launcher_policy.py': '51700e93ac457574f262bff05f48e5e55fa328e37da30f665721a312de9d826e', '.github/workflows/release.yml': 'd03f65f4eb9a27ce5616c31c90b3b41652e9aaf23d29da9cb1f8707eea64ff81', 'config/testnet/0.11/network-manifest.json': '386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754', 'release-evidence/v0.11-current-proof-fixture/manifest.json': '50a1c137b7d8d7d03181b7b9e1d353d98cfd26e708e178c75dd7925dff271a8c', 'scripts/check_qualified_formatting.py': 'be7732c0e30f9b770ef5395be762ec9ea133d39f7fc52170d17639e2579a71a9', 'config/qualified-formatting-baseline.json': '76a60a213994ee887c854cdd33031667a18472611efc7cf16cb8aa802206ec02'}

IMMUTABLE.update({'scripts/check_combined_upgrade_candidate.py': 'b8d186e7b004113e5c7d47444aa02eb5e67b27926ebccb19e1d426826bb4ec7d', 'scripts/qualify_combined_upgrade.py': 'fbdf033edab1ce47be2f98c4eb3cb7dc1cb25500fef180deaeac855114fe1bab', 'config/combined-upgrade-candidate-20261108.json': 'd8c267c5e879ceed00ba1ca91325882d7eed0aad8179b841a584ca4508316c9e'})

class CandidateError(RuntimeError):
    pass

def require(value, message):
    if not value:
        raise CandidateError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def diagnostic_tail(raw, limit):
    # Bound rendered UTF-8 bytes too, including replacement of invalid input.
    encoded = raw[-limit:].decode('utf-8', errors='replace').encode('utf-8')
    return encoded[-limit:].decode('utf-8', errors='ignore')

def strict_json(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate JSON key: ' + key)
            out[key] = value
        return out
    def invalid_constant(value):
        raise CandidateError('non-finite JSON constant rejected: ' + value)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    require(isinstance(value, dict), 'JSON object required')
    return value

def safe_file(root, relative):
    require(isinstance(relative, str) and bool(relative), 'relative path required')
    path = Path(relative)
    require(not path.is_absolute() and path.as_posix() == relative
            and all(p not in ('', '.', '..') for p in relative.split('/')), 'canonical path required')
    current = root
    for part in path.parts:
        current /= part
        require(not current.is_symlink(), 'symlink rejected: ' + relative)
        require(not (getattr(current.lstat(), 'st_file_attributes', 0) & 0x400), 'reparse path rejected')
    require(current.is_file(), 'regular file required: ' + relative)
    return current

def row(root, relative):
    raw = safe_file(root, relative).read_bytes()
    return {'path': relative, 'bytes': len(raw), 'sha256': sha(raw)}

def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=120, check=False)
    require(result.returncode == 0, 'authenticated Git base unavailable: ' + result.stderr.decode(errors='replace')[-500:])
    return result.stdout

def base_tree(root):
    require(git(root, 'rev-parse', BASE + '^{commit}').decode().strip() == BASE, 'immutable base commit differs')
    out = {}
    for entry in git(root, 'ls-tree', '-rz', '--full-tree', BASE).split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        require(kind == 'blob' and mode in ('100644', '100755'), 'submodule/symlink base entry rejected')
        out[name.decode()] = (mode, oid)
    return out

def owned(path):
    return path not in (CONFIG, GENERATED_ARTIFACT_CONFIG) and not path.startswith(EVIDENCE_ROOT)

def evidence_data(root, index_modes=None):
    """Admit bounded public wire data, never executable source or credentials."""
    index_modes = index_modes or {}
    base = root
    for part in Path(EVIDENCE_ROOT).parts:
        base /= part
        require(not base.is_symlink(), 'linked evidence directory rejected')
        if not base.exists():
            return
        require(base.is_dir(), 'candidate evidence directory must be regular')
    caps = {'.smzl': 171848, '.hgps': 177632, '.action': 177632 + 225}
    for parent, dirs, files in os.walk(base, followlinks=False):
        for name in dirs:
            require(not (Path(parent) / name).is_symlink(), 'linked evidence directory rejected')
        for name in files:
            relative = (Path(parent) / name).relative_to(root).as_posix()
            file = safe_file(root, relative)
            suffix = file.suffix
            require(suffix in ('.json', '.log', '.txt', *caps), 'candidate evidence permits public JSON/log/text/action/HGPS/SMZL data only')
            require(not file.stat().st_mode & 0o111 and index_modes.get(relative) != '100755', 'executable evidence rejected: ' + relative)
            if suffix in caps:
                require(0 < file.stat().st_size <= caps[suffix], 'public wire evidence byte cap exceeded: ' + relative)
                raw = file.read_bytes()
                require((suffix == '.smzl' and raw.startswith(b'SMZL'))
                        or (suffix == '.hgps' and raw.startswith(b'HGPSLC02'))
                        or (suffix == '.action' and raw[48:56] == bytes.fromhex('0c00070001000f00')),
                        'public wire evidence framing differs: ' + relative)

def inventory(root):
    paths = git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    index_modes = {}
    for entry in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            index_modes[name.decode()] = meta.decode().split()[0]
    evidence_data(root, index_modes)
    names = {p for p in paths if p and owned(p)}
    # Git ignore patterns do not constrain Cargo discovery. In particular bin/
    # may be globally ignored while src/bin/*.rs remains an automatic target.
    excluded = {'.git', 'target', 'node_modules', '.lake', '__pycache__', '.venv', 'venv'}
    for parent, dirs, files in os.walk(root, followlinks=False):
        relative = Path(parent).relative_to(root)
        if relative.parts and relative.parts[0] == 'release-evidence':
            dirs[:] = []; continue
        kept = []
        for name in dirs:
            if name in excluded:
                continue
            require(not (Path(parent) / name).is_symlink(), 'linked source directory rejected')
            kept.append(name)
        dirs[:] = kept
        for name in files:
            path = relative / name
            if (path.suffix in ('.rs', '.lean') or name in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'rust-toolchain', 'rust-toolchain.toml')
                    or (path.parts and path.parts[0] == '.cargo')
                    or (path.parts and path.parts[0] == 'scripts' and path.suffix in ('.py', '.sh'))):
                names.add(path.as_posix())
    output = []
    for path in sorted(names):
        file = safe_file(root, path)
        mode = '100755' if file.stat().st_mode & 0o111 else '100644'
        if os.name == 'nt' and path in index_modes:
            # Windows lacks POSIX executable bits. Match the existing artifact
            # manifest's Git-index interpretation of tracked source modes.
            mode = index_modes[path]
        output.append({**row(root, path), 'mode': mode})
    return output


def proof_identity(root):
    source = safe_file(root, 'circuits/transaction/src/private_spend.rs').read_text()
    types = safe_file(root, 'circuits/transaction/src/private_spend/types.rs').read_text()
    require('pub const RELATION_ID: &str = "' + RELATION_ID + '";' in types, 'relation ID differs')
    files = re.findall(r'\(\s*"([^"]+)"\s*,\s*include_bytes!\("([^"]+)"\)\s*,?\s*\)', source)
    require(len(files) == 41 and all(a == b for a, b in files), 'exact 41 relation inputs required')
    h = hashlib.sha512(b'Hegemon.PrivateSpend.SourceManifest.v1' + RELATION_ID.encode())
    rows = []
    for label, name in files:
        import os
        path = Path(os.path.abspath(root / 'circuits/transaction/src' / name))
        require(path.is_relative_to(root), 'relation path escapes source')
        relative = path.relative_to(root).as_posix()
        data = safe_file(root, relative).read_bytes(); encoded = label.encode()
        h.update(len(encoded).to_bytes(8, 'little') + encoded + len(data).to_bytes(8, 'little') + data)
        rows.append(row(root, relative))
    require(h.hexdigest() == RELATION and sha(safe_file(root, 'Cargo.lock').read_bytes()) == LOCK,
            'proof relation or Cargo.lock differs; new relation qualification required')
    return {'relation_id': RELATION_ID, 'relation_digest': RELATION,
            'cargo_lock_sha256': LOCK, 'source_inputs': rows}

def release_tuple(root):
    # This checks source preparation, never the published historical release record.
    path = safe_file(root, 'scripts/check_ntime_rolling_source.py')
    spec = importlib.util.spec_from_file_location('_ntime_source_preparation', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    try:
        module.verify_source(root)
    except RuntimeError as error:
        raise CandidateError(str(error)) from error

def authenticate(root):
    tree = base_tree(root)
    git(root, 'merge-base', '--is-ancestor', BASE, 'HEAD')
    for path, (_, oid) in tree.items():
        if path.startswith('release-evidence/combined-upgrade-20261108/'):
            raw = safe_file(root, path).read_bytes()
            require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid,
                    'historical combined evidence changed: ' + path)
    for path, digest in IMMUTABLE.items():
        require(path in tree and sha(git(root, 'show', BASE + ':' + path)) == digest,
                'immutable predecessor authentication failed: ' + path)
        require(sha(safe_file(root, path).read_bytes()) == digest,
                'historical source authority changed: ' + path)
    return tree

def binding(config):
    return sha(canonical({k: v for k, v in config.items() if k != 'independent_review'}))

def validate_config(config):
    require(set(config) == {'schema', 'status', 'baseline_commit', 'scope', 'boundaries',
                           'software_version', 'kind', 'proof_identity', 'source_inventory', 'source_inventory_sha256',
                           'reviewed_delta', 'independent_review', 'qualification_commands'}, 'candidate config fields differ')
    require(config['schema'] == SCHEMA and config['baseline_commit'] == BASE and config['scope'] == SCOPE
            and config['software_version'] == SOFTWARE_VERSION and config['kind'] == KIND,
            'candidate baseline/schema/scope differs')
    require(isinstance(config['boundaries'], dict) and set(config['boundaries']) == set(BOUNDARIES)
            and all(config['boundaries'][k] is v for k, v in BOUNDARIES.items()), 'candidate cannot grant production/activation/hardware authority')
    require(config['status'] in ('pending', 'frozen'), 'candidate status invalid')
    if config['status'] == 'pending':
        require(config['source_inventory'] == [] and config['source_inventory_sha256'] is None
                and config['reviewed_delta'] == [] and config['independent_review'] is None
                and config['qualification_commands'] == [], 'pending config cannot claim frozen evidence')
    else:
        require(isinstance(config['source_inventory'], list) and config['source_inventory'], 'source inventory missing')
        validate_inventory(config['source_inventory'])
        require(config['source_inventory_sha256'] == sha(canonical(config['source_inventory'])), 'source inventory digest differs')
        require(isinstance(config['reviewed_delta'], list) and config['reviewed_delta'], 'exact reviewed delta missing')
        validate_commands(config['qualification_commands'])
    return config

def validate_inventory(records):
    require(isinstance(records, list) and records, 'complete source inventory required')
    names = []
    for record in records:
        require(isinstance(record, dict) and set(record) == {'path', 'bytes', 'sha256', 'mode'},
                'exact source inventory row required')
        name = record['path']
        require(isinstance(name, str) and name and not Path(name).is_absolute()
                and all(p not in ('', '.', '..') for p in name.split('/')) and owned(name),
                'owned canonical source inventory path required')
        require(type(record['bytes']) is int and record['bytes'] >= 0
                and isinstance(record['sha256'], str) and re.fullmatch('[0-9a-f]{64}', record['sha256'])
                and record['mode'] in ('100644', '100755'), 'source inventory row identity differs')
        names.append(name)
    require(names == sorted(set(names)), 'ordered unique source inventory required')


def validate_commands(commands):
    require(isinstance(commands, list) and [r.get('name') for r in commands if isinstance(r, dict)] == list(CHECKS),
            'complete ordered affected qualification commands required')
    for command in commands:
        require(set(command) == {'name', 'argv', 'timeout_seconds'}, 'qualification command fields differ')
        require(command['argv'] == ['python3', '-I', '-B', 'scripts/qualify_ntime_rolling.py',
                '--suite', command['name'], '--artifact-manifest', '{artifact_manifest}'],
                'exact source-owned affected qualification command required')
        require(type(command['timeout_seconds']) is int and 1 <= command['timeout_seconds'] <= 7200,
                'bounded qualification timeout required')


def load_config(root):
    return validate_config(strict_json(safe_file(root, CONFIG).read_bytes()))

def source_check(root, config):
    validate_config(config)
    tree = authenticate(root)
    if config['status'] == 'frozen':
        require(inventory(root) == config['source_inventory'], 'frozen source inventory/path set differs before importing source helpers')
    release_tuple(root)
    require(config['proof_identity'] == proof_identity(root), 'source-bound relation inventory differs')
    if config['status'] == 'pending':
        return {'status': 'PASS_PENDING_SOURCE_PREPARATION', 'source_frozen': False, **BOUNDARIES}
    current = inventory(root)
    require(current == config['source_inventory'], 'frozen source inventory/path set differs')
    deltas = []
    for item in current:
        path = item['path']; raw = safe_file(root, path).read_bytes()
        oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if path in tree and oid == tree[path][1] and item['mode'] == tree[path][0]:
            continue
        before = sha(git(root, 'show', BASE + ':' + path)) if path in tree else None
        deltas.append({'path': path, 'before_sha256': before, 'after_sha256': item['sha256'], 'bytes': item['bytes'], 'before_mode': tree[path][0] if path in tree else None, 'after_mode': item['mode']})
    require(not ({p for p in tree if owned(p)} - {r['path'] for r in current}), 'base source removal rejected')
    require(deltas == config['reviewed_delta'], 'exact reviewed candidate delta differs')
    return {'status': 'PASS_FROZEN_SOURCE_PREPARATION', 'source_frozen': True,
            'candidate_binding_sha256': binding(config), 'source_inventory_sha256': config['source_inventory_sha256'],
            'source_inventory': current, **BOUNDARIES}

def pinned_json(root, reference):
    require(isinstance(reference, dict) and set(reference) == {'path', 'bytes', 'sha256'}, 'exact evidence pin required')
    require(reference['path'].startswith(EVIDENCE_ROOT), 'evidence must use candidate evidence namespace')
    require(row(root, reference['path']) == reference, 'evidence bytes differ')
    return strict_json(safe_file(root, reference['path']).read_bytes())

def review_check(root, config):
    require(config['status'] == 'frozen', 'candidate source is pending; freeze and actual independent review required')
    review = pinned_json(root, config['independent_review'])
    expected = {'schema': 'hegemon.ntime-rolling.independent-review.v1',
                'decision': 'ACCEPT_SOFTWARE_CANDIDATE_SCOPE', 'candidate_binding_sha256': binding(config),
                'source_inventory_sha256': config['source_inventory_sha256'],
                'qualification_commands_sha256': sha(canonical(config['qualification_commands'])), **BOUNDARIES}
    require(all(type(review.get(k)) is type(v) and review[k] == v for k, v in expected.items()), 'independent review binding/scope differs')
    require(review.get('review_kind') in ('independent_model_review', 'independent_human_review')
            and isinstance(review.get('reviewer'), str) and review['reviewer'].strip()
            and isinstance(review.get('limitations'), list) and review['limitations'], 'independent attribution and limitations required')
    validate_commands(config['qualification_commands'])
    return review

def validate_check(value, name, config, artifacts, *, root=ROOT, verify_logs=False):
    expected = {'schema': 'hegemon.ntime-rolling.actual-check.v1', 'name': name,
                'status': 'PASS', 'candidate_binding_sha256': binding(config),
                'source_inventory_sha256': config['source_inventory_sha256'],
                'artifact_manifest_sha256': artifacts['artifact_manifest_sha256'],
                'artifact_sha256': artifacts['artifact_sha256'], 'target_triple': artifacts['target_triple'],
                'actual_execution': True, 'processes_reaped': True, **BOUNDARIES}
    require(isinstance(value, dict) and all(type(value.get(k)) is type(v) and value[k] == v
                for k, v in expected.items()), 'fresh qualification identity/scope differs: ' + name)
    require(isinstance(value.get('gates'), dict) and set(value['gates']) == set(REQUIRED_GATES[name])
            and all(v is True for v in value['gates'].values()),
            'complete exact actual qualification gates required: ' + name)

    require(value.get('execution_scope') == 'same-source-rehearsal-not-ordinary-final-binary',
            'ordinary final artifact lifecycle claim rejected')
    runner_path = safe_file(root, 'scripts/qualify_ntime_rolling.py')
    spec = importlib.util.spec_from_file_location('_ntime_fixed_execution_plan', runner_path)
    runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
    plan = runner.suite_plan(name)
    executions = value.get('executions')
    require(isinstance(executions, list) and len(executions) == len(plan) and executions,
            'exact nonempty fresh execution inventory required: ' + name)
    for execution, command in zip(executions, plan, strict=True):
        require(isinstance(execution, dict), 'execution record required')
        actual_argv = execution.get('argv')
        expected_argv = command['argv']
        if 'adapter_count' in command:
            require(isinstance(actual_argv, list) and len(actual_argv) == len(expected_argv)
                    and isinstance(actual_argv[0], str)
                    and (Path(actual_argv[0]).is_absolute() or PureWindowsPath(actual_argv[0]).is_absolute())
                    and actual_argv[1:] == expected_argv[1:],
                    'exact isolated adapter command required')
        else:
            require(actual_argv == expected_argv, 'fixed qualification command differs')
        require(type(execution.get('exit_code')) is int and execution['exit_code'] == 0
                and execution.get('process_reaped') is True
                and execution.get('actual_command_execution') is True,
                'successful owned process closure required')
        require(execution.get('test_name') == command.get('exact_name'), 'exact executed test identity differs')
        expected_counts = ({'passed': 1, 'failed': 0, 'ignored': 0, 'measured': 0}
                           if 'exact_name' in command else
                           {'passed': command['adapter_count'], 'failed': 0, 'ignored': 0, 'skipped': 0}
                           if 'adapter_count' in command else None)
        counts = execution.get('test_counts')
        require(counts == expected_counts and (counts is None or
                all(type(v) is int and v >= 0 for v in counts.values())), 'exact positive test counts required')
        for field in ('started_unix', 'finished_unix', 'duration_seconds'):
            number = execution.get(field)
            require(type(number) in (int, float) and math.isfinite(number) and number >= 0,
                    'finite execution timing required')
        log = execution.get('log')
        require(isinstance(log, str) and log.startswith('target/ntime-qualification/')
                and log.endswith('.log') and all(p not in ('', '.', '..') for p in log.split('/')),
                'owned retained qualification log required')
        require(re.fullmatch('[0-9a-f]{64}', execution.get('log_sha256', '')) is not None,
                'retained log digest required')
        if verify_logs:
            raw = safe_file(root, log).read_bytes()
            require(sha(raw) == execution['log_sha256'], 'retained actual execution log changed')
            if 'exact_name' in command:
                require(runner.exact_test_output(raw, command['exact_name']) == expected_counts,
                        'retained exact test log differs')
            elif 'adapter_count' in command:
                require(runner.unittest_output(raw, command['adapter_count']) == expected_counts,
                        'retained complete adapter log differs')



@contextlib.contextmanager
def interruption_handlers():
    previous = {}
    def interrupted(signum, _frame):
        for registered in previous:
            signal.signal(registered, signal.SIG_IGN)
        raise CandidateError('candidate interrupted by signal ' + str(signum))
    try:
        signals = [signal.SIGTERM, signal.SIGINT]
        if hasattr(signal, 'SIGBREAK'):
            signals.append(signal.SIGBREAK)
        for signum in signals:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run_qualification(argv, root, timeout):
    # Catchable coordinator termination unwinds through the runner's own child
    # cleanup. A forced shutdown can never produce a qualification receipt.
    options = {'start_new_session': True} if os.name != 'nt' else {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    with interruption_handlers():
        process = None
        try:
            process = subprocess.Popen(argv, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            if process is not None:
                if process.poll() is None:
                    if os.name == 'nt':
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        process.send_signal(signal.SIGTERM)
                try:
                    process.communicate(timeout=35)
                except subprocess.TimeoutExpired:
                    if os.name == 'nt':
                        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                       capture_output=True, timeout=30, check=False)
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=30)
            raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def fresh_checks(root, config, artifacts, manifest_path):
    outputs = []
    source_paths = {r['path'] for r in config['source_inventory']}
    for command in config['qualification_commands']:
        require(set(command) == {'name', 'argv', 'timeout_seconds'}, 'qualification command fields differ')
        argv = command['argv']
        require(isinstance(argv, list) and len(argv) >= 4 and argv[:3] == ['python3', '-I', '-B']
                and argv[3].startswith('scripts/') and argv[3] in source_paths
                and all(isinstance(v, str) and v for v in argv), 'source-owned isolated Python qualification command required')
        require(type(command['timeout_seconds']) is int and 1 <= command['timeout_seconds'] <= 7200, 'bounded qualification timeout required')
        require('{artifact_manifest}' in argv[4:], 'qualification argv must bind the actual artifact manifest placeholder')
        actual_argv = [str(manifest_path.relative_to(root)) if v == '{artifact_manifest}' else v for v in argv]
        result = run_qualification([sys.executable, *actual_argv[1:]], root, command['timeout_seconds'])
        if result.returncode != 0 or result.stderr:
            require(False, 'fresh qualification failed: ' + command['name']
                    + '; exit=' + str(result.returncode)
                    + '; stderr tail (4096 bytes):\n' + diagnostic_tail(result.stderr, 4096)
                    + '\nstdout tail (4096 bytes):\n' + diagnostic_tail(result.stdout, 4096))
        value = strict_json(result.stdout)
        validate_check(value, command['name'], config, artifacts, root=root, verify_logs=True)
        outputs.append({'name': command['name'], 'command': command,
                        'receipt_sha256': sha(canonical(value)), 'stdout_sha256': sha(result.stdout), 'receipt': value})
    return outputs


def artifact_identity(root, manifest_path):
    relative = manifest_path.relative_to(root).as_posix()
    raw = safe_file(root, relative).read_bytes()
    manifest = strict_json(raw)
    artifacts = manifest.get('artifacts')
    expected = [('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'),
                ('walletd', 'walletd'), ('wallet', 'private-spend')]
    require(isinstance(artifacts, list) and len(artifacts) == 4
            and [(r.get('package'), r.get('binary')) for r in artifacts if isinstance(r, dict)] == expected,
            'exact four release artifacts required')
    require(isinstance(manifest.get('target_triple'), str) and manifest['target_triple'], 'artifact target required')
    require(manifest.get('cargo_lock_sha256') == LOCK, 'artifact proof lock identity differs')
    paths = [r.get('path') for r in artifacts]
    digests = [r.get('sha256') for r in artifacts]
    require(all(isinstance(p, str) for p in paths) and len(set(paths)) == 4
            and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in digests)
            and len(set(digests)) == 4, 'distinct artifact paths and SHA256s required')
    for artifact in artifacts:
        raw_artifact = safe_file(root, artifact['path']).read_bytes()
        require(type(artifact.get('size')) is int and artifact['size'] > 0
                and len(raw_artifact) == artifact['size'] and sha(raw_artifact) == artifact['sha256'],
                'artifact bytes differ: ' + artifact['binary'])
    return {'manifest_path': relative, 'artifact_manifest_sha256': sha(raw),
            'artifact_sha256': {r['binary']: r['sha256'] for r in artifacts},
            'target_triple': manifest['target_triple']}


def recheck_artifacts(root, manifest_path, receipt):
    actual = artifact_identity(root, manifest_path)
    require(all(actual[key] == receipt.get(key) for key in
                ('artifact_manifest_sha256', 'artifact_sha256', 'target_triple')),
            'artifact manifest or bytes changed during affected qualification')


def final_artifacts(root, config, manifest_path, min_free_gib):
    # Authenticate before importing or starting any executable. Change attribution only.
    require(load_config(root) == config, 'candidate config differs before execution')
    source_check(root, config); review_check(root, config)
    artifact_identity(root, manifest_path)
    path = safe_file(root, 'scripts/check_v011_release_successor.py')
    spec = importlib.util.spec_from_file_location('_combined_historical_executor', path)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    helper.CURRENT_SOURCE_KIND = KIND; helper.CURRENT_SCOPE = SCOPE; helper.CURRENT_NEW_VERSION = SOFTWARE_VERSION
    helper.CURRENT_RUNTIME_DELTAS['node/src/bin/native_node.rs'] = (None, sha(safe_file(root, 'node/src/bin/native_node.rs').read_bytes()))
    identity = strict_json(safe_file(root, 'config/v0113-release-successor.json').read_bytes())['current_identity']
    network = strict_json(safe_file(root, 'config/testnet/0.11/network-manifest.json').read_bytes())
    receipt = {'schema': 'hegemon.ntime-rolling.final-receipt.v1', 'software_version': SOFTWARE_VERSION, 'authorization_kind': KIND,
               'identity': identity, 'candidate_binding_sha256': binding(config),
               'source_inventory_sha256': config['source_inventory_sha256'], **BOUNDARIES}
    receipt = helper.artifact_gate(root, root, manifest_path, receipt, network, min_free_gib)
    receipt = helper.final_replay(root, manifest_path, receipt, min_free_gib)
    receipt['affected_checks'] = fresh_checks(root, config, receipt, manifest_path)
    recheck_artifacts(root, manifest_path, receipt)
    require(load_config(root) == config, 'candidate config changed during execution')
    source_check(root, config); review_check(root, config)
    receipt.update(status='PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE',
                   final_artifact_scope=SCOPE, affected_lifecycle_verified=True,
                   independent_source_review=config['independent_review'], **BOUNDARIES)
    return receipt

def validate_identity_smoke(smoke, identity):
    expected = {'node_rpc_version': 'Hegemon Native Node ' + SOFTWARE_VERSION,
                'wallet_cli_version': 'wallet ' + SOFTWARE_VERSION,
                'private_spend_cli_version': 'private-spend ' + SOFTWARE_VERSION,
                'walletd_version_cli': 'not implemented; artifact hash/source version checked',
                'height': 0, 'peers': 0, 'qualified_manifest': True,
                'owned_node_reaped': True, 'wrong_compiled_rules_manifest_rejected': True,
                'genesis': identity['genesis_hash']}
    require(isinstance(smoke, dict) and all(type(smoke.get(k)) is type(v) and smoke[k] == v
                for k, v in expected.items()), 'actual exact v0.11.5 isolated H0 identity tuple required')
    parameters = smoke.get('proof_parameters')
    expected_parameters = {'relation_id': RELATION_ID, 'relation_digest': RELATION,
                           'public_words': 86, 'max_proof_bytes': 171848,
                           'max_carrier_bytes': 177632, 'input_slots': 2,
                           'output_slots': 2, 'production_authorized': False}
    require(isinstance(parameters, dict) and all(type(parameters.get(k)) is type(v) and parameters[k] == v
                for k, v in expected_parameters.items()), 'actual H0 unchanged proof profile required')


def validate_final_receipt(receipt, manifest, manifest_digest, root=ROOT):
    config = load_config(root); source_check(root, config); review_check(root, config)
    require(isinstance(manifest, dict) and isinstance(receipt, dict), 'artifact/receipt objects required')
    require(receipt.get('schema') == 'hegemon.ntime-rolling.final-receipt.v1'
            and receipt.get('software_version') == SOFTWARE_VERSION
            and receipt.get('authorization_kind') == KIND and receipt.get('final_artifact_scope') == SCOPE
            and receipt.get('status') == 'PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE', 'ntime final receipt required')
    require(receipt.get('independent_source_review') == config['independent_review'], 'independent source review differs')
    require(receipt.get('candidate_binding_sha256') == binding(config)
            and receipt.get('source_inventory_sha256') == config['source_inventory_sha256'], 'ntime source receipt differs')
    require(all(receipt.get(k) is v for k, v in BOUNDARIES.items()), 'ntime receipt expanded authority')
    require(isinstance(manifest.get('artifacts'), list) and len(manifest['artifacts']) == 4
            and [(r.get('package'), r.get('binary')) for r in manifest['artifacts'] if isinstance(r, dict)] ==
                [('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'), ('walletd', 'walletd'), ('wallet', 'private-spend')]
            and manifest.get('cargo_lock_sha256') == LOCK, 'exact unchanged-lock final artifact set required')
    require(receipt.get('artifact_manifest_sha256') == manifest_digest
            and receipt.get('target_triple') == manifest['target_triple']
            and receipt.get('artifact_sha256') == {r['binary']: r['sha256'] for r in manifest['artifacts']}, 'ntime artifact identity differs')
    require(receipt.get('actual_new_binary_proof_verification') is True
            and receipt.get('current_binary_backend_artifacts_verified') is True
            and receipt.get('affected_lifecycle_verified') is True
            and [r.get('name') for r in receipt.get('affected_checks', [])] == list(CHECKS), 'actual proof/lifecycle evidence missing')
    for actual, command in zip(receipt['affected_checks'], config['qualification_commands'], strict=True):
        require(actual.get('command') == command and actual.get('receipt_sha256') == sha(canonical(actual.get('receipt')))
                and isinstance(actual.get('stdout_sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', actual['stdout_sha256']), 'affected command/receipt changed')
        validate_check(actual.get('receipt'), command['name'], config, receipt, root=root)
    helper_path = safe_file(root, 'scripts/check_v011_release_successor.py')
    spec = importlib.util.spec_from_file_location('_combined_final_proof_predicate', helper_path)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    helper.CURRENT_RUNTIME_DELTAS['node/src/bin/native_node.rs'] = (None, sha(safe_file(root, 'node/src/bin/native_node.rs').read_bytes()))
    require(receipt.get('current_binary_proof_verification', {}).get('target_triple') == manifest['target_triple'], 'proof receipt target differs')
    helper.validate_current_binary_proofs(receipt.get('current_binary_proof_verification'), receipt['artifact_sha256']['hegemon-node'], manifest_digest, RELATION, helper.CURRENT_FIXTURE_SHA256)
    identity = strict_json(safe_file(root, 'config/v0113-release-successor.json').read_bytes())['current_identity']
    require(receipt.get('identity') == identity, 'ntime identity differs')
    validate_identity_smoke(receipt.get('identity_smoke'), identity)
    return identity

@interruption_handlers()
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true'); mode.add_argument('--require-authorized', action='store_true')
    parser.add_argument('--artifact-manifest', type=Path); parser.add_argument('--require-final-artifact', action='store_true')
    parser.add_argument('--predecessor-root', type=Path, help='retained predecessor archive for inherited workflow attribution; base authenticated through pinned Git commit')
    parser.add_argument('--min-free-gib', type=int, default=4)
    args = parser.parse_args()
    try:
        config = load_config(ROOT); receipt = source_check(ROOT, config)
        if args.require_authorized:
            review_check(ROOT, config)
        require(not args.prepare or (args.artifact_manifest is None and not args.require_final_artifact), 'preparation cannot authorize final artifacts')
        require(not args.require_final_artifact or args.artifact_manifest is not None, 'final artifact manifest required')
        if args.artifact_manifest:
            require(args.require_authorized and args.require_final_artifact and args.min_free_gib >= 4, 'explicit final artifact authorization and disk reserve required')
            artifact = args.artifact_manifest.resolve(); require(artifact.is_relative_to(ROOT), 'artifact escapes source root')
            receipt = final_artifacts(ROOT, config, artifact, args.min_free_gib)
        print(json.dumps(receipt, sort_keys=True))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('ntime candidate: ' + str(error), file=sys.stderr); return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
