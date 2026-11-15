#!/usr/bin/env python3
"""v0.11.5 process-ownership successor to immutable current-proof verification.

All five proof cases, thirty negatives, fixture/source/artifact checks and proof
predicates remain the historical implementation. Only run_command is replaced.
The receipt explicitly identifies both historical logic and the new ownership
executor; no historical runner attribution is relabeled as new execution.
"""
from __future__ import annotations
import argparse
import hashlib
import types
import json
import os
from pathlib import Path
import re
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = 'scripts/check_v011_current_binary_proofs.py'
HISTORICAL_SHA256 = 'd2f0fae819828482093676f831a5d6c621013c02368cdddafcdf491d294eb2f2'
OWNER = 'scripts/v0115_process_ownership.py'
WRAPPER = 'scripts/check_v0115_current_binary_proofs.py'
CONFIG = 'config/ntime-rolling-candidate-v0115.json'
SCHEMA = 'hegemon.v0115.current-proof-execution-harness.v1'
CONTRACT = 'creation-time-windows-job-list-or-posix-session-v1'


class HarnessError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise HarnessError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_file(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute()
            and all(v not in ('', '.', '..') for v in relative.split('/')), 'canonical source path required')
    path = root
    for part in relative.split('/'):
        path /= part
        require(not path.is_symlink() and not (getattr(path.lstat(), 'st_file_attributes', 0) & 0x400),
                'linked/reparse source input rejected: ' + relative)
    require(path.is_file(), 'regular source file required: ' + relative)
    return path


def strict_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value): raise HarnessError('non-finite JSON constant: ' + value)
    value = json.loads(path.read_bytes(), object_pairs_hook=unique, parse_constant=constant)
    require(isinstance(value, dict), 'JSON object required')
    return value


def import_source(path, name, expected_sha256):
    # -B disables cache writes, not cache reads. Execute only the very source
    # bytes whose digest is checked here, never an existing timestamp/hash pyc.
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'pre-import source bytes changed: ' + str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path); module.__package__ = ''; module.__cached__ = None
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def frozen_sources(root):
    config = strict_json(source_file(root, CONFIG))
    require(config.get('schema') == 'hegemon.ntime-rolling.candidate.v1' and config.get('status') == 'frozen',
            'frozen v0.11.5 source contract required before importing execution helpers')
    rows = config.get('source_inventory')
    require(isinstance(rows, list), 'complete frozen source inventory required')
    expected = {}
    for name in (HISTORICAL, WRAPPER, OWNER):
        selected = [row for row in rows if isinstance(row, dict) and row.get('path') == name]
        require(len(selected) == 1 and set(selected[0]) == {'path', 'bytes', 'sha256', 'mode'},
                'exact source-owned execution harness pin required: ' + name)
        row = selected[0]
        require(type(row['bytes']) is int and row['bytes'] > 0 and isinstance(row['sha256'], str)
                and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'invalid frozen execution harness pin')
        path = source_file(root, name)
        require(path.stat().st_size == row['bytes'] and digest(path) == row['sha256'],
                'execution harness differs from frozen pre-import source pin: ' + name)
        expected[name] = row['sha256']
    require(expected[HISTORICAL] == HISTORICAL_SHA256, 'historical proof helper authority differs')
    require(isinstance(config.get('source_inventory_sha256'), str)
            and re.fullmatch('[0-9a-f]{64}', config['source_inventory_sha256']), 'frozen inventory digest required')
    return config, expected


def load_modules(root):
    # Expected hashes come from the prior frozen contract, never from the same
    # current file being imported. Historical proof code has a second fixed pin.
    config, pins = frozen_sources(root)
    historical = import_source(source_file(root, HISTORICAL), '_v0115_immutable_proof_logic', pins[HISTORICAL])
    owner = import_source(source_file(root, OWNER), '_v0115_current_process_ownership', pins[OWNER])
    return historical, owner, config, pins


def validate_ownership(value, windows):
    expected = {'schema': 'hegemon.v0115.process-ownership.v1',
                'backend': 'windows-creation-job-list' if windows else 'posix-session-process-group',
                'owned_before_execution': True, 'processes_reaped': True, 'active_processes_after': 0,
                'stdio_handle_allowlist': True, 'stdout_limit_bytes': 65536, 'stderr_limit_bytes': 65536,
                'reader_threads_joined': True}
    if windows:
        expected.update(kill_on_close=True, creation_time_job_association=True,
                        suspended_primary_thread_retained=True, exact_job_membership_checked_before_resume=True,
                        resume_prior_suspend_count=1, job_handle_inherited=False)
    require(isinstance(value, dict) and set(value) == set(expected) | {'accounting'}
            and all(type(value.get(k)) is type(v) and value[k] == v for k, v in expected.items()),
            'exact typed per-run process ownership required')
    accounting = value['accounting']
    if windows:
        require(isinstance(accounting, dict) and set(accounting) == {'total_processes', 'active_processes', 'terminated_processes'}
                and all(type(v) is int for v in accounting.values()) and accounting['total_processes'] == 1
                and accounting['active_processes'] == accounting['terminated_processes'] == 0,
                'successful Windows proof job must contain one process and be fully drained')
    else:
        require(isinstance(accounting, dict) and set(accounting) == {'active_processes'}
                and type(accounting['active_processes']) is int and accounting['active_processes'] == 0,
                'successful POSIX process group must be empty')


def validate_harness(receipt, root=ROOT):
    config, pins = frozen_sources(root)
    harness = receipt.get('execution_harness') if isinstance(receipt, dict) else None
    windows = 'windows' in receipt.get('target_triple', '')
    expected = {'schema': SCHEMA, 'contract': CONTRACT, 'historical_proof_logic_sha256': HISTORICAL_SHA256,
                'wrapper_path': WRAPPER, 'process_owner_path': OWNER,
                'runtime_platform': 'windows' if windows else 'posix',
                'source_inventory_sha256': config['source_inventory_sha256'], 'source_pins': pins,
                'source_inputs_before': pins, 'source_inputs_after': pins,
                'historical_run_command_replaced': True, 'proof_predicates_unchanged': True,
                'actual_owned_runs': 35, 'all_runs_owned_and_reaped': True}
    require(isinstance(harness, dict) and set(harness) == set(expected)
            and all(type(harness.get(k)) is type(v) and harness[k] == v for k, v in expected.items()),
            'exact new process execution harness attribution required')
    cases = receipt.get('cases')
    require(isinstance(cases, list) and len(cases) == 5, 'five process-owned proof cases required')
    total = 0
    for case in cases:
        require(isinstance(case, dict) and isinstance(case.get('negative_controls'), dict)
                and len(case['negative_controls']) == 6, 'six owned negative controls required per proof')
        for execution in (case, *case['negative_controls'].values()):
            require(isinstance(execution, dict), 'owned execution row required')
            validate_ownership(execution.get('process_ownership'), windows)
            total += 1
    require(total == 35, 'exact thirty-five owned verification runs required')
    return harness


def execute(args, root=ROOT):
    root = Path(root).resolve()
    historical, owner, config, pins = load_modules(root)
    historical.ROOT = root
    historical.run_command = owner.run_command  # The only historical behavior replaced.
    receipt = historical.execute(args)
    after_config, after_pins = frozen_sources(root)
    require(after_config == config and after_pins == pins, 'frozen execution harness changed during proof verification')
    receipt['execution_harness'] = {'schema': SCHEMA, 'contract': CONTRACT,
        'historical_proof_logic_sha256': HISTORICAL_SHA256, 'wrapper_path': WRAPPER,
        'process_owner_path': OWNER, 'runtime_platform': 'windows' if os.name == 'nt' else 'posix',
        'source_inventory_sha256': config['source_inventory_sha256'], 'source_pins': pins,
        'source_inputs_before': pins, 'source_inputs_after': after_pins,
        'historical_run_command_replaced': True, 'proof_predicates_unchanged': True,
        'actual_owned_runs': 35, 'all_runs_owned_and_reaped': True}
    validate_harness(receipt, root)
    output = Path(args.output) / 'receipt.json'
    output.write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-bin', required=True, type=Path)
    parser.add_argument('--artifact-manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--fixture-manifest', type=Path, default=ROOT / 'release-evidence/v0.11-current-proof-fixture/manifest.json')
    parser.add_argument('--timeout-seconds', type=int, default=180)
    parser.add_argument('--min-free-gib', type=int, default=4)
    args = parser.parse_args()
    try:
        require(1 <= args.timeout_seconds <= 600 and args.min_free_gib >= 4, 'bounded timeout and disk reserve required')
        print(json.dumps(execute(args), sort_keys=True))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('v0.11.5 owned current proof verifier: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
