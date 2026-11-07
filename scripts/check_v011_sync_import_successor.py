#!/usr/bin/env python3
"""Exact additive sync/import successor; inherited proof/H0 gates stay mandatory.

The historical checker and configuration remain immutable. Only two reviewed
runtime postimages and two new source paths specialize their source comparison.
Receipts retain distinct attribution and grant no current-network G8 authority.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/v011-sync-import-successor-20261106.json'
CONFIG_SHA256 = '9cc53dc52975d3f9cd5edd3caaaf11d971a77f773430b637377e64561aecd9d6'
PARENT_CHECKER = 'scripts/check_v011_release_successor.py'
PARENT_CHECKER_SHA256 = '390f5cbc69e877e29302db4af7b7382bbf6db9bdeccada01942ccba384b0fc67'
PARENT_CONFIG = 'config/v011-release-successor.json'
PARENT_CONFIG_SHA256 = '94bd9591a8232292d1928198b3d4778a27f7cc4c8fc560c0ff87ac3bfa22fadb'
KIND = 'reviewed_sync_import_successor_ci'
SCOPE = 'exact_sync_import_source_current_binary_backend_and_h0'
SOURCE_STATUS = 'PASS_EXACT_REVIEWED_SYNC_IMPORT_SOURCE_SUCCESSOR_ONLY'
FINAL_STATUS = 'PASS_EXACT_SYNC_IMPORT_SOURCE_CURRENT_BINARY_BACKEND_AND_H0'
OVERLAY = {
    'node/src/native/node_impl.rs': {'before_sha256': 'd1b451214cec69435049cce237e8863a84e62f0522038424091034bd30691fe6', 'after_sha256': 'c588a5dcc5987e2c3f94ca03fae643ae9425dcd0c3abe27f465f6961abbd0a65', 'bytes': 616181},
    'node/src/native/service.rs': {'before_sha256': '107b18ca430f3fb8dcebf407ed8c1d31d33f623139cce19504f79307a3af5ba3', 'after_sha256': '8c9593876583aa40c38a8d77362aeaa2c1eb390b9ac7edf7510d81af0f2750e6', 'bytes': 289968},
    'node/src/native/sync_control_backpressure_tests.rs': {'before_sha256': None, 'after_sha256': 'eda6eec5184fc7d01b7f31110e983bbe610b462f7bbbcd9a84ee8a15a65a57af', 'bytes': 17408},
    'node/src/native/service/sync_body_backpressure.rs': {'before_sha256': None, 'after_sha256': 'f78c7b4dcb1d6d3365b8e69c65c8bf3dbcaecd98e9df02015defc50824c8c3ab', 'bytes': 15808},
}


class SuccessorError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise SuccessorError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_file(root, relative):
    path = Path(relative)
    require(isinstance(relative, str) and not path.is_absolute() and path.parts
            and all(p not in ('.', '..') for p in path.parts)
            and path.as_posix() == relative, 'canonical relative file path required')
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), 'symlink rejected: ' + relative)
    require(current.is_file(), 'file missing: ' + relative)
    return current


def attribution():
    return {'schema': 'hegemon.release.sync-import-successor-binding.v1',
            'parent_checker': PARENT_CHECKER, 'parent_checker_sha256': PARENT_CHECKER_SHA256,
            'parent_config': PARENT_CONFIG, 'parent_config_sha256': PARENT_CONFIG_SHA256,
            'baseline_commit': 'e2fcbe4df99025d3b955d5053ebc1f21436db6f2',
            'overlay': copy.deepcopy(OVERLAY)}


def load_binding(root=ROOT, *, require_sources=True):
    # Authenticate executable bytes before import. No alternate checker argument.
    checker_path = safe_file(root, PARENT_CHECKER)
    require(digest(checker_path.read_bytes()) == PARENT_CHECKER_SHA256, 'immutable parent checker differs')
    parent_raw = safe_file(root, PARENT_CONFIG).read_bytes()
    require(digest(parent_raw) == PARENT_CONFIG_SHA256, 'immutable parent configuration differs')
    raw = safe_file(root, CONFIG).read_bytes()
    require(digest(raw) == CONFIG_SHA256, 'exact sync/import configuration differs')
    parent, config = json.loads(parent_raw), json.loads(raw)
    expected = copy.deepcopy(parent)
    expected['sync_import_successor'] = attribution()
    for path, row in OVERLAY.items():
        if row['before_sha256'] is None:
            require(path not in parent['reviewed_source_additions'], 'addition already exists in parent')
            expected['reviewed_source_additions'][path] = {'sha256': row['after_sha256'], 'bytes': row['bytes']}
        else:
            require(parent['reviewed_runtime_deltas'][path]['after_sha256'] == row['before_sha256'], 'parent postimage differs')
            expected['reviewed_runtime_deltas'][path]['after_sha256'] = row['after_sha256']
        if require_sources:
            source = safe_file(root, path).read_bytes()
            require(len(source) == row['bytes'] and digest(source) == row['after_sha256'], 'exact sync/import source postimage differs: ' + path)
    require(config == expected, 'configuration differs beyond exact sync/import overlay')
    spec = importlib.util.spec_from_file_location('_v011_sync_import_immutable_parent', checker_path)
    require(spec is not None and spec.loader is not None, 'cannot load pinned parent checker')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    # Specialize source constants only. The 598-file comparator, Cargo/network
    # guards, artifact executor and five proof/six-negative predicate are reused.
    helper.CONFIG = CONFIG
    helper.CURRENT_CONFIG_SHA256 = CONFIG_SHA256
    helper.CURRENT_RUNTIME_DELTAS = {p: (r['before_sha256'], r['after_sha256']) for p, r in config['reviewed_runtime_deltas'].items()}
    helper.CURRENT_SOURCE_ADDITIONS = copy.deepcopy(config['reviewed_source_additions'])
    helper.CURRENT_SOURCE_KIND = KIND
    helper.CURRENT_SCOPE = SCOPE
    return helper, config, parent


def source_gate(root, predecessor):
    helper, _, _ = load_binding(root)
    receipt, manifest = helper.current_source_gate(root, predecessor)
    receipt.update(status=SOURCE_STATUS, sync_import_successor=attribution())
    return helper, receipt, manifest


def project_parent_receipt(receipt, root=ROOT):
    """Validate new attribution, then adapt only source fields for old predicates.

    This detached object is never emitted as historical evidence. All binary,
    proof, H0, network, lifecycle and authority fields remain byte-for-byte data.
    """
    _, config, parent = load_binding(root, require_sources=False)
    expected = {'authorization_kind': KIND, 'status': FINAL_STATUS,
                'final_artifact_scope': SCOPE, 'source_successor_config_sha256': CONFIG_SHA256,
                'sync_import_successor': attribution(),
                'changed_paths': sorted(config['reviewed_runtime_deltas']),
                'added_source_paths': sorted(config['reviewed_source_additions']),
                'reviewed_runtime_deltas': config['reviewed_runtime_deltas'],
                'reviewed_source_additions': config['reviewed_source_additions']}
    require(isinstance(receipt, dict) and all(type(receipt.get(k)) is type(v) and receipt[k] == v for k, v in expected.items()), 'exact final sync/import source attribution required')
    projected = copy.deepcopy(receipt)
    projected.update(authorization_kind='reviewed_source_successor_ci',
                     status='PASS_EXACT_SOURCE_CURRENT_BINARY_BACKEND_AND_H0',
                     final_artifact_scope='exact_current_source_current_binary_backend_and_h0',
                     source_successor_config_sha256=PARENT_CONFIG_SHA256,
                     changed_paths=sorted(parent['reviewed_runtime_deltas']),
                     added_source_paths=sorted(parent['reviewed_source_additions']),
                     reviewed_runtime_deltas=copy.deepcopy(parent['reviewed_runtime_deltas']),
                     reviewed_source_additions=copy.deepcopy(parent['reviewed_source_additions']))
    del projected['sync_import_successor']
    return projected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-authorized', action='store_true')
    parser.add_argument('--predecessor-root', type=Path, default=ROOT / 'target/v011-predecessor')
    parser.add_argument('--artifact-manifest', type=Path)
    parser.add_argument('--require-final-artifact', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--min-free-gib', type=int, default=4)
    args = parser.parse_args()
    try:
        require(args.require_authorized, 'explicit --require-authorized intent required')
        require(args.min_free_gib >= 4, 'at least four GiB reserve required')
        require(not args.require_final_artifact or args.artifact_manifest is not None, 'final artifact phase requires an artifact manifest')
        require(args.predecessor_root.is_dir(), 'authenticated predecessor missing: run scripts/materialize_v011_predecessor.py explicitly before this gate')
        predecessor = args.predecessor_root.resolve(strict=True)
        require(predecessor != ROOT.resolve(), 'predecessor must be a separate immutable source tree')
        helper, receipt, manifest = source_gate(ROOT, predecessor)
        if args.artifact_manifest:
            artifact = args.artifact_manifest if args.artifact_manifest.is_absolute() else ROOT / args.artifact_manifest
            receipt = helper.artifact_gate(ROOT, predecessor, artifact, receipt, manifest, args.min_free_gib)
        if args.require_final_artifact:
            receipt = helper.final_replay(ROOT, artifact, receipt, args.min_free_gib)
            require(receipt.get('status') == 'PASS_EXACT_SOURCE_CURRENT_BINARY_BACKEND_AND_H0'
                    and receipt.get('final_artifact_scope') == SCOPE, 'inherited final proof/H0 verification did not complete')
            receipt['status'] = FINAL_STATUS
        output = json.dumps(receipt, sort_keys=True, indent=2) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output)
        print(output, end='')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError) as error:
        print('v0.11 sync/import successor rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
