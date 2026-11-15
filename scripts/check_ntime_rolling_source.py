#!/usr/bin/env python3
"""Check v0.11.5 source preparation; never qualify artifacts or authorize activation.

This checks declared source identity and unchanged proof inputs. Rust and native
tests establish behavior and the rules-preimage hash; this checker does neither.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/ntime-rolling-v0115.json'
VERSION = '0.11.5'
COMBINED_HEIGHT = 18_660
TIME_HEIGHT = 28_860
CHAIN_ID = '7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49'
GENESIS = 'd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3'
BASELINE = 'ad77c8d564944972b6ae5e7cab26fcf500972aff'
MAX_SKEW_MS = 90_000
BOUNDARIES = {'release_artifacts_qualified', 'activation_authorized',
              'deployment_verified', 'physical_asic_qualified', 'mainnet_authorized'}


def _load_proof_helper():
    path = ROOT / 'scripts/check_combined_upgrade_candidate.py'
    spec = importlib.util.spec_from_file_location('_ntime_unchanged_proof_inputs', path)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load unchanged proof-input checker')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proof_helper = _load_proof_helper()
SourceError = proof_helper.CandidateError
require = proof_helper.require


def read(root: Path, name: str, maximum: int = 2 * 1024 * 1024) -> str:
    path = proof_helper.safe_file(root, name)
    require(path.stat().st_size <= maximum, 'source input exceeds size bound: ' + name)
    return path.read_text(encoding='utf-8')


def integer_constant(source: str, name: str, *, optional: bool = False) -> int:
    if optional:
        pattern = rf'^pub const {name}: Option<u64> = Some\(([0-9][0-9_]*)\);$'
    else:
        pattern = rf'^pub const {name}: u64 = ([0-9][0-9_]*);$'
    values = re.findall(pattern, source, flags=re.MULTILINE)
    require(len(values) == 1, 'missing or duplicate integer declaration: ' + name)
    return int(values[0].replace('_', ''))


def hash_constant(source: str, name: str) -> str:
    arrays = re.findall(rf'^pub const {name}: Hash32 = \[([^\]]*)\];$',
                        source, flags=re.MULTILINE)
    require(len(arrays) == 1, 'missing or duplicate hash declaration: ' + name)
    values = re.findall(r'0x([0-9a-f]{2})', arrays[0])
    remainder = re.sub(r'0x[0-9a-f]{2}|[\s,]', '', arrays[0])
    require(len(values) == 32 and not remainder, 'exact 32-byte hash required: ' + name)
    return ''.join(values)


def verify_source(root: Path = ROOT) -> dict:
    root = Path(root).resolve()
    config = proof_helper.strict_json(read(root, CONFIG, 64 * 1024))
    require(set(config) == {'schema', 'software_version', 'baseline_commit', 'network',
            'chain_id', 'genesis_hash', 'combined_activation_height',
            'ntime_activation_height', 'ntime_rules_hash', 'max_future_skew_ms',
            'planned_activation', 'estimate_observation', 'boundaries', 'specification'},
            'source-preparation config fields differ')
    require(config['schema'] == 'hegemon.ntime-rolling.source-preparation.v1'
            and config['software_version'] == VERSION
            and config['baseline_commit'] == BASELINE and config['network'] == 'pre-mainnet',
            'source-preparation software/network identity differs')
    require(config['chain_id'] == CHAIN_ID and config['genesis_hash'] == GENESIS,
            'pre-mainnet chain or genesis identity differs')
    boundaries = config['boundaries']
    require(isinstance(boundaries, dict) and set(boundaries) == BOUNDARIES
            and all(value is False for value in boundaries.values()),
            'source preparation cannot grant release, activation, deployment, hardware or mainnet authority')
    planned = config['planned_activation']
    require(isinstance(planned, dict) and planned.get('planning_only') is True
            and planned.get('height_governs') is True,
            'activation date must remain planning-only; height governs')
    product = read(root, 'protocol/versioning/src/lib.rs')
    require(re.findall(r'^pub const RELEASE_VERSION: &str = "([^"\n]*)";$',
                       product, flags=re.MULTILINE) == [VERSION],
            'product version declaration differs')
    rules = read(root, 'consensus-light-client/src/pow_rules.rs')
    for field, name, expected in (
            ('combined_activation_height', 'PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT', COMBINED_HEIGHT),
            ('ntime_activation_height', 'PREMAINNET_TIME_ROLLING_ACTIVATION_HEIGHT', TIME_HEIGHT)):
        require(type(config[field]) is int and config[field] == expected
                and integer_constant(rules, name, optional=True) == expected,
                'source/config activation height differs: ' + field)
    require(hash_constant(rules, 'PREMAINNET_CHAIN_ID') == CHAIN_ID,
            'source pre-mainnet chain identity differs')
    profile_hash = hash_constant(rules, 'HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING')
    require(config['ntime_rules_hash'] == profile_hash and profile_hash != '00' * 32,
            'source/config time-rolling rules hash differs')
    reward = read(root, 'consensus/src/reward.rs')
    require(type(config['max_future_skew_ms']) is int
            and config['max_future_skew_ms'] == MAX_SKEW_MS
            and integer_constant(reward, 'MAX_FUTURE_SKEW_MS') == MAX_SKEW_MS,
            'future-skew bound differs')
    # Invoke only the unchanged relation inventory helper. The old candidate's
    # release tuple, authorization, frozen inventory and receipts are not reused.
    identity = proof_helper.proof_identity(root)
    return {'schema': 'hegemon.ntime-rolling.source-check.v1',
            'scope': 'source-preparation-only', 'software_version': VERSION,
            'chain_id': CHAIN_ID, 'genesis_hash': GENESIS,
            'combined_activation_height': COMBINED_HEIGHT,
            'ntime_activation_height': TIME_HEIGHT, 'ntime_rules_hash': profile_hash,
            'max_future_skew_ms': MAX_SKEW_MS,
            'proof_relation_digest': identity['relation_digest'],
            'proof_source_input_count': len(identity['source_inputs']),
            'cargo_lock_sha256': identity['cargo_lock_sha256'],
            'behavior_verified': False, 'rules_preimage_hash_verified': False,
            **{name: False for name in sorted(BOUNDARIES)}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify_source(args.root), sort_keys=True, separators=(',', ':')))
        return 0
    except (SourceError, OSError, ValueError, UnicodeError) as error:
        print('v0.11.5 source preparation: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
