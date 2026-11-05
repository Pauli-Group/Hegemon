#!/usr/bin/env python3
"""Read-only checks for a trusted Hegemon v0.11.2 node over a private tunnel.

This does not open a tunnel, validate consensus, create a wallet or submit a
transaction. The optional public-tip check trusts the project's explorer as a
second observation; it is not an independent consensus or finality check.
"""
import argparse
import datetime
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / 'config/testnet/0.11/release.json'
MANIFEST = ROOT / 'config/testnet/0.11/network-manifest.json'
# Source-owned v0.11.2 pre-mainnet tuple in protocol/versioning/src/launch_candidate.rs.
RELATION = ('b9d22c2f0cb49df519b34620c138d7f2d74fa135a76c7b526cd73a60bb5cd6ce'
            'c2f910dde83b1a848684e123d02ab0bbc8bdb384b1bcaff1b489fd8794c14685')
MANIFEST_FIELDS = ('schema', 'profile', 'genesis_timestamp_ms', 'pow_bits',
                   'rules_hash', 'launch_reference_rules_hash', 'funding_address',
                   'funding_subsidy_numerator', 'funding_subsidy_denominator')
# The CLI fetches canonical action chunks when synchronizing its encrypted wallet.
REQUIRED = ('chain_getBlockHash', 'chain_getBlockActionsChunk', 'hegemon_latestBlock',
            'hegemon_nodeConfig', 'hegemon_privateSpendParameters', 'hegemon_submitAction')
PUBLIC_EXPLORER = 'https://hegemonprotocol.com'
MAX_TIP_GAP = 12
MAX_REFERENCE_AGE = 120
MAX_REFERENCE_FUTURE = 30
# A recently refreshed explorer response can still describe a stalled chain.
# This conservative testnet readiness heuristic is not a finality guarantee.
MAX_TIP_IDLE = 20 * 60
MAX_BLOCK_FUTURE = 120
HASH32 = re.compile(r'0x[0-9a-fA-F]{64}\Z')


def endpoint(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', '::1')
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('Use an existing private tunnel on a loopback IP HTTP URL')
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError('Invalid RPC port') from error
    if port is None or not 1 <= port <= 65535:
        raise ValueError('Specify the loopback RPC port')
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_json(path):
    """Read only a fixed explorer path through the configured HTTPS proxy."""
    if path != '/testnet/status.json' and not re.fullmatch(
            r'/testnet-api/v1/block/[0-9]{1,15}\?limit=1', path):
        raise ValueError('Invalid public explorer path')
    request = urllib.request.Request(PUBLIC_EXPLORER + path,
                                     headers={'accept': 'application/json'})
    # Keep the inherited HTTPS proxy and certificate verification; reject redirects.
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=15) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Public explorer response too large')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Invalid public explorer response')
    return value


def compare_public_tip(url, node, read=None, fetch=public_json, now=None):
    """Compare one local-node snapshot with the trusted public testnet explorer.

    Both sources are trusted; a matching block does not independently validate
    consensus or guarantee finality. No wallet or transaction data are sent.
    """
    if read is None:
        read = rpc
    url = endpoint(url)
    release = json.loads(RELEASE.read_text())
    if (not isinstance(node, dict) or type(node.get('height')) is not int or node['height'] < 1
            or node.get('genesis') != release.get('genesis_hash')
            or node.get('chain_id') != release.get('chain_id')):
        raise ValueError('Invalid local node height or network identity')
    status = fetch('/testnet/status.json')
    if (not isinstance(status, dict) or status.get('network') != 'pre-mainnet-v0.11'
            or status.get('genesis_hash') != node.get('genesis')
            or status.get('chain_id') != node.get('chain_id')):
        raise ValueError('Public explorer reports the wrong network')
    if (status.get('available') is not True or status.get('error') is not None
            or type(status.get('peers')) is not int or status['peers'] < 1):
        raise ValueError('Public explorer is unavailable or has no connected peers')
    if type(status.get('syncing')) is not bool:
        raise ValueError('Invalid public explorer sync status')
    height = status.get('height')
    reference_hash = status.get('hash')
    tip_timestamp = status.get('block_timestamp_ms')
    if (type(height) is not int or not 1 <= height < 10**15
            or not isinstance(reference_hash, str) or not HASH32.fullmatch(reference_hash)
            or type(tip_timestamp) is not int or not 0 < tip_timestamp < 2**53):
        raise ValueError('Invalid public explorer tip')
    updated = status.get('updated_at')
    current_time = time.time() if now is None else now
    try:
        if not isinstance(updated, str) or len(updated) > 64:
            raise ValueError
        stamp = datetime.datetime.fromisoformat(updated.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError
        age = current_time - stamp.timestamp()
    except (ValueError, OverflowError, OSError):
        raise ValueError('Invalid public explorer update time') from None
    if not -MAX_REFERENCE_FUTURE <= age <= MAX_REFERENCE_AGE:
        raise ValueError('Public explorer status is stale or has a future timestamp')
    tip_idle = current_time - tip_timestamp / 1000
    if tip_idle < -MAX_BLOCK_FUTURE:
        raise ValueError('Public explorer tip block has a future timestamp')
    problems = []
    if status['syncing']:
        problems.append('reports syncing')
    if tip_idle > MAX_TIP_IDLE:
        problems.append(f'latest block is {int(tip_idle)} seconds old (limit {MAX_TIP_IDLE})')
    if problems:
        raise ValueError('Public explorer ' + '; '.join(problems))
    gap = node['height'] - height
    if abs(gap) > MAX_TIP_GAP:
        raise ValueError(f'Node and public explorer differ by {abs(gap)} blocks')
    common = min(node['height'], height)
    local_hash = read(url, 'chain_getBlockHash', [common])
    block = fetch(f'/testnet-api/v1/block/{common}?limit=1').get('block')
    if (not isinstance(local_hash, str) or not HASH32.fullmatch(local_hash)
            or not isinstance(block, dict) or type(block.get('height')) is not int
            or block['height'] != common or not isinstance(block.get('hash'), str)
            or not HASH32.fullmatch(block['hash'])
            or type(block.get('timestamp_ms')) is not int
            or not 0 < block['timestamp_ms'] < 2**53):
        raise ValueError('Invalid common-height block response')
    if local_hash.lower() != block['hash'].lower():
        raise ValueError('Node and public explorer disagree on the common block hash')
    if common == height and reference_hash.lower() != block['hash'].lower():
        raise ValueError('Public explorer tip changed during comparison')
    if common == height and tip_timestamp != block['timestamp_ms']:
        raise ValueError('Public explorer tip timestamp changed during comparison')
    common_idle = current_time - block['timestamp_ms'] / 1000
    if common_idle < -MAX_BLOCK_FUTURE or common_idle > MAX_TIP_IDLE:
        raise ValueError('Common block timestamp is outside the recent testnet window')
    after = read(url, 'chain_getBlockHash', [common])
    if not isinstance(after, str) or after.lower() != local_hash.lower():
        raise ValueError('Local node reorganized during comparison')
    return {'checked': True, 'matches': True, 'node_height': node['height'],
            'reference_height': height, 'height_difference': gap,
            'common_height': common, 'common_hash': local_hash.lower(),
            'reference_updated_at': updated, 'max_tip_gap': MAX_TIP_GAP,
            'reference_block_timestamp_ms': tip_timestamp,
            'reference_block_age_seconds': round(tip_idle, 3),
            'common_block_timestamp_ms': block['timestamp_ms'],
            'common_block_age_seconds': round(common_idle, 3),
            'max_block_age_seconds': MAX_TIP_IDLE,
            'source': PUBLIC_EXPLORER}


def rpc(url, method, params):
    data = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
                      separators=(',', ':')).encode()
    request = urllib.request.Request(endpoint(url), data=data,
                                     headers={'content-type': 'application/json',
                                              'accept': 'application/json'})
    # Do not send loopback requests through an inherited proxy or follow redirects.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('RPC response too large')
    value = json.loads(raw)
    if (not isinstance(value, dict) or type(value.get('id')) is not int
            or value['id'] != 1 or 'error' in value or 'result' not in value):
        raise ValueError('RPC method failed: ' + method)
    return value['result']


def probe(url, read=rpc):
    url = endpoint(url)
    release = json.loads(RELEASE.read_text())
    manifest_bytes = MANIFEST.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != release.get('network_manifest_sha256'):
        raise ValueError('Local release manifest does not match its pinned digest')
    manifest = json.loads(manifest_bytes)
    # The native node serializes this structure in declared Rust field order.
    canonical = json.dumps({name: manifest[name] for name in MANIFEST_FIELDS},
                           ensure_ascii=False, separators=(',', ':')).encode()
    digest = '0x' + hashlib.sha512(b'hegemon.native.network-manifest.sha512.v1\0'
                                   + canonical).hexdigest()
    genesis = read(url, 'chain_getBlockHash', [0])
    config = read(url, 'hegemon_nodeConfig', [])
    if (not isinstance(config, dict) or genesis != release.get('genesis_hash')
            or config.get('networkProfile') != 'pre-mainnet'
            or config.get('chainId') != release.get('chain_id')
            or config.get('networkManifestDigest') != digest
            or config.get('networkManifest') != manifest):
        raise ValueError('Node does not match the pinned v0.11 pre-mainnet identity')

    health = read(url, 'system_health', [])
    methods = read(url, 'rpc_methods', [])
    available = methods.get('methods') if isinstance(methods, dict) else None
    if not isinstance(available, list) or not all(isinstance(x, str) for x in available):
        raise ValueError('Node did not report RPC methods')
    if (not isinstance(health, dict) or type(health.get('isSyncing')) is not bool
            or type(health.get('peers')) is not int or health['peers'] < 0):
        raise ValueError('Invalid node health response')
    header = read(url, 'chain_getHeader', [])
    number = header.get('number') if isinstance(header, dict) else None
    if not isinstance(number, str) or not re.fullmatch(r'0x[0-9a-fA-F]+', number):
        raise ValueError('Invalid node height')

    missing = [name for name in REQUIRED if name not in available]
    parameters_match = False
    if 'hegemon_privateSpendParameters' in available:
        parameters = read(url, 'hegemon_privateSpendParameters', [])
        parameters_match = (isinstance(parameters, dict)
                            and parameters.get('relation_digest') == RELATION
                            and type(parameters.get('action_id')) is int
                            and parameters['action_id'] == 15
                            and type(parameters.get('public_words')) is int
                            and parameters['public_words'] == 86
                            and type(parameters.get('ciphertext_bytes')) is int
                            and parameters['ciphertext_bytes'] == 2608)

    height = int(number, 16)
    return {'network': 'v0.11 pre-mainnet', 'genesis': genesis,
            'chain_id': config['chainId'], 'height': height,
            'syncing': health['isSyncing'], 'peers': health['peers'],
            'missing_wallet_methods': missing,
            'private_spend_parameters_match': parameters_match,
            'basic_wallet_checks_passed': (not missing and parameters_match and height > 0
                                           and not health['isSyncing'] and health['peers'] > 0),
            'limitation': 'Trust the node and private tunnel; the wallet must still validate '
                          'the source authority and actual chain data.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc', required=True,
                        help='private tunnel endpoint, e.g. http://127.0.0.1:19944')
    parser.add_argument('--check-public-tip', action='store_true',
                        help='compare height and a block hash with the trusted public explorer')
    args = parser.parse_args()
    report = probe(args.rpc)
    if args.check_public_tip:
        try:
            report['public_reference'] = compare_public_tip(args.rpc, report)
        except (OSError, ValueError, TypeError, KeyError) as error:
            report['public_reference'] = {'checked': True, 'matches': False,
                                          'error': str(error)[:300]}
        report['public_testnet_ready'] = (report['basic_wallet_checks_passed']
                                          and report['public_reference']['matches'])
        report['limitation'] += (' The public explorer is a second trusted observation; '
                                 'matching snapshots do not prove consensus or finality.')
    print(json.dumps(report, indent=2))
    passed = report['public_testnet_ready'] if args.check_public_tip else report['basic_wallet_checks_passed']
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
