#!/usr/bin/env python3
"""Read-only checks for a trusted Hegemon v0.11.2 node over a private tunnel.

This does not open a tunnel, validate consensus, create a wallet or submit a
transaction. A successful report does not replace the wallet's own checks.
"""
import argparse
import hashlib
import json
import re
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
    report = probe(parser.parse_args().rpc)
    print(json.dumps(report, indent=2))
    return 0 if report['basic_wallet_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
