#!/usr/bin/env python3
"""Interface check for a scoped Hegemon swap gateway (DESIGN.md, "Hegemon remote gateway").

A gateway is a trusted-but-limited front for a Hegemon node: it must serve exactly the read methods the
private-spend wallet's `sync`/`verify-htlc` path needs plus the single write method `hegemon_submitAction`, and
nothing else. This check reuses `probe_hegemon_testnet.probe` (network identity, wallet parameters, required
methods) and then refuses a gateway that:

- lists any method outside the allow-list in `rpc_methods` (mining control, wallet scanning that takes a viewing
  key, proof generation, ciphertext/witness submission, storage reads, peer graphs, ...);
- answers an unknown method with anything but a JSON-RPC error;
- is missing a method the wallet needs.

It never calls an unsafe method (calling `hegemon_startMining` on a node that wrongly exposes it would start
mining), never submits an action and never sends a key. Pass `--rpc` for a loopback URL or a private tunnel;
a remote gateway is reached through a tunnel exactly as for the probe. This is an interface check, not a
deployment and not evidence that the node behind the gateway is honest.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_hegemon_testnet as probe_module  # noqa: E402

READ_METHODS = ('chain_getBlockHash', 'chain_getHeader', 'chain_getBlockActionsChunk', 'hegemon_latestBlock',
                'hegemon_nodeConfig', 'hegemon_privateSpendParameters', 'system_health', 'rpc_methods')
WRITE_METHODS = ('hegemon_submitAction',)
ALLOWED = frozenset(READ_METHODS + WRITE_METHODS)
# Methods the wallet CLI itself calls beyond the probe's required set; a gateway may omit them only if the wallet
# commands that need them are documented as unsupported.
OPTIONAL = frozenset({'chain_getHeader', 'system_health', 'rpc_methods'})
UNKNOWN_SENTINEL = 'hegemon_gatewayInterfaceCheckUnknownMethod'


def probe_unknown(url, read):
    """True when an unknown method is answered with a JSON-RPC error rather than a result."""
    try:
        read(url, UNKNOWN_SENTINEL, [])
    except ValueError as error:
        return 'RPC method failed' in str(error)
    except OSError:
        return False
    return False


def check_gateway(url, read=probe_module.rpc, probe=probe_module.probe):
    """Return a report; `interface_ok` is true only when every check passes."""
    report = probe(url, read)
    methods = read(url, 'rpc_methods', [])
    listed = methods.get('methods') if isinstance(methods, dict) else None
    if not isinstance(listed, list) or not all(isinstance(m, str) for m in listed):
        raise ValueError('Gateway did not report RPC methods')
    extra = sorted(set(listed) - ALLOWED)
    missing = sorted((ALLOWED - OPTIONAL) - set(listed))
    unknown_is_error = probe_unknown(url, read)
    problems = []
    if extra:
        problems.append('exposes methods outside the gateway allow-list: ' + ', '.join(extra))
    if missing:
        problems.append('missing required methods: ' + ', '.join(missing))
    if not unknown_is_error:
        problems.append('an unknown method did not return a JSON-RPC error')
    if not report.get('private_spend_parameters_match'):
        problems.append('private-spend parameters do not match the pinned relation')
    return {'interface_ok': not problems, 'problems': problems, 'allowed_methods': sorted(ALLOWED), 'extra_methods': extra,
            'missing_methods': missing, 'unknown_method_rejected': unknown_is_error, 'probe': report,
            'limitation': 'Interface and identity only. The gateway and its node are trusted for liveness and for not '
                          'withholding data; the wallet still verifies escrows from canonical block data.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc', required=True, help='loopback or tunnel endpoint of the gateway, e.g. http://127.0.0.1:19944')
    args = parser.parse_args(argv)
    try:
        report = check_gateway(args.rpc)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({'interface_ok': False, 'problems': [str(error)[:300]]}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['interface_ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
