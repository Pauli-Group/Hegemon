"""Locate chain tool binaries without hard-coded /workspace paths.

Resolution order for a tool: the environment variable HEGEMON_TOOL_<NAME> (for
example HEGEMON_TOOL_ANVIL), then the tools directory, then PATH. The tools
directory is HEGEMON_CHAIN_TOOLS, else ~/.local/opt/chain-tools, else the legacy
/workspace/chain-tools. `scripts/setup_multichain_htlc_tools.py --tools DIR` fills it.
"""
import os
import shutil
from pathlib import Path

RELATIVE = {
    'anvil': ['foundry/anvil'],
    'forge': ['foundry/forge'],
    'cast': ['foundry/cast'],
    'solc': ['solc'],
    'cardano-cli': ['cardano/bin/cardano-cli'],
    'cardano-node': ['cardano/bin/cardano-node'],
    'cardano-testnet': ['cardano/bin/cardano-testnet'],
    'aiken': ['aiken/aiken-x86_64-unknown-linux-musl/aiken'],
    'ogmios': ['ogmios/bin/ogmios'],
    'bitcoind': ['bitcoin/bin/bitcoind', '../bitcoin-32.1/bin/bitcoind'],
    'bitcoin-cli': ['bitcoin/bin/bitcoin-cli', '../bitcoin-32.1/bin/bitcoin-cli'],
}
EXTRA = {'aiken': [Path.home() / '.aiken/bin/aiken']}


def tools_directory():
    explicit = os.environ.get('HEGEMON_CHAIN_TOOLS')
    if explicit:
        return Path(explicit)
    for candidate in (Path.home() / '.local/opt/chain-tools', Path('/workspace/chain-tools')):
        if candidate.is_dir():
            return candidate
    return Path.home() / '.local/opt/chain-tools'


def find_tool(name):
    """Path of the tool or None."""
    override = os.environ.get('HEGEMON_TOOL_' + name.upper().replace('-', '_'))
    if override:
        path = Path(override)
        return path if path.is_file() else None
    base = tools_directory()
    for relative in RELATIVE.get(name, []):
        path = (base / relative).resolve()
        if path.is_file():
            return path
    for path in EXTRA.get(name, []):
        if path.is_file():
            return path
    found = shutil.which(name)
    return Path(found) if found else None


def tool(name):
    path = find_tool(name)
    if path is None:
        raise FileNotFoundError(f'Tool {name} not found; set HEGEMON_TOOL_{name.upper().replace("-", "_")} or HEGEMON_CHAIN_TOOLS, or run scripts/setup_multichain_htlc_tools.py --tools DIR')
    return path


def tool_default(name):
    """Argparse default: the located tool, else the bare name so the failure message names the tool."""
    return find_tool(name) or Path(name)


def missing(*names):
    """Names of the tools that cannot be found; empty when all are present."""
    return [name for name in names if find_tool(name) is None]


def skip_unless_tools(*names):
    """unittest decorator: skip with an explicit message naming each missing tool and how to supply it, never pass silently."""
    import unittest
    absent = missing(*names)
    reason = ('missing tool(s): ' + ', '.join(absent) + '; set HEGEMON_TOOL_<NAME> or HEGEMON_CHAIN_TOOLS, '
              'or run scripts/setup_multichain_htlc_tools.py --tools DIR (Bitcoin Core: unpack to DIR/bitcoin)') if absent else ''
    return unittest.skipIf(bool(absent), reason)


def main(argv=None):
    """`python3 -m swap_engine.tools [NAME ...]`: print where each tool resolves; exit 3 if any named tool is missing."""
    import sys
    names = list(sys.argv[1:] if argv is None else argv) or sorted(RELATIVE)
    for name in names:
        print(f'{name:16} {find_tool(name) or "MISSING"}')
    absent = missing(*names)
    if absent:
        print('missing: ' + ', '.join(absent) + ' (set HEGEMON_TOOL_<NAME> or HEGEMON_CHAIN_TOOLS, or run scripts/setup_multichain_htlc_tools.py --tools DIR)', file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
