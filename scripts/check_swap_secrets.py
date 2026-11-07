#!/usr/bin/env python3
"""Scan the files git would commit for swap-series secrets: private keys, WIF and extended keys, preimage or key hex
assigned to a secret-looking name, long signed-transaction hex and literal passphrases.

Usage: python3 scripts/check_swap_secrets.py [--all] [PATH ...]

By default it looks at the swap-related paths of `git ls-files --cached --others --exclude-standard`, so ignored files
(`hidden/`, `tools/user-sim/`, build output, local stores) are never read. Exit status 1 when anything outside the
allowlist is found. Matches print the file, line, rule and the first characters only, never the whole value.

The allowlist holds values that are public by construction: the official BIP-322 test key, repeated-byte vectors,
throwaway keys of the test wallets, and spent testnet transactions whose preimage is already on chain. Anything added
here needs a reason.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SWAP_PATHS = re.compile(
    r'^(scripts/|swap-ui/|swap-service/|config/swap/|contracts/|docs/SWAP|runbooks/|\.github/|\.cursor/|\.agent/(SWAP|ETHEREUM|LOCAL|MULTI|PUBLIC|HOSTED|HEGEMON)|'
    r'[A-Z_]*RESULTS\.md$|DESIGN\.md$|METHODS\.md$|CHANGELOG\.md$|Makefile$|\.nvmrc$)')

RULES = {
    'private-key-block': re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    'extended-private-key': re.compile(r'\b[xt]prv[1-9A-HJ-NP-Za-km-z]{50,}'),
    'wif-key': re.compile(r'\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b'),
    'secret-hex': re.compile(r'(?i)(priv(?:ate)?[_ -]?key|secret|preimage|mnemonic|seed)["\']?\s*[:=]\s*["\']?(?:0x)?([0-9a-f]{64})(?![0-9a-f])'),
    'signed-transaction-hex': re.compile(r'(?<![0-9a-fA-F])0[12]000000[0-9a-f]{300,}'),
    'literal-passphrase': re.compile(r'(?i)(?:passphrase|password|passwd)["\']?\s*[:=]\s*["\']([^"\'\s,()]{8,})["\']'),
}

# (path regexp, rule) pairs that are known and intended.
ALLOW_FILES = [
    (r'^scripts/make_identity_vectors\.py$', 'wif-key'),          # official BIP-322 test vector key from bitcoin/bips
    (r'^swap-ui/test-wallets\.mjs$', None),                        # throwaway test wallets, no value anywhere
    (r'^scripts/test_check_swap_secrets\.py$', None),             # deliberately contains one sample of every rule
    (r'^swap-ui/fixtures/[0-9a-f]{64}\.cbor\.hex$', None),         # spent public testnet transactions; preimage already on chain
]


def repeated_bytes(value):
    """A value made of one or two distinct bytes is a test pattern, not a secret."""
    return len({value[i:i + 2] for i in range(0, len(value), 2)}) <= 2


def candidate_files(paths, everything):
    if paths:
        return [str(Path(p)) for p in paths]
    out = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    names = [name for name in out.splitlines() if name]
    return names if everything else [name for name in names if SWAP_PATHS.match(name)]


def allowed(name, rule):
    return any(re.match(pattern, name) and (only is None or only == rule) for pattern, only in ALLOW_FILES)


def scan_text(name, text):
    """Findings for one file's text: a list of (line, rule, preview)."""
    findings = []
    for rule, pattern in RULES.items():
        if allowed(name, rule):
            continue
        for match in pattern.finditer(text):
            if rule == 'secret-hex' and repeated_bytes(match.group(2).lower()):
                continue
            if rule == 'wif-key' and not re.search(r'[0-9]', match.group(0)):
                continue  # an identifier, not a key: real WIF text always contains digits
            if rule == 'literal-passphrase' and (match.group(1).lower() in {'passphrase', 'password', 'secret'} or match.group(1).startswith('<')):
                continue
            findings.append((text.count('\n', 0, match.start()) + 1, rule, match.group(0)[:24]))
    return findings


def scan(paths=(), everything=False, root=ROOT):
    results = []
    for name in candidate_files(list(paths), everything):
        path = Path(name) if Path(name).is_absolute() else root / name
        try:
            if path.stat().st_size > 3_000_000:
                continue
            text = path.read_text(errors='ignore')
        except OSError:
            continue
        for line, rule, preview in scan_text(name, text):
            results.append((name, line, rule, preview))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--all', action='store_true', help='scan every file git would commit, not only swap-related paths')
    parser.add_argument('paths', nargs='*')
    args = parser.parse_args(argv)
    findings = scan(args.paths, args.all)
    for name, line, rule, preview in findings:
        print(f'{name}:{line}: {rule}: {preview}…')
    if findings:
        print(f'{len(findings)} possible secret(s); fix them or, if public by construction, add a reasoned allowlist entry', file=sys.stderr)
        return 1
    print('no swap-series secrets found')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
