#!/usr/bin/env python3
"""Run unchanged Clippy coverage with two exact proof-source padding exceptions.

Only reversed_empty_ranges is downgraded to a warning for machine inspection.
Every occurrence except the two hash-pinned empty padding ranges rejects the run;
all other correctness/suspicious errors and Cargo failures remain blocking.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LINT = 'clippy::reversed_empty_ranges'
MAX_LINE = 4 * 1024 * 1024
DENY = ['-D', 'clippy::correctness', '-D', 'clippy::suspicious',
        '-D', 'unused_must_use', '-D', 'unsafe_op_in_unsafe_fn']
EXCEPTIONS = {
    'circuits/transaction/src/private_spend_packed_poseidon.rs': {
        'sha256': '17fe979a0f052cfb474ad71e12e04c0c41ac5a6d296a0798edab609371cbc833',
        'line': 83, 'column_start': 17, 'column_end': 41,
        'byte_start': 3841, 'byte_end': 3865, 'text': 'LIVE_CALLS..PADDED_CALLS'},
    'circuits/transaction/src/smallwood_htlc/packed_poseidon_lowering.rs': {
        'sha256': 'ec8312b4eff08d8e0e0b4f07420595fabc3b1a05abd0003ed7fb80b9620891d6',
        'line': 98, 'column_start': 21, 'column_end': 29,
        'byte_start': 3735, 'byte_end': 3743, 'text': '128..128'},
}

class Rejected(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Rejected(message)

def pinned_sources(root):
    result = {}
    for relative, expected in EXCEPTIONS.items():
        path = root
        for part in Path(relative).parts:
            path = path / part
            require(not path.is_symlink(), 'linked padding source: ' + relative)
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected['sha256'],
                'qualified padding source changed: ' + relative)
        require(raw[expected['byte_start']:expected['byte_end']] == expected['text'].encode(),
                'padding range source binding differs: ' + relative)
        result[relative] = raw
    return result

def validate_exception(root, diagnostic, sources):
    require(diagnostic.get('level') == 'warning', 'padding lint must remain a checked warning')
    spans = diagnostic.get('spans')
    require(isinstance(spans, list), 'padding diagnostic lacks spans')
    primary = [span for span in spans if span.get('is_primary') is True]
    require(len(primary) == 1, 'padding diagnostic must have one exact primary range')
    span = primary[0]
    require(isinstance(span.get('file_name'), str), 'padding diagnostic lacks source path')
    path = Path(span['file_name'])
    path = (path if path.is_absolute() else root / path).resolve()
    try:
        relative = path.relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise Rejected('padding diagnostic escapes source checkout') from error
    require(relative in EXCEPTIONS and relative in sources, 'new empty/reversed range: ' + relative)
    expected = EXCEPTIONS[relative]
    wanted = {'line_start': expected['line'], 'line_end': expected['line'],
              'column_start': expected['column_start'], 'column_end': expected['column_end'],
              'byte_start': expected['byte_start'], 'byte_end': expected['byte_end']}
    require(all(type(span.get(key)) is int and span[key] == value for key, value in wanted.items()),
            'empty/reversed range span differs: ' + relative)
    require(span.get('expansion') is None, 'macro-generated padding diagnostic rejected')
    require(sources[relative][span['byte_start']:span['byte_end']] == expected['text'].encode(),
            'empty/reversed range text differs: ' + relative)

def inspect_message(root, message, sources):
    require(isinstance(message, dict), 'malformed compiler diagnostic')
    code = message.get('code')
    if isinstance(code, dict) and code.get('code') == LINT:
        validate_exception(root, message, sources)
    require(message.get('level') not in ('error', 'failure-note', 'ice'),
            'blocking compiler diagnostic remains')
    children = message.get('children', [])
    require(isinstance(children, list), 'malformed compiler child diagnostics')
    for child in children:
        inspect_message(root, child, sources)

def cargo_command(arguments):
    require(arguments and '--all-targets' in arguments, 'unchanged all-targets coverage required')
    require('--' not in arguments and not any(arg.startswith('--message-format') for arg in arguments),
            'wrapper owns compiler flags and JSON format')
    require(all(arg in ('-p', '--all-targets') or not arg.startswith('-') for arg in arguments),
            'only package selection and all-targets arguments are accepted')
    packages = []
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        if arg == '--all-targets':
            index += 1
            continue
        require(arg == '-p' and index + 1 < len(arguments) and not arguments[index + 1].startswith('-'),
                'malformed package selection')
        packages.append(arguments[index + 1]); index += 2
    require(packages and len(packages) == len(set(packages)), 'distinct selected packages required')
    return ['cargo', 'clippy', '--message-format=json', *arguments, '--', *DENY, '-W', LINT]

def run(root, arguments):
    command = cargo_command(arguments)
    sources = pinned_sources(root)
    rejected = False
    finished = False
    with subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE) as process:
        assert process.stdout is not None
        while True:
            raw = process.stdout.readline(MAX_LINE + 1)
            if not raw:
                break
            try:
                require(len(raw) <= MAX_LINE, 'Clippy JSON record exceeds memory bound')
                row = json.loads(raw)
                require(isinstance(row, dict) and isinstance(row.get('reason'), str), 'non-Cargo JSON output')
                if row['reason'] == 'compiler-message':
                    diagnostic = row.get('message')
                    if isinstance(diagnostic, dict) and isinstance(diagnostic.get('rendered'), str):
                        print(diagnostic['rendered'], end='', file=sys.stderr)
                    inspect_message(root, diagnostic, sources)
                elif row['reason'] == 'build-finished':
                    require(not finished, 'duplicate Cargo completion record')
                    finished = True
                    require(row.get('success') is True, 'Cargo reported a failed build')
                else:
                    require(row['reason'] in ('compiler-artifact', 'build-script-executed', 'future-incompat-report'),
                            'unexpected Cargo JSON record: ' + row['reason'])
            except (ValueError, TypeError, KeyError, AttributeError) as error:
                print('Clippy policy rejected: ' + str(error), file=sys.stderr)
                rejected = True
        code = process.wait()
    require(pinned_sources(root) == sources, 'qualified padding source changed during Clippy')
    if code:
        return code if code > 0 else 128 - code
    if not finished:
        print('Clippy policy rejected: missing Cargo completion record', file=sys.stderr)
        rejected = True
    return 1 if rejected else 0

def main():
    try:
        return run(ROOT, sys.argv[1:])
    except (OSError, ValueError) as error:
        print('Clippy policy rejected: ' + str(error), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
