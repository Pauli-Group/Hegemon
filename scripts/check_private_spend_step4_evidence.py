#!/usr/bin/env python3
"""Bounded, read-only inventory audit; never a Step4 qualification checker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_FILES = 2048
MAX_BYTES = 64 * 1024 * 1024
MAX_JSON = 8 * 1024 * 1024
MAX_DEPTH = 24
MAX_REFERENCES = 8192
MAX_TOTAL_BYTES = 256 * 1024 * 1024
FREEZE = '.agent/private-spend-local-freeze-20261005.json'
HASH = re.compile(r'^[0-9a-fA-F]{64}$')
SOURCE_KEYS = {'source', 'destination', 'target', 'integrated_source'}


def open_exact(path):
    """Open every path component without following links, including ancestors."""
    parts = Path(path).parts
    if not Path(path).is_absolute() or '..' in parts:
        raise ValueError('absolute path without parent traversal required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)


def pathlike(value):
    return isinstance(value, str) and '/' in value and not any(c.isspace() for c in value) and not value.startswith('-') and '://' not in value


def references(value, pointer='$', depth=0):
    """Yield only explicit paths; never turn an unbound digest into a path."""
    if depth > MAX_DEPTH:
        raise ValueError('metadata depth limit exceeded')
    if isinstance(value, list):
        for i, child in enumerate(value):
            yield from references(child, f'{pointer}[{i}]', depth + 1)
    elif isinstance(value, dict):
        command = value.get('command', [])
        if isinstance(command, list):
            for i, arg in enumerate(command):
                if not pathlike(arg):
                    continue
                expected = value.get('output_olean_sha256') if i and command[i-1] == '-o' else None
                if i == len(command)-1 and arg.endswith('.lean'):
                    expected = value.get('source_sha256', expected)
                yield f'{pointer}.command[{i}]', arg, expected, 'command_file'
        for key, child in sorted(value.items()):
            ref = f'{pointer}.{key}'
            if pathlike(key) and isinstance(child, str) and HASH.fullmatch(child):
                yield ref, key, child, 'file_hash_map'
            elif isinstance(child, str) and (key == 'path' or key.endswith('_path') or key in SOURCE_KEYS or key.endswith('_receipt')):
                stem = key[:-5] if key.endswith('_path') else key
                expected = value.get(stem + '_sha256')
                if key == 'path':
                    expected = value.get('sha256')
                elif key in SOURCE_KEYS:
                    expected = value.get('source_sha256', value.get('sha256', expected))
                yield ref, child, expected, 'explicit_file'
            elif key in {'lean_path_roots'} and isinstance(child, list):
                for i, item in enumerate(child):
                    if isinstance(item, str):
                        yield f'{ref}[{i}]', item, None, 'directory_reference'
            if key != 'command':
                yield from references(child, ref, depth + 1)


def audit(root, receipt=None):
    root = Path(os.path.abspath(root))
    rows, documents, unbound, errors = [], [], [], []
    cache, parsed = {}, set()
    total_bytes = 0

    def inspect(raw, expected, origin, pointer, role):
        nonlocal total_bytes
        row = {'metadata': origin, 'pointer': pointer, 'path': raw, 'role': role}
        if expected is not None:
            row['expected_sha256'] = expected
        candidate = Path(raw)
        if '..' in candidate.parts or not raw or '\x00' in raw:
            row['status'] = 'REJECTED_PATH'
            rows.append(row)
            return None
        candidate = candidate if candidate.is_absolute() else root / candidate
        name = str(candidate)
        row['resolved_path'] = name
        row['inside_source_root'] = candidate.is_relative_to(root)
        if name not in cache:
            if len(cache) >= MAX_FILES:
                cache[name] = ('FILE_LIMIT', None, None)
            else:
                try:
                    fd = open_exact(candidate)
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        os.close(fd)
                        cache[name] = ('AVAILABLE_DIRECTORY' if stat.S_ISDIR(info.st_mode) else 'NOT_REGULAR', None, None)
                    elif info.st_size > MAX_BYTES or total_bytes + info.st_size > MAX_TOTAL_BYTES:
                        os.close(fd)
                        cache[name] = ('SIZE_LIMIT', None, None)
                    else:
                        with os.fdopen(fd, 'rb') as stream:
                            data = stream.read(MAX_BYTES + 1)
                            total_bytes += len(data)
                            if len(data) > MAX_BYTES:
                                cache[name] = ('SIZE_LIMIT', None, None)
                            else:
                                cache[name] = ('AVAILABLE', hashlib.sha256(data).hexdigest(), data if candidate.suffix == '.json' and len(data) <= MAX_JSON else None)
                except FileNotFoundError:
                    cache[name] = ('MISSING', None, None)
                except (OSError, ValueError):
                    cache[name] = ('REJECTED_OR_UNREADABLE', None, None)
        status, digest, data = cache[name]
        if expected is not None:
            if not isinstance(expected, str) or not HASH.fullmatch(expected):
                status = 'INVALID_DESCRIPTOR'
            elif status == 'AVAILABLE':
                status = 'HASH_MATCH' if digest == expected.lower() else 'HASH_MISMATCH'
            elif status == 'AVAILABLE_DIRECTORY':
                status = 'NOT_REGULAR'
        row['status'] = status
        if digest:
            row['actual_sha256'] = digest
        if role == 'frozen_source':
            row['source_kind'] = 'documentation' if candidate.suffix == '.md' else 'runtime_or_formal_source'
        rows.append(row)
        return (name, data) if data is not None and status in {'AVAILABLE', 'HASH_MATCH'} else None

    def read_metadata(raw, expected=None, origin='<entry>', pointer='$', role='metadata', depth=0):
        if len(rows) >= MAX_REFERENCES:
            if not any(e.get('error') == 'reference limit' for e in errors):
                errors.append({'error': 'reference limit'})
            return
        result = inspect(str(raw), expected, origin, pointer, role)
        if result is None:
            return
        name, data = result
        if name in parsed:
            return
        if depth > MAX_DEPTH:
            errors.append({'path': name, 'error': 'metadata recursion limit'})
            return
        parsed.add(name)
        status, digest, _ = cache[name]
        cache[name] = (status, digest, None)
        try:
            obj = json.loads(data)
            if not isinstance(obj, dict):
                raise ValueError('metadata must be an object')
            documents.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'historical_claims': {k: obj[k] for k in ('schema', 'status', 'qualification_status', 'production_authorized', 'qualification_gates_closed', 'security_gates_closed', 'boundary', 'claim_boundary', 'limitations', 'meaning') if k in obj}})
            if role == 'freeze' and (not isinstance(obj.get('source_files'), list) or not obj['source_files']):
                errors.append({'path': name, 'error': 'freeze source_files absent or empty'})
            if role == 'freeze':
                if not isinstance(obj.get('ignored_cli_source'), dict) or not isinstance(obj['ignored_cli_source'].get('path'), str):
                    errors.append({'path': name, 'error': 'freeze ignored_cli_source missing or invalid'})
                for item in obj.get('source_files', []):
                    if not isinstance(item, dict) or not isinstance(item.get('path'), str) or not HASH.fullmatch(str(item.get('sha256', ''))):
                        errors.append({'path': name, 'error': 'invalid frozen source descriptor'})
            refs = list(references(obj))
            if len(refs) > MAX_REFERENCES:
                errors.append({'path': name, 'error': 'reference limit'})
                refs = refs[:MAX_REFERENCES]
            for ptr, path, pin, refrole in refs:
                if '.source_files[' in ptr:
                    refrole = 'frozen_source'
                    if pin is None:
                        errors.append({'path': name, 'error': 'frozen source lacks hash', 'pointer': ptr})
                elif '.ignored_cli_source.' in ptr:
                    refrole = 'ignored_cli_source'
                    if pin is None:
                        errors.append({'path': name, 'error': 'ignored CLI lacks hash'})
                read_metadata(path, pin, name, ptr, refrole, depth + 1)
            # Unbound hashes are historical claims; do not guess file locations.
            def hashes(node, ptr='$'):
                if isinstance(node, dict):
                    for k, v in sorted(node.items()):
                        if isinstance(v, str) and (k.endswith('_sha256') or k == 'sha256' or HASH.fullmatch(v)):
                            if not any(pin == v for _, _, pin, _ in refs):
                                unbound.append({'metadata': name, 'pointer': ptr + '.' + k, 'sha256': v})
                        elif isinstance(v, (dict, list)):
                            hashes(v, ptr + '.' + k)
                elif isinstance(node, list):
                    for i, v in enumerate(node):
                        hashes(v, f'{ptr}[{i}]')
            hashes(obj)
        except (ValueError, RecursionError) as exc:
            errors.append({'path': name, 'error': str(exc)})

    read_metadata(receipt or root / FREEZE, role='freeze')
    # One bounded directory listing; never walk the source tree or evidence roots.
    agent_dir = root / '.agent'
    try:
        fd = open_exact(agent_dir)
        try:
            names = sorted(n for n in os.listdir(fd) if n.startswith('private-spend-') and n.endswith('.json'))
        finally:
            os.close(fd)
        if len(names) > MAX_FILES:
            errors.append({'path': str(agent_dir), 'error': 'metadata listing limit'})
        else:
            for name in names:
                if name != Path(FREEZE).name:
                    read_metadata(agent_dir / name)
    except (OSError, ValueError):
        errors.append({'path': str(agent_dir), 'error': 'metadata directory unavailable or unsafe'})
    rows.sort(key=lambda r: (r['metadata'], r['pointer'], r['path']))
    counts = {}
    for row in rows:
        counts[row['status']] = counts.get(row['status'], 0) + 1
    failed = bool(errors or any(r['status'] not in {'AVAILABLE', 'AVAILABLE_DIRECTORY', 'HASH_MATCH'} for r in rows))
    return {'schema': 'hegemon.private-spend.step4-evidence-inventory.v1', 'source_root': str(root), 'inventory_status': 'INCOMPLETE_OR_CHANGED' if failed else 'REFERENCED_FILES_AVAILABLE', 'qualification_status': 'NOT_ESTABLISHED_BY_THIS_AUDIT', 'gates_passed_by_this_audit': 0, 'production_authorized': False, 'limits': {'files': MAX_FILES, 'references': MAX_REFERENCES, 'file_bytes': MAX_BYTES, 'total_bytes': MAX_TOTAL_BYTES, 'json_bytes': MAX_JSON, 'metadata_depth': MAX_DEPTH}, 'limitations': ['File availability and hash equality do not prove semantics, soundness, ZK, lifecycle, independent review, or release authority.', 'Metadata statuses and receipts are historical claims; no Lean, Rust, proof verifier, node, or lifecycle execution is performed.', 'Only explicit file references are opened; directories are observed without traversal; unbound hashes do not identify available evidence.', 'Relative paths resolve against source_root; explicitly named external files retain their original location and cannot substitute for the frozen source tree.', 'Missing or changed references require regeneration or independent reacquisition; this report is insufficient to close any qualification gate.'], 'summary': {'references': len(rows), 'unique_paths': len(cache), 'metadata_documents': len(documents), 'status_counts': dict(sorted(counts.items())), 'frozen_document_drift': [r['path'] for r in rows if r['role'] == 'frozen_source' and r.get('source_kind') == 'documentation' and r['status'] != 'HASH_MATCH'], 'frozen_runtime_or_formal_drift': [r['path'] for r in rows if r['role'] == 'frozen_source' and r.get('source_kind') != 'documentation' and r['status'] != 'HASH_MATCH']}, 'documents': sorted(documents, key=lambda r: r['path']), 'references': rows, 'unbound_hash_claims': sorted(unbound, key=lambda r: (r['metadata'], r['pointer'])), 'errors': sorted(errors, key=lambda r: json.dumps(r, sort_keys=True))}, 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--receipt', help='Explicit freeze receipt; default is the dated freeze under root')
    parser.add_argument('--output', required=True, help='Report destination, or - for stdout; must be outside source root')
    args = parser.parse_args(argv)
    if args.output != '-' and Path(os.path.abspath(args.output)).is_relative_to(Path(os.path.abspath(args.root))):
        parser.error('output must be outside the read-only source root')
    report, code = audit(args.root, args.receipt)
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output == '-':
        sys.stdout.write(encoded)
    else:
        dest = Path(os.path.abspath(args.output))
        parent_fd = open_exact(dest.parent)
        try:
            fd = os.open(dest.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        with os.fdopen(fd, 'w') as stream:
            stream.write(encoded)
    return code


if __name__ == '__main__':
    sys.exit(main())
