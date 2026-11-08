#!/usr/bin/env python3
"""Freeze exact candidate bytes against a supplied reviewed path allowlist.

This records source preparation only. It never creates review/qualification
receipts or changes pending production, activation or hardware authority.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('combined_candidate', ROOT / 'scripts/check_combined_upgrade_candidate.py')
gate = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(gate)

def freeze(root, allowed, debt_paths=()):
    config = gate.load_config(root)
    gate.require(config['status'] == 'pending', 'already frozen; prepare an explicitly reviewed new candidate before refreezing')
    gate.require(isinstance(allowed, list) and allowed and allowed == sorted(set(allowed))
                 and all(isinstance(p, str) and gate.owned(p) for p in allowed), 'sorted exact reviewed path allowlist required')
    tree = gate.authenticate(root); current = gate.inventory(root); changes = []
    for item in current:
        path = item['path']; data = gate.safe_file(root, path).read_bytes()
        oid = gate.hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if path in tree and oid == tree[path][1] and item['mode'] == tree[path][0]:
            continue
        before = gate.sha(gate.git(root, 'show', gate.BASE + ':' + path)) if path in tree else None
        changes.append({'path': path, 'before_sha256': before, 'after_sha256': item['sha256'], 'bytes': item['bytes'], 'before_mode': tree[path][0] if path in tree else None, 'after_mode': item['mode']})
    gate.require([r['path'] for r in changes] == allowed, 'observed delta differs from exact reviewed allowlist')
    config.update(status='frozen', source_inventory=current, source_inventory_sha256=gate.sha(gate.canonical(current)), reviewed_delta=changes)
    baseline = gate.strict_json(gate.safe_file(root, 'config/qualified-formatting-baseline.json').read_bytes())
    prior_debt = {r['path'] for r in baseline['files']}
    gate.require(list(debt_paths) == sorted(set(debt_paths)) and set(debt_paths) <= prior_debt,
                 'formatting exceptions must name only exact existing predecessor debt paths')
    changed = {r['path']: r for r in changes}
    gate.require(set(debt_paths) <= set(changed), 'formatting migration must be an actual reviewed changed path')
    config['formatting_debt_migrations'] = [changed[p] for p in debt_paths]
    gate.validate_config(config); gate.source_check(root, config)
    return config

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-paths',type=Path,required=True)
    p.add_argument('--formatting-debt-paths',type=Path,help='optional separately reviewed exact changed predecessor debt paths; new debt paths always reject')
    p.add_argument('--write',action='store_true',help='write frozen source configuration; independent review remains unset')
    a=p.parse_args()
    try:
        allowed=json.loads(a.allow_paths.read_text());debt=json.loads(a.formatting_debt_paths.read_text()) if a.formatting_debt_paths else []
        config=freeze(ROOT,allowed,debt)
        if a.write:
            (ROOT/gate.CONFIG).write_text(json.dumps(config,indent=2,sort_keys=True)+'\n')
        print(json.dumps({'status':'FROZEN_SOURCE_ONLY' if a.write else 'CHECKED_FREEZE_INPUTS',
                          'candidate_binding_sha256':gate.binding(config),
                          'source_inventory_sha256':config['source_inventory_sha256'],
                          'reviewed_paths':allowed,**gate.BOUNDARIES},sort_keys=True))
    except (OSError,ValueError,gate.CandidateError) as error:
        print('candidate freeze: '+str(error),file=sys.stderr);return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
