#!/usr/bin/env python3
"""Pinned rustfmt with exact eec3bb14 debt and separately reviewed migrations.

New formatting-debt paths always reject. A changed old debt file requires an
explicit source-bound formatting_debt_migrations row, not only a runtime delta.
Historical formatting files and baseline are never edited.
"""
from __future__ import annotations
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);out=importlib.util.module_from_spec(spec);spec.loader.exec_module(out);return out
gate=module(ROOT/'scripts/check_combined_upgrade_candidate.py','combined_formatting_gate')

def policy(root):
    config=gate.load_config(root);gate.source_check(root,config)
    gate.require(config['status']=='frozen','formatting requires frozen candidate source; preparation remains diagnostic while pending')
    old=module(gate.safe_file(root,'scripts/check_qualified_formatting.py'),'combined_original_formatting')
    baseline=old.load_baseline(gate.safe_file(root,old.BASELINE))
    changed={r['path']:r for r in config['reviewed_delta']}
    migrations={r['path']:r for r in config['formatting_debt_migrations']}
    gate.require(len(migrations)==len(config['formatting_debt_migrations']) and set(migrations)<=set(baseline),'new or duplicate formatting debt migration rejected')
    for path,item in migrations.items():
        gate.require(item==changed.get(path),'formatting migration is not exact reviewed delta')
    inherited={}
    for path in baseline:
        data=gate.git(root,'show',gate.BASE+':'+path)
        predecessor=gate.sha(data)
        if path not in changed:
            inherited[path]=predecessor
        elif path in migrations:
            gate.require(migrations[path]['before_sha256']==predecessor,'formatting predecessor differs')
            inherited[path]=migrations[path]['after_sha256']
        # A changed file without an explicit debt migration is absent; rustfmt
        # success passes, any formatting failure is new/unreviewed and rejects.
    old.REVIEWED_SOURCE_MIGRATIONS=[]
    return old,inherited

def run(root,manifest):
    old,baseline=policy(root)
    version=subprocess.run(['cargo','+1.91.1','fmt','--version'],cwd=root,capture_output=True,text=True,timeout=60)
    gate.require(version.returncode==0 and not version.stderr and version.stdout.strip()==old.RUSTFMT_VERSION,'pinned rustfmt differs')
    argv=['cargo','+1.91.1','fmt']
    if old.MANIFESTS[manifest]:argv+=['--manifest-path',old.MANIFESTS[manifest]]
    argv+=['--all','--','--check','--color','never']
    result=subprocess.run(argv,cwd=root,capture_output=True,text=True,timeout=180)
    old.verify_failures(root,old.parse_failure(root,result.returncode,result.stdout,result.stderr),baseline)
    policy(root)
    print('Combined candidate formatting: PASS; unchanged predecessor debt and explicit exact migrations only')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',choices=('workspace','htlc','proof-backend'),default='workspace');a=p.parse_args()
    try:run(ROOT,a.manifest)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        print('Combined formatting rejected: '+str(error),file=sys.stderr);return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
