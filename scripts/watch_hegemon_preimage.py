#!/usr/bin/env python3
"""Save a confirmed local Hegemon claim preimage as an encrypted backup."""
import argparse
import getpass
import hmac
import json
import os
from pathlib import Path
from hegemon_preimage_observer import observe_hegemon_preimage
from unlock_swap_backup import save_recovered_backup


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hegemon-rpc',required=True);p.add_argument('--hegemon-manifest',type=Path,required=True);p.add_argument('--hegemon-genesis',required=True)
    p.add_argument('--hashlock',required=True);p.add_argument('--start-height',type=int,required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--confirmations',type=int,default=2);p.add_argument('--timeout',type=int,default=120)
    a=p.parse_args();os.umask(0o077)
    if not os.isatty(0):p.error('an interactive local terminal is required')
    print('Observe only your trusted, peerless Hegemon Development node. Confirmations are not finality; a revealed preimage may remain public after rollback.',flush=True)
    if input('Type OBSERVE to continue: ').strip()!='OBSERVE':raise ValueError('observation declined locally')
    secret=None;buffers=[]
    try:
        secret,snapshot=observe_hegemon_preimage(a.hegemon_rpc,manifest=a.hegemon_manifest,genesis=a.hegemon_genesis,hashlock=a.hashlock,start_height=a.start_height,confirmations=a.confirmations,timeout=a.timeout)
        first=getpass.getpass('New separate encrypted backup passphrase: ');second=getpass.getpass('Repeat encrypted backup passphrase: ')
        if len(first)<12 or len(first)>1024 or not hmac.compare_digest(first.encode(),second.encode()):raise ValueError('backup passphrases must match and contain at least 12 characters')
        phrase=bytearray(first.encode());buffers.append(phrase);del first,second
        path=save_recovered_backup(a.output_dir,secret,phrase,label='Observed Hegemon claim')
        print(json.dumps({'saved':str(path),'hashlock':a.hashlock,'snapshot':snapshot,'note':'Import this encrypted backup into the local board; check the chain independently.'}),flush=True)
    finally:
        if secret is not None:secret[:]=b'\0'*len(secret)
        for item in buffers:item[:]=b'\0'*len(item)

if __name__=='__main__':main()
