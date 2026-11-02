#!/usr/bin/env python3
"""Save an observed local Cardano claim preimage as an encrypted browser backup."""
import argparse
import getpass
import hmac
import json
import os
from pathlib import Path
from cardano_preimage_observer import observe_local_preimage
from unlock_swap_backup import save_recovered_backup


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ogmios-url',required=True);p.add_argument('--ogmios-pid',type=int,required=True)
    p.add_argument('--cardano-node-pid',type=int,required=True);p.add_argument('--cardano-socket',type=Path,required=True)
    p.add_argument('--cardano-network-dir',type=Path,required=True);p.add_argument('--cardano-genesis',required=True)
    p.add_argument('--checkpoint-slot',type=int,required=True);p.add_argument('--checkpoint-hash',required=True)
    p.add_argument('--outref',required=True);p.add_argument('--hashlock',required=True);p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--confirmations',type=int,default=2);p.add_argument('--timeout',type=int,default=120)
    a=p.parse_args();os.umask(0o077)
    if not os.isatty(0):p.error('an interactive local terminal is required')
    print('Observe only your trusted, peerless local Cardano node. Confirmations are not finality; a revealed preimage may remain public after rollback.',flush=True)
    if input('Type OBSERVE to continue: ').strip()!='OBSERVE':raise ValueError('observation declined locally')
    secret=None;buffers=[]
    try:
        secret,snapshot=observe_local_preimage(url=a.ogmios_url,ogmios_pid=a.ogmios_pid,node_pid=a.cardano_node_pid,node_socket=a.cardano_socket,network_dir=a.cardano_network_dir,genesis_hash=a.cardano_genesis,checkpoint={'slot':a.checkpoint_slot,'id':a.checkpoint_hash},outref=a.outref,hashlock=a.hashlock,confirmations=a.confirmations,timeout=a.timeout)
        first=getpass.getpass('New separate encrypted backup passphrase: ');second=getpass.getpass('Repeat encrypted backup passphrase: ')
        if len(first)<12 or len(first)>1024 or not hmac.compare_digest(first.encode(),second.encode()):raise ValueError('backup passphrases must match and contain at least 12 characters')
        phrase=bytearray(first.encode());buffers.append(phrase);del first,second
        path=save_recovered_backup(a.output_dir,secret,phrase)
        print(json.dumps({'saved':str(path),'hashlock':a.hashlock,'snapshot':snapshot,'note':'Import this encrypted backup into the local board; check the chain independently.'}),flush=True)
    finally:
        if secret is not None:secret[:]=b'\0'*len(secret)
        for item in buffers:item[:]=b'\0'*len(item)

if __name__=='__main__':main()
