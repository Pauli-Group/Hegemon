#!/usr/bin/env python3
"""Install pinned Linux x86_64 tools and build the local HTLC contracts."""
import argparse, hashlib, json, os, platform, subprocess, tarfile, time, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ASSETS={
 'foundry':('https://github.com/foundry-rs/foundry/releases/download/v1.8.7/foundry_v1.8.7_linux_amd64.tar.gz','ba470eb718e779e4b0e3f1520b5284231b1bf98e9a39de07fb8f77ed70525bcf', {'anvil':'foundry/anvil','cast':'foundry/cast','forge':'foundry/forge'}),
 'aiken':('https://github.com/aiken-lang/aiken/releases/download/v1.1.24/aiken-x86_64-unknown-linux-musl.tar.gz','c378acccdaf9533f3375ea623c948d3dcb21f7e8c5ecbb741162c53653470b13',{'aiken-x86_64-unknown-linux-musl/aiken':'aiken/aiken-x86_64-unknown-linux-musl/aiken'}),
 'cardano':('https://github.com/IntersectMBO/cardano-node/releases/download/11.1.3/cardano-node-11.1.3-linux-amd64.tar.gz','530fb99986fbdccc46f9ee0dd86cabb1393b015feac9173cb731d89fa748365f',{'./bin/cardano-node':'cardano/bin/cardano-node','./bin/cardano-cli':'cardano/bin/cardano-cli','./bin/cardano-testnet':'cardano/bin/cardano-testnet'}),
 'solc':('https://github.com/ethereum/solidity/releases/download/v0.8.30/solc-static-linux','f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7',{})}

def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tools',type=Path,default=Path(os.environ.get('HEGEMON_CHAIN_TOOLS') or Path.home()/'.local/opt/chain-tools'));p.add_argument('--verify-only',action='store_true');a=p.parse_args()
 if platform.system()!='Linux' or platform.machine()!='x86_64':raise SystemExit('This tool manifest requires Linux x86_64')
 a.tools.mkdir(parents=True,exist_ok=True);manifest={}
 for name,(url,sha,members) in ASSETS.items():
  archive=a.tools/(name+'.tar.gz' if members else name)
  if not archive.exists() or digest(archive)!=sha:
   if a.verify_only:raise SystemExit('Missing or changed tool archive: '+str(archive))
   tmp=archive.with_name(archive.name+'.part')
   for attempt in range(4):
    try:urllib.request.urlretrieve(url,tmp);break
    except OSError:
     if attempt==3:raise
     time.sleep(1+attempt)
   if digest(tmp)!=sha:raise SystemExit('Downloaded tool checksum mismatch: '+name)
   tmp.replace(archive)
  if members:
   with tarfile.open(archive,'r:gz') as tar:
    for member,target in members.items():
     data=tar.extractfile(member).read();dest=a.tools/target
     if dest.exists() and digest(dest)==hashlib.sha256(data).hexdigest():continue
     if a.verify_only:raise SystemExit('Missing or changed tool executable: '+str(dest))
     dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);dest.chmod(0o755)
  else:archive.chmod(0o755)
  manifest[name]={'url':url,'sha256':sha,'executable_sha256':{target:digest(a.tools/target) for target in members.values()}}
 (a.tools/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 if not a.verify_only:
  subprocess.run([a.tools/'foundry/forge','build','--root',ROOT/'contracts/ethereum','--use',a.tools/'solc'],check=True)
  subprocess.run([a.tools/'aiken/aiken-x86_64-unknown-linux-musl/aiken','build',ROOT/'contracts/cardano'],check=True)
 print('Pinned tools verified'+(' and contracts built' if not a.verify_only else ''))
if __name__=='__main__':main()
