#!/usr/bin/env python3
"""Real private-spend HTLC swaps with fresh local Ethereum or Cardano chains."""
import argparse, hashlib, json, os, re, subprocess, time
from pathlib import Path
from local_private_spend_swap import ROOT, PASS, HANDOFF, SECRET, wallet, mine, port, stop, require
from release_private_spend_lifecycle_io import rpc, height, chunks
from htlc_counterpart import Ethereum, Cardano, TOOLS

def scenario(a, name):
    d=a.output/name; d.mkdir(mode=0o700)
    rec={'scenario':name,'status':'running','counterpart_chain':a.chain,'hegemon_seeds':'',
         'production_authorized':False,'proofs':{},'checks':{}}
    node=counterpart=None; handle=None
    phrase=os.urandom(24).hex().encode(); hp=os.urandom(24).hex().encode()
    (d/'wallet.pass').write_bytes(phrase+b'\n')
    (d/'handoff.pass').write_bytes(hp+b'\n')
    rec['source_commit']=subprocess.check_output(['git','-C',ROOT,'rev-parse','HEAD'],text=True).strip()
    rec['binary_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (a.node,a.wallet)}
    wallets={n:d/(n+'.store') for n in ('alice','bob','treasury')}
    def call(n, command, extra=(), label=None, expected=True, offline=False):
        argv=['--wallet',wallets[n]]
        if not offline: argv += ['--manifest',d/'manifest.json','--genesis',genesis,'--rpc',url,'--development-local-candidate']
        return wallet(a.wallet,[*argv,*command],[(PASS,phrase),*extra],d,label or (n+'-'+command[0]),expected)
    try:
        addresses={}
        for n in wallets:
            out,_=call(n,['bootstrap-new'],[(b'Confirm encrypted wallet passphrase: ',phrase)],offline=True)
            addresses[n]=json.loads(out.splitlines()[-1])['address']
        manifest=json.loads(subprocess.check_output([a.node,'--print-development-candidate-manifest','--development-funding-address',addresses['treasury']]))
        require(manifest['development_candidate']['private_spend_only'], 'manifest must select private-spend')
        manifest['pow_bits']=0x207fffff
        (d/'manifest.json').write_text(json.dumps(manifest,indent=2))
        rec['wallet_proof_threads']=2
        rec['relation_digest']=manifest['development_candidate']['private_spend_source']['relation_digest']
        rp, pp=port(),port(); url=f'http://127.0.0.1:{rp}'
        env={k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_')}
        env.update(HEGEMON_MINER_ADDRESS=addresses['alice'],HEGEMON_SEEDS='',HEGEMON_MINE='0',HEGEMON_BOOTSTRAP_AUTHORING='1',RAYON_NUM_THREADS='2',RUST_LOG='warn')
        handle=(d/'node.log').open('wb')
        node=subprocess.Popen([a.node,'--dev','--network','development','--network-manifest',d/'manifest.json','--development-candidate','--base-path',d/'chain','--rpc-port',str(rp),'--rpc-methods','unsafe','--listen-addr',f'127.0.0.1:{pp}','--port',str(pp)],env=env,stdout=handle,stderr=subprocess.STDOUT,start_new_session=True)
        deadline=time.monotonic()+120
        while True:
            require(node.poll() is None,'node exited: '+str(d/'node.log'))
            try: genesis=rpc(url,'chain_getBlockHash',[0]); break
            except (OSError,RuntimeError):
                require(time.monotonic()<deadline,'node RPC unavailable'); time.sleep(.2)
        rec['genesis']=genesis
        for n in wallets: call(n,['sync'])
        print(name+': mining fresh Hegemon rewards',flush=True); mine(url,121)
        def notes(n,kind='ordinary'):
            text,_=call(n,['status'])
            return [(int(p),int(v)) for p,v in re.findall(r'^'+kind+r' position=(\d+) value=(\d+)',text,re.M)]
        def prepare(n, command, extra=(), label=None):
            label=label or command[0]
            print(name+': proving '+label,flush=True)
            text,metrics=call(n,command,extra,label)
            attempt=re.search(r'candidate ([0-9a-f]{64})',text).group(1)
            rec['proofs'][label]=metrics
            call(n,['export',attempt,d/(label+'.action')],label=label+'-export')
            raw=(d/(label+'.action')).read_bytes()
            before=height(url)
            call(n,['submit',attempt],label=label+'-submit')
            mine(url,before+1)
            actions,_,_=chunks(url,rpc(url,'chain_getBlockHash',[before+1]))
            require(raw in actions,label+' bytes absent from canonical block')
            text,_=call(n,['status'],label=label+'-included')
            require(re.search(attempt+r' .*mined=Some',text),label+' not marked mined')
            rec['checks'][label+'_canonical']=True
            return before+1
        # Give Bob a native fee note before locking Alice's other mature reward.
        prepare('alice',['ordinary','--inputs',str(notes('alice')[0][0]),'--recipient',addresses['bob'],'--amount','10000','--fee','1'],label='fund-bob')
        timeout=height(url)+16; secret=os.urandom(32); hashed=hashlib.sha256(secret).hexdigest()
        lock_height=prepare('alice',['lock','--inputs',str(notes('alice')[0][0]),'--claim',addresses['bob'],'--refund',addresses['alice'],'--hashlock',hashed,'--timeout',str(timeout),'--amount','100000','--fee','1','--release-secret','--refund-handoff',d/'refund.bin'],[(HANDOFF,hp)])
        call('alice',['import-refund-handoff',d/'refund.bin','--block-height',str(lock_height),'--refund-index','0'],[(HANDOFF,hp)])
        locked=notes('bob','htlc')[0][0]
        call('alice',['refund','--locked',str(locked),'--fee-input',str(notes('alice')[0][0]),'--recipient',addresses['alice'],'--fee','1'],label='early-refund',expected=False)
        rec['checks']['early_refund_rejected']=True
        print(name+': starting fresh '+a.chain+' chain',flush=True)
        counterpart=({'ethereum':Ethereum,'cardano':Cardano}[a.chain])(d/a.chain,a.tools)
        counterpart.isolated()
        revealed=None
        if name!='no_counterparty':
            counterpart.lock(bytes.fromhex(hashed))
            if name in ('happy','late_claim'):
                revealed=counterpart.claim(secret)
                require(hashlib.sha256(revealed).hexdigest()==hashed,'confirmed counterpart hashlock mismatch')
            else:
                counterpart.refund()
        if name=='happy':
            prepare('bob',['claim','--locked',str(locked),'--fee-input',str(notes('bob')[0][0]),'--recipient',addresses['bob'],'--fee','1'],[(SECRET,revealed.hex().encode())])
            require(any(v==100000 for p,v in notes('bob')), 'Bob did not receive locked HGN')
        else:
            mine(url,timeout)
            prepare('alice',['refund','--locked',str(locked),'--fee-input',str(notes('alice')[0][0]),'--recipient',addresses['alice'],'--fee','1'])
            require(any(v==100000 for p,v in notes('alice')), 'Alice did not recover HGN')
            if name=='late_claim':
                call('bob',['claim','--locked',str(locked),'--fee-input',str(notes('bob')[0][0]),'--recipient',addresses['bob'],'--fee','1'],[(SECRET,revealed.hex().encode())],label='late-claim',expected=False)
                rec['checks']['late_claim_rejected']=True
        counterpart.isolated()
        rec['counterpart']=counterpart.receipt
        require(rpc(url,'system_health')['peers']==0,'Hegemon acquired a peer')
        rec['checks']['zero_peers']=True; rec['status']='passed'
        rec['hegemon_final_height']=height(url)
        rec['counterpart_data']=str(d/a.chain)
        return rec
    except Exception as e:
        rec['status']='failed'; rec['error']=str(e); raise
    finally:
        if counterpart is not None:
            rec['counterpart']=counterpart.receipt
            counterpart.close()
        stop(node)
        if handle: handle.close()
        rec['owned_nodes_stopped']=True
        (d/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chain',choices=['ethereum','cardano'],required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--scenario',choices=['all','happy','no_counterparty','both_refund','late_claim'],default='all')
    p.add_argument('--node',type=Path,default=ROOT/'target/release/hegemon-node')
    p.add_argument('--wallet',type=Path,default=ROOT/'target/release/private-spend')
    p.add_argument('--tools',type=Path,default=TOOLS)
    a=p.parse_args();a.output=a.output.resolve();os.umask(0o077)
    a.output.mkdir(mode=0o700,exist_ok=False)
    cases=['happy','no_counterparty','both_refund','late_claim'] if a.scenario=='all' else [a.scenario]
    results=[]
    try:
        for name in cases:
            results.append(scenario(a,name))
    finally:
        (a.output/'summary.json').write_text(json.dumps({'chain':a.chain,'status':'passed' if len(results)==len(cases) else 'failed','scenarios':results},indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(a.output/'summary.json')}),flush=True)

if __name__=='__main__':main()
