#!/usr/bin/env python3
"""Fresh, peerless Development/private-spend and Bitcoin regtest swap scenarios."""
import argparse, fcntl, hashlib, json, os, pty, re, select, signal, socket
import subprocess, termios, time
from pathlib import Path
from development_atomic_swap_rehearsal import (
    BitcoinRPC, descriptor_checksum, rehearsal_bitcoin_key, spend_contract,
    confirmed_bitcoin_preimage, wait_bitcoin_confirmations,
)
from release_private_spend_lifecycle_io import rpc, height, chunks

ROOT = Path(__file__).resolve().parents[1]
PASS = b"Encrypted wallet passphrase: "
HANDOFF = b"Encrypted refund handoff passphrase: "
SECRET = b"Private 32-byte preimage (hex): "


def require(ok, message):
    if not ok: raise RuntimeError(message)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def stop(proc):
    if proc is None or proc.poll() is not None: return
    os.killpg(proc.pid, signal.SIGTERM)
    try: proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL); proc.wait()


def wallet(binary, args, secrets, directory, label, expected=True, timeout=600):
    """PTY secrets with echo disabled; wait4 records the actual child high-water RSS."""
    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave); attrs[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    def ctty():
        os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    env = {k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_')}
    env['RAYON_NUM_THREADS'] = os.environ.get('SWAP_PROVE_THREADS', '2')  # 2 is the conservative default
    proc = subprocess.Popen([str(binary), *map(str,args)], stdin=slave, stdout=slave,
                            stderr=slave, preexec_fn=ctty, env=env)
    os.close(slave); output = bytearray(); sent = 0; start = time.monotonic()
    try:
        while True:
            if select.select([master], [], [], .1)[0]:
                try: output.extend(os.read(master, 65536))
                except OSError: pass
            if sent < len(secrets) and secrets[sent][0] in output:
                os.write(master, secrets[sent][1] + b'\n'); sent += 1
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                proc.returncode = os.waitstatus_to_exitcode(status)
                while select.select([master], [], [], 0)[0]:
                    try:
                        data = os.read(master,65536)
                        if not data: break
                        output.extend(data)
                    except OSError: break
                break
            require(time.monotonic()-start < timeout, f'wallet command exceeded {timeout} seconds')
            require(len(output)<4*1024*1024, 'wallet output exceeded bound')
        text = output.decode(errors='replace')
        (directory / (label+'.log')).write_text(text)
        metrics = {'seconds':round(time.monotonic()-start,3), 'peak_rss_kib':usage.ru_maxrss,
                   'exit_code':proc.returncode}
        if expected is None: pass
        elif expected: require(proc.returncode==0 and sent==len(secrets), f'{label} failed; see {directory / (label+".log")}')
        else: require(proc.returncode!=0, label+' unexpectedly succeeded')
        return text, metrics
    finally:
        os.close(master)
        if proc.returncode is None: stop(proc)


def mine(url, target):
    rpc(url,'hegemon_startMining',[{'threads':1}])
    try:
        deadline=time.monotonic()+900
        while height(url)<target:
            require(time.monotonic()<deadline, 'mining stalled')
            time.sleep(.05)
    finally: rpc(url,'hegemon_stopMining')
    require(rpc(url,'system_health')['peers']==0, 'Hegemon acquired a peer')


def descriptor(btc, name, value):
    result=btc.call('importdescriptors',[{'desc':value+'#'+descriptor_checksum(value), 'timestamp':'now','active':False}],wallet=name,sensitive=True)
    require(result[0].get('success'), 'descriptor import failed')


def scenario(a, name):
    d=a.output/name; d.mkdir(mode=0o700)
    rec={'scenario':name,'status':'running','bitcoin_chain':'regtest','hegemon_seeds':'',
         'production_authorized':False,'proofs':{},'checks':{}}
    node=bitcoin=None; handle=None
    phrase=os.urandom(24).hex().encode(); hp=os.urandom(24).hex().encode()
    (d/'wallet.pass').write_bytes(phrase+b'\n')
    (d/'handoff.pass').write_bytes(hp+b'\n')
    rec['source_commit']=subprocess.check_output(['git','-C',ROOT,'rev-parse','HEAD'],text=True).strip()
    rec['binary_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (a.node,a.wallet,a.bitcoind)}
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
        # Fresh peerless Bitcoin node; no public-network discovery or connections.
        bd=d/'bitcoin'; bd.mkdir(); bp=port()
        bitcoin=subprocess.Popen([a.bitcoind,'-regtest',f'-datadir={bd}','-server=1','-listen=0','-connect=0','-discover=0','-dnsseed=0','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1',f'-rpcport={bp}','-fallbackfee=0.0002','-printtoconsole=0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        btc=BitcoinRPC(f'http://127.0.0.1:{bp}',bd/'regtest/.cookie')
        deadline=time.monotonic()+30
        while True:
            require(bitcoin.poll() is None,'Bitcoin exited')
            try:
                require(btc.call('getblockchaininfo')['chain']=='regtest','wrong Bitcoin chain'); break
            except (OSError,RuntimeError):
                require(time.monotonic()<deadline,'Bitcoin RPC unavailable'); time.sleep(.2)
        for n in ('alice','bob'): btc.call('createwallet',n,False,False,'',False,True)
        ap,ak=rehearsal_bitcoin_key(); bpub,bkey=rehearsal_bitcoin_key()
        dest=btc.call('getnewaddress',wallet='bob'); btc.call('generatetoaddress',101,dest)
        refund=btc.call('getblockcount')+5
        def desc(x,y): return f'wsh(or_i(and_v(v:sha256({hashed}),pk({x})),and_v(v:after({refund}),pk({y}))))'
        public=btc.call('getdescriptorinfo',desc(ap,bpub))['descriptor']
        contract=btc.call('deriveaddresses',public)[0]
        descriptor(btc,'alice',desc(ak,bpub)); descriptor(btc,'bob',desc(ap,bkey))
        tx=None
        if name!='no_btc':
            tx=btc.call('sendtoaddress',contract,0.001,wallet='bob'); btc.call('generatetoaddress',1,dest)
            funding=btc.call('gettransaction',tx,wallet='bob')
            decoded=btc.call('getrawtransaction',tx,True,funding['blockhash'])
            vout=next(v for v in decoded['vout'] if v['scriptPubKey'].get('address')==contract)
            info=btc.call('getaddressinfo',contract,wallet='alice')
            witness=bytes.fromhex(info['hex']); script=bytes.fromhex(vout['scriptPubKey']['hex'])
            if name in ('happy','late_claim'):
                target=btc.call('getnewaddress',wallet='alice')
                claimtx=spend_contract(btc,'alice',tx,vout['n'],100000,script,witness,target,0xffffffff,0,secret)
                wait_bitcoin_confirmations(btc,claimtx,'alice',1,dest)
                require(confirmed_bitcoin_preimage(btc,claimtx,'alice',bytes.fromhex(hashed))==secret,'Bitcoin preimage mismatch')
                rec['checks']['bitcoin_claim_confirmed']=True
                rec['bitcoin_claim_txid']=claimtx
            else:
                btc.call('generatetoaddress',refund-btc.call('getblockcount')+1,dest)
                refundtx=spend_contract(btc,'bob',tx,vout['n'],100000,script,witness,dest,0xfffffffe,refund)
                wait_bitcoin_confirmations(btc,refundtx,'bob',1,dest)
                rec['checks']['bitcoin_refund_confirmed']=True
        if name=='happy':
            prepare('bob',['claim','--locked',str(locked),'--fee-input',str(notes('bob')[0][0]),'--recipient',addresses['bob'],'--fee','1'],[(SECRET,secret.hex().encode())])
            require(any(v==100000 for p,v in notes('bob')), 'Bob did not receive locked HGN')
        else:
            mine(url,timeout)
            prepare('alice',['refund','--locked',str(locked),'--fee-input',str(notes('alice')[0][0]),'--recipient',addresses['alice'],'--fee','1'])
            require(any(v==100000 for p,v in notes('alice')), 'Alice did not recover HGN')
            if name=='late_claim':
                call('bob',['claim','--locked',str(locked),'--fee-input',str(notes('bob')[0][0]),'--recipient',addresses['bob'],'--fee','1'],[(SECRET,secret.hex().encode())],label='late-claim',expected=False)
                rec['checks']['late_claim_rejected']=True
        require(not btc.call('getpeerinfo'),'Bitcoin acquired a peer')
        require(rpc(url,'system_health')['peers']==0,'Hegemon acquired a peer')
        rec['checks']['zero_peers']=True; rec['status']='passed'
        rec['hegemon_final_height']=height(url)
        rec['bitcoin_final_height']=btc.call('getblockcount')
        return rec
    except Exception as e:
        rec['status']='failed'; rec['error']=str(e); raise
    finally:
        stop(bitcoin); stop(node)
        if handle: handle.close()
        rec['owned_nodes_stopped']=True
        (d/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--scenario',choices=['all','happy','no_btc','both_refund','late_claim'],default='all')
    p.add_argument('--node',type=Path,default=ROOT/'target/release/hegemon-node')
    p.add_argument('--wallet',type=Path,default=ROOT/'target/release/private-spend')
    p.add_argument('--bitcoind',type=Path,default=Path('/workspace/bitcoin-32.1/bin/bitcoind'))
    a=p.parse_args(); a.output=a.output.resolve(); a.output.mkdir(mode=0o700,exist_ok=False)
    os.umask(0o077)
    results=[]
    for n in (['happy','no_btc','both_refund','late_claim'] if a.scenario=='all' else [a.scenario]):
        results.append(scenario(a,n))
    (a.output/'summary.json').write_text(json.dumps({'status':'passed','scenarios':results},indent=2)+'\n')
    print(json.dumps({'status':'passed','summary':str(a.output/'summary.json')}),flush=True)

if __name__=='__main__': main()
