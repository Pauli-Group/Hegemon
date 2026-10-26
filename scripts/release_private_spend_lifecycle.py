#!/usr/bin/env python3
"""Actual local lifecycle for one source-authorized release tuple.
Legacy 2-of-3 fixtures exercise six proof cases. Single-key fixtures exercise
ordinary, lock, claim and refund plus an ordinary allocated-reward payout;
they never claim fresh approval/final proof coverage or close G8 by themselves.
External single-key fixtures instead exercise the selected network with disposable
miner actors and verify the actual public treasury output without treasury keys.
That mode explicitly leaves treasury spending unexercised.
No host deployment, generated funding recipient, or Development bypass.
Use only approved disposable actor stores, never real operator secrets.
"""
import argparse, fcntl, hashlib, json, math, os, pty, re, select, shutil, signal, socket, subprocess, sys, termios, time
from pathlib import Path
import release_private_spend_lifecycle_io as h
import importlib.util, datetime, threading

OWNED=[]
STATE={}
OUT=None
RESOURCE_FLOOR=40

def interrupted(signum,frame):
    # Non-TTY children inherit the central group. Wallet's required controlling
    # TTY session is explicitly killed on owned interruption before parent exit.
    for proc in OWNED:
        if proc.poll() is None:
            try:proc.send_signal(signal.SIGTERM)
            except ProcessLookupError:pass
            if getattr(proc,'_hegemon_owned_ctty',False):
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
    raise RuntimeError('owned lifecycle interrupted by signal '+str(signum))

def wallet_cli(binary,argv,secrets,timeout=None):
    master,slave=pty.openpty();attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
    def ctty():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    env=os.environ.copy();env['RAYON_NUM_THREADS']='2'
    proc=subprocess.Popen([str(binary),*map(str,argv)],stdin=slave,stdout=slave,stderr=slave,close_fds=True,preexec_fn=ctty,env=env)
    proc._hegemon_owned_ctty=True
    OWNED.append(proc);os.close(slave);buf=bytearray();sent=0
    try:
        while True:
            ready,_,_=select.select([master],[],[],.2)
            if ready:
                try:b=os.read(master,8192)
                except OSError:b=b''
                if not b and proc.poll() is not None:break
                buf.extend(b);require(len(buf)<=2*1024*1024,'wallet diagnostic output exceeds bound')
            if sent<len(secrets) and secrets[sent][0] in buf:
                os.write(master,bytes(secrets[sent][1])+b'\n');sent+=1
            if proc.poll() is not None and not ready:break
        proc.wait()
        if proc.returncode!=0 or sent!=len(secrets):
            private(OUT/('wallet-failure-'+str(proc.pid)+'.log'),bytes(buf))
            raise RuntimeError('wallet CLI failed; private diagnostics retained for pid '+str(proc.pid))
        return buf.decode('utf-8','replace')
    finally:
        for _,secret in secrets:
            for i in range(len(secret)):secret[i]=0
        os.close(master)
h.wallet_cli=wallet_cli

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(c, m):
    if not c: raise RuntimeError(m)
def save(): h.atomic_json(OUT/'receipt.json', STATE)
def mark(k,v=True): STATE.setdefault('gates',{})[k]=v; save(); print(k, flush=True)
def private(p,b):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f: f.write(b); f.flush(); os.fsync(f.fileno())
def capture(cmd):
    p=subprocess.Popen(list(map(str,cmd)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=False)
    OWNED.append(p); out,err=p.communicate()
    if p.returncode!=0:
        private(OUT/('cli-failure-'+str(p.pid)+'.log'),err)
        raise RuntimeError('local CLI command failed: '+str(cmd[1]))
    return out.decode()
def jline(t): return h.json_line(t)
def stop(p):
    if p.poll() is None: p.send_signal(signal.SIGTERM)
    try: p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.send_signal(signal.SIGKILL); p.wait(); raise RuntimeError('owned node needed SIGKILL')
    require(p.returncode==0,'owned node exited nonzero')
def wait(fn, label):
    started=time.monotonic()
    while True:
        try:
            v=fn()
            if v:return v
        except (h.GateError, ConnectionError, OSError, ValueError):pass
        if time.monotonic()-started>180: raise RuntimeError('no progress at '+label)
        time.sleep(.25)
def start(a, name, port, rpcport, seeds, miner):
    base=OUT/name; base.mkdir(mode=0o700,exist_ok=True)
    env={k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_')}
    env.update(HEGEMON_MINER_ADDRESS=miner,HEGEMON_SEEDS=seeds,HEGEMON_MINE='0',HEGEMON_BOOTSTRAP_AUTHORING='1',RAYON_NUM_THREADS='2')
    # Cold prefix snapshots retain B's identity; competing forks need their own
    # persisted key while preserving the cloned original for evidence.
    if name.startswith('fork-'):
        env['HEGEMON_PQ_IDENTITY_SEED_PATH']=str(OUT/(name+'.peer-identity.seed'))
    log=(OUT/(name+'-'+str(time.time_ns())+'.log')).open('xb')
    p=subprocess.Popen([str(a.node),'--network',a.network_profile,'--network-manifest',str(OUT/'manifest.json'),'--base-path',str(base),'--listen-addr',f'127.0.0.1:{port}','--port',str(port),'--rpc-port',str(rpcport),'--rpc-methods','unsafe','--name',name],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=False)
    p.is_node=True; OWNED.append(p); log.close(); url=f'http://127.0.0.1:{rpcport}'
    cfg=wait(lambda:h.rpc(url,'hegemon_nodeConfig'),'node startup')
    require(cfg['networkProfile']==a.network_profile and cfg['networkManifest']==STATE['manifest'] and cfg['chainId']=='0x'+a.identity['chain_id'] and cfg['networkManifestDigest']=='0x'+a.identity['manifest_digest'],'node manifest mismatch')
    require(h.rpc(url,'chain_getBlockHash',[0])=='0x'+a.identity['genesis_hash'],'genesis mismatch')
    params=h.rpc(url,'hegemon_privateSpendParameters')
    require(params==a.contract['parameters'],'fresh binary proof parameters mismatch'); require(params.get('production_authorized') is False,'static descriptor flag changed; source capability supplies authority'); STATE['parameters']=params
    return p,url,cfg
def converge(urls):
    def ready():
        hs=[h.height(u) for u in urls]
        return hs[0] if len(set(hs))==1 and len(set(h.rpc(u,'chain_getBlockHash',[hs[0]]) for u in urls))==1 else False
    # Height zero is a valid converged initial state.
    wait(lambda:len(set(h.rpc(u,'chain_getBlockHash',[h.height(u)]) for u in urls))==1,'tip convergence')
    return h.height(urls[0])
def pair(a,miner):
    pa,ua,_=start(a,'node-a',31371,20971,'127.0.0.1:31372',miner)
    pb,ub,_=start(a,'node-b',31372,20972,'127.0.0.1:31371',miner)
    wait(lambda:all(h.rpc(u,'system_health')['peers']>=1 for u in (ua,ub)),'reciprocal peers')
    converge([ua,ub]);return [pa,pb],[ua,ub]
def mining(url,target):
    status=h.rpc(url,'hegemon_miningStatus');require(status['mining_sync_gate_open'],'mining sync gate closed')
    h.rpc(url,'hegemon_startMining',[{'threads':1}])
    try:
        if a.contract['schema']=='hegemon.private-spend.local-release-lifecycle-input.v2':
            wait_mining_height(url,target)
        else:wait(lambda:h.height(url)>=target,'mining canonical block')
    finally:h.rpc(url,'hegemon_stopMining')
    time.sleep(.3)
def mining_no_progress_seconds(status,height,sample_age_seconds):
    """Harness budget only: 32 expected native PoW intervals, bounded 600..3600s.

    miningStatus difficulty fields are compact targets, not numeric difficulty.
    Use next_difficulty for current work. Invalid/stale/inactive samples retain
    the original 600s fallback; status activity never counts as chain progress.
    """
    if not isinstance(status,dict) or type(height) is not int or height<0:return 600
    if type(sample_age_seconds) not in (int,float) or not 0<=sample_age_seconds<=5 or not math.isfinite(sample_age_seconds):return 600
    if status.get('is_mining') is not True or status.get('mining_sync_gate_open') is not True or status.get('syncing') is not False:return 600
    if type(status.get('block_height')) is not int or status['block_height']!=height:return 600
    rate=status.get('hash_rate');bits=status.get('next_difficulty')
    if type(rate) not in (int,float) or not 1<=rate<=10**18 or not math.isfinite(rate):return 600
    if type(bits) is not int or not 0<bits<=0xffffffff or bits&0x00800000:return 600
    exponent=bits>>24;mantissa=bits&0x007fffff
    if not mantissa or exponent>32:return 600
    target=mantissa<<8*(exponent-3) if exponent>3 else mantissa>>8*(3-exponent)
    if not 0<target<=(0x7fffff<<232):return 600
    # Match the positive canonical Bitcoin80 compact codec, including the
    # small-exponent truncation and sign-bit normalization boundaries.
    size=(target.bit_length()+7)//8
    encoded=target<<8*(3-size) if size<=3 else target>>8*(size-3)
    if encoded&0x00800000:encoded>>=8;size+=1
    if bits!=(size<<24)|encoded:return 600
    expected_seconds=(2**256/(target+1))/rate
    return math.ceil(max(600,min(3600,32*expected_seconds)))

def wait_mining_height(url,target):
    # Real 120-block maturity at the protocol cadence takes hours. Bound a lack
    # of actual canonical progress, not the legitimate total mining duration.
    high=h.height(url);last=time.monotonic();status=None;sampled=None
    while high<target:
        current=h.height(url)
        if current>high:
            block_hash=h.rpc(url,'chain_getBlockHash',[current])
            require(isinstance(block_hash,str) and re.fullmatch(r'0x[0-9a-fA-F]{64}',block_hash),'mining progress has no canonical hash')
            high=current;last=time.monotonic()
        now=time.monotonic()
        if sampled is None or now-sampled>=5:
            sampled=now
            try:status=h.rpc(url,'hegemon_miningStatus')
            except (h.GateError,ConnectionError,OSError,ValueError):status=None
        timeout=mining_no_progress_seconds(status,high,time.monotonic()-sampled)
        if time.monotonic()-last>timeout:raise RuntimeError('no canonical mining height progress for'+str(timeout)+'s')
        if high<target:time.sleep(.25)
def ps(a,i,url,cmd,extra=()):
    return h.ps(a.private_spend,OUT/f'signer-{i}.store',(OUT/f'signer-{i}.pass').read_bytes().strip(),OUT/'manifest.json',STATE['genesis'],url,cmd,extra=extra)
def rows(text):return [(kind,int(pos),int(val)) for kind,pos,val in re.findall(r'(ordinary|htlc|accumulator|treasury-value) position=(\d+) value=(\d+)',text)]
def notes(a,i,url):return rows(ps(a,i,url,['notes']))
def ids(text,kind):
    m=re.search(kind+r' ([0-9a-f]{64})',text);require(m,'CLI '+kind+' identifier missing');return m.group(1)
def inspect(path,urls,first,last):
    raw=path.read_bytes(); found=[]
    for height in range(first,last+1):
        bh=h.rpc(urls[0],'chain_getBlockHash',[height]); records=[h.chunks(u,bh) for u in urls]
        require(all(x==records[0] for x in records),'canonical body divergence')
        acts,meta,body=records[0]
        count=acts.count(raw)
        if count:require(count==1,'duplicate canonical action');found.append((height,bh,meta,body))
    require(len(found)==1,'exact action missing or duplicated in canonical range')
    height,bh,meta,body=found[0]
    return {'height':height,'block_hash':bh,'action_sha256':sha(path),'canonical_body_sha256':hashlib.sha256(body).hexdigest(),'action_body_hash':meta['action_body_hash'],'bytes':len(raw)}
def submit(a,i,urls,attempt,path):
    before=h.height(urls[0]);raw=path.read_bytes();tx='0x'+raw[:48].hex()
    ps(a,i,urls[0],['submit',attempt])
    wait(lambda:all(h.pending(u,tx)==raw for u in urls),'exact RPC relay and mempool')
    STATE.setdefault('pending',{})[path.stem]={'sha256':sha(path),'A_B_exact':True};save()
    mining(urls[0],before+1);tip=converge(urls)
    row=inspect(path,urls,before+1,tip);row['attempt_id']=attempt;row['wallet']=i
    return row
def action(a,i,urls,name,cmd,extra=()):
    prefix='prefix-'+name; snapshot(active_nodes(),prefix)
    _,restarted=pair(a,STATE['miner']); urls[:]=restarted
    aid=ids(ps(a,i,urls[0],cmd,extra),'candidate');path=OUT/(name+'.action')
    ps(a,i,urls[0],['export',aid,str(path)])
    case={'ordinary':'ordinary','lock':'lock','claim':'claim','refund':'refund','treasury-approve':'approval','treasury-finalize':'final'}[cmd[0]]
    measurement=a.contract['cases'][case]; transport=a.contract['transport']; offset=transport['fixed_bytes']
    carrier=public_args(path.read_bytes())
    require(len(carrier)==measurement['carrier_bytes'] and len(carrier)-offset==measurement['proof_bytes'],'fresh measured proof/carrier geometry mismatch')
    require(carrier[:8].hex()==transport['magic'] and carrier[8:24].hex()==transport['identity'] and carrier[offset:offset+4].hex()==transport['inner_magic'],'fresh transport identity mismatch')
    require(carrier[24:72].hex()==a.contract['parameters']['relation_digest'][:96],'fresh relation digest mismatch')
    require(carrier[72:104].hex()==h.rpc(urls[0],'hegemon_nodeConfig')['chainId'].removeprefix('0x'),'proof chain binding mismatch')
    reference=int.from_bytes(carrier[136:144],'little');require(h.rpc(urls[0],'chain_getBlockHash',[reference])=='0x'+carrier[104:136].hex(),'proof reference is not canonical')
    private(OUT/(name+'.carrier.hgps'),carrier);private(OUT/(name+'.proof.smzd'),carrier[offset:])
    STATE.setdefault('proofs',{})[name]={'carrier_sha512':hashlib.sha512(carrier).hexdigest(),'proof_sha512':hashlib.sha512(carrier[offset:]).hexdigest(),'carrier_bytes':len(carrier),'proof_bytes':len(carrier)-offset,'reference_parent_height':reference,'reference_parent_hash':'0x'+carrier[104:136].hex(),'wallet_local_proof_verify':True,'case':case};save()
    row=submit(a,i,urls,aid,path);STATE.setdefault('actions',{})[name]=row;mark(name)
    _,adopted=reorg(a,active_nodes(),urls,STATE['miner'],prefix,name); urls[:]=adopted
    return STATE['resubmitted_'+name]
def active_nodes(): return [p for p in OWNED if getattr(p,'is_node',False) and p.poll() is None]
def copy_fresh(source,target):
    require(not target.exists(),'copy target must be fresh')
    logical=sum(f.stat().st_size for f in source.rglob('*') if f.is_file())
    require(shutil.disk_usage(OUT).free>DISK_RESERVE+logical+2**20,'copy cannot preserve selected disk reserve')
    shutil.copytree(source,target)

def closed_rpc(port):
    with socket.socket() as s:
        s.settimeout(.2)
        return s.connect_ex(('127.0.0.1',port))!=0

def snapshot(nodes,name):
    for p in active_nodes():stop(p)
    source_authorization(a);resource_check(a.quota_snapshot)
    copy_fresh(OUT/'node-b',OUT/name)
def canonical_bodies(urls):
    tip=converge(urls);result=[]
    for height in range(1,tip+1):
        bh=h.rpc(urls[0],'chain_getBlockHash',[height]);require(all(h.rpc(u,'chain_getBlockHash',[height])==bh for u in urls),'canonical hash divergence')
        data=[h.chunks(u,bh) for u in urls];require(all(x==data[0] for x in data),'full body divergence')
        result.append({'height':height,'block_hash':bh,'body_sha256':hashlib.sha256(data[0][2]).hexdigest()})
    return result
def reorg(a,nodes,urls,miner,snap,name):
    row=STATE['actions'][name];path=OUT/(name+'.action');raw=path.read_bytes();oldtip=converge(urls)
    oldwork=int(h.rpc(urls[0],'chain_getHeader')['cumulativeWork'],16)
    for p in nodes:stop(p)
    # A separate cold prefix DB constructs a real competing branch with greater work.
    forkname='fork-'+name;copy_fresh(OUT/snap,OUT/forkname)
    pf,uf,_=start(a,forkname,31374,20974,'',miner)
    prefix=h.height(uf);mining(uf,oldtip+2)
    while int(h.rpc(uf,'chain_getHeader')['cumulativeWork'],16)<=oldwork:
        require(h.height(uf)-prefix<10,'winning fork exceeds source reference window')
        mining(uf,h.height(uf)+1)
    forktip=h.height(uf);forkhash=h.rpc(uf,'chain_getBlockHash',[forktip]);newwork=int(h.rpc(uf,'chain_getHeader')['cumulativeWork'],16)
    STATE.setdefault('forks',{})[name]={'prefix':prefix,'old_tip':oldtip,'old_work':oldwork,'fork_tip':forktip,'fork_work':newwork,'fork_hash':forkhash};save();stop(pf)
    # Join the higher-work node and await actual A/B canonical adoption.
    pf,uf,_=start(a,forkname,31374,20974,'127.0.0.1:31371',miner)
    pa,ua,_=start(a,'node-a',31371,20971,'127.0.0.1:31374,127.0.0.1:31372',miner)
    pb,ub,_=start(a,'node-b',31372,20972,'127.0.0.1:31371,127.0.0.1:31374',miner)
    wait(lambda:all(h.rpc(u,'chain_getBlockHash',[forktip])==forkhash for u in (ua,ub)),'higher work adoption')
    converge([ua,ub,uf]);stop(pf);urls=[ua,ub];nodes=[pa,pb]
    require(h.rpc(ua,'chain_getBlockHash',[row['height']])!=row['block_hash'],'target action not orphaned')
    for height in range(row['height'],forktip+1):require(raw not in h.chunks(ua,h.rpc(ua,'chain_getBlockHash',[height]))[0],'target persisted on winning prefix')
    at=ps(a,row['wallet'],ua,['attempts']);line=next(x for x in at.splitlines() if row['attempt_id'] in x)
    require('mined=None' in line,'wallet did not rollback target mined tuple')
    mark(name+'_reorg_rollback')
    require(sha(path)==row['action_sha256'],'target bytes changed')
    new=submit(a,row['wallet'],urls,row['attempt_id'],path);STATE['resubmitted_'+name]=new
    require('mined=Some' in next(x for x in ps(a,row['wallet'],ua,['attempts']).splitlines() if row['attempt_id'] in x),'resubmitted wallet receipt absent')
    mark(name+'_unchanged_resubmission');return nodes,urls
def public_args(raw):
    # PendingActionWire: fixed header, four SCALE vectors, public_args vector,
    # fee:u64, Option<CandidateArtifact>. Current independent routes use None.
    def compact_len(pos):
        require(pos<len(raw),'truncated SCALE vector length')
        mode=raw[pos]&3
        size=(1,2,4)[mode] if mode<3 else (raw[pos]>>2)+5
        require(mode!=3 or size==5,'SCALE vector length exceeds u32')
        require(pos+size<=len(raw),'truncated SCALE compact integer')
        value=int.from_bytes(raw[pos:pos+size],'little')>>2 if mode<3 else int.from_bytes(raw[pos+1:pos+size],'little')
        require(mode==0 or value>=(64,16384,1<<30)[mode-1],'noncanonical SCALE compact integer')
        return value,pos+size
    require(len(raw)>=104,'truncated PendingActionWire header')
    p=104
    for width in (48,48,48,4):
        count,p=compact_len(p)
        require(count<=(len(raw)-p)//width,'truncated PendingActionWire vector')
        p+=count*width
    length,p=compact_len(p);end=p+length
    require(end+9==len(raw),'action argument/fee/option framing has trailing/truncated bytes')
    fee=int.from_bytes(raw[end:end+8],'little')
    require(raw[end+8]==0,'current independent action requires candidate_artifact=None')
    args=raw[p:end]
    if int.from_bytes(raw[52:54],'little')==1 and int.from_bytes(raw[54:56],'little')==15:
        # PrivateSpend PublicStatement::preamble places its fee after the
        # seven root limbs, at200..208; wallet wire repeats that same u64.
        require(len(args)>=208 and fee==int.from_bytes(args[200:208],'little'),'private action outer/inner fee mismatch')
    return args
def treasury_reward(url,height):
    bh=h.rpc(url,'chain_getBlockHash',[height]);acts,meta,body=h.chunks(url,bh)
    for raw in acts:
        if int.from_bytes(raw[52:54],'little')!=1 or int.from_bytes(raw[54:56],'little')!=12:continue
        b=public_args(raw);require(len(b)==4699 and b[2349]==1,'allocated reward codec mismatch')
        b=b[2350:];w=[int.from_bytes(b[i*8:i*8+8],'little') for i in range(18)]
        return {'value':w[0],'asset_id':w[1],'recipient_key':w[2:6],'authorization_key':w[6:10],'rho':w[10:14],'randomness':w[14:18]},b[144:200].hex(),bh
    raise RuntimeError('allocated reward missing')

def external_treasury_readback(args,urls):
    """Check an actual public allocation without importing its spending key.

    The 24-byte full-authorization extension occupies randomness[0:3] in the
    single-key reward opening (wallet/src/poseidon2_v8_coinbase.rs). The final
    randomness limb remains fresh. This verifies issuance and recipient binding,
    not decryption, ownership, spending, or a complete treasury lifecycle.
    """
    require(args.custody=='external-single-key','external treasury mode required')
    pin_input(args.fixture['operator_custody_rehearsal'])
    keys=h.public_v8_address_keys(STATE['manifest']['funding_address'])
    rows=[treasury_reward(url,1) for url in urls]
    require(rows and all(row==rows[0] for row in rows),'canonical treasury output differs between release nodes')
    opening,commitment,block_hash=rows[0]
    bodies=[h.chunks(url,block_hash) for url in urls]
    require(all(body==bodies[0] for body in bodies),'complete treasury block body differs')
    rewards=[raw for raw in bodies[0][0] if int.from_bytes(raw[52:54],'little')==1 and int.from_bytes(raw[54:56],'little')==12]
    require(len(rewards)==1,'height-one block must contain exactly one allocated reward action')
    require(opening['value']==100_000_000 and opening['asset_id']==0,'height-one treasury allocation must be one HGN in native base units')
    require(opening['recipient_key']==keys['recipient_key'] and opening['authorization_key']==keys['authorization_key'] and opening['randomness'][:3]==keys['authorization_extension'],'actual treasury reward does not bind the complete approved recipient')
    STATE['external_treasury_readback']={'height':1,'block_hash':block_hash,'commitment':commitment,'opening':opening,'address_sha256':hashlib.sha256(STATE['manifest']['funding_address'].encode('ascii')).hexdigest(),'nodes_checked':len(urls),'canonical_body_sha256':hashlib.sha256(bodies[0][2]).hexdigest(),'treasury_spend_exercised':False}
    mark('treasury_canonical_value')

DISK_RESERVE=5*2**30
RESOURCE_STOP=threading.Event()

def pin_input(value):
    require(isinstance(value,dict) and set(value)=={'path','sha256'},'input pin must name exact bytes')
    p=Path(value['path']).absolute();require(p.is_file() and not p.is_symlink(),'input must be regular nonsymlink file')
    require(sha(p)==value['sha256'],'input bytes differ from frozen contract')
    return p

def prefix_files(root):
    require(root.is_dir() and not root.is_symlink() and root.resolve()==root.absolute(),'canonical prefix database must be a real directory')
    rows=[]
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(),'canonical prefix cannot contain symlinks')
        if path.is_dir():continue
        require(path.is_file(),'canonical prefix cannot contain special files')
        rows.append({'path':path.relative_to(root).as_posix(),'sha256':sha(path),'bytes':path.stat().st_size})
    require(rows and sum(row['bytes'] for row in rows)<=32*2**20,'canonical prefix database outside bounded size')
    return rows

def restore_canonical_prefix(args,miner):
    if args.canonical_prefix is None:return None
    require(args.custody=='external-single-key' and args.contract['schema']=='hegemon.private-spend.local-release-lifecycle-input.v2','prefix continuation only supports the external v2 lifecycle')
    pin={'path':str(args.canonical_prefix.absolute()),'sha256':args.canonical_prefix_sha256}
    checkpoint=json.loads(pin_input(pin).read_text())
    require(set(checkpoint)=={'schema','parent_receipt','parent_contract','parent_binding','database','files','height','block_hash'} and checkpoint['schema']=='hegemon.private-spend.canonical-prefix-input.v1','typed canonical prefix input required')
    require(type(checkpoint['height']) is int and 0<checkpoint['height']<120 and re.fullmatch(r'0x[0-9a-f]{64}',checkpoint['block_hash']),'prefix must precede reward maturity')
    parent_path=pin_input(checkpoint['parent_receipt']);parent=json.loads(parent_path.read_text())
    old=json.loads(pin_input(checkpoint['parent_contract']).read_text())
    binding=json.loads(pin_input(checkpoint['parent_binding']).read_text())
    require(old['release_binding_sha256']==checkpoint['parent_binding']['sha256'] and binding['identity']==args.identity,'prefix original source binding differs')
    changed={'release_binding_sha256','harness_sha256','watchdog_sha256'}
    require(set(old)==set(args.contract) and all(old[k]==args.contract[k] for k in old if k not in changed),'prefix must use identical runtime, binaries, network and proof contract')
    require(parent.get('schema')=='hegemon.private-spend.actualnode.compff01.v1' and parent.get('status')=='NON_PASS' and parent.get('failure')=='no canonical mining height progress for600s','only the closed pre-proof progress timeout may continue')
    require(parent.get('contract_sha256')==checkpoint['parent_contract']['sha256'] and parent.get('harness_sha256')==old['harness_sha256'] and parent.get('progress_watchdog_sha256')==old['watchdog_sha256'] and parent.get('recovered_helper_sha256')==old['io_sha256'],'original producer pins differ')
    require(parent.get('release_identity')==args.identity and parent.get('artifact_sha256')==args.contract['artifact_sha256'] and parent.get('binaries')==args.contract['binaries'] and parent.get('runtime_inventory_sha256')==args.contract['runtime_inventory']['sha256'],'prefix execution identity differs')
    require(parent.get('manifest')==STATE['manifest'] and parent.get('genesis')==STATE['genesis'] and parent.get('miner')==miner and parent.get('custody')=='external-single-key','prefix network or miner differs')
    require(parent.get('gates')=={} and parent.get('fresh_proof_cases')==[] and not any(parent.get(k) for k in ('actions','canonical_bodies','pending','canonical_prefix_continuation')),'prefix must precede every proof and action gate')
    require(parent.get('all_owned_exit0') is True and parent.get('all_owned_reaped') is True and parent.get('rpc_closed') is True,'prefix parent did not close cleanly')
    require(parent.get('owned_processes') and all(row.get('exit_code')==0 and row.get('reaped') is True for row in parent['owned_processes']),'prefix process closure incomplete')
    for row in parent['owned_processes']:
        require(type(row.get('pid')) is int and row['pid']>1,'invalid parent process identifier')
        try:os.kill(row['pid'],0)
        except ProcessLookupError:pass
        else:raise RuntimeError('parent process identifier remains live; refuse cold copy')
    source=Path(checkpoint['database'])
    require(source.is_absolute() and source==parent_path.parent/'node-a'/'native-chain.sled' and parent_path.name=='receipt.json','prefix may copy only the original node-A native database')
    require(not (OUT/'node-a').exists() and not (OUT/'node-b').exists(),'prefix destination nodes must be fresh')
    require(prefix_files(source)==checkpoint['files'],'closed prefix snapshot changed')
    (OUT/'node-a').mkdir(mode=0o700)
    destination=OUT/'node-a'/'native-chain.sled';shutil.copytree(source,destination)
    require(prefix_files(source)==checkpoint['files'] and prefix_files(destination)==checkpoint['files'],'prefix copy or source changed')
    STATE['canonical_prefix_continuation']={'schema':'hegemon.private-spend.canonical-prefix-continuation.v1','input':pin,'current_contract':{'path':str(args.contract_path),'sha256':sha(args.contract_path)},'parent_receipt':checkpoint['parent_receipt'],'parent_contract':checkpoint['parent_contract'],'parent_binding':checkpoint['parent_binding'],'initial_height':checkpoint['height'],'initial_block_hash':checkpoint['block_hash'],'snapshot_files':checkpoint['files'],'restored_node':'node-a','fresh_import_node':'node-b','peer_identity_reused':False,'wallet_state_reused':False,'prefix_remined':False,'parent_status':'NON_PASS','fresh_native_import_verified':False}
    save();return checkpoint

def verify_canonical_prefix(checkpoint,urls):
    if checkpoint is None:return
    height=checkpoint['height'];tip=checkpoint['block_hash'];previous=STATE['genesis'];records=[]
    require(all(h.height(url)==height and h.rpc(url,'chain_getBlockHash',[height])==tip for url in urls),'restored/fresh imported prefix tip differs')
    for number in range(1,height+1):
        hashes=[h.rpc(url,'chain_getBlockHash',[number]) for url in urls]
        require(len(set(hashes))==1,'prefix canonical hash divergence')
        block_hash=hashes[0];headers=[h.rpc(url,'chain_getHeader',[block_hash]) for url in urls]
        bodies=[h.chunks(url,block_hash) for url in urls]
        require(headers[0]==headers[1] and bodies[0]==bodies[1],'fresh node did not import exact canonical prefix bytes')
        acts,meta,body=bodies[0];header=headers[0]
        number_value=header['number'];number_value=int(number_value,16) if isinstance(number_value,str) and number_value.startswith('0x') else int(number_value)
        require(number_value==number and header['parentHash']==previous and meta['parent_hash']==previous and meta['height']==number,'prefix header/body chain is not contiguous')
        require(len(acts)==1 and len(acts[0])>=56 and int.from_bytes(acts[0][52:54],'little')==1 and int.from_bytes(acts[0][54:56],'little')==12,'prefix must contain only actual reward actions')
        require(len(public_args(acts[0]))==4699,'prefix reward codec differs')
        records.append({'height':number,'block_hash':block_hash,'header':header,'body_metadata':meta,'canonical_body_sha256':hashlib.sha256(body).hexdigest(),'reward_action_sha256':hashlib.sha256(acts[0]).hexdigest()});previous=block_hash
    path=OUT/'canonical-prefix-readback.json'
    h.atomic_json(path,{'schema':'hegemon.private-spend.canonical-prefix-readback.v1','genesis':STATE['genesis'],'records':records,'nodes':['node-a','node-b']})
    STATE['canonical_prefix_continuation'].update(fresh_native_import_verified=True,readback={'path':str(path),'sha256':sha(path)},verified_block_count=len(records))
    save()

def authenticated_inventory(args,bound):
    inventory=json.loads(pin_input(args.contract['runtime_inventory']).read_text())
    require(inventory.get('schema')=='hegemon.private-spend.release-inventory.v1' and isinstance(inventory.get('files'),list),'complete reviewed runtime inventory required')
    if args.contract['schema']=='hegemon.private-spend.local-release-lifecycle-input.v1':
        require(len(inventory['files'])==541,'complete historical runtime inventory required')
    else:
        # The actual source checker above authenticates the retained parent plus
        # reviewed additions. Consume its exact bound current inventory instead
        # of imposing the historical parent row count on a reviewed successor.
        current=bound['runtime_inventory']
        require(current['sha256']==args.contract['runtime_inventory']['sha256'],'runtime inventory hash differs from authenticated source binding')
        current_path=Path(current['path'])
        if not current_path.is_absolute():current_path=args.source_root/current_path
        reviewed=json.loads(pin_input({'path':str(current_path),'sha256':current['sha256']}).read_text())
        rows=inventory['files'];expected=reviewed.get('files')
        require(reviewed.get('schema')=='hegemon.private-spend.release-inventory.v1' and isinstance(expected,list) and all(isinstance(row,dict) and isinstance(row.get('path'),str) for row in rows+expected),'authenticated runtime path records required')
        paths={row['path'] for row in rows};expected_paths={row['path'] for row in expected}
        require(len(rows)==len(paths) and len(expected)==len(expected_paths) and paths==expected_paths,'runtime inventory path set differs from authenticated source binding')
    return inventory

def source_authorization(args):
    command=[sys.executable,'-I','-B',str(args.source_root/'scripts/check_private_spend_launch_authorization.py'),'--require-authorized']
    child=subprocess.Popen(command,cwd=args.source_root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    OWNED.append(child);out,err=child.communicate()
    require(child.returncode==0,'actual source-owned release authorization did not pass')
    receipt=json.loads(out)
    require(receipt['schema']=='hegemon.private-spend.release-authorization.v2' and receipt['authorization_kind']=='qualified_source_tuple' and receipt['identity']==args.identity and receipt['binding_sha256']==args.contract['release_binding_sha256'] and receipt['deployment_verified'] is False,'actual source authorization tuple changed')
    registry=json.loads((args.source_root/'scripts/private_spend_launch_authorized_registry.json').read_text())
    binding=registry['release']['binding'];require(binding['sha256']==args.contract['release_binding_sha256'],'source binding differs')
    require(sha(args.source_root/binding['path'])==binding['sha256'],'source binding bytes changed')
    bound=json.loads((args.source_root/binding['path']).read_text())
    require(bound[args.manifest_field]['sha256']==args.contract[args.manifest_field]['sha256'] and bound['runtime_inventory']['sha256']==args.contract['runtime_inventory']['sha256'],'lifecycle inputs differ from exact source-reviewed network/source inventory')
    inventory=authenticated_inventory(args,bound)
    for row in inventory['files']:require(sha(args.source_root/row['path'])==row['sha256'],'current runtime source changed')
    for name,item in args.contract['binaries'].items():
        p=pin_input(item);require(p.is_relative_to(args.source_root),'produced binary must be below release checkout')
    require({name:args.contract['binaries'][name]['sha256'] for name in ('hegemon-node','wallet','walletd')}==args.contract['artifact_sha256'],'produced release artifact hash map differs')
    return receipt

def resource_check(snapshot):
    record=json.loads(snapshot.read_text())
    checked=datetime.datetime.fromisoformat(record['checked_at'].replace('Z','+00:00'))
    age=(datetime.datetime.now(datetime.timezone.utc)-checked).total_seconds()
    require(0<=age<=45 and record['snapshot_kind']=='actual-account-quota' and record['policy']=='ordinary-quota-supervision','sole ordinary-quota snapshot stale or malformed')
    require(record['ordinary_floor_percent']==RESOURCE_FLOOR and type(record['ordinary_remaining_percent']) in (int,float) and record['ordinary_remaining_percent']>RESOURCE_FLOOR and record['ordinary_usage_allowed'] is True,'inclusive ordinary quota floor reached')
    require(shutil.disk_usage(OUT or Path.cwd()).free>DISK_RESERVE,'selected disk reserve reached')

def supervise(snapshot):
    while not RESOURCE_STOP.wait(.5):
        try:resource_check(snapshot)
        except BaseException:
            os.kill(os.getpid(),signal.SIGTERM);return

def fixture_custody(fixture):
    """Validate the explicit custody schema without inventing a launch recipient."""
    require(isinstance(fixture,dict),'private custody fixture must be an object')
    if fixture.get('schema')=='hegemon.private-spend.private-release-fixture.v1':
        require(set(fixture)=={'schema','chain_id','funding_address','account_id','descriptor','signers'},'legacy private custody fixture fields differ')
        require(isinstance(fixture['account_id'],str) and len(fixture['account_id'])==64 and len(bytes.fromhex(fixture['account_id']))==32,'canonical treasury account id')
        mode='2-of-3'
    elif fixture.get('schema')=='hegemon.private-spend.private-release-fixture.v3':
        require(set(fixture)=={'schema','chain_id','funding_address','custody','signers','operator_custody_rehearsal'} and fixture['custody']=='external-single-key','external single-key custody fixture schema')
        h.public_v8_address_keys(fixture['funding_address'])
        mode='external-single-key'
    else:
        require(fixture.get('schema')=='hegemon.private-spend.private-release-fixture.v2' and set(fixture)=={'schema','chain_id','funding_address','custody','signers'} and fixture['custody']=='single-key','single-key custody fixture schema')
        mode='single-key'
    require(isinstance(fixture['signers'],list) and len(fixture['signers'])==3,'three existing disposable lifecycle actor stores required')
    for signer in fixture['signers']:
        require(isinstance(signer,dict) and set(signer)=={'wallet','passphrase','public'} and isinstance(signer['public'],dict) and set(signer['public'])=={'signer_tag','signer_receive_address'},'custody signer fields differ')
        require(len(bytes.fromhex(signer['public']['signer_tag']))==56,'full seven-limb signer tag required')
    if mode in ('single-key','external-single-key'):
        require(len({signer['public']['signer_tag'] for signer in fixture['signers']})==3,'single-key lifecycle actors must have distinct credentials')
    if mode=='external-single-key':
        require(all(signer['public']['signer_receive_address']!=fixture['funding_address'] for signer in fixture['signers']),'external treasury must not be one of the disposable actors')
    if mode=='single-key':
        require(fixture['funding_address']==fixture['signers'][0]['public']['signer_receive_address'],'single-key funding recipient must be the supplied first actor address')
        require(len({signer['public']['signer_tag'] for signer in fixture['signers']})==3,'single-key lifecycle actors must have distinct credentials')
    return mode

def load_args(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract',type=Path,required=True);parser.add_argument('--contract-sha256',required=True)
    parser.add_argument('--private-fixture',type=Path,required=True);parser.add_argument('--private-fixture-sha256',required=True)
    parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--quota-snapshot',type=Path,required=True)
    parser.add_argument('--canonical-prefix',type=Path)
    parser.add_argument('--canonical-prefix-sha256')
    parser.add_argument('--ordinary-floor-percent',type=int,default=40,help='latest authorized ordinary remaining-quota floor; snapshot must match')
    args=parser.parse_args(argv);args.source_root=args.source_root.resolve(strict=True)
    require((args.canonical_prefix is None)==(args.canonical_prefix_sha256 is None),'prefix path and hash must be supplied together')
    contract_path=pin_input({'path':str(args.contract),'sha256':args.contract_sha256});args.contract_path=contract_path;args.contract=json.loads(contract_path.read_text())
    legacy=args.contract.get('schema')=='hegemon.private-spend.local-release-lifecycle-input.v1'
    require(legacy or args.contract.get('schema')=='hegemon.private-spend.local-release-lifecycle-input.v2','lifecycle contract schema')
    args.manifest_field='mainnet_manifest' if legacy else 'network_manifest'
    require(set(args.contract)=={'schema','release_binding_sha256','identity',args.manifest_field,'runtime_inventory','binaries','artifact_sha256','parameters','cases','transport','compression_mode_id','emission_schedule_id','harness_sha256','io_sha256','watchdog_sha256'},'exact release lifecycle contract fields required')
    require(0<=args.ordinary_floor_percent<100,'ordinary quota floor must be in [0,100)')
    args.identity=args.contract['identity'];require(args.identity['kind']=='PrivateSpend' and args.identity['activation_height']==1,'retained canonical height-one treasury lifecycle requires an approved activation at one')
    require(args.contract['compression_mode_id']==args.identity['compression_mode'] and args.contract['emission_schedule_id']==args.identity['emission_schedule'],'mode/supply identity differs')
    require(set(args.contract['binaries'])=={'hegemon-node','wallet','walletd','private-spend','treasury-v8'},'three release binaries and two actual production wallet tools required')
    args.node=pin_input(args.contract['binaries']['hegemon-node']);args.private_spend=pin_input(args.contract['binaries']['private-spend']);args.treasury_v8=pin_input(args.contract['binaries']['treasury-v8'])
    require(args.node.name=='hegemon-node','retained receipt key requires canonical node name')
    require(args.contract['harness_sha256']==sha(__file__) and args.contract['io_sha256']==sha(Path(h.__file__)) and args.contract['watchdog_sha256']==sha(Path(__file__).with_name('release_private_spend_progress_watchdog.py')),'source-frozen harness bytes differ')
    manifest=json.loads(pin_input(args.contract[args.manifest_field]).read_text())
    args.network_profile='mainnet' if legacy else args.identity.get('network_profile')
    require(args.network_profile in ('pre-mainnet','mainnet') and manifest['profile']==args.network_profile and 'development_candidate' not in manifest,'explicit release profile must match identity and cannot carry Development authority')
    fixture_path=pin_input({'path':str(args.private_fixture),'sha256':args.private_fixture_sha256});args.fixture=json.loads(fixture_path.read_text())
    args.custody=fixture_custody(args.fixture)
    args.custody_rehearsal=None
    if args.custody=='external-single-key':
        require(not legacy and args.network_profile=='pre-mainnet','external treasury observation requires explicit pre-mainnet lifecycle v2')
        args.custody_rehearsal=pin_input(args.fixture['operator_custody_rehearsal'])
        rehearsal=json.loads(args.custody_rehearsal.read_text())
        require(rehearsal.get('schema')=='hegemon.treasury.backup-restore-rehearsal.v1' and rehearsal.get('status')=='PASSED_LOCAL_RESTORE_REHEARSAL' and rehearsal.get('public_records_match') is True and rehearsal.get('address_sha256')==hashlib.sha256(args.fixture['funding_address'].encode('ascii')).hexdigest(),'external treasury custody rehearsal does not bind the exact recipient')
    require(args.fixture['chain_id']==args.identity['chain_id'] and args.fixture['funding_address']==manifest['funding_address'],'custodians do not match supplied approved network')
    for signer in args.fixture['signers']:
        for key in ('wallet','passphrase'):pin_input(signer[key])
    descriptor=None
    if args.custody=='2-of-3':
        descriptor=json.loads(pin_input(args.fixture['descriptor']).read_text())
        require(bytes(descriptor['chain_id']).hex()==args.identity['chain_id'] and bytes(descriptor['account_id']).hex()==args.fixture['account_id'],'descriptor chain/account mismatch')
        require(len(descriptor['signer_tags'])==3,'exact current 2-of-3 policy required')
    require(set(args.contract['cases'])=={'ordinary','approval','final','lock','claim','refund'},'all six geometry cases required')
    if legacy:
        require(all(row=={'carrier_bytes':1931869,'proof_bytes':1926125} for row in args.contract['cases'].values()),'exact historical SMZD geometry required')
    else:
        require(all(isinstance(row,dict) and set(row)=={'carrier_bytes','proof_bytes'} and isinstance(row['carrier_bytes'],int) and not isinstance(row['carrier_bytes'],bool) and isinstance(row['proof_bytes'],int) and not isinstance(row['proof_bytes'],bool) and 4<=row['proof_bytes']<=args.contract['parameters']['max_proof_bytes'] and row['carrier_bytes']==row['proof_bytes']+args.contract['transport']['fixed_bytes'] and row['carrier_bytes']<=args.contract['parameters']['max_carrier_bytes'] for row in args.contract['cases'].values()),'current measured case geometry must match actual native parameter bounds')
    require(args.contract['parameters']['relation_digest']==args.identity['relation_digest'],'current common relation binding required')
    require(args.contract['parameters']['public_words']==77 if legacy else isinstance(args.contract['parameters']['public_words'],int) and not isinstance(args.contract['parameters']['public_words'],bool) and args.contract['parameters']['public_words']>0,'actual current native public word count required')
    expected_transport={'magic':'484750534c433031','identity':'01000b00070001000f000800020c0100','inner_magic':'534d5a44','fixed_bytes':5744} if legacy else {'magic':'484750534c433032','identity':'01000c00070001000f000800020c0100','inner_magic':'534d5a4c','fixed_bytes':5784}
    require(args.contract['transport']==expected_transport,'exact profile-specific common transport required')
    args.inventory=pin_input(args.contract['runtime_inventory'])
    args.contract['cases']=dict(args.contract['cases'])
    args.fresh_cases=set(args.contract['cases']) if args.custody=='2-of-3' else {'ordinary','lock','claim','refund'}
    return args,manifest,descriptor

def verified_signer_public(args,index):
    """Current public-tag is bare hex; historical JSON output remains accepted."""
    wallet=OUT/f'signer-{index}.store';phrase=OUT/f'signer-{index}.pass'
    output=capture([args.treasury_v8,'public-tag','--wallet',wallet,'--passphrase-file',phrase]).strip()
    if output.startswith('{'):
        return jline(output)
    require(re.fullmatch('[0-9a-f]{112}',output) is not None,'signer public tag is not canonical56-byte hex')
    record=jline(wallet_cli(args.private_spend,['--wallet',wallet,'bootstrap-address','--index','0'],[(h.PASS_PROMPT,bytearray(phrase.read_bytes().strip()))]))
    require(record.get('schema')=='hegemon.private-spend.bootstrap.v1' and record.get('custody')=='single-key' and record.get('address_index')==0,'offline signer address record differs')
    return {'signer_tag':output,'signer_receive_address':record['address']}

def main():
    global OUT,STATE,a,RESOURCE_FLOOR,DISK_RESERVE
    a,manifest,bound=load_args();RESOURCE_FLOOR=a.ordinary_floor_percent
    DISK_RESERVE=(15 if a.contract['schema']=='hegemon.private-spend.local-release-lifecycle-input.v2' else 5)*2**30
    resource_check(a.quota_snapshot);source_authorization(a)
    OUT=a.root.absolute();require(not OUT.exists() and not OUT.is_relative_to(a.source_root),'fresh private lifecycle root must be outside release source tree')
    OUT.mkdir(mode=0o700,parents=True)
    STATE={'schema':'hegemon.private-spend.actualnode.compff01.v1','status':'NON_PASS','production_authorized':False,'deployment_verified':False,'gates':{},'owned_processes':[],'runtime_inventory_sha256':sha(a.inventory),'emission_schedule_id':a.identity['emission_schedule'],'release_identity':a.identity,'artifact_sha256':a.contract['artifact_sha256'],'contract_sha256':sha(a.contract_path),'harness_sha256':sha(__file__),'recovered_helper_sha256':sha(Path(h.__file__)),'binaries':{name:dict(item) for name,item in a.contract['binaries'].items()},'manifest':manifest,'genesis':'0x'+a.identity['genesis_hash']}
    STATE.update(custody=a.custody,required_fresh_proof_cases=sorted(a.fresh_cases),fresh_proof_cases=[],reused_proof_cases=[],unexercised_proof_cases=sorted(set(a.contract['cases'])-a.fresh_cases),release_gate_closed=False)
    if a.custody=='external-single-key':
        STATE.update(treasury_custody_status='operator_custody_rehearsed_not_spent',treasury_spend_exercised=False,operator_custody_rehearsal=dict(a.fixture['operator_custody_rehearsal']),unexercised_release_checks=['treasury_payout','treasury_single_key_payout','treasury_single_key_payout_reorg_rollback','treasury_single_key_payout_unchanged_resubmission'])
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    supervisor=threading.Thread(target=supervise,args=(a.quota_snapshot,),daemon=True);supervisor.start();nodes=[]
    try:
        for port in (31371,31372,31373,31374,20971,20972,20973,20974):
            with socket.socket() as sock:sock.bind(('127.0.0.1',port))
        watchdog_path=Path(__file__).with_name('release_private_spend_progress_watchdog.py')
        ws=importlib.util.spec_from_file_location('release_lifecycle_watchdog',watchdog_path);wd=importlib.util.module_from_spec(ws);ws.loader.exec_module(wd);wd.install(sys.modules[__name__])
        STATE['progress_watchdog_sha256']=sha(watchdog_path)
        os.environ['RUST_LOG']='info,hegemon_node=debug';STATE['node_log_filter']=os.environ['RUST_LOG']
        signers=[]
        for i,signer in enumerate(a.fixture['signers']):
            private(OUT/f'signer-{i}.store',pin_input(signer['wallet']).read_bytes())
            private(OUT/f'signer-{i}.pass',pin_input(signer['passphrase']).read_bytes())
            public=verified_signer_public(a,i)
            require(public==signer['public'],'copied encrypted wallet custodian differs');signers.append(public)
        if a.custody=='2-of-3':
            private(OUT/'policy-bound.json',pin_input(a.fixture['descriptor']).read_bytes())
            capture([a.treasury_v8,'import-policy','--wallet',OUT/'signer-0.store','--passphrase-file',OUT/'signer-0.pass','--private-descriptor',OUT/'policy-bound.json'])
            displayed=jline(capture([a.treasury_v8,'show-policy','--wallet',OUT/'signer-0.store','--passphrase-file',OUT/'signer-0.pass']))
            require(displayed=={'account_id':a.fixture['account_id'],'chain_id':a.identity['chain_id'],'receive_address':manifest['funding_address'],'threshold':2,'signers':3},'actual encrypted custodian cannot control approved funding recipient')
        elif a.custody=='single-key':
            require(signers[0]['signer_receive_address']==manifest['funding_address'],'actual single-key custodian cannot control approved funding recipient')
        else:
            require(all(signer['signer_receive_address']!=manifest['funding_address'] for signer in signers),'external recipient unexpectedly belongs to a disposable actor')
        miner=signers[0]['signer_receive_address'];STATE['miner']=miner;h.atomic_json(OUT/'manifest.json',manifest);save()
        checkpoint=restore_canonical_prefix(a,miner)
        nodes,urls=pair(a,miner);ua,ub=urls;cfg=h.rpc(ua,'hegemon_nodeConfig')
        verify_canonical_prefix(checkpoint,urls)
        if a.custody=='2-of-3':
            account=a.fixture['account_id'];active=[tuple(tag) for tag in bound['signer_tags'][:3]]
            require(active==sorted(active) and len(set(active))==3,'descriptor signer order differs')
            slots={}
            for i,signer in enumerate(signers):
                tag=bytes.fromhex(signer['signer_tag']);require(len(tag)==56,'public signer tag geometry differs')
                words=tuple(int.from_bytes(tag[n:n+8],'little') for n in range(0,56,8))
                require(active.count(words)==1,'wallet signer does not match one descriptor slot')
                slots[i]=active.index(words)
            require(len(set(slots.values()))==3,'signer slots not distinct');STATE['signer_slots']=slots;save()
            for i in (1,2):capture([a.treasury_v8,'import-policy','--wallet',OUT/f'signer-{i}.store','--passphrase-file',OUT/f'signer-{i}.pass','--private-descriptor',OUT/'policy-bound.json'])
        for i in range(3):ps(a,i,ua,['sync'])
        addresses=[ps(a,i,ua,['address','--index','0']).strip().splitlines()[-1] for i in range(3)];require(addresses[0]==miner,'miner ownership mismatch')
        # Reward at h is first spendable in block h+120. Mine enough for six
        # independent early rewards before constructing any funded spend.
        mining(ua,126);tip=converge(urls);mark('canonical_issuance');mark('reward_maturity_wait')
        allocated_position=None
        if a.custody=='single-key':
            # Keep the actual allocated reward unspent until the treasury-payout
            # assertion; the same key owns miner and treasury rewards here.
            _,allocated_commit,_=treasury_reward(ua,1)
            ps(a,0,ua,['sync'])
            allocated=jline(capture([a.treasury_v8,'canonical-position','--wallet',OUT/'signer-0.store','--passphrase-file',OUT/'signer-0.pass','--commitment',allocated_commit]))['positions']
            require(len(allocated)==1,'ambiguous allocated commitment');allocated_position=allocated[0]
        # Real ordinary transfers fund distinct signer fee notes.
        for i in (1,2):
            src=next(x for x in notes(a,0,ua) if x[0]=='ordinary' and x[2]>10000000 and x[1]!=allocated_position)
            action(a,0,urls,'fee_fund_'+str(i),['ordinary','--inputs',str(src[1]),'--recipient',addresses[i],'--amount','10000000','--fee','1000'])
        # Claim uses the exact persisted preimage bound by the freshly generated Lock.
        private(OUT/'claim-preimage.hex',os.urandom(32).hex().encode()+b'\n');pre=bytes.fromhex((OUT/'claim-preimage.hex').read_text().strip())
        srcs=[x for x in notes(a,0,ua) if x[0]=='ordinary' and x[2]>1001000 and x[1]!=allocated_position];require(len(srcs)>=2,'distinct lock and fee inputs missing')
        timeout=h.height(ua)+100
        action(a,0,urls,'claim_lock',['lock','--inputs',str(srcs[0][1]),'--claim',addresses[0],'--refund',addresses[1],'--hashlock',hashlib.sha256(pre).hexdigest(),'--timeout',str(timeout),'--amount','1000000','--fee','1000'])
        locked=next(x[1] for x in notes(a,0,ua) if x[0]=='htlc')

        action(a,0,urls,'claim',['claim','--locked',str(locked),'--fee-input',str(srcs[1][1]),'--recipient',addresses[0],'--fee','1000'],[(b'Private 32-byte preimage (hex): ',bytearray(pre.hex().encode()))])
        require(any(x[0]=='ordinary' and x[2]==1000000 for x in notes(a,0,ua)),'claim payout missing');mark('claim_payout')
        ua,ub=urls
        if a.custody=='external-single-key':
            external_treasury_readback(a,urls)
        else:
            # Treasury value is a real canonical public allocated coinbase note.
            opening,commit,bh=treasury_reward(ua,1);op=OUT/'allocated-opening.json';h.atomic_json(op,opening)
            ps(a,0,ua,['sync']);pos=jline(capture([a.treasury_v8,'canonical-position','--wallet',OUT/'signer-0.store','--passphrase-file',OUT/'signer-0.pass','--commitment',commit]))['positions'];require(len(pos)==1,'ambiguous allocated commitment')
            position=pos[0];mark('treasury_canonical_value');amount=opening['value']//2
            if a.custody=='single-key':
                require(any(x[0]=='ordinary' and x[1]==position and x[2]==opening['value'] for x in notes(a,0,ua)),'single-key treasury reward not owned by supplied wallet')
                action(a,0,urls,'treasury_single_key_payout',['ordinary','--inputs',str(position),'--recipient',addresses[2],'--amount',str(amount),'--fee','1000'])
            else:
                capture([a.treasury_v8,'import-coinbase','--wallet',OUT/'signer-0.store','--passphrase-file',OUT/'signer-0.pass','--account-id',account,'--public-opening',op,'--position',str(position)]);mark('treasury_canonical_value')
                fees=[next(x[1] for x in notes(a,i,ua) if x[0]=='ordinary' and x[2]==10000000) for i in (1,2)]
                amount=opening['value']//2;template=ids(ps(a,0,ua,['treasury-propose','--account',account,'--value-position',str(position),'--recipient',addresses[2],'--amount',str(amount),'--change',addresses[0],'--fee','1000']),'template')
                handoff=OUT/'treasury-template.enc';hp=(OUT/'signer-1.pass').read_bytes().strip();ps(a,0,ua,['export-template',template,str(handoff)],[(b'Encrypted handoff passphrase: ',bytearray(hp))])
                tids=[ids(ps(a,i,ua,['import-template',str(handoff)],[(b'Encrypted handoff passphrase: ',bytearray(hp))]),'template') for i in (1,2)]
                STATE['treasury_cursor']={'template_ids':{'0':template,'1':tids[0],'2':tids[1]},'fee_positions':fees,'value_position':position,'signer_slots':slots};save()
                action(a,1,urls,'approval1',['treasury-approve','--template',tids[0],'--signer',str(slots[1]),'--fee-input',str(fees[0]),'--next-recipient',addresses[2],'--fee','1000'])
                acc1=next(x[1] for x in notes(a,2,ua) if x[0]=='accumulator')
                action(a,2,urls,'approval2',['treasury-approve','--template',tids[1],'--accumulator',str(acc1),'--signer',str(slots[2]),'--fee-input',str(fees[1]),'--next-recipient',addresses[0],'--fee','1000'])
                acc2=next(x[1] for x in notes(a,0,ua) if x[0]=='accumulator')

                action(a,0,urls,'final',['treasury-finalize','--template',template,'--account',account,'--value-position',str(position),'--accumulator',str(acc2)])
            require(any(x[0]=='ordinary' and x[2]==amount for x in notes(a,2,ua)),'treasury payout missing');mark('treasury_payout')
        ua,ub=urls
        # A separate locked output exercises the Refund selector with a distinct custodian.
        src=next(x for x in notes(a,0,ua) if x[0]=='ordinary' and x[2]>1001000)
        refundfee=next(x[1] for x in notes(a,1,ua) if x[0]=='ordinary' and x[2]>=1000)
        timeout=h.height(ua)+16;handoff=OUT/'refund.handoff';rp=(OUT/'signer-1.pass').read_bytes().strip()
        lockrow=action(a,0,urls,'refund_lock',['lock','--inputs',str(src[1]),'--claim',addresses[0],'--refund',addresses[1],'--hashlock','00'*32,'--timeout',str(timeout),'--amount','1000000','--fee','1000','--refund-handoff',str(handoff)],[(h.HANDOFF_PROMPT,bytearray(rp))])
        ps(a,1,ua,['import-refund-handoff',str(handoff),'--block-height',str(lockrow['height']),'--refund-index','0'],[(h.HANDOFF_PROMPT,bytearray(rp))])
        locked=next(x[1] for x in notes(a,1,ua) if x[0]=='htlc')
        mining(ua,timeout+1);converge(urls);
        action(a,1,urls,'refund',['refund','--locked',str(locked),'--fee-input',str(refundfee),'--recipient',addresses[1],'--fee','1000'])
        require(any(x[0]=='ordinary' and x[2]==1000000 for x in notes(a,1,ua)),'refund payout missing');mark('refund_payout')
        ua,ub=urls
        # Retained exact carriers survive persistent restart and a fresh node sync.
        for p0 in active_nodes():stop(p0)
        nodes,urls=pair(a,miner);ua,ub=urls;mark('persistent_restart')
        pc,uc,_=start(a,'node-c',31373,20973,'127.0.0.1:31371,127.0.0.1:31372',miner);nodes.append(pc)
        target=h.height(ua);wait(lambda:h.height(uc)>=target,'fresh node full sync');converge(urls+[uc])
        STATE['canonical_bodies']=canonical_bodies(urls+[uc]);mark('fresh_node_all_bodies')
        if a.custody=='external-single-key':external_treasury_readback(a,urls+[uc])
        for name,row in STATE['actions'].items():
            selected=STATE.get('resubmitted_'+name,row);check=inspect(OUT/(name+'.action'),urls+[uc],selected['height'],selected['height']);require(check['action_sha256']==row['action_sha256'],'carrier changed')
        fresh={row['case'] for row in STATE['proofs'].values()}
        require(fresh==a.fresh_cases,'required fresh wallet cases missing')
        STATE['fresh_proof_cases']=sorted(fresh)
        expected={'fee_fund_1','fee_fund_2','claim_lock','claim','refund_lock','refund'}
        expected.update({'approval1','approval2','final'} if a.custody=='2-of-3' else ({'treasury_single_key_payout'} if a.custody=='single-key' else set()))
        require(set(STATE['actions'])==expected,'required fresh actions missing');require(all(STATE['gates'].get(name+'_unchanged_resubmission') for name in STATE['actions']),'per-action reorg lifecycle missing');source_authorization(a)
        mark('all_exact_carriers_restart_fresh_node')
        # Single-key validation does not silently replace the release gate's
        # six-case evidence requirement. Approval/final remain unexercised here;
        # any reuse needs a separate explicit review of exact source/backend pins.
        STATE['status']={'2-of-3':'PASS_LOCAL_RELEASE_TUPLE','single-key':'PASS_LOCAL_SINGLE_KEY_INTERFACE_LIFECYCLE','external-single-key':'PASS_LOCAL_EXTERNAL_TREASURY_NETWORK_LIFECYCLE'}[a.custody]
        save()
    except Exception as e:
        STATE['failure']=str(e)[:240];save();raise
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        for proc in OWNED:
            if proc.poll() is None:
                try:stop(proc)
                except Exception as e:STATE['cleanup_error']=str(e);STATE['status']='NON_PASS'
            STATE['owned_processes'].append({'pid':proc.pid,'exit_code':proc.returncode,'reaped':proc.poll() is not None})
        STATE['all_owned_reaped']=all(p0.poll() is not None for p0 in OWNED);STATE['all_owned_exit0']=all(p0.returncode==0 for p0 in OWNED);STATE['rpc_closed']=all(closed_rpc(port) for port in (20971,20972,20973,20974));
        if not (STATE['all_owned_reaped'] and STATE['all_owned_exit0'] and STATE['rpc_closed']):STATE['status']='NON_PASS'
        RESOURCE_STOP.set();supervisor.join(timeout=2);save()

if __name__ == "__main__":
    main()
