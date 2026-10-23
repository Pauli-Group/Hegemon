"""Harness-only 180s stall watchdog; queued cursor progress never proves adoption."""
import hashlib, re, time
from pathlib import Path

ANNOUNCE=re.compile(r'received complete native sync announce peer=(0x[0-9a-f]{64}) height=(\d+) hash=(0x[0-9a-f]{64})')
REQUEST=re.compile(r'queued native sync target request best_height=\d+ target=(\d+) from_height=(\d+) to_height=(\d+) target_peer="(0x[0-9a-f]{64})"')

class ForwardCursor:
    def __init__(self, target, target_hash):
        self.target=target;self.target_hash=target_hash;self.peers={};self.minimum=None;self.high=None
    def line(self, line):
        announce=ANNOUNCE.search(line)
        if announce:
            peer,height,block_hash=announce.groups();self.peers[peer]=(int(height),block_hash)
        request=REQUEST.search(line)
        if not request:return None
        target,start,end,peer=request.groups();target,start,end=map(int,(target,start,end))
        if target!=self.target or end!=self.target or not 1<=start<=self.target or self.peers.get(peer)!=(self.target,self.target_hash):return None
        if self.high is None:
            if self.minimum is None or start<=self.minimum:
                self.minimum=start;return None
            # Ignore the early high request and all descending backfill. Only
            # the first upward edge from the minimum establishes a highwater.
            self.high=start;return start
        if start>self.high:self.high=start;return start
        return None

def install(module):
    original_start=module.start;original_wait=module.wait;logs={}
    def start(*args,**kwargs):
        name=args[1];before=set(module.OUT.glob(name+'-*.log'));result=original_start(*args,**kwargs)
        added=set(module.OUT.glob(name+'-*.log'))-before
        module.require(len(added)==1,'watchdog must bind one exact fresh node log')
        logs[result[1]]=next(iter(added));return result
    def wait(fn,label):
        v={name:cell.cell_contents for name,cell in zip(fn.__code__.co_freevars,fn.__closure__ or ())}
        if label=='retained actual CLAIM fork adoption':target,block_hash,urls=v['target_height'],v['target_hash'],[v['ua'],v['ub']]
        elif label=='higher work adoption':target,block_hash,urls=v['forktip'],v['forkhash'],[v['ua'],v['ub']]
        elif label=='current-node historical higher-work adoption':target,block_hash,urls=v['winner_height'],v['fork']['fork_hash'],[v['ua'],v['ub']]
        elif label=='fresh node full sync':
            target=v['target'];urls=[v['uc']];sources=[u for u in logs if u not in urls]
            hashes=[]
            for url in sources:
                try:
                    if module.h.height(url)>=target:hashes.append(module.h.rpc(url,'chain_getBlockHash',[target]))
                except (module.h.GateError,ConnectionError,OSError,ValueError):pass
            module.require(hashes and len(set(hashes))==1,'fresh sync target not bound to live canonical source');block_hash=hashes[0]
        else:return original_wait(fn,label)
        module.require(all(url in logs for url in urls),'missing exact current node log')
        began=time.monotonic();last=began;states={u:ForwardCursor(target,block_hash) for u in urls};offsets={u:0 for u in urls};pending={u:b'' for u in urls};canonical_high={u:None for u in urls}
        entry={'label':label,'target_height':target,'target_hash':block_hash,'stall_seconds':180,'total_runtime_cap':None,'logs':{u:str(logs[u]) for u in urls},'events':[]}
        module.STATE.setdefault('progress_watchdog_runs',[]).append(entry);module.save()
        try:
            while True:
                try:
                    result=fn()
                    if result:entry['result']='predicate_satisfied';return result
                except (module.h.GateError,ConnectionError,OSError,ValueError):pass
                for url in urls:
                    with logs[url].open('rb') as stream:
                        stream.seek(offsets[url]);data=stream.read();offsets[url]=stream.tell()
                    parts=(pending[url]+data).split(b'\n');pending[url]=parts.pop()
                    for raw in parts:
                        cursor=states[url].line(raw.decode('utf-8','replace'))
                        if cursor is not None:
                            now=time.monotonic();last=now
                            entry['events'].append({'kind':'forward_request_cursor','url':url,'from_height':cursor,'elapsed_seconds':now-began,'log_offset':offsets[url],'line_sha256':hashlib.sha256(raw).hexdigest()});module.save()
                    # Exact canonical progress is a stronger independent signal.
                    try:
                        height=module.h.height(url);h=module.h.rpc(url,'chain_getBlockHash',[height]);expected=module.h.rpc('http://127.0.0.1:20971','chain_getBlockHash',[height])
                        if canonical_high[url] is None:canonical_high[url]=height
                        elif height>canonical_high[url] and height<=target and h==expected:
                            canonical_high[url]=height;now=time.monotonic();last=now;entry['events'].append({'kind':'canonical_height','url':url,'height':height,'hash':h,'elapsed_seconds':now-began});module.save()
                    except (module.h.GateError,ConnectionError,OSError,ValueError):pass
                if time.monotonic()-last>180:
                    entry['result']='stalled_180_seconds';raise RuntimeError('no verified forward cursor/canonical progress for180s at '+label)
                time.sleep(.25)
        finally:
            entry['elapsed_seconds']=time.monotonic()-began;entry['stall_age_seconds']=time.monotonic()-last
            entry['log_sha256_at_wait_end']={u:hashlib.sha256(logs[u].read_bytes()).hexdigest() for u in urls};module.save()
    module.start=start;module.wait=wait
