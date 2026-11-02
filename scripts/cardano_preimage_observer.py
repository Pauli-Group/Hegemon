"""Observe a confirmed local Cardano HTLC claim through a trusted Ogmios stream.

The transaction CBOR is bound to its body hash and the expected spent output;
the redeemer for that particular input must contain the expected SHA-256
preimage. A rollback, changed ancestry, disconnect or timeout fails closed.
The node and its locally configured Ogmios process are trust assumptions.
"""
import hashlib
import io
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
import cbor2
from websockets.sync.client import connect
from cardano_local_actions import local_node_identity


def local_ogmios_identity(pid,url,node_socket,node_config):
    parsed=urlsplit(url)
    if type(pid) is not int or pid<=0 or parsed.scheme!='ws' or parsed.hostname!='127.0.0.1' or not parsed.port or parsed.username or parsed.path not in ('','/') or parsed.query or parsed.fragment:raise ValueError('invalid local Ogmios identity')
    proc=Path('/proc')/str(pid)
    if proc.stat().st_uid!=os.getuid() or os.path.basename(os.readlink(proc/'exe'))!='ogmios':raise ValueError('configured process is not local Ogmios')
    args=(proc/'cmdline').read_bytes().split(b'\0')
    for flag,expected in ((b'--node-socket',Path(node_socket)),(b'--node-config',Path(node_config))):
        if flag not in args or Path(os.fsdecode(args[args.index(flag)+1])).resolve()!=expected.resolve():raise ValueError('Ogmios node configuration mismatch')
    if b'--host' not in args or args[args.index(b'--host')+1]!=b'127.0.0.1' or b'--port' not in args or args[args.index(b'--port')+1]!=str(parsed.port).encode() or not ({b'--include-cbor',b'--include-transaction-cbor'}&set(args)):raise ValueError('Ogmios must listen on loopback and include transaction CBOR')
    inodes=set()
    for fd in (proc/'fd').iterdir():
        try:target=os.readlink(fd)
        except FileNotFoundError:continue
        if target.startswith('socket:['):inodes.add(target[8:-1])
    expected='0100007F:'+format(parsed.port,'04X')
    if not any((fields:=line.split())[1].upper()==expected and fields[3]=='0A' and fields[9] in inodes for line in (proc/'net/tcp').read_text().splitlines()[1:]):raise ValueError('Ogmios does not own the configured loopback listener')
    return (proc/'stat').read_text().rsplit(')',1)[1].split()[19]


def claim_preimage(txid,tx_cbor,outref,hashlock):
    if not isinstance(txid,str) or not re.fullmatch('[0-9a-f]{64}',txid) or not isinstance(outref,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]{0,9})',outref) or not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock):raise ValueError('invalid Cardano observation terms')
    if not isinstance(tx_cbor,str) or len(tx_cbor)>2_000_000 or len(tx_cbor)%2 or not re.fullmatch('[0-9a-f]+',tx_cbor):raise ValueError('invalid Cardano transaction CBOR')
    raw=bytes.fromhex(tx_cbor)
    if not raw or raw[0]!=0x84:raise ValueError('unsupported Cardano transaction encoding')
    try:
        source=io.BytesIO(raw);source.seek(1);cbor2.CBORDecoder(source).decode();body_end=source.tell()
        source.seek(0);tx=cbor2.CBORDecoder(source).decode()
        if source.tell()!=len(raw) or not isinstance(tx,list) or len(tx)!=4 or not isinstance(tx[0],dict) or not isinstance(tx[1],dict):raise ValueError('invalid Cardano transaction')
    except (cbor2.CBORDecodeError,EOFError,TypeError,RecursionError) as e:raise ValueError('invalid Cardano transaction CBOR') from e
    if hashlib.blake2b(raw[1:body_end],digest_size=32).hexdigest()!=txid:raise ValueError('Cardano transaction ID mismatch')
    if tx[2] is not True:return None
    inputs=tx[0].get(0)
    if not isinstance(inputs,(set,list,tuple)):raise ValueError('invalid Cardano transaction inputs')
    normalized=[]
    for item in inputs:
        if not isinstance(item,(list,tuple)) or len(item)!=2 or not isinstance(item[0],bytes) or len(item[0])!=32 or type(item[1]) is not int or not 0<=item[1]<=0xffffffff:raise ValueError('invalid Cardano transaction input')
        normalized.append((item[0],item[1]))
    if len(set(normalized))!=len(normalized):raise ValueError('duplicate Cardano transaction input')
    tx_hash,index=outref.split('#');target=(bytes.fromhex(tx_hash),int(index))
    if target not in normalized:return None
    spend_index=sorted(normalized).index(target);redeemers=tx[1].get(5)
    if isinstance(redeemers,dict):entry=redeemers.get((0,spend_index))
    elif isinstance(redeemers,list):
        matches=[entry[2:] for entry in redeemers if isinstance(entry,(list,tuple)) and len(entry)==4 and entry[0]==0 and entry[1]==spend_index]
        if len(matches)>1:raise ValueError('duplicate Cardano spend redeemer')
        entry=matches[0] if matches else None
    else:entry=None
    if not isinstance(entry,(list,tuple)) or not entry:return None
    data=entry[0]
    if not isinstance(data,cbor2.CBORTag) or data.tag!=121 or not isinstance(data.value,(list,tuple)) or len(data.value)!=1 or not isinstance(data.value[0],bytes) or len(data.value[0])!=32:return None
    secret=bytearray(data.value[0])
    if hashlib.sha256(secret).hexdigest()!=hashlock:secret[:]=b'\0'*len(secret);return None
    return secret


def observe_preimage(url,checkpoint,outref,hashlock,*,confirmations=2,timeout=120,max_blocks=10000):
    parsed=urlsplit(url)
    if parsed.scheme!='ws' or parsed.hostname!='127.0.0.1' or not parsed.port or parsed.username or parsed.path not in ('','/') or parsed.query or parsed.fragment:raise ValueError('Ogmios must use an explicit loopback WebSocket')
    if not isinstance(checkpoint,dict) or set(checkpoint)!={'slot','id'} or type(checkpoint['slot']) is not int or checkpoint['slot']<0 or not isinstance(checkpoint['id'],str) or not re.fullmatch('[0-9a-f]{64}',checkpoint['id']):raise ValueError('invalid Cardano checkpoint')
    if type(confirmations) is not int or not 1<=confirmations<=100 or not 0<timeout<=3600 or not 1<=max_blocks<=100000:raise ValueError('invalid observation limits')
    # Validate before opening a socket, including references which may never be seen.
    if not isinstance(outref,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]{0,9})',outref) or not isinstance(hashlock,str) or not re.fullmatch('[0-9a-f]{64}',hashlock):raise ValueError('invalid Cardano observation terms')
    deadline=time.monotonic()+timeout;candidate=None;candidate_height=None;previous=checkpoint['id'];last_slot=checkpoint['slot'];previous_height=None;initial=True
    try:
        with connect(url,open_timeout=min(timeout,10),close_timeout=2,max_size=16*1024*1024,proxy=None) as socket:
            socket.send(json.dumps({'jsonrpc':'2.0','method':'findIntersection','params':{'points':[checkpoint]},'id':1}))
            response=json.loads(socket.recv(timeout=max(.1,deadline-time.monotonic())))
            if response.get('id')!=1 or response.get('result',{}).get('intersection')!=checkpoint:raise ValueError('Cardano checkpoint is not on the observed chain')
            for _ in range(max_blocks):
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ValueError('Cardano observation timed out')
                socket.send(json.dumps({'jsonrpc':'2.0','method':'nextBlock','id':2}))
                response=json.loads(socket.recv(timeout=remaining))
                if response.get('id')!=2 or not isinstance(response.get('result'),dict):raise ValueError('invalid Cardano chain response')
                event=response['result']
                if event.get('direction')=='backward':
                    if initial and event.get('point')==checkpoint:initial=False;continue
                    raise ValueError('Cardano chain rolled back; any seen preimage may already be exposed. Restart observation from a safe checkpoint.')
                block=event.get('block')
                if event.get('direction')!='forward' or not isinstance(block,dict) or block.get('ancestor')!=previous or not isinstance(block.get('id'),str) or not re.fullmatch('[0-9a-f]{64}',block['id']) or type(block.get('slot')) is not int or block['slot']<=last_slot or type(block.get('height')) is not int:raise ValueError('Cardano chain ancestry changed')
                if previous_height is not None and block['height']!=previous_height+1:raise ValueError('Cardano block height is not contiguous')
                previous_height=block['height'];initial=False
                previous=block['id'];last_slot=block['slot']
                transactions=block.get('transactions',[])
                if not isinstance(transactions,list):raise ValueError('invalid Cardano block transactions')
                if candidate is None:
                    for tx in transactions:
                        if not isinstance(tx,dict) or not isinstance(tx.get('id'),str) or not isinstance(tx.get('cbor'),str):raise ValueError('Ogmios must include transaction CBOR')
                        found=claim_preimage(tx['id'],tx['cbor'],outref,hashlock)
                        if found is not None:candidate=found;candidate_height=block['height'];break
                if candidate is not None and block['height']-candidate_height+1>=confirmations:
                    result=candidate;candidate=None
                    return result,{'claim_block':candidate_height,'confirmations':block['height']-candidate_height+1,'tip_hash':block['id'],'tip_slot':block['slot']}
            raise ValueError('Cardano observation block limit reached')
    finally:
        if candidate is not None:candidate[:]=b'\0'*len(candidate)


def observe_local_preimage(*,url,ogmios_pid,node_pid,node_socket,network_dir,genesis_hash,checkpoint,outref,hashlock,confirmations=2,timeout=120):
    node_stamp,_=local_node_identity(node_pid,node_socket,network_dir,genesis_hash)
    ogmios_stamp=local_ogmios_identity(ogmios_pid,url,node_socket,Path(network_dir)/'configuration.yaml')
    secret=None
    try:
        secret,snapshot=observe_preimage(url,checkpoint,outref,hashlock,confirmations=confirmations,timeout=timeout)
        if local_node_identity(node_pid,node_socket,network_dir,genesis_hash)[0]!=node_stamp or local_ogmios_identity(ogmios_pid,url,node_socket,Path(network_dir)/'configuration.yaml')!=ogmios_stamp:raise ValueError('Local observation processes changed; the preimage may already be exposed.')
        result=secret;secret=None;return result,snapshot
    finally:
        if secret is not None:secret[:]=b'\0'*len(secret)
