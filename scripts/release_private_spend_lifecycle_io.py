"""Bounded loopback canonical-byte I/O retained from the actual G6 runner.
The pending observer requires a source-authorized production RPC; unsupported
current builds reject instead of substituting a Development observation.
"""
import hashlib, http.client, json, os, urllib.parse
from pathlib import Path
MAX_RPC = 10 * 1024 * 1024
PASS_PROMPT = b"Encrypted wallet passphrase: "
HANDOFF_PROMPT = b"Encrypted refund handoff passphrase: "
class GateError(RuntimeError): pass


def public_v8_address_keys(address):
    """Decode public address-v5 keys only; never opens a wallet or backup.

    Mirrors wallet/src/address.rs's Bech32m/version/suite/length and canonical
    field checks. Native node admission remains authoritative for the KEM key.
    """
    if not isinstance(address, str) or address != address.lower() or not address.startswith('shca1'):
        raise GateError('canonical lowercase shca address required')
    alphabet='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    try: values=[alphabet.index(c) for c in address[5:]]
    except ValueError: raise GateError('invalid address alphabet') from None
    if len(values)<6: raise GateError('truncated address checksum')
    generators=(0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)
    checksum=1
    for value in [ord(c)>>5 for c in 'shca']+[0]+[ord(c)&31 for c in 'shca']+values:
        high=checksum>>25;checksum=((checksum&0x1ffffff)<<5)^value
        for i,generator in enumerate(generators):
            if (high>>i)&1: checksum^=generator
    if checksum!=0x2bc830a3: raise GateError('invalid Bech32m checksum')
    accumulator=0;bits=0;payload=bytearray()
    for value in values[:-6]:
        accumulator=((accumulator<<5)|value)&0xfff;bits+=5
        if bits>=8:
            bits-=8;payload.append((accumulator>>bits)&255)
    if bits>=5 or (accumulator<<(8-bits))&255: raise GateError('noncanonical address padding')
    if len(payload)!=1663 or payload[:3]!=b'\x05\x07\x00':
        raise GateError('full V8 suite-seven address required')
    words=lambda start,count:[int.from_bytes(payload[i:i+8],'little') for i in range(start,start+8*count,8)]
    recipient=words(7,4);authorization=words(39,4);extension=words(71,3)
    if any(word>=((1<<64)-(1<<32)+1) for word in recipient+authorization+extension) or not any(recipient) or not any(authorization):
        raise GateError('noncanonical V8 public key limbs')
    return {'recipient_key':recipient,'authorization_key':authorization,'authorization_extension':extension}

def atomic_json(path, obj):
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, sort_keys=True, indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)


def rpc(url, method, params=None):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise GateError("RPC must use loopback HTTP")
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=15)
    try:
        c.request("POST", u.path or "/", json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or []}), {"Content-Type":"application/json"})
        raw=c.getresponse().read(MAX_RPC+1)
    finally: c.close()
    if len(raw)>MAX_RPC: raise GateError("RPC response exceeded bound")
    r=json.loads(raw)
    if r.get("error"): raise GateError("RPC failed: "+method)
    return r.get("result")


def json_line(text):
    for line in reversed(text.splitlines()):
        try:
            v=json.loads(line)
            if isinstance(v,dict):return v
        except ValueError:pass
    raise GateError("wallet command returned no JSON; output suppressed")


def height(url):
    n=rpc(url,"chain_getHeader")["number"]
    return int(n,16) if isinstance(n,str) and n.startswith("0x") else int(n)


def compact(data, pos):
    b=data[pos]; mode=b&3
    if mode==0:return b>>2,pos+1
    if mode==1:return (((data[pos+1]<<8)|b)>>2),pos+2
    if mode==2:return int.from_bytes(data[pos:pos+4],"little")>>2,pos+4
    n=(b>>2)+4
    if n>8:raise GateError("SCALE compact integer too large")
    return int.from_bytes(data[pos+1:pos+1+n],"little"),pos+1+n


def decode_action_vec(body):
    count,pos=compact(body,0); out=[]
    if count>10000:raise GateError("action vector count exceeds cap")
    for _ in range(count):
        n,pos=compact(body,pos)
        if n>MAX_RPC or pos+n>len(body):raise GateError("malformed action vector")
        out.append(body[pos:pos+n]);pos+=n
    if pos!=len(body):raise GateError("trailing bytes in action body SCALE vector")
    return out


def chunks(url, block_hash):
    first=rpc(url,"chain_getBlockActionsChunk",[block_hash,0])
    schema="hegemon.native.action-body-chunk-v1"
    if first.get("schema")!=schema:raise GateError("canonical body schema mismatch")
    meta={k:first[k] for k in ("height","parent_hash","tx_count","extrinsics_root","action_body_hash","action_body_len","chunk_count")}
    body=bytearray()
    for i in range(first["chunk_count"]):
        r=first if i==0 else rpc(url,"chain_getBlockActionsChunk",[block_hash,i])
        if r.get("schema")!=schema or r.get("chunk_index")!=i or r.get("block_hash").lower()!=block_hash.lower():raise GateError("canonical chunk identity mismatch")
        if any(r.get(k)!=v for k,v in meta.items()):raise GateError("canonical chunk metadata changed")
        b=bytes.fromhex(r["chunk"].removeprefix("0x"))
        if len(b)!=r["chunk_len"]:raise GateError("canonical chunk length mismatch")
        body.extend(b)
    if len(body)!=meta["action_body_len"]:raise GateError("canonical body incomplete")
    return decode_action_vec(bytes(body)),meta,bytes(body)


def pending(url, tx):
    out=bytearray(); off=0; total=None
    while total is None or off<total:
        r=rpc(url,"hegemon_pendingActionChunk",[tx,off,262144])
        if not isinstance(r,dict) or r.get("schema")!="hegemon.pending-action-chunk-v1":raise GateError("pending bytes unavailable")
        if r["tx_hash"].lower()!=tx.lower() or r["offset"]!=off:raise GateError("pending chunk binding mismatch")
        b=bytes.fromhex(r["chunk"].removeprefix("0x"))
        if not b or len(b)!=r["chunk_len"] or (total is not None and total!=r["total_len"]):raise GateError("pending chunk malformed")
        total=r["total_len"];out.extend(b);off+=len(b)
    return bytes(out)


def ps(binary, wallet, phrase, manifest, genesis, url, command, *args, extra=()):
    # Omit all Development/retained-test switches. Actual source authority must
    # be enforced by this production driver before proving and submission.
    argv=["--wallet",str(wallet),"--manifest",str(manifest),"--genesis",genesis,"--rpc",url,*command,*map(str,args)]
    return wallet_cli(binary,argv,[(PASS_PROMPT,bytearray(phrase))]+list(extra))
