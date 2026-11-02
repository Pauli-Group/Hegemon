"""Terminal-approved HTLC transactions for a peerless local Cardano node.

Only the operator configures the node, signing key and backup paths. Client
requests contain public terms and UTxO references, never signing keys or
preimages. This does not coordinate a swap or establish public-chain finality.
"""
import datetime
import getpass
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from cardano_escrow_verifier import verify_cardano_htlc
from htlc_counterpart import ROOT,TOOLS,no_tcp_peers
from unlock_swap_backup import unlock_backup


def peerless_topology(topology):
    if not isinstance(topology,dict):return False
    roots=[topology.get('publicRoots'),topology.get('localRoots')]
    return (topology.get('useLedgerAfterSlot')==-1 and topology.get('bootstrapPeers') in (None,[])
            and all(isinstance(group,list) for group in roots)
            and all(isinstance(root,dict) and root.get('accessPoints')==[] for group in roots for root in group))


def local_node_identity(pid,socket,net,genesis_hash):
    if type(pid) is not int or pid<=0 or not re.fullmatch('[0-9a-f]{64}',genesis_hash or ''):raise ValueError('invalid local Cardano node identity')
    proc=Path('/proc')/str(pid);socket=Path(socket).resolve(strict=True);net=Path(net).resolve(strict=True)
    if proc.stat().st_uid!=os.getuid() or os.path.basename(os.readlink(proc/'exe'))!='cardano-node':raise ValueError('configured process is not the local Cardano node')
    args=(proc/'cmdline').read_bytes().split(b'\0')
    if b'--socket-path' not in args or Path(os.fsdecode(args[args.index(b'--socket-path')+1])).resolve()!=socket:raise ValueError('Cardano socket does not match node process')
    if b'--host-addr' not in args or args[args.index(b'--host-addr')+1] not in (b'127.0.0.1',b'::1'):raise ValueError('Cardano node must listen on loopback')
    config_path=net/'configuration.yaml';topology_path=net/'node-data/node1/topology.json'
    for flag,expected in ((b'--config',config_path),(b'--topology',topology_path)):
        if flag not in args or Path(os.fsdecode(args[args.index(flag)+1])).resolve()!=expected.resolve():raise ValueError('Cardano node configuration does not match the local network')
    inodes=set()
    for fd in (proc/'fd').iterdir():
        try:target=os.readlink(fd)
        except FileNotFoundError:continue
        if target.startswith('socket:['):inodes.add(target[8:-1])
    matched=False
    for line in (proc/'net/unix').read_text().splitlines()[1:]:
        fields=line.split(maxsplit=7)
        if len(fields)==8 and fields[6] in inodes and Path(fields[7]).resolve()==socket:matched=True;break
    if not matched:raise ValueError('configured Cardano socket is not owned by node process')
    config=json.loads(config_path.read_text())
    if config.get('PeerSharing') is not False or (config_path.parent/config.get('ShelleyGenesisFile','')).resolve()!=(net/'shelley-genesis.json').resolve():raise ValueError('Cardano configuration is not isolated')
    topology=json.loads(topology_path.read_text())
    if not peerless_topology(topology):raise ValueError('Cardano topology must have no peers')
    raw=(net/'shelley-genesis.json').read_bytes();genesis=json.loads(raw)
    if hashlib.sha256(raw).hexdigest()!=genesis_hash or genesis.get('networkId')!='Testnet' or genesis.get('networkMagic')!=424242:raise ValueError('wrong local Cardano genesis')
    class Process:pass
    process=Process();process.pid=pid;no_tcp_peers(process)
    # Linux start time distinguishes a replaced process at the same PID.
    started=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    return started,genesis


def private_key(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Cardano signing key cannot be a symlink')
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('Cardano signing key must be a private user-owned file')
    return path.resolve(strict=True)


def private_journal_directory(path):
    if path is None:raise ValueError('configure a private Cardano journal directory')
    path=Path(path).resolve(strict=True);info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('Cardano journal directory must be user-owned and mode 0700')
    return path


def record_prepared(directory,txid,request,genesis_hash):
    directory=private_journal_directory(directory);path=directory/(txid+'.json')
    record={'version':1,'state':'prepared_or_submitted','txid':txid,'genesis_sha256':genesis_hash,'request':request}
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(path,flags,0o600),'w') as handle:
        json.dump(record,handle,sort_keys=True);handle.write('\n');handle.flush();os.fsync(handle.fileno())
    directory_fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(directory_fd)
    finally:os.close(directory_fd)
    return path


def uint(value,maximum,positive=False):
    if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,19}',value) or int(value)>maximum or (positive and value=='0'):raise ValueError('invalid Cardano integer')
    return int(value)


def value_terms(value):
    if not isinstance(value,dict) or 'lovelace' not in value or len(value)>100:raise ValueError('invalid Cardano value')
    result={'lovelace':uint(value['lovelace'],2**63-1,True)}
    for policy,assets in value.items():
        if policy=='lovelace':continue
        if not re.fullmatch('[0-9a-f]{56}',policy) or not isinstance(assets,dict) or not 0<len(assets)<=100:raise ValueError('invalid Cardano asset policy')
        result[policy]={}
        for name,quantity in assets.items():
            if not isinstance(name,str) or not re.fullmatch('(?:[0-9a-f]{2}){0,32}',name):raise ValueError('invalid Cardano asset name')
            result[policy][name]=uint(quantity,2**63-1,True)
    return result


def ref(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]{0,9})',value):raise ValueError('invalid Cardano output reference')
    return value


def run_cardano_action(*,chain,pid,genesis_hash,signing_key,journal_dir,request,backup=None,confirm=input,password=getpass.getpass):
    common={'operation','hashlock','claimant','refundee','expiry_ms','expected_value'}
    op=request.get('operation') if isinstance(request,dict) else None
    if op not in ('lock','claim','refund') or set(request)!=(common|({'inputs'} if op=='lock' else {'outref','fee_input','collateral'})):raise ValueError('invalid Cardano action fields')
    for name,length in (('hashlock',64),('claimant',56),('refundee',56)):
        if not isinstance(request[name],str) or not re.fullmatch('[0-9a-f]{'+str(length)+'}',request[name]):raise ValueError('invalid Cardano terms')
    expiry=uint(request['expiry_ms'],2**63-1,True);value=value_terms(request['expected_value']);key=private_key(signing_key)
    identity,genesis=local_node_identity(pid,chain.socket,chain.net,genesis_hash)
    aiken=getattr(chain,'aiken',TOOLS/'aiken/aiken-x86_64-unknown-linux-musl/aiken')
    trusted_script=subprocess.check_output([str(aiken),'blueprint','convert',str(ROOT/'contracts/cardano')],text=True)
    if chain.script.read_text()!=trusted_script:raise ValueError('Cardano validator differs from pinned blueprint')
    start=int(datetime.datetime.fromisoformat(genesis['systemStart'].replace('Z','+00:00')).timestamp()*1000);slot_ms=round(genesis['slotLength']*1000)
    if slot_ms<=0 or expiry<start or (expiry-start)%slot_ms:raise ValueError('expiry must align with a local slot')
    expiry_slot=(expiry-start)//slot_ms;tip=chain.tip();current=tip['slot']
    if op in ('lock','claim') and expiry_slot-current<5:raise ValueError('Cardano deadline too close')
    if op=='refund' and current<expiry_slot:raise ValueError('refund is not yet available')
    if op=='lock':
        if not isinstance(request['inputs'],list) or not 1<=len(request['inputs'])<=10:raise ValueError('one to ten funding inputs required')
        inputs=[ref(x) for x in request['inputs']]
        if len(set(inputs))!=len(inputs):raise ValueError('duplicate Cardano inputs')
    else:
        inputs=[ref(request['fee_input']),ref(request['collateral'])];ref(request['outref'])
        if len(set(inputs+[request['outref']]))!=3:raise ValueError('Cardano inputs must differ')
    with tempfile.TemporaryDirectory(prefix='cardano-local-action-') as scratch:
        scratch=Path(scratch);vkey=scratch/'payment.vkey';body=scratch/'tx.body';signed=scratch/'tx.signed'
        try:
            chain.run('key','verification-key','--signing-key-file',key,'--verification-key-file',vkey)
            keyhash=chain.run('address','key-hash','--payment-verification-key-file',vkey).strip()
            address=chain.run('address','build','--payment-verification-key-file',vkey,'--testnet-magic',chain.magic).strip()
        except Exception as e:raise ValueError('could not derive the configured Cardano payment address') from e
        if keyhash!=request['claimant' if op=='claim' else 'refundee']:raise ValueError('configured signing key does not match this action')
        owned=chain.utxos(address)
        if any(item not in owned for item in inputs):raise ValueError('selected Cardano inputs are not at the configured payment address')
        if op!='lock' and (set(owned[request['collateral']]['value'])!={'lovelace'} or owned[request['collateral']]['value']['lovelace']<=0):raise ValueError('collateral must be an ADA-only output')
        if op!='lock':
            verify_cardano_htlc(chain,outref=request['outref'],hashlock=request['hashlock'],claimant=request['claimant'],refundee=request['refundee'],expiry_ms=expiry,expected_value=value,genesis_sha256=genesis_hash,allow_expired=op=='refund',aiken=aiken)
        print('\nCardano local test action (not an atomic swap):\n'+json.dumps(request,indent=2),flush=True)
        if op=='claim':print('The claim preimage is passed to the local Cardano node before submission and becomes public when submitted.',flush=True)
        if confirm('Type APPROVE to continue this local Cardano action: ').strip()!='APPROVE':raise ValueError('action declined locally')
        buffers=[]
        try:
            datum={'constructor':0,'fields':[{'bytes':request['hashlock']},{'bytes':request['claimant']},{'bytes':request['refundee']},{'int':expiry}]}
            assets=''.join('+'+str(quantity)+' '+policy+'.'+name for policy,values in value.items() if policy!='lovelace' for name,quantity in values.items())
            if op=='lock':
                datum_file=scratch/'datum.json';datum_file.write_text(json.dumps(datum))
                script_address=chain.run('address','build','--payment-script-file',chain.script,'--testnet-magic',chain.magic).strip()
                argv=sum((['--tx-in',item] for item in inputs),[])+['--tx-out',script_address+'+'+str(value['lovelace'])+assets,'--tx-out-inline-datum-file',datum_file,'--change-address',address]
            else:
                secret=None
                if op=='claim':
                    if backup:
                        phrase=bytearray(password('Encrypted preimage backup passphrase (local terminal only): ').encode());buffers.append(phrase);secret=unlock_backup(backup,phrase);buffers.append(secret)
                    else:
                        text=password('Claim preimage as 64 lowercase hexadecimal characters (local terminal only): ')
                        if not re.fullmatch('[0-9a-f]{64}',text):raise ValueError('invalid claim preimage')
                        secret=bytearray.fromhex(text);buffers.append(secret);del text
                    if hashlib.sha256(secret).hexdigest()!=request['hashlock']:raise ValueError('preimage does not match hashlock')
                redeemer=scratch/'redeemer.json';redeemer.write_text(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]} if secret is not None else {'constructor':1,'fields':[]}))
                argv=['--tx-in',request['outref'],'--tx-in-script-file',chain.script,'--tx-in-inline-datum-present','--tx-in-redeemer-file',redeemer,'--tx-in',inputs[0],'--tx-in-collateral',inputs[1],'--required-signer-hash',keyhash,'--tx-out',address+'+'+str(value['lovelace'])+assets,'--change-address',address,'--invalid-hereafter' if op=='claim' else '--invalid-before',str(expiry_slot)]
            try:
                chain.run('transaction','build','--testnet-magic',chain.magic,'--socket-path',chain.socket,*argv,'--out-file',body)
                chain.run('transaction','sign','--tx-body-file',body,'--signing-key-file',key,'--testnet-magic',chain.magic,'--out-file',signed)
                txid=chain.run('transaction','txid','--tx-file',signed,'--output-text').strip()
            except Exception as e:raise ValueError('Cardano transaction could not be prepared; check local inputs and terms') from e
            if not re.fullmatch('[0-9a-f]{64}',txid):raise ValueError('invalid prepared Cardano transaction ID')
            if local_node_identity(pid,chain.socket,chain.net,genesis_hash)[0]!=identity:raise ValueError('Cardano node changed before submission')
            try:record=record_prepared(journal_dir,txid,request,genesis_hash)
            except FileExistsError as e:raise ValueError('Transaction record already exists; check its outcome before retrying.') from e
            except OSError as e:raise ValueError('Could not save a private transaction record; this attempt was not submitted. Check existing records before retrying.') from e
            print('Prepared Cardano transaction '+txid+'; recovery record: '+str(record),flush=True)
            if local_node_identity(pid,chain.socket,chain.net,genesis_hash)[0]!=identity:raise ValueError('Cardano node changed before submission; check the saved transaction record')
            try:chain.run('transaction','submit','--tx-file',signed,'--testnet-magic',chain.magic,'--socket-path',chain.socket)
            except Exception as e:raise ValueError('Submission outcome uncertain. Check the transaction before retrying.') from e
            if local_node_identity(pid,chain.socket,chain.net,genesis_hash)[0]!=identity:raise ValueError('Node changed; action outcome may be uncertain. Check the transaction.')
            return {'operation':op,'txid':txid,'submitted':True,'confirmed':False,'journal_record':record.name}
        finally:
            for item in buffers:item[:]=b'\0'*len(item)
