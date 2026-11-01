"""Actual loopback Ethereum and Cardano HTLC counterparts for local swap tests."""
import datetime, hashlib, json, os, subprocess, time
from pathlib import Path
from local_private_spend_swap import ROOT, port, stop, require
from release_private_spend_lifecycle_io import rpc

TOOLS=Path('/workspace/chain-tools')

def wait_for(fn, label, seconds=90):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            value=fn()
            if value:return value
        except (OSError,RuntimeError,ValueError,subprocess.CalledProcessError):pass
        time.sleep(.2)
    raise RuntimeError('timed out: '+label)


def no_tcp_peers(proc, rpc_port=None):
    inodes=set()
    for fd in Path(f'/proc/{proc.pid}/fd').iterdir():
        try: target=os.readlink(fd)
        except FileNotFoundError: continue
        if target.startswith('socket:['): inodes.add(target[8:-1])
    for table in ('tcp','tcp6'):
        for line in Path(f'/proc/{proc.pid}/net/{table}').read_text().splitlines()[1:]:
            fields=line.split()
            if fields[9] in inodes and fields[3]=='01':
                require(rpc_port is not None and int(fields[1].split(':')[1],16)==rpc_port,'node has an unexpected established TCP connection')


class Ethereum:
    amount=10**18
    def __init__(self, directory, tools=TOOLS):
        self.d=directory; self.d.mkdir(mode=0o700)
        self.receipt={'chain':'ethereum','checks':{},'transactions':{}}
        self.log=(self.d/'anvil.log').open('wb')
        self.proc=None
        try:
            self.url='http://127.0.0.1:'+str(port())
            self.proc=subprocess.Popen([tools/'foundry/anvil','--host','127.0.0.1','--port',self.url.rsplit(':',1)[1], '--chain-id','31337','--hardfork','cancun','--silent'],stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
            wait_for(lambda:rpc(self.url,'eth_chainId')=='0x7a69','Anvil RPC')
            self.alice,self.bob,self.outsider=rpc(self.url,'eth_accounts')[:3]
            self.artifact=json.loads((ROOT/'contracts/ethereum/out/HegemonHTLC.sol/HegemonHTLC.json').read_text())
            self.receipt['creation_code_sha256']=hashlib.sha256(bytes.fromhex(self.artifact['bytecode']['object'].removeprefix('0x'))).hexdigest()
        except BaseException:self.close();raise
    def send(self, sender, data, to=None, value=0, succeeds=True):
        tx={'from':sender,'data':data,'value':hex(value),'gas':hex(2_000_000)}
        if to:tx['to']=to
        ident=rpc(self.url,'eth_sendTransaction',[tx])
        receipt=wait_for(lambda:rpc(self.url,'eth_getTransactionReceipt',[ident]),'Ethereum receipt')
        require(int(receipt['status'],16)==int(succeeds),'unexpected Ethereum execution status')
        rpc(self.url,'evm_mine');rpc(self.url,'evm_mine')
        block=rpc(self.url,'eth_getBlockByNumber',[receipt['blockNumber'],False])
        require(block['hash']==receipt['blockHash'] and ident in block['transactions'],'Ethereum receipt not canonical')
        (self.d/(ident+'.json')).write_text(json.dumps(receipt,indent=2))
        return receipt
    def balance(self, account):return int(rpc(self.url,'eth_getBalance',[account,'latest']),16)
    def data(self, signature, suffix=''):return '0x'+self.artifact['methodIdentifiers'][signature]+suffix
    def lock(self, hashlock):
        self.expiry=int(rpc(self.url,'eth_getBlockByNumber',['latest',False])['timestamp'],16)+600
        code=self.artifact['bytecode']['object']
        args=hashlock.hex()+self.alice[2:].rjust(64,'0')+format(self.expiry,'064x')
        r=self.send(self.bob,code+args,value=self.amount)
        self.contract=r['contractAddress']
        require(self.balance(self.contract)==self.amount,'ETH escrow amount mismatch')
        self.receipt['transactions']['lock']=r['transactionHash']
        for label,sender,data in [
            ('wrong_secret',self.alice,self.data('claim(bytes32)','00'*32)),
            ('unauthorized_claim',self.outsider,self.data('claim(bytes32)','00'*32)),
            ('early_refund',self.bob,self.data('refund()'))]:
            self.send(sender,data,self.contract,succeeds=False)
            require(self.balance(self.contract)==self.amount,'rejected call changed ETH escrow')
            self.receipt['checks'][label+'_rejected']=True
    def claim(self, secret):
        before=self.balance(self.alice)
        r=self.send(self.alice,self.data('claim(bytes32)',secret.hex()),self.contract)
        cost=int(r['gasUsed'],16)*int(r['effectiveGasPrice'],16)
        require(self.balance(self.alice)==before+self.amount-cost and self.balance(self.contract)==0,'ETH claim payment mismatch')
        require(len(r['logs'])==1,'missing claim event')
        revealed=bytes.fromhex(r['logs'][0]['data'][2:66])
        require(hashlib.sha256(revealed).digest()==hashlib.sha256(secret).digest(),'Ethereum confirmed preimage mismatch')
        self.receipt['transactions']['claim']=r['transactionHash']; self.receipt['checks']['claim_confirmed']=True
        self.send(self.alice,self.data('claim(bytes32)',secret.hex()),self.contract,succeeds=False)
        self.receipt['checks']['repeat_claim_rejected']=True
        return revealed
    def refund(self):
        rpc(self.url,'evm_setNextBlockTimestamp',[self.expiry]);rpc(self.url,'evm_mine')
        self.send(self.alice,self.data('refund()'),self.contract,succeeds=False)
        before=self.balance(self.bob)
        r=self.send(self.bob,self.data('refund()'),self.contract)
        cost=int(r['gasUsed'],16)*int(r['effectiveGasPrice'],16)
        require(self.balance(self.bob)==before+self.amount-cost and self.balance(self.contract)==0,'ETH refund payment mismatch')
        self.send(self.alice,self.data('claim(bytes32)','00'*32),self.contract,succeeds=False)
        self.receipt['transactions']['refund']=r['transactionHash']
        self.receipt['checks'].update(refund_confirmed=True,unauthorized_refund_rejected=True,claim_after_refund_rejected=True)
    def isolated(self):
        no_tcp_peers(self.proc,int(self.url.rsplit(':',1)[1]))
        self.receipt['checks']['zero_peers']=True
    def close(self):
        stop(self.proc)
        self.log.close()


class Cardano:
    amount=10_000_000
    magic='424242'
    def __init__(self, directory, tools=TOOLS, existing=None):
        self.d=directory;self.d.mkdir(mode=0o700)
        self.cli=tools/'cardano/bin/cardano-cli';self.nodebin=tools/'cardano/bin/cardano-node'
        self.receipt={'chain':'cardano','checks':{},'transactions':{}}
        self.proc=None;self.log=(self.d/'node.log').open('wb'); self.serial=0
        try:
            self.net=existing or self.d/'network'
            if not existing:
                env=dict(os.environ,CARDANO_CLI=str(self.cli),CARDANO_NODE=str(self.nodebin))
                subprocess.run([tools/'cardano/bin/cardano-testnet','create-env','--num-pool-nodes','1','--num-dreps','0','--slot-length','0.2','--active-slots-coeff','0.5','--epoch-length','500','--testnet-magic',self.magic,'--output',self.net],env=env,check=True,stdout=self.log,stderr=self.log)
                start=int(time.time())+2
                for era in ('shelley','byron'):
                    path=self.net/(era+'-genesis.json');gen=json.loads(path.read_text())
                    if era=='shelley':gen['systemStart']=datetime.datetime.fromtimestamp(start,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:gen['startTime']=start
                    path.write_text(json.dumps(gen,indent=2))
                self.socket=self.net/'node.socket'
                # Unix socket paths have a 107-byte platform limit.
                require(len(str(self.socket).encode())<100,'Cardano socket path too long; choose shorter output path')
                keys=self.net/'pools-keys/pool1'
                self.proc=subprocess.Popen([self.nodebin,'run','--config',self.net/'configuration.yaml','--topology',self.net/'node-data/node1/topology.json','--database-path',self.net/'db','--shelley-kes-key',keys/'kes.skey','--shelley-vrf-key',keys/'vrf.skey','--shelley-operational-certificate',keys/'opcert.cert','--byron-delegation-certificate',keys/'byron-delegation.cert','--byron-signing-key',keys/'byron-delegate.key','--socket-path',self.socket,'--host-addr','127.0.0.1','--port',str(port())],stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True,cwd=self.net)
            else:self.socket=self.net/'socket/node1/sock'
            wait_for(lambda:self.tip().get('block',0)>0,'Cardano blocks')
            self.genesis=json.loads((self.net/'shelley-genesis.json').read_text())
            self.start_ms=int(datetime.datetime.fromisoformat(self.genesis['systemStart'].replace('Z','+00:00')).timestamp()*1000)
            self.slot_ms=round(self.genesis['slotLength']*1000)
            self.actors={}
            for index,name in enumerate(('alice','bob','outsider'),1):
                key=self.net/f'utxo-keys/utxo{index}/utxo'
                self.actors[name]={'address':self.run('address','build','--payment-verification-key-file',key.with_suffix('.vkey'),'--testnet-magic',self.magic).strip(),'skey':key.with_suffix('.skey'),'hash':self.run('address','key-hash','--payment-verification-key-file',key.with_suffix('.vkey')).strip()}
            self.script=self.d/'htlc.plutus'
            # Build artifacts are generated from the pinned Aiken project before running.
            self.script.write_text(subprocess.check_output([tools/'aiken/aiken-x86_64-unknown-linux-musl/aiken','blueprint','convert',ROOT/'contracts/cardano'],text=True))
            self.address=self.run('address','build','--payment-script-file',self.script,'--testnet-magic',self.magic).strip()
            self.receipt['script_sha256']=hashlib.sha256(self.script.read_bytes()).hexdigest()
            for name in self.actors:self.split(name)
        except BaseException:self.close();raise
    def run(self,*args,check=True):
        p=subprocess.run([str(self.cli),'conway',*map(str,args)],capture_output=True,text=True,timeout=60)
        if check and p.returncode:raise RuntimeError('Cardano CLI failed: '+p.stderr[-2000:])
        return p.stdout if check else p
    def query(self,*args):
        return json.loads(self.run('query',*args,'--testnet-magic',self.magic,'--socket-path',self.socket,'--output-json'))
    def tip(self):return self.query('tip')
    def utxos(self,address):return self.query('utxo','--address',address)
    def files(self,label):
        self.serial+=1;prefix=self.d/(str(self.serial)+'-'+label)
        return Path(str(prefix)+'.body'),Path(str(prefix)+'.signed')
    def build(self,args,body,expected=True,spent=False):
        result=self.run('transaction','build','--testnet-magic',self.magic,'--socket-path',self.socket,*args,'--out-file',body,check=False)
        (Path(str(body)+'.log')).write_text(result.stdout+result.stderr)
        if expected:require(result.returncode==0,'Cardano build rejected: '+result.stderr[-2000:])
        else:
            reason = any(x in result.stderr for x in ('not present in the UTxO','not found in the UTxO','TxInsDoNotExist','BadInputsUTxO','does not exist in the UTxO')) if spent else 'scripts have execution failures' in result.stderr
            require(result.returncode!=0 and reason,'unexpected negative Cardano failure: '+result.stderr[:1500])
        return result.returncode==0
    def submit(self,body,signed,name,output_address):
        self.run('transaction','sign','--tx-body-file',body,'--signing-key-file',self.actors[name]['skey'],'--testnet-magic',self.magic,'--out-file',signed)
        ident=self.run('transaction','txid','--tx-file',signed,'--output-text').strip()
        self.run('transaction','submit','--tx-file',signed,'--testnet-magic',self.magic,'--socket-path',self.socket)
        found=wait_for(lambda:{k:v for k,v in self.utxos(output_address).items() if k.startswith(ident+'#')},'Cardano transaction inclusion')
        observed=self.tip()['block']
        wait_for(lambda:self.tip()['block']>=observed+2,'Cardano confirmation depth')
        require(all(k in self.utxos(output_address) for k in found),'Cardano output disappeared before confirmation')
        return ident,found
    def split(self,name):
        address=self.actors[name]['address'];available=self.utxos(address)
        collateral=[k for k,v in available.items() if v['value'].get('lovelace')==20_000_000]
        if collateral:self.actors[name]['collateral']=collateral[0];return
        key=max(available,key=lambda k:available[k]['value'].get('lovelace',0))
        body,signed=self.files(name+'-collateral')
        self.build(['--tx-in',key,'--tx-out',address+'+20000000','--change-address',address],body)
        _,out=self.submit(body,signed,name,address)
        self.actors[name]['collateral']=next(k for k,v in out.items() if v['value'].get('lovelace')==20_000_000)
    def fee_input(self,name):
        out=self.utxos(self.actors[name]['address'])
        return max((k for k in out if k!=self.actors[name]['collateral']),key=lambda k:out[k]['value'].get('lovelace',0))
    def lock(self,hashlock):
        self.expiry_slot=self.tip()['slot']+300 # sixty local seconds, no public network timing claim
        self.expiry_ms=self.start_ms+self.expiry_slot*self.slot_ms
        datum={'constructor':0,'fields':[{'bytes':hashlock.hex()},{'bytes':self.actors['alice']['hash']},{'bytes':self.actors['bob']['hash']},{'int':self.expiry_ms}]}
        self.datum=self.d/'terms.json';self.datum.write_text(json.dumps(datum))
        body,signed=self.files('lock')
        self.build(['--tx-in',self.fee_input('bob'),'--tx-out',self.address+'+'+str(self.amount),'--tx-out-inline-datum-file',self.datum,'--change-address',self.actors['bob']['address']],body)
        ident,out=self.submit(body,signed,'bob',self.address)
        self.locked=next(k for k,v in out.items() if v['value'].get('lovelace')==self.amount)
        self.receipt['transactions']['lock']=ident
        self.spend('alice',b'\0'*32,expected=False,label='wrong-secret')
        self.spend('outsider',b'\0'*32,expected=False,label='unauthorized-claim')
        self.spend('bob',None,expected=False,label='early-refund',early=True)
        self.receipt['checks'].update(wrong_secret_rejected=True,unauthorized_claim_rejected=True,early_refund_rejected=True)
    def spend(self,name,secret,expected=True,label='spend',early=False,late=False,spent=False):
        claim=secret is not None
        redeemer=self.d/(label+'-redeemer.json')
        redeemer.write_text(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]} if claim else {'constructor':1,'fields':[]}))
        body,signed=self.files(label)
        args=['--tx-in',self.locked,'--tx-in-script-file',self.script,'--tx-in-inline-datum-present','--tx-in-redeemer-file',redeemer,'--tx-in',self.fee_input(name),'--tx-in-collateral',self.actors[name]['collateral'],'--required-signer-hash',self.actors[name]['hash'],'--tx-out',self.actors[name]['address']+'+'+str(self.amount),'--change-address',self.actors[name]['address']]
        if claim:
            args+=['--invalid-hereafter',str(self.expiry_slot+(10 if late else 0))]
        else:
            args+=['--invalid-before',str(self.tip()['slot'] if early else self.expiry_slot)]
        if not self.build(args,body,expected,spent):return None
        ident,out=self.submit(body,signed,name,self.actors[name]['address'])
        require(self.locked not in self.utxos(self.address),'Cardano escrow input remains unspent')
        require(any(v['value'].get('lovelace')==self.amount for v in out.values()),'ADA payout amount mismatch')
        self.receipt['transactions'][label]=ident
        self.receipt['checks'][label+'_confirmed']=True
        return signed
    def claim(self,secret):
        signed=self.spend('alice',secret,label='claim')
        import cbor2
        # The confirmed body commits its redeemers via script-data hash. Recover
        # the preimage from that exact signed transaction, not the input secret.
        tx=cbor2.loads(bytes.fromhex(json.loads(signed.read_text())['cborHex']))
        redeemers=tx[1][5]
        values=redeemers.values() if isinstance(redeemers,dict) else [r[2:] for r in redeemers]
        secrets=[entry[0].value[0] for entry in values if isinstance(entry[0],cbor2.CBORTag) and entry[0].tag==121]
        require(len(secrets)==1 and secrets[0]==secret,'confirmed Cardano transaction preimage mismatch')
        self.receipt['checks']['confirmed_submitted_witness_preimage']=True
        # Re-submitting the exact signed spend must be rejected by the node.
        self.spend('alice',secret,expected=False,label='repeat-claim',spent=True)
        self.receipt['checks']['repeat_claim_rejected']=True
        return secrets[0]
    def refund(self):
        wait_for(lambda:self.tip()['slot']>=self.expiry_slot,'Cardano refund slot',seconds=90)
        self.spend('alice',None,expected=False,label='unauthorized-refund')
        self.spend('alice',b'\0'*32,expected=False,label='expired-claim',late=True)
        signed=self.spend('bob',None,label='refund')
        self.spend('bob',None,expected=False,label='repeat-refund',spent=True)
        self.receipt['checks'].update(unauthorized_refund_rejected=True,expired_claim_rejected=True,repeat_refund_rejected=True)
    def isolated(self):
        topology=json.loads((self.net/'node-data/node1/topology.json').read_text())
        require(not topology['publicRoots'][0]['accessPoints'] and not topology['localRoots'][0]['accessPoints'] and topology.get('useLedgerAfterSlot')==-1,'Cardano topology enables peers')
        no_tcp_peers(self.proc)
        self.receipt['checks'].update(empty_topology=True,zero_peers=True)
        self.receipt['genesis_sha256']=hashlib.sha256((self.net/'shelley-genesis.json').read_bytes()).hexdigest()
    def close(self):
        stop(self.proc);self.log.close()
