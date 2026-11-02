#!/usr/bin/env python3
"""Real private-spend HTLC swaps with fresh local Ethereum or Cardano chains."""
import argparse, hashlib, json, os, re, subprocess, time
from pathlib import Path
from local_private_spend_swap import ROOT, PASS, HANDOFF, SECRET, wallet, mine, port, stop, require
from release_private_spend_lifecycle_io import rpc, height, chunks
from htlc_counterpart import Ethereum, Cardano, TOOLS
from hegemon_companion_check import check_hegemon_companion
from hegemon_companion_actions_check import TestHegemonActions

def scenario(a, name):
    d=a.output/name; d.mkdir(mode=0o700)
    rec={'scenario':name,'status':'running','counterpart_chain':a.chain,'hegemon_seeds':'',
         'production_authorized':False,'proofs':{},'checks':{}}
    node=counterpart=actions=None; handle=None
    phrase=os.urandom(24).hex().encode(); hp=os.urandom(24).hex().encode()
    (d/'wallet.pass').write_bytes(phrase+b'\n')
    (d/'handoff.pass').write_bytes(hp+b'\n')
    rec['source_commit']=subprocess.check_output(['git','-C',ROOT,'rev-parse','HEAD'],text=True).strip()
    rec['binary_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (a.node,a.wallet)}
    sources=[ROOT/'scripts/local_multichain_htlc_swap.py',ROOT/'scripts/htlc_counterpart.py',
             ROOT/'scripts/hegemon_companion_check.py',ROOT/'scripts/local_swap_companion.py',
             ROOT/'scripts/hegemon_companion_actions_check.py',ROOT/'scripts/hegemon_action_runner.py',ROOT/'scripts/hegemon_local_actions.py',
             ROOT/'wallet/src/bin/private_spend.rs',ROOT/'wallet/src/private_spend_build.rs']
    if a.chain=='cardano':sources.append(ROOT/'contracts/cardano/validators/htlc.ak')
    elif a.ethereum_test_token:sources.extend([ROOT/'contracts/ethereum/TokenHTLC.sol',ROOT/'contracts/ethereum/test/TokenHTLC.t.sol'])
    else:sources.append(ROOT/'contracts/ethereum/HegemonHTLC.sol')
    rec['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
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
        def include(n,attempt,label,metrics,action_client=None):
            rec['proofs'][label]=metrics
            call(n,['export',attempt,d/(label+'.action')],label=label+'-export')
            raw=(d/(label+'.action')).read_bytes()
            before=height(url)
            if action_client:
                submitted=action_client.action({'operation':'submit','attempt':attempt})
                require(submitted['submitted'] and not submitted['confirmed'],'invalid companion submission response')
            else:call(n,['submit',attempt],label=label+'-submit')
            mine(url,before+1)
            actions,_,_=chunks(url,rpc(url,'chain_getBlockHash',[before+1]))
            require(raw in actions,label+' bytes absent from canonical block')
            text,_=call(n,['status'],label=label+'-included')
            require(re.search(attempt+r' .*mined=Some',text),label+' not marked mined')
            rec['checks'][label+'_canonical']=True
            return before+1
        def prepare(n, command, extra=(), label=None):
            label=label or command[0]
            print(name+': proving '+label,flush=True)
            text,metrics=call(n,command,extra,label)
            attempt=re.search(r'candidate ([0-9a-f]{64})',text).group(1)
            return include(n,attempt,label,metrics)
        # Give Bob a native fee note before locking Alice's other mature reward.
        fund_input=str(notes('alice')[0][0])
        if a.exercise_hegemon_actions:
            actions=TestHegemonActions(d/'alice-actions',binary=a.wallet,wallet_path=wallets['alice'],manifest=d/'manifest.json',genesis=genesis,rpc_url=url,phrase=phrase,handoff_phrase=hp)
            require(actions.request('/hegemon/action',{'operation':'status'},credential='0'*64)[0]==403,'action endpoint accepted wrong token')
            require(actions.request('/hegemon/action',{'operation':'status','secret':'forbidden'})[0]==400,'action endpoint accepted secret field')
            actions.action({'operation':'status'},approve=False,expected=False)
            status=actions.action({'operation':'status'});require('synced' in status['status'],'companion status missing')
            print(name+': proving ordinary transfer through local companion',flush=True)
            candidate=actions.action({'operation':'ordinary','inputs':[fund_input],'recipient':addresses['bob'],'amount':'10000','fee':'1'})
            require(not candidate['submitted'],'ordinary transfer unexpectedly submitted')
            include('alice',candidate['attempt'],'fund-bob',candidate['metrics'],actions)
            rec['checks']['companion_ordinary_and_submission']=True
        else:prepare('alice',['ordinary','--inputs',fund_input,'--recipient',addresses['bob'],'--amount','10000','--fee','1'],label='fund-bob')
        timeout=height(url)+16; secret=os.urandom(32); hashed=hashlib.sha256(secret).hexdigest()
        lock_input=str(notes('alice')[0][0])
        if a.exercise_hegemon_actions:
            print(name+': proving lock through local companion',flush=True)
            candidate=actions.action({'operation':'lock','inputs':[lock_input],'claim':addresses['bob'],'refund':addresses['alice'],
                                      'hashlock':hashed,'timeout':str(timeout),'amount':'100000','fee':'1'})
            require(not candidate['submitted'],'lock unexpectedly submitted')
            handoff=actions.handoffs/candidate['refund_handoff']
            lock_height=include('alice',candidate['attempt'],'lock',candidate['metrics'],actions)
            rec['checks']['companion_lock_and_submission']=True
            actions.close();actions=None
        else:
            handoff=d/'refund.bin'
            lock_height=prepare('alice',['lock','--inputs',lock_input,'--claim',addresses['bob'],'--refund',addresses['alice'],'--hashlock',hashed,'--timeout',str(timeout),'--amount','100000','--fee','1','--release-secret','--refund-handoff',handoff],[(HANDOFF,hp)])
        call('alice',['import-refund-handoff',handoff,'--block-height',str(lock_height),'--refund-index','0'],[(HANDOFF,hp)])
        mine(url,lock_height+1)
        locked=notes('bob','htlc')[0][0]
        verify=['verify-htlc','--locked',str(locked),'--claim',addresses['bob'],'--refund',addresses['alice'],
                '--hashlock',hashed,'--timeout',str(timeout),'--amount','100000']
        verified,_=call('bob',verify,label='verify-htlc')
        require(json.loads(verified.splitlines()[-1])['verified'] is True,'Hegemon terms not verified')
        for flag,value in [('--hashlock','00'*32),('--claim',addresses['treasury']),('--amount','99999'),('--timeout',str(timeout+1))]:
            bad=verify.copy();bad[bad.index(flag)+1]=value
            denied,_=call('bob',bad,label='verify-bad-'+flag[2:],expected=False)
            require('HTLC terms mismatch' in denied,'Hegemon verifier failed for an unexpected reason')
        for flag,value,reason in [('--min-confirmations','1000000','insufficient confirmations'),('--min-remaining-blocks','1000000','HTLC deadline too close')]:
            denied,_=call('bob',[*verify,flag,value],label='verify-bad-'+flag[2:],expected=False)
            require(reason in denied,'Hegemon verification limit failed for an unexpected reason')
        rec['hegemon_companion']=check_hegemon_companion(d/'companion',binary=a.wallet,wallet_path=wallets['bob'],
            manifest=d/'manifest.json',genesis=genesis,rpc_url=url,phrase=phrase,
            terms={'locked':str(locked),'claim':addresses['bob'],'refund':addresses['alice'],
                   'hashlock':hashed,'timeout':str(timeout),'amount':'100000',
                   'min_confirmations':'2','min_remaining_blocks':'2'})
        rec['checks']['hegemon_terms_verified']=True
        call('alice',['refund','--locked',str(locked),'--fee-input',str(notes('alice')[0][0]),'--recipient',addresses['alice'],'--fee','1'],label='early-refund',expected=False)
        rec['checks']['early_refund_rejected']=True
        print(name+': starting fresh '+a.chain+' chain',flush=True)
        if a.chain=='cardano':
            counterpart=Cardano(d/a.chain,a.tools,test_tokens=a.cardano_test_tokens)
        else:
            counterpart=Ethereum(d/a.chain,a.tools,test_token=a.ethereum_test_token)
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
            fee_input=str(notes('bob')[0][0])
            if a.exercise_hegemon_actions:
                actions=TestHegemonActions(d/'bob-actions',binary=a.wallet,wallet_path=wallets['bob'],manifest=d/'manifest.json',genesis=genesis,rpc_url=url,phrase=phrase,handoff_phrase=hp)
                print(name+': proving claim through local companion',flush=True)
                candidate=actions.action({'operation':'claim','locked':str(locked),'fee_input':fee_input,'recipient':addresses['bob'],'fee':'1'},secret=revealed)
                require(not candidate['submitted'],'claim unexpectedly submitted')
                include('bob',candidate['attempt'],'claim',candidate['metrics'],actions)
                rec['checks']['companion_claim_and_submission']=True
                actions.close();actions=None
            else:prepare('bob',['claim','--locked',str(locked),'--fee-input',fee_input,'--recipient',addresses['bob'],'--fee','1'],[(SECRET,revealed.hex().encode())])
            require(any(v==100000 for p,v in notes('bob')), 'Bob did not receive locked HGN')
        else:
            mine(url,timeout)
            fee_input=str(notes('alice')[0][0])
            if a.exercise_hegemon_actions:
                actions=TestHegemonActions(d/'alice-refund-actions',binary=a.wallet,wallet_path=wallets['alice'],manifest=d/'manifest.json',genesis=genesis,rpc_url=url,phrase=phrase,handoff_phrase=hp)
                print(name+': proving refund through local companion',flush=True)
                candidate=actions.action({'operation':'refund','locked':str(locked),'fee_input':fee_input,'recipient':addresses['alice'],'fee':'1'})
                require(not candidate['submitted'],'refund unexpectedly submitted')
                include('alice',candidate['attempt'],'refund',candidate['metrics'],actions)
                rec['checks']['companion_refund_and_submission']=True
                actions.close();actions=None
            else:prepare('alice',['refund','--locked',str(locked),'--fee-input',fee_input,'--recipient',addresses['alice'],'--fee','1'])
            require(any(v==100000 for p,v in notes('alice')), 'Alice did not recover HGN')
            if name=='late_claim':
                call('bob',['claim','--locked',str(locked),'--fee-input',str(notes('bob')[0][0]),'--recipient',addresses['bob'],'--fee','1'],[(SECRET,revealed.hex().encode())],label='late-claim',expected=False)
                rec['checks']['late_claim_rejected']=True
        denied,_=call('bob',verify,label='verify-spent',expected=False)
        require('unspent private note absent' in denied,'Hegemon spent check failed for an unexpected reason')
        rec['checks']['hegemon_spent_rejected']=True
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
        if actions is not None:actions.close()
        stop(node)
        if handle: handle.close()
        rec['owned_nodes_stopped']=True
        (d/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chain',choices=['ethereum','cardano'],required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--scenario',choices=['all','happy','no_counterparty','both_refund','late_claim'],default='all')
    p.add_argument('--cardano-test-tokens',action='store_true',help='mint disposable fungible and NFT fixtures on the isolated Cardano chain')
    p.add_argument('--ethereum-test-token',choices=['erc20','erc721','erc1155'],help='use a disposable token fixture on the isolated Ethereum chain')
    p.add_argument('--exercise-hegemon-actions',action='store_true',help='prepare and submit Hegemon HTLC actions through locally approved companion terminals')
    p.add_argument('--node',type=Path,default=ROOT/'target/release/hegemon-node')
    p.add_argument('--wallet',type=Path,default=ROOT/'target/release/private-spend')
    p.add_argument('--tools',type=Path,default=TOOLS)
    a=p.parse_args();a.output=a.output.resolve();os.umask(0o077)
    if a.cardano_test_tokens and a.chain!='cardano':p.error('--cardano-test-tokens requires --chain cardano')
    if a.ethereum_test_token and a.chain!='ethereum':p.error('--ethereum-test-token requires --chain ethereum')
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
