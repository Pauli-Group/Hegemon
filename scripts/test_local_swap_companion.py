import os
import hashlib
import json
import itertools
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
import local_swap_companion
from local_swap_companion import HOSTED_ORIGIN, DesktopKeyring, GuiApproval, HostedWalletSession, NODE_ACTIVITY_FRACTIONS, NODE_ACTIVITY_PHASES, NodeActivityMonitor, WalletActivity, cardano_wire_terms, describe_companion_status, describe_node_activity, estimate_node_remaining, format_node_eta, hegemon_wire_terms, hosted_balance_view, private_token, read_node_activity, wallet_progress_event
from probe_hegemon_testnet import MANIFEST, MANIFEST_FIELDS, RELEASE, RELATION, REQUIRED

class LocalCompanionTest(unittest.TestCase):
    def test_swap_note_selector_uses_only_available_notes_and_selects_smallest_sufficient_set(self):
        rng=random.Random(3)
        for _ in range(300):
            values=[rng.randrange(1,100) for _ in range(rng.randrange(0,14))]
            excluded={str(i) for i in rng.sample(range(len(values)),min(len(values),rng.randrange(3)))}
            need=rng.randrange(1,170)
            rows=[{'position':str(i),'value':str(v)} for i,v in enumerate(values)]
            request={'amount':str(need),'fee':'0','exclude':sorted(excluded)}
            choices=[(v,(str(i),)) for i,v in enumerate(values) if str(i) not in excluded and v>=need]
            if not choices:
                choices=[(values[a]+values[b],(str(a),str(b))) for a,b in itertools.combinations(range(len(values)),2) if str(a) not in excluded and str(b) not in excluded and values[a]+values[b]>=need]
            snapshot={'synced_height':'100','available':rows}
            if not choices:
                with self.assertRaises(ValueError):local_swap_companion.select_swap_notes(snapshot,request)
                continue
            selected=local_swap_companion.select_swap_notes(snapshot,request)
            self.assertEqual(int(selected['total']),min(x[0] for x in choices))
            self.assertTrue(all(p not in excluded for p in selected['inputs']))
            self.assertEqual(sum(values[int(p)] for p in selected['inputs']),int(selected['total']))
        for request in ({'amount':'0','fee':'0','exclude':[]},{'amount':str(2**64-1),'fee':'1','exclude':[]},{'amount':'1','fee':'0','exclude':['1','1']}):
            with self.assertRaises(ValueError):local_swap_companion.select_swap_notes({'synced_height':'1','available':[]},request)
    def test_token_private_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);token=root/'token'
            first=private_token(token)
            self.assertEqual(len(first),64);self.assertEqual(private_token(token),first)
            self.assertEqual(token.stat().st_mode & 0o777,0o600)
            link=root/'link';link.symlink_to(token)
            with self.assertRaises(OSError):private_token(link)
            os.chmod(token,0o644)
            with self.assertRaises(ValueError):private_token(token)
    def test_cardano_decimal_values_are_exact_and_bounded(self):
        policy='a'*56
        terms={'expiry_ms':'1800000000000','expected_value':{'lovelace':'10000000',policy:{'00':'9007199254740993'}}}
        parsed=cardano_wire_terms(terms)
        self.assertEqual(parsed['expected_value'][policy]['00'],9007199254740993)
        for bad in ('1e6','01',str(2**63)):
            with self.assertRaises(ValueError):cardano_wire_terms({**terms,'expiry_ms':bad})
        with self.assertRaises(ValueError):cardano_wire_terms({**terms,'expiry_ms':9007199254740993})
    def test_hegemon_decimal_values_are_exact_and_bounded(self):
        data={'locked':'0','timeout':'9007199254740993','amount':'100','min_confirmations':'2',
              'min_remaining_blocks':'2','hashlock':'a'*64,'claim':'claim','refund':'refund'}
        with patch('local_swap_companion.public_v8_address_keys'):
            self.assertEqual(hegemon_wire_terms(data)['timeout'],'9007199254740993')
            with self.assertRaises(ValueError):hegemon_wire_terms({**data,'timeout':str(2**64)})
            with self.assertRaises(ValueError):hegemon_wire_terms({**data,'amount':'0'})
    def test_swap_htlc_read_checks_the_wallet_and_current_public_tip_without_exposing_notes(self):
        terms={'locked':'7','timeout':'120','amount':'100','min_confirmations':'2',
               'min_remaining_blocks':'3','hashlock':'aa'*32,'claim':'claim','refund':'refund','action_id':'ab'*48,'refund_ready':False}
        response={'verified':True,'position':7,'created_height':98,'reference_height':100,'confirmations':3,
                  'refund_ready':False,'commitment':'cd'*56,'created_block_hash':'0x'+'ef'*32,'reference_block_hash':'0x'+'12'*32}
        with tempfile.TemporaryDirectory() as d:
            session=HostedWalletSession(rpc='http://127.0.0.1:9944',wallet_path=Path(d)/'wallet',manifest=Path(d)/'manifest',genesis='g',binary=Path(d)/'private-spend',scratch=d)
            calls=[]
            def fake_wallet(_binary,argv,secrets,_scratch,_label):
                calls.append((argv,bytes(secrets[0][1])))
                return json.dumps(response)+'\n',{}
            node=lambda:{'height':101,'chain_id':'0x'+'34'*32}
            options={'check_node':node,'verify_action':lambda *a,**k:True,'read_block':lambda _:'0x'+'12'*32}
            with patch('local_swap_companion.public_v8_address_keys'),patch('local_swap_companion.wallet',fake_wallet):
                with self.assertRaises(PermissionError):session.verify_swap_htlc(terms,**options)
                session._phrase=bytearray(b'disposable')
                result=session.verify_swap_htlc(terms,**options)
                self.assertEqual(result,{'verified':True,'position':'7','created_height':'98','reference_height':'100','confirmations':'3','commitment':'cd'*56,'action_id':'ab'*48,'refund_ready':False})
                self.assertNotIn('disposable',json.dumps(result))
                self.assertIn('verify-htlc',calls[-1][0]);self.assertEqual(calls[-1][1],b'disposable')
                for change in ({'position':8},{'confirmations':1},{'reference_height':101},{'verified':False}):
                    original=response.copy();response.update(change)
                    with self.subTest(change=change),self.assertRaisesRegex(ValueError,'stale or inconsistent'):
                        session.verify_swap_htlc(terms,**options)
                    response.clear();response.update(original)
                with self.assertRaisesRegex(ValueError,'stale or inconsistent'):
                    session.verify_swap_htlc(terms,**{**options,'check_node':lambda:{'height':118,'chain_id':'0x'+'34'*32}})
                response['refund_ready']=True
                result=session.verify_swap_htlc({**terms,'refund_ready':True},**{**options,'check_node':lambda:{'height':120,'chain_id':'0x'+'34'*32}})
                self.assertTrue(result['refund_ready']);self.assertIn('--refund-ready',calls[-1][0])
                with self.assertRaisesRegex(ValueError,'stale or inconsistent'):
                    session.verify_swap_htlc({**terms,'refund_ready':True},**options)
                session.close()
    def test_swap_address_is_derived_locally_and_checked_after_unlock(self):
        with tempfile.TemporaryDirectory() as d:
            session=HostedWalletSession(rpc='http://127.0.0.1:9944',wallet_path=Path(d)/'wallet',manifest=Path(d)/'manifest',genesis='g',binary=Path(d)/'private-spend',scratch=d)
            calls=[]
            def fake_wallet(_binary,argv,secrets,_scratch,_label):calls.append((argv,bytes(secrets[0][1])));return 'shca1testaddress\n',{}
            with patch('local_swap_companion.public_v8_address_keys') as validate,patch('local_swap_companion.wallet',fake_wallet):
                with self.assertRaises(PermissionError):session.swap_address(check_node=lambda:{'height':100})
                session._phrase=bytearray(b'disposable')
                self.assertEqual(session.swap_address(check_node=lambda:{'height':100}),{'address':'shca1testaddress'})
                self.assertEqual(calls[-1][0][-3:],['address','--index','0']);validate.assert_called_once_with('shca1testaddress')
                session.close()
    def test_swap_htlc_lookup_and_inclusion_keep_wallet_output_local(self):
        with tempfile.TemporaryDirectory() as d:
            session=HostedWalletSession(rpc='http://127.0.0.1:9944',wallet_path=Path(d)/'wallet',manifest=Path(d)/'manifest',genesis='g',binary=Path(d)/'private-spend',scratch=d)
            candidate='aa'*32;action='bb'*48;block='cc'*32;anchor='dd'*32
            output={'text':json.dumps({'position':'7','created_height':'98','synced_height':'100'})}
            def fake_wallet(*_args):return output['text'],{}
            node=lambda:{'height':100}
            def read(_url,method,params):
                self.assertEqual(method,'chain_getBlockHash')
                return '0x'+(block if params==[98] else anchor)
            body=lambda _url,_block:([bytes.fromhex(action)+bytes(8)],{'height':98},None)
            with patch('local_swap_companion.wallet',fake_wallet):
                with self.assertRaises(PermissionError):session.locate_swap_htlc('ab'*56,check_node=node)
                session._phrase=bytearray(b'disposable')
                self.assertEqual(session.locate_swap_htlc('ab'*56,check_node=node),{'position':'7','created_height':'98','synced_height':'100'})
                output['text']=json.dumps({'attempt':candidate,'action_id':action,'mined':{'height':'98','block_hash':'0x'+block},'inputs_consumed':True,'synced_height':'100'})
                request={'attempt':candidate,'action_id':action}
                self.assertEqual(session.swap_attempt_inclusion(request,check_node=node,read=read,body=body),{'state':'confirmed','block_height':'98','block_hash':'0x'+block,'confirmations':3,'action_id':action})
                self.assertEqual(session.swap_attempt_inclusion({**request,'action_id':None},check_node=node,read=read,body=body)['action_id'],action)
                with self.assertRaisesRegex(ValueError,'does not match'):
                    session.swap_attempt_inclusion({**request,'action_id':'ee'*48},check_node=node,read=read,body=body)
                with self.assertRaisesRegex(ValueError,'absent or ambiguous'):
                    session.swap_attempt_inclusion(request,check_node=node,read=read,body=lambda *_:([],{'height':98},None))
                with self.assertRaisesRegex(ValueError,'no longer canonical'):
                    session.swap_attempt_inclusion(request,check_node=node,read=lambda *_:'0x'+'ff'*32,body=body)
                output['text']=json.dumps({'attempt':candidate,'action_id':action,'mined':None,'inputs_consumed':False,'synced_height':'100'})
                self.assertEqual(session.swap_attempt_inclusion(request,check_node=node,read=read,body=body),{'state':'pending','action_id':action})
                session.close()
    def test_swap_node_rejects_wrong_or_missing_private_spend_parameters(self):
        with patch('probe_hegemon_testnet.assert_public_profile',return_value=({'height':100,'basic_wallet_checks_passed':False},{})):
            with self.assertRaisesRegex(ValueError,'private-spend parameters'):
                local_swap_companion.read_hosted_swap_node('http://127.0.0.1:9944','genesis','manifest')
    def test_hegemon_companion_refuses_noninteractive_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            process=subprocess.run([sys.executable,'scripts/local_swap_companion.py','--token-file',str(Path(d)/'token'),
                '--hegemon-wallet','/tmp/wallet','--hegemon-manifest','/tmp/manifest',
                '--hegemon-genesis','a'*64,'--hegemon-rpc','http://127.0.0.1:19944'],
                stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(process.returncode,0)
            self.assertIn('interactive local terminal',process.stderr)
    def test_hegemon_public_and_development_actions_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as d:
            process=subprocess.run([sys.executable,'scripts/local_swap_companion.py','--token-file',str(Path(d)/'token'),
                '--hegemon-wallet','/tmp/wallet','--hegemon-manifest','/tmp/manifest',
                '--hegemon-genesis','a'*64,'--hegemon-rpc','http://127.0.0.1:19944',
                '--hegemon-public','--enable-hegemon-actions','--hegemon-handoff-dir',d],
                stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(process.returncode,0)
            self.assertIn('mutually exclusive',process.stderr)

    def test_hosted_node_status_restricts_origin_and_wallet_options(self):
        with tempfile.TemporaryDirectory() as d:
            base=[sys.executable,'scripts/local_swap_companion.py','--token-file',str(Path(d)/'token'),
                  '--hosted-node-status','--hegemon-rpc','http://127.0.0.1:19944']
            for extra in (['--origin','https://other.example'],['--hegemon-wallet','/tmp/wallet'],['--hegemon-public']):
                process=subprocess.run(base+extra,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
                self.assertNotEqual(process.returncode,0)
            process=subprocess.run(base[:-1]+['http://example.com:9944'],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(process.returncode,0)

    def test_hosted_node_status_is_pinned_authorized_and_read_only(self):
        release=json.loads(RELEASE.read_text());manifest=json.loads(MANIFEST.read_text())
        canonical=json.dumps({name:manifest[name] for name in MANIFEST_FIELDS},ensure_ascii=False,separators=(',',':')).encode()
        digest='0x'+hashlib.sha512(b'hegemon.native.network-manifest.sha512.v1\0'+canonical).hexdigest()
        responses={
            'chain_getBlockHash':release['genesis_hash'],
            'hegemon_nodeConfig':{'networkProfile':'pre-mainnet','chainId':release['chain_id'],
                                  'networkManifestDigest':digest,'networkManifest':manifest},
            'system_health':{'isSyncing':False,'peers':8},
            'rpc_methods':{'methods':list(REQUIRED)},
            'chain_getHeader':{'number':'0x21d3'},
            'hegemon_privateSpendParameters':{'relation_digest':RELATION,'action_id':15,'public_words':86,'ciphertext_bytes':2608},
        }
        calls=[]
        class RPC(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                calls.append(request['method'])
                data=json.dumps({'jsonrpc':'2.0','id':request['id'],'result':responses[request['method']]}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        rpc=ThreadingHTTPServer(('127.0.0.1',0),RPC)
        threading.Thread(target=rpc.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as d:
                token_path=Path(d)/'token'
                with socket.socket() as probe_port:
                    probe_port.bind(('127.0.0.1',0));port=probe_port.getsockname()[1]
                process=subprocess.Popen([sys.executable,'scripts/local_swap_companion.py','--hosted-node-status',
                    '--hegemon-rpc',f'http://127.0.0.1:{rpc.server_port}','--token-file',str(token_path),'--port',str(port)],
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
                try:
                    deadline=time.monotonic()+10
                    while not token_path.exists() and time.monotonic()<deadline and process.poll() is None:time.sleep(.02)
                    self.assertTrue(token_path.exists(),'companion did not start')
                    token=token_path.read_text().strip()
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    def request(path,method='GET',origin=HOSTED_ORIGIN,bearer=token,extra=None):
                        headers={'Origin':origin,'Authorization':'Bearer '+bearer,**(extra or {})}
                        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=b'{}' if method=='POST' else None,headers=headers,method=method)
                        for attempt in range(100):
                            try:return opener.open(req,timeout=2)
                            except urllib.error.HTTPError as error:return error
                            except urllib.error.URLError:
                                if attempt==99:raise
                                time.sleep(.02)
                    with request('/health') as response:
                        self.assertEqual(response.status,200)
                        self.assertEqual(json.load(response)['capabilities'],['hegemon-public-status'])
                        self.assertEqual(response.headers['Access-Control-Allow-Origin'],HOSTED_ORIGIN)
                    with request('/hegemon/status') as response:
                        self.assertEqual(json.load(response),{'network':'v0.11 pre-mainnet','height':'8659','syncing':False,'peers':8,'wallet_rpc_ready':True})
                    self.assertEqual(set(calls),set(responses))
                    with request('/health','OPTIONS',extra={'Access-Control-Request-Private-Network':'true'}) as response:
                        self.assertEqual(response.status,204)
                        self.assertEqual(response.headers['Access-Control-Allow-Methods'],'GET, OPTIONS')
                        self.assertEqual(response.headers['Access-Control-Allow-Private-Network'],'true')
                    for response in (request('/health',origin='https://other.example'),request('/health',bearer='0'*64),
                                     request('/health',extra={'Host':'evil.example'}),request('/hegemon/action','POST'),request('/hegemon/head')):
                        with response:self.assertIn(response.status,(403,404))
                    with request('/hegemon/balance') as response:
                        self.assertEqual(response.status,404)
                        self.assertNotIn(b'position=',response.read())
                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    process.stderr.close()
        finally:
            rpc.shutdown();rpc.server_close()

    def test_hosted_wallet_status_rejects_other_modes_and_a_noninteractive_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            wallet=Path(d)/'wallet'
            fd=os.open(wallet,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            os.write(fd,b'wallet');os.close(fd)
            base=[sys.executable,'scripts/local_swap_companion.py','--token-file',str(Path(d)/'token'),
                  '--hosted-wallet-status','--hegemon-rpc','http://127.0.0.1:19944','--hegemon-wallet',str(wallet)]
            process=subprocess.run(base,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(process.returncode,0)
            self.assertIn('interactive local terminal',process.stderr)
            for extra in (['--hosted-node-status'],['--hegemon-public'],['--enable-hegemon-actions'],['--origin','https://other.example'],['--hegemon-genesis','aa'*32]):
                process=subprocess.run(base+extra,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
                self.assertNotEqual(process.returncode,0,extra)
            missing=[sys.executable,'scripts/local_swap_companion.py','--token-file',str(Path(d)/'token'),
                     '--hosted-wallet-status','--hegemon-rpc','http://127.0.0.1:19944']
            process=subprocess.run(missing,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(process.returncode,0)
            self.assertIn('one wallet file',process.stderr)

    def test_hosted_swap_mode_requires_private_opt_in_and_rejects_other_origins(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);wallet=root/'wallet';wallet.write_bytes(b'disposable');wallet.chmod(0o600)
            token_path=root/'token';handoff=root/'handoffs';handoff.mkdir(mode=0o700)
            with socket.socket() as probe_port:
                probe_port.bind(('127.0.0.1',0));port=probe_port.getsockname()[1]
            argv=['local_swap_companion.py','--hosted-hegemon-swap','--hegemon-rpc','http://127.0.0.1:9',
                  '--hegemon-wallet',str(wallet),'--hegemon-handoff-dir',str(handoff),
                  '--private-spend',str(root/'fake-binary'),'--token-file',str(token_path),'--port',str(port)]
            calls=[];results={}
            def action(**kwargs):
                calls.append(kwargs['request'])
                if kwargs['preimage_backup']:
                    backup=kwargs['preimage_backup'];results['backup_path']=backup
                    self.assertEqual(backup.stat().st_mode & 0o777,0o600)
                    self.assertEqual(json.loads(backup.read_text())['envelope']['hashlock'],'ab'*32)
                return {'operation':kwargs['request']['operation'],'status':'disposable'}
            def client():
                try:
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));deadline=time.monotonic()+10;token=''
                    while time.monotonic()<deadline:
                        if token_path.exists():
                            token=token_path.read_text().strip()
                            try:
                                opener.open(urllib.request.Request(f'http://127.0.0.1:{port}/health',headers={'Origin':HOSTED_ORIGIN,'Authorization':'Bearer '+token}),timeout=1);break
                            except Exception:time.sleep(.02)
                    def call(path,method='GET',body=None,origin=HOSTED_ORIGIN,bearer=token):
                        data=None if body is None else json.dumps(body).encode()
                        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers={'Origin':origin,'Authorization':'Bearer '+bearer,'Content-Type':'application/json'},method=method)
                        try:return opener.open(req,timeout=5)
                        except urllib.error.HTTPError as error:return error
                    with call('/health') as response:results['capabilities']=json.load(response)['capabilities']
                    with call('/hegemon/swap/action','POST',{'operation':'status'},origin='https://evil.example') as response:results['wrong_origin']=response.status
                    with call('/hegemon/swap/action','POST',{'operation':'status'},bearer='0'*64) as response:results['wrong_token']=response.status
                    with call('/hegemon/swap/verify','POST',{'sample':'request'}) as response:results['verify']=(response.status,json.load(response))
                    with call('/hegemon/swap/observe','POST',{'sample':'request'}) as response:results['observe']=(response.status,json.load(response))
                    with call('/hegemon/swap/select','POST',{'amount':'8','fee':'1','exclude':[]}) as response:results['selection']=(response.status,json.load(response))
                    with call('/hegemon/swap/select','POST',{'amount':'8','fee':'1','exclude':[]},origin='https://evil.example') as response:results['selection_wrong_origin']=response.status
                    with call('/hegemon/swap/head') as response:results['head']=(response.status,json.load(response))
                    with call('/hegemon/swap/action','POST',{'operation':'status'}) as response:results['action']=(response.status,json.load(response))
                    envelope={'version':1,'iterations':600000,'hashlock':'ab'*32,'salt':'cd'*16,'iv':'ef'*12,'ciphertext':'12'*48}
                    with call('/hegemon/swap/action','POST',{'action':{'operation':'claim'},'secret_envelope':envelope}) as response:results['claim']=response.status
                    with call('/hegemon/swap/action','POST',{'action':{'operation':'refund'},'secret_envelope':envelope}) as response:results['bad_secret']=response.status
                    with call('/hegemon/action','POST',{'operation':'status'}) as response:results['legacy']=response.status
                except Exception as error:results['error']=error
                finally:
                    if local_swap_companion.active_server:local_swap_companion.active_server.shutdown()
            threading.Thread(target=client,daemon=True).start()
            with patch('sys.argv',argv),patch('local_swap_companion.os.isatty',return_value=True),\
                 patch('local_swap_companion.check_swap_wallet_binary'),patch('probe_hegemon_testnet.assert_public_profile',return_value=({'height':100,'genesis':'0x'+'ab'*32,'chain_id':'0x'+'cd'*32,'basic_wallet_checks_passed':True},{})),\
                 patch('local_swap_companion.HostedWalletSession.verify_swap_htlc',return_value={'verified':True,'position':'7'}),\
                 patch('local_swap_companion.HostedWalletSession.available_swap_notes',return_value={'synced_height':'100','available':[{'position':'7','value':'10'},{'position':'8','value':'20'}]}),\
                 patch('hegemon_swap_observer.observe_claim_request',return_value={'state':'pending'}),\
                 patch('local_swap_companion.run_hegemon_action',side_effect=action):
                local_swap_companion.main()
            if 'error' in results:raise results['error']
            self.assertIn('hegemon-swap-actions',results['capabilities'])
            self.assertEqual(results['wrong_origin'],403);self.assertEqual(results['wrong_token'],403)
            self.assertEqual(results['verify'],(200,{'verified':True,'snapshot':{'verified':True,'position':'7'}}))
            self.assertEqual(results['observe'],(200,{'state':'pending'}));self.assertEqual(results['legacy'],404)
            self.assertEqual(results['selection'],(200,{'inputs':['7'],'total':'10','synced_height':'100'}));self.assertEqual(results['selection_wrong_origin'],403)
            self.assertEqual(results['head'],(200,{'network':'pre-mainnet','height':'100','genesis':'0x'+'ab'*32,'chain_id':'0x'+'cd'*32}))
            self.assertEqual(results['action'][0],200);self.assertEqual(results['claim'],200);self.assertEqual(results['bad_secret'],409)
            self.assertFalse(results['backup_path'].exists());self.assertEqual(calls,[{'operation':'status'},{'operation':'claim'}])

    def test_hosted_balance_view_and_session_keep_totals_and_refresh(self):
        text='\n'.join(['ordinary position=7 value=5',
            'balance synced_height=10 available_atoms=5000000 available_notes=2 reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false immature_atoms=11',
            'htlc position=9 value=3'])
        view=hosted_balance_view(text,12)
        encoded=json.dumps(view)
        self.assertNotIn('position',encoded)
        self.assertNotIn('ordinary',encoded)
        self.assertEqual(view['available_atoms'],'5000000')
        self.assertEqual(view['immature_atoms'],'11')
        self.assertEqual(view['observed_height'],'12')
        self.assertIs(view['watch_only'],False)
        calls=[]
        chain={'height':10}
        def fake_wallet(_binary,_args,secrets,directory,label,expected=True,timeout=600,on_output=None):
            calls.append(bytes(secrets[0][1]))
            body=text.replace('synced_height=10','synced_height=%s'%chain['height'])
            (Path(directory)/(label+'.log')).write_text(body)
            return body,{}
        with tempfile.TemporaryDirectory() as d:
            session=HostedWalletSession(rpc='http://127.0.0.1:9',wallet_path=Path(d)/'wallet',manifest=Path(d)/'manifest',genesis='aa'*32,binary=Path(d)/'private-spend',scratch=d,read_node=lambda:{'height':chain['height']})
            with patch('local_swap_companion.wallet',fake_wallet),patch('local_swap_companion.confirm_unlock',return_value='NO'),patch('local_swap_companion.read_passphrase',return_value='unit-test-passphrase'):
                with self.assertRaises(ValueError):session.unlock()
            with patch('local_swap_companion.wallet',fake_wallet),patch('local_swap_companion.confirm_unlock',return_value='UNLOCK'),patch('local_swap_companion.read_passphrase',return_value='unit-test-passphrase'):
                unlocked=session.unlock()
                self.assertEqual(unlocked['available_atoms'],'5000000')
                self.assertEqual(len(calls),1)
                self.assertEqual(calls[0],b'unit-test-passphrase')
                session.balance()
                self.assertEqual(len(calls),1)
                session._cached_at-=61
                session.balance()
                self.assertEqual(len(calls),1,'an unchanged chain height reuses the saved read')
                chain['height']=13
                session.balance()
                self.assertEqual(len(calls),2)
                session._cached['synced_height']='7'
                session._cached_at=time.monotonic()
                chain['height']=10
                session.balance()
                self.assertEqual(len(calls),3)
                self.assertFalse((Path(d)/'hegemon-hosted-balance.log').exists())
            session.close()
            with self.assertRaises(PermissionError):session.balance()

    def test_status_stamps_the_tip_after_the_wallet_read_and_retries_a_large_gap_once(self):
        caught='\n'.join(['balance synced_height=12 available_atoms=5000000 available_notes=1 reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false immature_atoms=0'])
        behind='\n'.join(['balance synced_height=10 available_atoms=5000000 available_notes=1 reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false immature_atoms=0'])
        chain={'height':10}
        calls=[]
        def catching_wallet(_binary,_args,secrets,directory,label,expected=True,timeout=600,on_output=None):
            calls.append('catch')
            chain['height']=12
            return caught,{}
        with tempfile.TemporaryDirectory() as d:
            session=HostedWalletSession(rpc='http://127.0.0.1:9',wallet_path=Path(d)/'wallet',manifest=Path(d)/'manifest',genesis='aa'*32,binary=Path(d)/'private-spend',scratch=d,read_node=lambda:{'height':chain['height']})
            with patch('local_swap_companion.wallet',catching_wallet),patch('local_swap_companion.confirm_unlock',return_value='UNLOCK'),patch('local_swap_companion.read_passphrase',return_value='unit-test-passphrase'):
                unlocked=session.unlock()
            self.assertEqual(calls,['catch'])
            self.assertEqual(unlocked['synced_height'],'12')
            self.assertEqual(unlocked['observed_height'],'12')
            session._cached['synced_height']='14'
            session._cached_at=time.monotonic()
            chain['height']=10
            def still_behind(_binary,_args,secrets,directory,label,expected=True,timeout=600,on_output=None):
                calls.append(session.activity.snapshot()['phase'])
                return behind,{}
            with patch('local_swap_companion.wallet',still_behind):
                refreshed=session.balance()
            self.assertEqual(calls,['catch','syncing'])
            self.assertEqual(refreshed['synced_height'],'10')
            self.assertEqual(refreshed['observed_height'],'10')
            self.assertEqual(session.activity.snapshot(),{'phase':'idle'})
            chain['height']=15
            with patch('local_swap_companion.wallet',still_behind):
                lagged=session.balance()
            self.assertEqual(calls,['catch','syncing','syncing','syncing'])
            self.assertEqual(lagged['synced_height'],'10')
            self.assertEqual(lagged['observed_height'],'15')

    def test_hosted_wallet_status_balance_omits_note_rows(self):
        secret='local-terminal-secret'
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            wallet=root/'wallet'
            fd=os.open(wallet,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            os.write(fd,b'not-a-real-wallet');os.close(fd)
            counter=root/'runs'
            script=root/'private-spend'
            script.write_text('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\nPath(%r).open("a").write("ran\\n")\nsys.stdout.write("Encrypted wallet passphrase: ")\nsys.stdout.flush()\nsys.stdin.readline()\nsys.stdout.write("ordinary position=7 value=5\\n")\nsys.stdout.write("balance synced_height=8659 available_atoms=5000000 available_notes=2 reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false immature_atoms=11\\n")\nsys.stdout.write("htlc position=9 value=3\\n")\nsys.stdout.flush()\n'%str(counter))
            script.chmod(0o700)
            with socket.socket() as probe_port:
                probe_port.bind(('127.0.0.1',0));port=probe_port.getsockname()[1]
            token_path=root/'token'
            argv=['local_swap_companion.py','--hosted-wallet-status','--hegemon-rpc','http://127.0.0.1:9','--hegemon-wallet',str(wallet),'--private-spend',str(script),'--token-file',str(token_path),'--port',str(port)]
            state={'ready':True}
            def read_node(_rpc):
                if not state['ready']:raise LookupError('hegemon_node_not_ready')
                return {'height':8659,'basic_wallet_checks_passed':True}
            results={}
            def client():
                try:
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    deadline=time.monotonic()+15
                    token=''
                    while time.monotonic()<deadline:
                        if token_path.exists():
                            token=token_path.read_text().strip()
                            try:
                                opener.open(urllib.request.Request(f'http://127.0.0.1:{port}/health',headers={'Origin':HOSTED_ORIGIN,'Authorization':'Bearer '+token}),timeout=1)
                                break
                            except Exception:time.sleep(.02)
                    def call(path,method='GET',body=None):
                        data=None if body is None else body
                        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers={'Origin':HOSTED_ORIGIN,'Authorization':'Bearer '+token,'Content-Type':'application/json'},method=method)
                        try:return opener.open(req,timeout=10)
                        except urllib.error.HTTPError as error:return error
                    with call('/hegemon/balance') as response:
                        results['locked']=(response.status,response.read())
                    with call('/hegemon/unlock','POST',b'{}') as response:
                        results['unlock']=(response.status,response.read())
                    with call('/hegemon/wallet-activity') as response:
                        results['activity']=(response.status,response.read())
                    with call('/hegemon/balance') as response:
                        results['balance']=(response.status,response.read())
                    with call('/hegemon/balance') as response:
                        results['cached']=(response.status,response.read())
                    state['ready']=False
                    with call('/hegemon/balance') as response:
                        results['down']=(response.status,response.read())
                except Exception as error:
                    results['error']=error
                finally:
                    server=local_swap_companion.active_server
                    if server:server.shutdown()
            threading.Thread(target=client,daemon=True).start()
            with patch('sys.argv',argv),patch('local_swap_companion.os.isatty',return_value=True),patch('local_swap_companion.read_hosted_node',read_node),patch('local_swap_companion.confirm_unlock',return_value='UNLOCK'),patch('local_swap_companion.read_passphrase',return_value=secret):
                local_swap_companion.main()
            self.assertNotIn('error',results,results.get('error'))
            self.assertEqual(results['locked'][0],409)
            self.assertEqual(json.loads(results['locked'][1]),{'error':'wallet_locked'})
            self.assertEqual(results['unlock'][0],200)
            unlocked=json.loads(results['unlock'][1])
            self.assertEqual(unlocked['unlocked'],True)
            self.assertEqual(unlocked['balance']['available_atoms'],'5000000')
            self.assertEqual(unlocked['balance']['immature_atoms'],'11')
            self.assertIs(unlocked['balance']['watch_only'],False)
            for name in ('locked','unlock','balance','cached','down'):
                body=results[name][1]
                self.assertNotIn(b'position=',body)
                self.assertNotIn(b'ordinary',body)
                self.assertNotIn(secret.encode(),body)
            self.assertEqual(results['cached'][0],200)
            self.assertEqual(json.loads(results['balance'][1])['available_atoms'],'5000000')
            self.assertEqual(counter.read_text().count('ran'),1,'a fresh balance read must not run private-spend again')
            self.assertEqual(results['down'][0],503)
            self.assertEqual(json.loads(results['down'][1]),{'error':'hegemon_node_not_ready'})
            self.assertEqual(results['activity'][0],200)
            activity=json.loads(results['activity'][1])
            self.assertEqual(activity,{'phase':'idle'})
            self.assertNotIn(b'position=',results['activity'][1])
            self.assertNotIn(secret.encode(),results['activity'][1])

    def test_wallet_activity_reports_block_progress_and_drops_note_rows(self):
        self.assertIsNone(wallet_progress_event('ordinary position=7 value=5'))
        self.assertIsNone(wallet_progress_event('Encrypted wallet passphrase: local-terminal-secret'))
        self.assertEqual(wallet_progress_event('Syncing blocks: 12000/15445; new notes 3'),('sync',12000,15445))
        self.assertEqual(wallet_progress_event('Resuming from saved block 15440 of 15445.'),('resume',15440,15445))
        self.assertEqual(wallet_progress_event('Saved wallet is already at block 15445.'),('saved',15445,15445))
        self.assertEqual(wallet_progress_event('Checking wallet history: 4/9'),('history',4,9))
        self.assertEqual(wallet_progress_event('wallet-progress stage=sync current=4 target=9 notes=1 elapsed_ms=20'),('sync',4,9))
        self.assertEqual(wallet_progress_event('wallet-progress stage=unlock current=8724 target=36840 notes=0 elapsed_ms=20'),('history',8724,36840))
        self.assertIsNone(wallet_progress_event('Syncing blocks: 9/4; new notes 0'))
        activity=WalletActivity()
        activity.add_output(b'ordinary position=7 value=5\nResuming from saved block 15440 of 15445.\nSyncing blocks: 100/15445; new notes 2\npartial')
        self.assertEqual(activity.snapshot(),{'phase':'syncing','current_height':'100','target_height':'15445','resumed':True,'kind':'blocks'})
        notes=WalletActivity()
        notes.add_output(b'wallet-progress stage=unlock current=8724 target=36840 notes=0 elapsed_ms=20\n')
        self.assertEqual(notes.snapshot(),{'phase':'syncing','current_height':'8724','target_height':'36840','kind':'history'})
        sentence=describe_companion_status(notes.snapshot())
        self.assertEqual(sentence,'Checking saved notes: 8724 of 36840.')
        self.assertNotIn('block',sentence)
        encoded=json.dumps(activity.snapshot())
        self.assertNotIn('position',encoded)
        self.assertNotIn('notes',encoded)

    def test_desktop_keyring_roundtrip_keeps_the_passphrase_off_the_command_and_off_disk(self):
        phrase='saved-passphrase'
        with tempfile.TemporaryDirectory() as d:
            wallet=Path(d)/'wallet'
            wallet.write_bytes(b'not-a-real-wallet')
            memory={}
            def run(argv,input=None,capture_output=True,timeout=10):
                self.assertEqual(argv[0],'secret-tool')
                self.assertNotIn(phrase,' '.join(argv))
                self.assertNotIn('>',argv)
                key=tuple(argv[argv.index('service'):])
                if argv[1]=='store':
                    memory[key]=input
                    return subprocess.CompletedProcess(argv,0,b'',b'')
                if argv[1]=='lookup':
                    stored=memory.get(key)
                    return subprocess.CompletedProcess(argv,0 if stored else 1,stored or b'',b'')
                if argv[1]=='clear':
                    memory.pop(key,None)
                    return subprocess.CompletedProcess(argv,0,b'',b'')
                self.fail(argv)
            ring=DesktopKeyring(run)
            self.assertIsNone(ring.load(wallet))
            ring.save(wallet,phrase)
            self.assertEqual(ring.load(wallet),phrase)
            self.assertEqual(memory[next(iter(memory))],phrase.encode()+b'\n')
            self.assertEqual(list(Path(d).iterdir()),[wallet])
            ring.delete(wallet)
            self.assertIsNone(ring.load(wallet))
            with self.assertRaises(ValueError):
                ring.save(wallet,'has\nnewline')
            def missing(argv,input=None,capture_output=True,timeout=10):
                raise FileNotFoundError(argv[0])
            with self.assertRaises(local_swap_companion.KeyringUnavailable) as caught:
                DesktopKeyring(missing).save(wallet,phrase)
            self.assertNotIn(phrase,str(caught.exception))
            self.assertEqual(list(Path(d).iterdir()),[wallet])

    def test_gui_approval_unlocks_without_putting_the_passphrase_on_the_activity_read(self):
        phrase='window-only-passphrase'
        text='balance synced_height=10 available_atoms=5000000 available_notes=1 reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false immature_atoms=0\n'
        saved=[]
        class Ring:
            def save(self,path,secret):saved.append(secret)
            def delete(self,path):saved.append('deleted')
            def load(self,path):return None
        def fake_wallet(_binary,_args,secrets,directory,label,expected=True,timeout=600,on_output=None):
            self.assertEqual(bytes(secrets[0][1]),phrase.encode())
            return text,{}
        self.assertEqual(describe_companion_status({'phase':'syncing','current_height':'15440','target_height':'15445','resumed':True}),'Resuming from the saved wallet: block 15440 of 15445.')
        with tempfile.TemporaryDirectory() as d:
            prompt=GuiApproval()
            session=HostedWalletSession(rpc='http://127.0.0.1:9',wallet_path=Path(d)/'wallet',manifest=Path(d)/'manifest',genesis='aa'*32,binary=Path(d)/'private-spend',scratch=d,read_node=lambda:{'height':10},prompt=prompt,keyring=Ring())
            def approve():
                while not prompt.waiting():time.sleep(0.01)
                self.assertTrue(prompt.submit(phrase,True))
            threading.Thread(target=approve,daemon=True).start()
            with patch('local_swap_companion.wallet',fake_wallet),patch('local_swap_companion.confirm_unlock',side_effect=AssertionError('terminal prompt used')),patch('local_swap_companion.read_passphrase',side_effect=AssertionError('terminal prompt used')):
                view=session.unlock()
            self.assertEqual(saved,[phrase])
            self.assertNotIn(phrase,json.dumps(view))
            self.assertNotIn(phrase,json.dumps(session.activity.snapshot()))
            self.assertEqual(session.activity.snapshot(),{'phase':'idle'})
            prompt=GuiApproval()
            session.prompt=prompt
            def decline():
                while not prompt.waiting():time.sleep(0.01)
                self.assertTrue(prompt.decline())
            threading.Thread(target=decline,daemon=True).start()
            with patch('local_swap_companion.confirm_unlock',side_effect=AssertionError('terminal prompt used')):
                with self.assertRaisesRegex(ValueError,'wallet unlock declined locally'):
                    session.unlock()
            self.assertNotIn(phrase,json.dumps(session.activity.snapshot()))

class NodeActivityTest(unittest.TestCase):
    def test_each_startup_phase_names_the_step_and_its_fraction(self):
        for phase, title in NODE_ACTIVITY_PHASES.items():
            fractional = phase in NODE_ACTIVITY_FRACTIONS
            view = describe_node_activity({
                'source': 'file', 'phase': phase, 'pid_alive': True,
                'current': 14200 if fractional else None,
                'total': 15818 if fractional else None,
                'remaining_seconds': 360, 'slowed': False,
            })
            self.assertEqual(view['title'], title)
            self.assertEqual(view['tone'], 'working')
            self.assertIn('not accepting connections', view['consequence'])
            if fractional:
                self.assertEqual(view['fraction'], 'Block 14,200 of 15,818')
                self.assertAlmostEqual(view['progress'], 14200 / 15818)
                self.assertEqual(view['time_line'], 'About 6 minutes left')
            else:
                self.assertEqual(view['fraction'], '')
                self.assertIsNone(view['progress'])
        ready = describe_node_activity({'source': 'file', 'phase': 'ready', 'pid_alive': True})
        self.assertEqual(ready['consequence'], 'The node is not accepting connections yet.')

    def test_eta_rounds_above_ninety_seconds_and_marks_a_slower_stretch(self):
        self.assertEqual(format_node_eta(60, False, False), 'Under a minute left')
        self.assertEqual(format_node_eta(90, False, True), 'Under a minute to the current target.')
        self.assertEqual(format_node_eta(91, False, False), 'About 2 minutes left')
        self.assertEqual(format_node_eta(360, False, True), 'About 6 minutes to the current target.')
        remaining, slowed = estimate_node_remaining([(0, 0), (10, 1000), (110, 1100)], 2100)
        self.assertTrue(slowed)
        self.assertEqual(remaining, 1000)
        self.assertEqual(format_node_eta(remaining, slowed, False), 'This stretch slowed down. About 17 minutes at this pace.')
        steady, steady_slow = estimate_node_remaining([(0, 0), (10, 100)], 200)
        self.assertFalse(steady_slow)
        self.assertEqual(steady, 10)

    def test_dead_pid_and_quiet_pid_are_different(self):
        dead = describe_node_activity({
            'source': 'file', 'phase': 'rechecking_proofs', 'pid_alive': False,
            'current': 14200, 'total': 15818,
        })
        self.assertEqual(dead['title'], 'Not running')
        self.assertEqual(dead['tone'], 'stopped')
        self.assertEqual(dead['consequence'], 'The node stopped during rechecking private proofs at block 14,200 of 15,818.')
        quiet = describe_node_activity({
            'source': 'file', 'phase': 'rechecking_proofs', 'pid_alive': True, 'quiet': True,
            'quiet_minutes': 3, 'current': 14200, 'total': 15818, 'remaining_seconds': 10,
        })
        self.assertEqual(quiet['title'], 'Rechecking private proofs')
        self.assertEqual(quiet['tone'], 'working')
        self.assertEqual(quiet['time_line'], 'Still on this step. Last update was 3 minutes ago.')

    def test_caught_up_service_and_closed_port(self):
        caught = describe_node_activity({'source': 'rpc', 'height': 16427, 'target': 16427, 'syncing': False, 'peers': 15})
        self.assertEqual(caught['title'], 'Caught up')
        self.assertEqual(caught['tone'], 'caught_up')
        self.assertEqual(caught['progress'], 1.0)
        self.assertEqual(caught['consequence'], 'Ready. Height 16,427, 15 peers.')
        one = describe_node_activity({'source': 'rpc', 'height': 5, 'target': 5, 'syncing': False, 'peers': 1})
        self.assertEqual(one['consequence'], 'Ready. Height 5, 1 peer.')
        closed = describe_node_activity({'source': 'none', 'endpoint': '127.0.0.1:9944'})
        self.assertEqual(closed['title'], 'Not running')
        self.assertEqual(closed['consequence'], 'Nothing is listening on 127.0.0.1:9944.')

    def test_activity_file_ignores_symlink_and_bad_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'node-activity.json'
            body = {'phase': 'loading_rows', 'current': None, 'total': None, 'updated_at_ms': 10, 'pid': 4, 'note': 'ignored'}
            path.write_text(json.dumps(body))
            self.assertEqual(read_node_activity(path)['phase'], 'loading_rows')
            path.write_text(json.dumps({'phase': 'nope', 'current': None, 'total': None, 'updated_at_ms': 10, 'pid': 4}))
            self.assertIsNone(read_node_activity(path))
            path.write_text(json.dumps({'phase': 'rechecking_proofs', 'current': 20, 'total': 10, 'updated_at_ms': 10, 'pid': 4}))
            self.assertIsNone(read_node_activity(path))
            path.write_bytes(b'{' + b'x' * 5000)
            self.assertIsNone(read_node_activity(path))
            path.write_text(json.dumps(body))
            link = root / 'link.json'
            link.symlink_to(path)
            self.assertIsNone(read_node_activity(link))

    def test_monitor_prefers_rpc_and_reports_a_dead_or_quiet_file(self):
        caught = NodeActivityMonitor(
            'http://127.0.0.1:9944', Path('/unused'),
            read_rpc=lambda url: {'height': 16427, 'target': 16427, 'syncing': False, 'peers': 1},
            read_file=lambda path: self.fail('file read while RPC answered'),
            clock=lambda: 1_000_000)
        caught.poll_once()
        self.assertEqual(caught.snapshot()['consequence'], 'Ready. Height 16,427, 1 peer.')

        dead_record = {'phase': 'rechecking_proofs', 'current': 14200, 'total': 15818, 'updated_at_ms': 1_000_000_000, 'pid': 99}
        dead = NodeActivityMonitor(
            'http://127.0.0.1:9944', Path('/unused'),
            read_rpc=lambda url: (_ for _ in ()).throw(OSError('closed')),
            read_file=lambda path: dead_record, pid_alive=lambda pid: False, clock=lambda: 1_000_000)
        dead.poll_once()
        self.assertEqual(dead.snapshot()['consequence'], 'The node stopped during rechecking private proofs at block 14,200 of 15,818.')

        quiet_record = dict(dead_record, updated_at_ms=1_000_000_000 - 180_000)
        quiet = NodeActivityMonitor(
            'http://127.0.0.1:9944', Path('/unused'),
            read_rpc=lambda url: (_ for _ in ()).throw(OSError('closed')),
            read_file=lambda path: quiet_record, pid_alive=lambda pid: pid == 99, clock=lambda: 1_000_000)
        quiet.poll_once()
        self.assertEqual(quiet.snapshot()['title'], 'Rechecking private proofs')
        self.assertEqual(quiet.snapshot()['time_line'], 'Still on this step. Last update was 3 minutes ago.')

if __name__=='__main__':unittest.main()
