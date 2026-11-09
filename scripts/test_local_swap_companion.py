import os
import hashlib
import json
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
from local_swap_companion import HOSTED_ORIGIN, cardano_wire_terms, hegemon_wire_terms, private_token
from probe_hegemon_testnet import MANIFEST, MANIFEST_FIELDS, RELEASE, RELATION, REQUIRED

class LocalCompanionTest(unittest.TestCase):
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
                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    process.stderr.close()
        finally:
            rpc.shutdown();rpc.server_close()

if __name__=='__main__':unittest.main()
