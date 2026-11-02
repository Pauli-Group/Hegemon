#!/usr/bin/env python3
"""Loopback-only local escrow companion.

By default it only verifies escrows. Optional Hegemon Development actions
require explicit startup opt-in and local terminal approval. The bearer token
is stored in a user-private file and is not a wallet passphrase.
"""
import argparse
import datetime
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import tempfile
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from bitcoin_escrow_verifier import verify_bitcoin_htlc
from cardano_escrow_verifier import verify_cardano_htlc
from development_atomic_swap_rehearsal import BitcoinRPC
from htlc_counterpart import ROOT, TOOLS
from hegemon_action_runner import run_hegemon_action
from hegemon_local_actions import private_handoff_directory
from ethereum_local_anchor import ethereum_local_head
from bitcoin_local_actions import run_bitcoin_action
from cardano_local_actions import run_cardano_action,local_node_identity,private_key,private_journal_directory
from local_private_spend_swap import PASS, wallet
from release_private_spend_lifecycle_io import rpc, json_line, public_v8_address_keys, height


def private_token(path):
    parent=path.parent.stat()
    if parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)&0o077:
        raise ValueError('token directory must be owned by this user and mode 0700')
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd,'w') as f:
            f.write(secrets.token_hex(32)+'\n');f.flush();os.fsync(f.fileno())
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>128:
            raise ValueError('token must be a private mode-0600 regular file')
        token=f.read().strip()
    if len(token)!=64 or any(c not in '0123456789abcdef' for c in token):raise ValueError('invalid companion token file')
    return token


def cardano_wire_terms(data):
    """Convert decimal strings exactly; browser numbers cannot represent u64 values."""
    def decimal(value):
        if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,18}',value):raise ValueError('invalid Cardano integer')
        result=int(value)
        if result>=2**63:raise ValueError('Cardano integer out of range')
        return result
    value=data['expected_value']
    if not isinstance(value,dict):raise ValueError('invalid Cardano value')
    converted={}
    for policy,assets in value.items():
        if policy=='lovelace':converted[policy]=decimal(assets)
        else:
            if not isinstance(assets,dict):raise ValueError('invalid Cardano asset map')
            converted[policy]={name:decimal(quantity) for name,quantity in assets.items()}
    return {**data,'expiry_ms':decimal(data['expiry_ms']),'expected_value':converted}


def hegemon_wire_terms(data):
    values={}
    for field in ('locked','timeout','amount','min_confirmations','min_remaining_blocks'):
        value=data[field]
        if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,19}',value) or int(value)>=2**64:raise ValueError('invalid Hegemon integer')
        values[field]=value
    if values['amount']=='0' or values['min_confirmations']=='0' or values['min_remaining_blocks']=='0':raise ValueError('invalid Hegemon verification limits')
    if not isinstance(data['hashlock'],str) or not re.fullmatch('[0-9a-f]{64}',data['hashlock']):raise ValueError('invalid hashlock')
    for field in ('claim','refund'):public_v8_address_keys(data[field])
    return {**data,**values}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bitcoin-rpc',help='Bitcoin Core regtest RPC on loopback')
    p.add_argument('--bitcoin-cookie',type=Path)
    p.add_argument('--enable-bitcoin-actions',action='store_true',help='enable locally approved Bitcoin regtest wallet actions')
    p.add_argument('--bitcoin-wallet',help='preloaded Bitcoin Core descriptor wallet name')
    p.add_argument('--bitcoin-genesis',help='expected regtest genesis hash')
    p.add_argument('--bitcoin-preimage-backup',type=Path,help='optional private exported browser backup for local claims')
    p.add_argument('--cardano-socket',type=Path)
    p.add_argument('--cardano-network-dir',type=Path,help='directory containing the trusted local Shelley genesis')
    p.add_argument('--enable-cardano-actions',action='store_true',help='enable locally approved isolated Cardano actions')
    p.add_argument('--cardano-node-pid',type=int,help='process ID of the local Cardano node owning the socket')
    p.add_argument('--cardano-genesis',help='SHA-256 of the trusted local Shelley genesis')
    p.add_argument('--cardano-signing-key',type=Path,help='private local payment signing key')
    p.add_argument('--cardano-journal-dir',type=Path,help='private directory for durable public transaction records')
    p.add_argument('--cardano-preimage-backup',type=Path,help='optional private exported browser backup for local claims')
    p.add_argument('--ethereum-rpc',help='non-forked Anvil RPC on loopback, chain ID 31337')
    p.add_argument('--cardano-cli',type=Path,default=TOOLS/'cardano/bin/cardano-cli')
    p.add_argument('--aiken',type=Path,default=TOOLS/'aiken/aiken-x86_64-unknown-linux-musl/aiken')
    p.add_argument('--hegemon-wallet',type=Path)
    p.add_argument('--hegemon-manifest',type=Path)
    p.add_argument('--hegemon-genesis')
    p.add_argument('--hegemon-rpc')
    p.add_argument('--private-spend',type=Path,default=ROOT/'target/release/private-spend')
    p.add_argument('--enable-hegemon-actions',action='store_true',help='enable locally approved Development-only wallet actions')
    p.add_argument('--hegemon-handoff-dir',type=Path,help='private directory for encrypted refund handoffs')
    p.add_argument('--hegemon-preimage-backup',type=Path,help='optional private exported browser backup for local claims')
    p.add_argument('--token-file',type=Path,required=True,help='0600 file inside a user-owned 0700 directory')
    p.add_argument('--origin',default='http://127.0.0.1:8787')
    p.add_argument('--port',type=int,default=8788)
    args=p.parse_args();os.umask(0o077)
    origin=urlsplit(args.origin)
    if origin.scheme!='http' or origin.hostname not in ('127.0.0.1','localhost') or not origin.port or origin.path or origin.query or origin.fragment or origin.username:raise ValueError('origin must be an explicit loopback HTTP origin')
    if not 1<=args.port<=65535:raise ValueError('invalid port')
    if bool(args.bitcoin_rpc)!=bool(args.bitcoin_cookie):p.error('Bitcoin RPC and cookie must be supplied together')
    if args.enable_bitcoin_actions:
        if not args.bitcoin_rpc or not args.bitcoin_wallet or not re.fullmatch('[A-Za-z0-9_-]{1,64}',args.bitcoin_wallet) or not re.fullmatch('[0-9a-f]{64}',args.bitcoin_genesis or ''):p.error('Bitcoin actions require a local RPC, cookie, wallet name and genesis')
        if not os.isatty(0):p.error('Bitcoin actions require an interactive local terminal')
    elif args.bitcoin_wallet or args.bitcoin_genesis or args.bitcoin_preimage_backup:p.error('Bitcoin wallet options require Bitcoin actions')
    if bool(args.cardano_socket)!=bool(args.cardano_network_dir):p.error('Cardano socket and network directory must be supplied together')
    if args.enable_cardano_actions:
        if not args.cardano_socket or not args.cardano_node_pid or not args.cardano_genesis or not args.cardano_signing_key or not args.cardano_journal_dir:p.error('Cardano actions require the socket, network directory, node PID, genesis, signing key and journal directory')
        if not os.isatty(0):p.error('Cardano actions require an interactive local terminal')
        local_node_identity(args.cardano_node_pid,args.cardano_socket,args.cardano_network_dir,args.cardano_genesis);private_key(args.cardano_signing_key);private_journal_directory(args.cardano_journal_dir)
    elif args.cardano_node_pid or args.cardano_genesis or args.cardano_signing_key or args.cardano_journal_dir or args.cardano_preimage_backup:p.error('Cardano wallet options require Cardano actions')
    hegemon_options=[args.hegemon_wallet,args.hegemon_manifest,args.hegemon_genesis,args.hegemon_rpc]
    if any(hegemon_options) and not all(hegemon_options):p.error('all Hegemon wallet, manifest, genesis and RPC options are required')
    if not args.bitcoin_rpc and not args.cardano_socket and not args.ethereum_rpc and not all(hegemon_options):p.error('configure at least one local node')
    if args.ethereum_rpc:ethereum_local_head(args.ethereum_rpc)
    if all(hegemon_options):
        if not os.isatty(0):p.error('Hegemon verification requires an interactive local terminal')
        endpoint=urlsplit(args.hegemon_rpc)
        if endpoint.scheme!='http' or endpoint.hostname not in ('127.0.0.1','localhost') or endpoint.username or not re.fullmatch('(0x)?[0-9a-f]{64}',args.hegemon_genesis):p.error('Hegemon requires a loopback RPC and canonical genesis hash')
    if args.enable_hegemon_actions:
        if not all(hegemon_options):p.error('Hegemon actions require all Hegemon options')
        private_handoff_directory(args.hegemon_handoff_dir)
    if args.hegemon_preimage_backup and not args.enable_hegemon_actions:p.error('preimage backup requires Hegemon actions')
    token=private_token(args.token_file)
    btc=BitcoinRPC(args.bitcoin_rpc,args.bitcoin_cookie) if args.bitcoin_rpc else None
    if args.enable_bitcoin_actions:
        if btc.call('getblockchaininfo')['chain']!='regtest' or btc.call('getblockhash',0)!=args.bitcoin_genesis or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin requires the configured isolated regtest chain')
        btc.call('getwalletinfo',wallet=args.bitcoin_wallet)
    scratch=tempfile.TemporaryDirectory(prefix='hegemon-local-companion-')
    cardano=None
    if args.cardano_socket:
        if not stat.S_ISSOCK(args.cardano_socket.stat().st_mode):raise ValueError('Cardano socket must be a local Unix socket')
        class CardanoView:
            magic='424242'
            net=args.cardano_network_dir
            socket=args.cardano_socket
            aiken=args.aiken
            script=Path(scratch.name)/'validator.plutus'
            script.write_text(subprocess.check_output([str(args.aiken),'blueprint','convert',str(ROOT/'contracts/cardano')],text=True))
            def run(self,*values):
                result=subprocess.run([str(args.cardano_cli),'conway',*map(str,values)],capture_output=True,text=True,timeout=60)
                if result.returncode:raise RuntimeError('local Cardano CLI request failed')
                return result.stdout
            def query(self,*values):
                return json.loads(self.run('query',*values,'--testnet-magic',self.magic,'--socket-path',args.cardano_socket,'--output-json'))
            def tip(self):return self.query('tip')
            def utxos(self,address):return self.query('utxo','--address',address)
        cardano=CardanoView()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def permitted(self):
            return self.headers.get('Host')==f'127.0.0.1:{args.port}' and self.headers.get('Origin')==args.origin
        def reply(self,status,value):
            data=json.dumps(value,separators=(',',':')).encode()
            self.send_response(status)
            if self.permitted():self.send_header('Access-Control-Allow-Origin',args.origin)
            self.send_header('Vary','Origin');self.send_header('Cache-Control','no-store')
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
        def do_OPTIONS(self):
            if not self.permitted():return self.reply(403,{'error':'forbidden'})
            self.send_response(204);self.send_header('Access-Control-Allow-Origin',args.origin)
            self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers','authorization, content-type')
            self.send_header('Vary','Origin');self.end_headers()
        def authorized(self):
            value=self.headers.get('Authorization','')
            return self.permitted() and value.startswith('Bearer ') and re.fullmatch('[0-9a-f]{64}',value[7:]) is not None and hmac.compare_digest(value[7:],token)
        def do_GET(self):
            if not self.authorized():return self.reply(403,{'error':'forbidden'})
            try:
                if self.path=='/health':
                    capabilities=(['bitcoin-regtest-verify'] if btc else [])+(['bitcoin-regtest-actions'] if args.enable_bitcoin_actions else [])+(['cardano-local-verify'] if cardano else [])+(['cardano-local-actions'] if args.enable_cardano_actions else [])+(['ethereum-local-anchor'] if args.ethereum_rpc else [])+(['hegemon-local-verify'] if all(hegemon_options) else [])+(['hegemon-local-actions'] if args.enable_hegemon_actions else [])
                    return self.reply(200,{'status':'ok','capabilities':capabilities})
                if self.path=='/bitcoin/head' and btc:
                    info=btc.call('getblockchaininfo')
                    if info['chain']!='regtest' or btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not isolated regtest')
                    return self.reply(200,{'genesis':btc.call('getblockhash',0),'height':str(info['blocks']),'tip_hash':info['bestblockhash']})
                if self.path=='/ethereum/head' and args.ethereum_rpc:
                    return self.reply(200,ethereum_local_head(args.ethereum_rpc))
                if self.path=='/cardano/head' and cardano:
                    raw=(cardano.net/'shelley-genesis.json').read_bytes();genesis=json.loads(raw)
                    if genesis.get('networkId')!='Testnet' or genesis.get('networkMagic')!=424242:raise ValueError('wrong Cardano network')
                    start=int(datetime.datetime.fromisoformat(genesis['systemStart'].replace('Z','+00:00')).timestamp())*1000
                    slot_ms=Decimal(str(genesis['slotLength']))*1000
                    if slot_ms!=slot_ms.to_integral_value():raise ValueError('unsupported slot duration')
                    tip=cardano.tip()
                    return self.reply(200,{'genesis':hashlib.sha256(raw).hexdigest(),'time_ms':str(start+tip['slot']*int(slot_ms)),'tip_hash':tip['hash']})
                if self.path=='/hegemon/head' and all(hegemon_options):
                    genesis=str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or genesis!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon node is not isolated')
                    return self.reply(200,{'genesis':genesis,'height':str(height(args.hegemon_rpc))})
                return self.reply(404,{'error':'not found'})
            except Exception:
                return self.reply(502,{'error':'local node status unavailable'})
        def do_POST(self):
            if not self.authorized():return self.reply(403,{'error':'forbidden'})
            if self.path not in ('/bitcoin/verify','/bitcoin/action','/cardano/verify','/cardano/action','/hegemon/verify','/hegemon/action'):return self.reply(404,{'error':'not found'})
            if self.headers.get_content_type()!='application/json':return self.reply(400,{'error':'JSON required'})
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:raise ValueError('invalid body size')
                data=json.loads(self.rfile.read(length))
                if self.path=='/bitcoin/action':
                    if not args.enable_bitcoin_actions:raise ValueError('Bitcoin actions are not enabled')
                    result=run_bitcoin_action(btc=btc,wallet=args.bitcoin_wallet,genesis=args.bitcoin_genesis,request=data,backup=args.bitcoin_preimage_backup)
                    return self.reply(200,{'completed':True,'result':result})
                if self.path=='/cardano/action':
                    if not args.enable_cardano_actions:raise ValueError('Cardano actions are not enabled')
                    result=run_cardano_action(chain=cardano,pid=args.cardano_node_pid,genesis_hash=args.cardano_genesis,signing_key=args.cardano_signing_key,journal_dir=args.cardano_journal_dir,request=data,backup=args.cardano_preimage_backup)
                    return self.reply(200,{'completed':True,'result':result})
                if self.path=='/hegemon/action':
                    if not args.enable_hegemon_actions:raise ValueError('Hegemon actions are not enabled')
                    manifest=json.loads(args.hegemon_manifest.read_text())
                    if manifest.get('profile')!='development' or manifest.get('development_candidate',{}).get('private_spend_only') is not True:raise ValueError('actions require a private-spend Development manifest')
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon node is not the configured isolated chain')
                    base=['--wallet',args.hegemon_wallet,'--manifest',args.hegemon_manifest,'--genesis',args.hegemon_genesis,'--rpc',args.hegemon_rpc,'--development-local-candidate']
                    result=run_hegemon_action(binary=args.private_spend,base_args=base,scratch=scratch.name,request=data,handoff_dir=args.hegemon_handoff_dir,preimage_backup=args.hegemon_preimage_backup)
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Node changed; action outcome may be uncertain. Check wallet status.')
                    return self.reply(200,{'completed':True,'result':result})
                expected=({'txid','vout','amount_sats','hashlock','claimant_key','refund_key','refund_height','genesis_hash'} if self.path=='/bitcoin/verify'
                          else {'outref','hashlock','claimant','refundee','expiry_ms','expected_value','genesis_sha256'} if self.path=='/cardano/verify'
                          else {'locked','claim','refund','hashlock','timeout','amount','min_confirmations','min_remaining_blocks'})
                if not isinstance(data,dict) or set(data)!=expected:raise ValueError('invalid request fields')
                if self.path=='/bitcoin/verify':
                    if btc is None:raise ValueError('Bitcoin verifier is not configured')
                    if btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not isolated')
                    result=verify_bitcoin_htlc(btc,**data)
                    if btc.call('getconnectioncount')!=0:raise ValueError('Bitcoin node is not isolated')
                elif self.path=='/cardano/verify':
                    if cardano is None:raise ValueError('Cardano verifier is not configured')
                    result=verify_cardano_htlc(cardano,**cardano_wire_terms(data),aiken=args.aiken)
                else:
                    if not all(hegemon_options):raise ValueError('Hegemon verifier is not configured')
                    values=hegemon_wire_terms(data)
                    if rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon node is not the configured isolated chain')
                    print('\nHegemon verification request (no funds will be moved):\n'+json.dumps(values,indent=2),flush=True)
                    if input('Type VERIFY to approve this local wallet read: ').strip()!='VERIFY':raise ValueError('verification declined locally')
                    phrase=getpass.getpass('Hegemon encrypted wallet passphrase (local terminal only): ')
                    if not phrase:raise ValueError('passphrase required')
                    argv=['--wallet',args.hegemon_wallet,'--manifest',args.hegemon_manifest,'--genesis',args.hegemon_genesis,'--rpc',args.hegemon_rpc,'--development-local-candidate','verify-htlc']
                    for field in ('locked','claim','refund','hashlock','timeout','amount','min_confirmations','min_remaining_blocks'):
                        argv.extend(['--'+field.replace('_','-'),values[field]])
                    try:
                        text,_=wallet(args.private_spend,argv,[(PASS,phrase.encode())],Path(scratch.name),'hegemon-verify')
                    except RuntimeError as e:
                        raise ValueError('Hegemon wallet did not verify the note') from e
                    finally:del phrase
                    result=json_line(text)
                    if result.get('verified') is not True or rpc(args.hegemon_rpc,'system_health')['peers']!=0 or str(rpc(args.hegemon_rpc,'chain_getBlockHash',[0])).removeprefix('0x')!=args.hegemon_genesis.removeprefix('0x'):raise ValueError('Hegemon verification unavailable')
                    fields=('position','created_height','reference_height','confirmations')
                    if any(type(result.get(field)) is not int or result[field]<0 for field in fields):raise ValueError('invalid Hegemon verifier result')
                    result={'verified':True,**{field:str(result[field]) for field in fields}}
                self.reply(200,{'verified':True,'snapshot':result})
            except (ValueError,TypeError,json.JSONDecodeError) as e:
                self.reply(400,{'error':str(e)})
            except Exception:
                self.reply(502,{'error':'local operation failed; check wallet status before retrying'})
    server=HTTPServer(('127.0.0.1',args.port),Handler)
    def terminate(_signum,_frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,terminate)
    print(f'Local companion listening on 127.0.0.1:{args.port}; token file: {args.token_file}; Hegemon actions: {args.enable_hegemon_actions}',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close();scratch.cleanup()

if __name__=='__main__':main()
