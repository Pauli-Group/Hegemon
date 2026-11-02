"""Exercise the local companion's terminal-approved Hegemon verification."""
import fcntl
import http.client
import json
import os
import pty
import select
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path
from htlc_counterpart import ROOT, wait_for
from local_private_spend_swap import port, require, stop


def check_hegemon_companion(directory, *, binary, wallet_path, manifest, genesis, rpc_url, phrase, terms, only_denial=False):
    directory.mkdir(mode=0o700)
    token_file=directory/'token';cp=port();master,slave=pty.openpty()
    attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
    def ctty():
        os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    process=subprocess.Popen([sys.executable,ROOT/'scripts/local_swap_companion.py','--hegemon-wallet',wallet_path,
        '--hegemon-manifest',manifest,'--hegemon-genesis',genesis,'--hegemon-rpc',rpc_url,'--private-spend',binary,
        '--token-file',token_file,'--port',str(cp)],stdin=slave,stdout=slave,stderr=slave,preexec_fn=ctty)
    os.close(slave)
    try:
        token=wait_for(lambda:(v if len(v:=token_file.read_text().strip())==64 else None),'Hegemon companion token')
        def request(path,body=None,credential=None,origin='http://127.0.0.1:8787'):
            conn=http.client.HTTPConnection('127.0.0.1',cp,timeout=180)
            try:
                headers={'Origin':origin,'Authorization':'Bearer '+(credential or token)}
                if body is not None:headers['Content-Type']='application/json'
                conn.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
                response=conn.getresponse();return response.status,json.loads(response.read())
            finally:conn.close()
        wait_for(lambda:request('/health')[0]==200,'Hegemon companion server')
        require(request('/health',credential='0'*64)[0]==403,'companion accepted wrong token')
        require(request('/health',origin='http://attacker.invalid')[0]==403,'companion accepted wrong origin')
        head_status,head=request('/hegemon/head')
        require(head_status==200 and head.get('genesis')==genesis.removeprefix('0x') and int(head['height'])>0,'companion Hegemon head mismatch')
        require(request('/hegemon/verify',terms,credential='0'*64)[0]==403,'Hegemon endpoint accepted wrong token')
        require(request('/hegemon/verify',terms,origin='http://attacker.invalid')[0]==403,'Hegemon endpoint accepted wrong origin')
        def approved_verify(values,expected,approve=True):
            result=[]
            def invoke():
                try:result.append(request('/hegemon/verify',values))
                except Exception as e:result.append(e)
            thread=threading.Thread(target=invoke,daemon=True);thread.start()
            output=bytearray();approved=unlocked=False;deadline=time.monotonic()+180
            while thread.is_alive():
                require(time.monotonic()<deadline,'Hegemon companion verification timed out')
                require(process.poll() is None,'Hegemon companion exited')
                if select.select([master],[],[],.1)[0]:
                    try:output.extend(os.read(master,65536))
                    except OSError:pass
                if not approved and b'Type VERIFY to approve this local wallet read:' in output:
                    os.write(master,b'VERIFY\n' if approve else b'NO\n');approved=True
                if not unlocked and b'Hegemon encrypted wallet passphrase (local terminal only):' in output:
                    os.write(master,phrase+b'\n');unlocked=True
                require(len(output)<100_000,'companion output exceeded bound')
            thread.join()
            require(approved and unlocked==approve,'unexpected local approval or passphrase prompt')
            require(len(result)==1 and not isinstance(result[0],Exception),'companion HTTP request failed')
            status,body=result[0]
            require((status==200 and body.get('verified') is True)==expected,'unexpected Hegemon companion result')
            if not expected:require(status==400 and body.get('error')==('Hegemon wallet did not verify the note' if approve else 'verification declined locally'),'unexpected Hegemon rejection reason')
            require(phrase not in output,'companion echoed the wallet passphrase')
            return body
        approved_verify(terms,False,approve=False)
        if only_denial:
            return {'declined_without_passphrase':True,'unauthorized_rejected':True,'wrong_origin_rejected':True}
        good=approved_verify(terms,True)
        bad={**terms,'amount':str(int(terms['amount'])+1)}
        approved_verify(bad,False)
        return {'verified_snapshot':good['snapshot'],'unauthorized_rejected':True,'wrong_origin_rejected':True,'altered_amount_rejected':True,'terminal_approval_required':True,'passphrase_not_echoed':True}
    finally:
        stop(process);os.close(master)
