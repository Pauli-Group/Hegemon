"""Drive opt-in local Hegemon actions through an approved test terminal."""
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


class TestHegemonActions:
    def __init__(self,directory,*,binary,wallet_path,manifest,genesis,rpc_url,phrase,handoff_phrase,backup=None,backup_phrase=None):
        self.directory=directory;directory.mkdir(mode=0o700)
        self.handoffs=directory/'handoffs';self.handoffs.mkdir(mode=0o700)
        self.port=port();token_file=directory/'token';self.master,slave=pty.openpty()
        attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
        def ctty():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        command=[sys.executable,ROOT/'scripts/local_swap_companion.py','--hegemon-wallet',wallet_path,
            '--hegemon-manifest',manifest,'--hegemon-genesis',genesis,'--hegemon-rpc',rpc_url,'--private-spend',binary,
            '--token-file',token_file,'--port',str(self.port),'--enable-hegemon-actions','--hegemon-handoff-dir',self.handoffs]
        if backup:command.extend(['--hegemon-preimage-backup',backup])
        self.process=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,preexec_fn=ctty)
        os.close(slave);self.phrase=phrase;self.handoff_phrase=handoff_phrase;self.backup_phrase=backup_phrase
        try:
            self.token=wait_for(lambda:(v if len(v:=token_file.read_text().strip())==64 else None),'action companion token')
            wait_for(lambda:self.request('/health')[0]==200,'action companion server')
        except BaseException:self.close();raise
    def close(self):
        stop(self.process);os.close(self.master)
    def request(self,path,body=None,credential=None,origin='http://127.0.0.1:8787'):
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=700)
        try:
            headers={'Origin':origin,'Authorization':'Bearer '+(credential or self.token)}
            if body is not None:headers['Content-Type']='application/json'
            conn.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
            response=conn.getresponse();return response.status,json.loads(response.read())
        finally:conn.close()
    def action(self,data,*,secret=None,approve=True,expected=True):
        result=[]
        def invoke():
            try:result.append(self.request('/hegemon/action',data))
            except Exception as e:result.append(e)
        thread=threading.Thread(target=invoke,daemon=True);thread.start()
        output=bytearray();sent=set();deadline=time.monotonic()+700
        prompts=[(b'Type APPROVE to continue this local wallet action:',b'APPROVE' if approve else b'NO'),
                 (b'Hegemon encrypted wallet passphrase (local terminal only):',self.phrase),
                 (b'New encrypted refund handoff passphrase (local terminal only):',self.handoff_phrase),
                 (b'Repeat refund handoff passphrase (local terminal only):',self.handoff_phrase)]
        if secret is not None:prompts.append((b'Encrypted preimage backup passphrase (local terminal only):',self.backup_phrase) if self.backup_phrase else (b'Claim preimage as 64 lowercase hexadecimal characters (local terminal only):',secret.hex().encode()))
        while thread.is_alive():
            require(time.monotonic()<deadline,'Hegemon action companion timed out')
            require(self.process.poll() is None,'Hegemon action companion exited')
            if select.select([self.master],[],[],.1)[0]:
                try:output.extend(os.read(self.master,65536))
                except OSError:pass
            for index,(prompt,value) in enumerate(prompts):
                if index not in sent and prompt in output:
                    os.write(self.master,value+b'\n');sent.add(index)
            require(len(output)<100_000,'action companion output exceeded bound')
        thread.join();require(len(result)==1 and not isinstance(result[0],Exception),'action companion HTTP failed')
        while select.select([self.master],[],[],0)[0]:
            try:
                chunk=os.read(self.master,65536)
                if not chunk:break
                output.extend(chunk)
            except OSError:break
        status,body=result[0]
        require(0 in sent,'local approval prompt missing')
        require((status==200 and body.get('completed') is True)==expected,
                f"unexpected local action outcome: HTTP {status}, error={body.get('error')!r}")
        if not approve:require(status==400 and body.get('error')=='action declined locally' and 1 not in sent,'denied action requested a password')
        else:require(1 in sent,'local wallet passphrase prompt missing')
        if expected and data.get('operation')=='lock':require(2 in sent and 3 in sent,'handoff passphrase confirmation missing')
        if expected and data.get('operation')=='claim':require(4 in sent,'claim preimage prompt missing')
        for value in (self.phrase,self.handoff_phrase,self.backup_phrase,secret.hex().encode() if secret else b''):
            if value:require(value not in output,'local action echoed a secret')
        return body.get('result')
