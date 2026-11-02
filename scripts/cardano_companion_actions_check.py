"""Drive opt-in Cardano actions through a disposable local terminal."""
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
from htlc_counterpart import ROOT,wait_for
from local_private_spend_swap import port,require,stop


class TestCardanoActions:
    def __init__(self,directory,*,chain,key,genesis,backup=None,backup_phrase=None):
        directory.mkdir(mode=0o700);self.journal=directory/'journal';self.journal.mkdir(mode=0o700);self.port=port();token_file=directory/'token';self.master,slave=pty.openpty()
        attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
        def ctty():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        command=[sys.executable,ROOT/'scripts/local_swap_companion.py','--cardano-socket',chain.socket,'--cardano-network-dir',chain.net,
            '--cardano-node-pid',str(chain.proc.pid),'--cardano-genesis',genesis,'--cardano-signing-key',key,'--cardano-journal-dir',self.journal,'--enable-cardano-actions',
            '--cardano-cli',chain.cli,'--token-file',token_file,'--port',str(self.port)]
        if backup:command.extend(['--cardano-preimage-backup',backup])
        self.process=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,preexec_fn=ctty)
        os.close(slave);self.backup_phrase=backup_phrase
        try:
            self.token=wait_for(lambda:(v if len(v:=token_file.read_text().strip())==64 else None),'Cardano action companion token')
            wait_for(lambda:self.request('/health')[0]==200,'Cardano action companion server')
        except BaseException:self.close();raise
    def close(self):stop(self.process);os.close(self.master)
    def request(self,path,body=None,credential=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=120)
        try:
            headers={'Origin':'http://127.0.0.1:8787','Authorization':'Bearer '+(credential or self.token)}
            if body is not None:headers['Content-Type']='application/json'
            conn.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
            response=conn.getresponse();return response.status,json.loads(response.read())
        finally:conn.close()
    def action(self,data,*,secret=None,expected=True,approve=True):
        result=[]
        def invoke():
            try:result.append(self.request('/cardano/action',data))
            except Exception as e:result.append(e)
        thread=threading.Thread(target=invoke,daemon=True);thread.start();output=bytearray();sent=set();deadline=time.monotonic()+120
        prompts=[(b'Type APPROVE to continue this local Cardano action:',b'APPROVE' if approve else b'NO')]
        if secret is not None:prompts.append((b'Encrypted preimage backup passphrase (local terminal only):',self.backup_phrase) if self.backup_phrase else (b'Claim preimage as 64 lowercase hexadecimal characters (local terminal only):',secret.hex().encode()))
        while thread.is_alive():
            require(time.monotonic()<deadline and self.process.poll() is None,'Cardano action companion timed out or exited')
            if select.select([self.master],[],[],.1)[0]:
                try:output.extend(os.read(self.master,65536))
                except OSError:pass
            for index,(prompt,value) in enumerate(prompts):
                if index not in sent and prompt in output:os.write(self.master,value+b'\n');sent.add(index)
            require(len(output)<100_000,'Cardano action terminal output exceeded bound')
        thread.join();require(len(result)==1 and not isinstance(result[0],Exception),'Cardano action HTTP failed')
        while select.select([self.master],[],[],0)[0]:
            try:
                chunk=os.read(self.master,65536)
                if not chunk:break
                output.extend(chunk)
            except OSError:break
        status,body=result[0]
        require((status==200 and body.get('completed') is True)==expected,f"unexpected Cardano action outcome: HTTP {status}, error={body.get('error')!r}")
        if expected or not approve:require(0 in sent,'local Cardano approval prompt missing')
        if expected and secret is not None:require(1 in sent,'local Cardano preimage prompt missing')
        if secret is not None:require(secret.hex().encode() not in output,'Cardano action echoed a preimage')
        if self.backup_phrase:require(self.backup_phrase not in output,'Cardano action echoed a backup passphrase')
        return body.get('result')
