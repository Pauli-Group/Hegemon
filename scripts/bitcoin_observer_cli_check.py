"""Drive the local Bitcoin observer CLI through a disposable terminal."""
import fcntl
import json
import os
import pty
import select
import subprocess
import sys
import termios
import time
from htlc_counterpart import ROOT
from local_private_spend_swap import require,stop


def check_bitcoin_observer_cli(*,url,cookie,genesis,txid,vout,hashlock,start_height,output,secret):
    master,slave=pty.openpty();attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
    def ctty():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    process=subprocess.Popen([sys.executable,ROOT/'scripts/watch_bitcoin_preimage.py','--bitcoin-rpc',url,'--bitcoin-cookie',cookie,'--bitcoin-genesis',genesis,
        '--txid',txid,'--vout',str(vout),'--hashlock',hashlock,'--start-height',str(start_height),'--output-dir',output],stdin=slave,stdout=slave,stderr=slave,preexec_fn=ctty);os.close(slave)
    phrase=b'local disposable observer passphrase';prompts=[(b'Type OBSERVE to continue:',b'OBSERVE'),(b'New separate encrypted backup passphrase:',phrase),(b'Repeat encrypted backup passphrase:',phrase)]
    received=bytearray();sent=set();deadline=time.monotonic()+60
    try:
        while process.poll() is None:
            require(time.monotonic()<deadline,'Bitcoin observer CLI timed out')
            if select.select([master],[],[],.1)[0]:
                try:received.extend(os.read(master,65536))
                except OSError:pass
            for index,(prompt,value) in enumerate(prompts):
                if index not in sent and prompt in received:os.write(master,value+b'\n');sent.add(index)
            require(len(received)<100_000,'Bitcoin observer output exceeded bound')
        while select.select([master],[],[],0)[0]:
            try:
                chunk=os.read(master,65536)
                if not chunk:break
                received.extend(chunk)
            except OSError:break
        require(process.returncode==0 and sent=={0,1,2},'Bitcoin observer CLI did not complete')
        require(secret.hex().encode() not in received and phrase not in received,'Bitcoin observer echoed a secret')
        lines=received.decode(errors='replace').splitlines();result=next(json.loads(line) for line in lines if line.startswith('{"saved"'))
        return result,phrase
    finally:stop(process);os.close(master)
