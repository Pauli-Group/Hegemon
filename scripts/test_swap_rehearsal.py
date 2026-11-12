"""Exercise the local Worker rehearsal without real wallets or chain transactions."""
import json
import os
import select
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MODULE=os.environ.get('SWAP_MINIFLARE_MODULE')


@unittest.skipUnless(MODULE and Path(MODULE).is_dir(),'set SWAP_MINIFLARE_MODULE to the pinned Wrangler Miniflare package')
class SwapRehearsalTest(unittest.TestCase):
    def test_loopback_worker_persists_its_own_offers_without_wrangler_state(self):
        with tempfile.TemporaryDirectory(prefix='swap-rehearsal-test-') as directory:
            root=Path(directory);state=root/'state';state.mkdir(mode=0o700)
            with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            if port==8788:self.skipTest('ephemeral port happened to match the companion port')
            url=f'http://127.0.0.1:{port}';env={**os.environ,'SWAP_MINIFLARE_MODULE':MODULE}
            def start():
                process=subprocess.Popen(['node',str(ROOT/'scripts/run_swap_rehearsal.mjs'),'--state',str(state),'--port',str(port)],
                                         cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    if process.poll() is not None:
                        raise AssertionError('Local rehearsal failed: '+process.stderr.read())
                    if select.select([process.stdout],[],[],.05)[0]:
                        line=process.stdout.readline()
                        if line.startswith('Local testnet rehearsal: '):
                            with urllib.request.urlopen(url+'/health',timeout=5) as response:self.assertEqual(json.load(response),{'status':'ok'})
                            return process
                process.terminate();process.wait(timeout=5);raise AssertionError('Local rehearsal did not start')
            def stop(process):
                process.terminate()
                try:process.wait(timeout=10)
                finally:process.stdout.close();process.stderr.close()
                self.assertIn(process.returncode,(0,143,-15))
            process=start()
            try:
                with urllib.request.urlopen(url+'/',timeout=5) as response:self.assertIn(b'Guided swap',response.read())
                offer={'visibility':'public','expires':int(time.time())+3600,'give':{'chain':'cardano','kind':'ada','id':'','amount':'1000000'},'receive':{'chain':'bitcoin','kind':'btc','id':'','amount':'10000'}}
                request=urllib.request.Request(url+'/offers',data=json.dumps(offer).encode(),headers={'Content-Type':'application/json'},method='POST')
                with urllib.request.urlopen(request,timeout=5) as response:offer_id=json.load(response)['id']
            finally:stop(process)
            process=start()
            try:
                with urllib.request.urlopen(url+'/offers',timeout=5) as response:self.assertEqual([item['id'] for item in json.load(response)['offers']],[offer_id])
            finally:stop(process)
            self.assertFalse((state/'.wrangler').exists())
            self.assertFalse((root/'.wrangler').exists())

    def test_nonempty_unmarked_state_directory_is_left_alone(self):
        with tempfile.TemporaryDirectory(prefix='swap-rehearsal-test-') as directory:
            state=Path(directory)/'state';state.mkdir(mode=0o700);other=state/'other';other.write_text('keep')
            result=subprocess.run(['node',str(ROOT/'scripts/run_swap_rehearsal.mjs'),'--state',str(state)],cwd=directory,
                                  env={**os.environ,'SWAP_MINIFLARE_MODULE':MODULE},capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertEqual(other.read_text(),'keep');self.assertFalse((state/'.hegemon-swap-rehearsal').exists())


if __name__=='__main__':unittest.main()
