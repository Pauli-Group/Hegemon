"""Exercise the real Tk controls with disposable wallet responses, never a node."""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from local_swap_companion import CompanionWindow, GuiApproval, HostedWalletSession


@unittest.skipUnless(os.environ.get('DISPLAY'), 'a graphical DISPLAY is required for the Tk window check')
class CompanionWindowTest(unittest.TestCase):
    def test_local_unlock_full_address_clipboard_refresh_and_failed_read(self):
        try:
            import tkinter as tk
        except ImportError:
            self.skipTest('python3-tk is required')
        phrase='disposable-window-test-passphrase'
        address='shca1'+'q'*2667
        calls=[];failures=[]
        class Monitor:
            def start(self):pass
            def stop(self):pass
            def snapshot(self):return {'tone':'caught_up','title':'Caught up','fraction':'','progress':1,'time_line':'Ready. Height 16,909, 10 peers.','consequence':''}
        with tempfile.TemporaryDirectory() as directory:
            prompt=GuiApproval()
            session=HostedWalletSession(rpc='http://127.0.0.1:9',wallet_path=Path(directory)/'test.wallet',manifest=Path(directory)/'manifest',genesis='aa'*32,binary=Path(directory)/'binary',scratch=directory,read_node=lambda:{'height':16909},prompt=prompt)
            def wallet(_binary,argv,secrets,*args,**kwargs):
                calls.append(argv)
                self.assertEqual(bytes(secrets[0][1]),phrase.encode())
                if 'address' in argv:return address+'\n',{}
                time.sleep(.05)
                refreshed = sum('status' in call for call in calls) > 1
                amount = '1134567890' if refreshed else '1234567890'
                reserved = '200000000' if refreshed else '100000000'
                return f'balance synced_height=16909 available_atoms={amount} available_notes=1 reserved_atoms={reserved} reserved_notes=1 htlc_atoms=200000000 htlc_notes=1 watch_only=false immature_atoms=0\n',{}
            real_tk=tk.Tk
            def make_root():
                root=real_tk()
                def widgets(parent):
                    for child in parent.winfo_children():
                        yield child
                        yield from widgets(child)
                def button(text):return next(w for w in widgets(root) if isinstance(w,tk.Button) and w.cget('text')==text)
                def labels():return [w.cget('text') for w in widgets(root) if isinstance(w,tk.Label)]
                def finish(error=None):
                    if error:failures.append(error)
                    root.quit()
                def check_ready(deadline):
                    try:
                        if session.display.snapshot()['address'] is None or '12.3456789' not in labels():
                            self.assertLess(time.monotonic(),deadline,'local unlock did not complete')
                            root.after(100,lambda:check_ready(deadline));return
                        self.assertIn('12.3456789',labels())
                        self.assertNotIn(phrase,str(session.display.snapshot()))
                        self.assertEqual(len(calls),2)
                        button('Copy receiving address').invoke()
                        self.assertEqual(root.clipboard_get(),address,'copy must retain all 2672 characters')
                        screenshot=os.environ.get('HEGEMON_COMPANION_SCREENSHOT')
                        if screenshot:
                            root.update_idletasks()
                            subprocess.run(['import','-window',str(root.winfo_id()),screenshot],check=True,timeout=10)
                        root.geometry('520x560');root.update_idletasks()
                        canvas=next(w for w in root.winfo_children() if isinstance(w,tk.Canvas))
                        self.assertGreater(canvas.bbox('all')[3],canvas.winfo_height())
                        canvas.yview_moveto(1);root.update_idletasks()
                        self.assertGreater(canvas.yview()[0],0,'lower controls must be reachable on a short display')
                        button('Refresh').invoke()
                        root.after(500,check_refresh)
                    except Exception as error:finish(error)
                def check_refresh():
                    try:
                        self.assertEqual(len(calls),3,'explicit Refresh must read reservations again even at the same block')
                        self.assertIn('11.3456789',labels(),'Refresh must publish the new spendable amount')
                        session.read_node=lambda:(_ for _ in ()).throw(LookupError('offline'))
                        button('Refresh').invoke()
                        root.after(500,check_failed_read)
                    except Exception as error:finish(error)
                def check_failed_read():
                    try:
                        self.assertIn('Check needed',labels())
                        self.assertIn('11.3456789',labels(),'a failed read must not turn the balance into zero')
                        finish()
                    except Exception as error:finish(error)
                def start():
                    try:
                        self.assertIn('Locked',labels())
                        self.assertEqual(button('Copy receiving address').cget('state'),'disabled')
                        entry=next(w for w in widgets(root) if isinstance(w,tk.Entry) and w.cget('show')=='*')
                        entry.insert(0,phrase)
                        button('Unlock').invoke()
                        self.assertEqual(entry.get(),'','the passphrase entry is cleared after approval')
                        root.after(100,lambda:check_ready(time.monotonic()+10))
                    except Exception as error:finish(error)
                root.after(500,start)
                root.after(15000,lambda:finish(AssertionError('window test timed out')))
                return root
            with patch('tkinter.Tk',make_root),patch('local_swap_companion.wallet',wallet),patch('local_swap_companion.public_v8_address_keys'):
                CompanionWindow(token='00'*32,wallet_path=session.wallet_path,prompt=prompt,activity=session.activity,monitor=Monitor(),session=session).run()
            session.close()
            if failures:raise failures[0]
