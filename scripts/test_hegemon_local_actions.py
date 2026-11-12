import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from hegemon_local_actions import build_action

class HegemonLocalActionsTest(unittest.TestCase):
    def setUp(self):
        self.validator=patch('hegemon_local_actions.public_v8_address_keys',return_value={});self.validator.start()
        self.addCleanup(self.validator.stop)
    def test_lock_uses_only_configured_private_handoff_directory(self):
        with tempfile.TemporaryDirectory() as d:
            data={'operation':'lock','inputs':['1'],'claim':'claim','refund':'refund','hashlock':'a'*64,'timeout':'200','amount':'100','fee':'1'}
            args,path=build_action(data,Path(d))
            self.assertEqual(path.parent,Path(d));self.assertIn('--release-secret',args);self.assertEqual(args[-1],str(path))
            with self.assertRaises(ValueError):build_action({**data,'secret':'b'*64},Path(d))
            with self.assertRaises(ValueError):build_action({**data,'inputs':['1','1']},Path(d))
            os.chmod(d,0o755)
            with self.assertRaises(ValueError):build_action(data,Path(d))
    def test_spend_never_accepts_preimage_or_wallet_paths(self):
        data={'operation':'claim','locked':'0','fee_input':'2','recipient':'claim','fee':'1'}
        args,path=build_action(data);self.assertEqual(args[0],'claim');self.assertIsNone(path)
        for bad in ({**data,'secret':'a'*64},{**data,'wallet':'/tmp/other'}, {**data,'fee':'1e6'}):
            with self.assertRaises(ValueError):build_action(bad)
    def test_submit_requires_exact_attempt_identifier(self):
        self.assertEqual(build_action({'operation':'submit','attempt':'a'*64})[0],['submit','a'*64])
        with self.assertRaises(ValueError):build_action({'operation':'submit','attempt':'../other'})
    def test_refund_handoff_import_accepts_only_a_private_file_in_the_configured_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);name='a'*32+'.bin';path=root/name;path.write_bytes(b'encrypted');path.chmod(0o600)
            data={'operation':'import-refund-handoff','handoff':name,'block_height':'123'}
            args,_=build_action(data,root);self.assertEqual(args,['import-refund-handoff',str(path),'--block-height','123','--refund-index','0'])
            for bad in ({**data,'handoff':'../'+name},{**data,'block_height':'0'},{**data,'refund_index':'1'}):
                with self.assertRaises(ValueError):build_action(bad,root)
            path.chmod(0o644)
            with self.assertRaises(ValueError):build_action(data,root)
            path.unlink();path.symlink_to('/etc/hosts')
            with self.assertRaises(OSError):build_action(data,root)

if __name__=='__main__':unittest.main()
