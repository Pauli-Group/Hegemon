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

if __name__=='__main__':unittest.main()
