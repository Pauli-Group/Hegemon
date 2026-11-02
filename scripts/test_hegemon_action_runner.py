import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from hegemon_action_runner import run_hegemon_action

class HegemonActionRunnerTest(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)
        self.addresses=patch('hegemon_local_actions.public_v8_address_keys',return_value={});self.addresses.start();self.addCleanup(self.addresses.stop)
    def call(self,data,**kwargs):
        return run_hegemon_action(binary=Path('/unused'),base_args=[],scratch=self.path,request=data,handoff_dir=self.path,**kwargs)
    def test_denial_occurs_before_any_wallet_or_password(self):
        with patch('hegemon_action_runner.wallet') as child:
            with self.assertRaisesRegex(ValueError,'declined'):self.call({'operation':'status'},confirm=lambda _: 'NO',password=lambda _:self.fail('password requested'))
            child.assert_not_called()
    def test_lock_collects_secrets_locally_and_wipes_buffers(self):
        data={'operation':'lock','inputs':['1'],'claim':'claim','refund':'refund','hashlock':'a'*64,'timeout':'200','amount':'100','fee':'1'}
        supplied=iter(['wallet passphrase','separate handoff passphrase','separate handoff passphrase']);captured=[]
        def fake_wallet(_binary,args,prompts,_scratch,_label):
            captured.extend(value for _,value in prompts)
            path=Path(args[args.index('--refund-handoff')+1]);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
            return 'candidate '+'b'*64,{}
        with patch('hegemon_action_runner.wallet',side_effect=fake_wallet):
            result=self.call(data,confirm=lambda _: 'APPROVE',password=lambda _:next(supplied))
        self.assertEqual(result['attempt'],'b'*64);self.assertFalse(result['submitted'])
        self.assertTrue((self.path/result['refund_handoff']).is_file())
        self.assertTrue(all(not any(value) for value in captured))
    def test_claim_secret_never_enters_request_or_response(self):
        data={'operation':'claim','locked':'1','fee_input':'2','recipient':'claim','fee':'1'}
        supplied=iter(['wallet passphrase','c'*64]);captured=[]
        def fake_wallet(_binary,_args,prompts,_scratch,_label):
            captured.extend(value for _,value in prompts);return 'candidate '+'b'*64,{}
        with patch('hegemon_action_runner.wallet',side_effect=fake_wallet):
            result=self.call(data,confirm=lambda _: 'APPROVE',password=lambda _:next(supplied))
        self.assertNotIn('c'*64,str(result));self.assertTrue(all(not any(value) for value in captured))
    def test_submit_returns_distinct_attempt_and_action_ids(self):
        data={'operation':'submit','attempt':'a'*64}
        with patch('hegemon_action_runner.wallet',return_value=('submitted '+'b'*96,{})):
            result=self.call(data,confirm=lambda _: 'APPROVE',password=lambda _: 'wallet passphrase')
        self.assertEqual(result['attempt'],'a'*64)
        self.assertEqual(result['txid'],'b'*96)
        self.assertTrue(result['submitted']);self.assertFalse(result['confirmed'])

    def test_missing_submit_ack_requires_status_check(self):
        with patch('hegemon_action_runner.wallet',return_value=('unexpected output',{})):
            with self.assertRaisesRegex(ValueError,'check wallet status before retrying'):
                self.call({'operation':'submit','attempt':'a'*64},confirm=lambda _: 'APPROVE',password=lambda _: 'wallet passphrase')
    def test_claim_can_unlock_local_backup_without_sending_it_to_client(self):
        data={'operation':'claim','locked':'1','fee_input':'2','recipient':'claim','fee':'1'}
        supplied=iter(['wallet passphrase','separate backup passphrase']);captured=[];recovered=bytearray(b'\x03'*32)
        def fake_wallet(_binary,_args,prompts,_scratch,_label):
            captured.extend(value for _,value in prompts)
            self.assertEqual(prompts[-1][1],b'03'*32)
            return 'candidate '+'b'*64,{}
        with patch('hegemon_action_runner.wallet',side_effect=fake_wallet),patch('hegemon_action_runner.unlock_backup',return_value=recovered):
            result=self.call(data,confirm=lambda _: 'APPROVE',password=lambda _:next(supplied),preimage_backup=self.path/'backup')
        self.assertNotIn('03'*32,str(result));self.assertTrue(all(not any(value) for value in captured));self.assertFalse(any(recovered))

if __name__=='__main__':unittest.main()
