import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from eth_abi import encode
from public_sepolia_browser_fixture import initialize,submit,ROOT,AMOUNT

class SepoliaBrowserFixtureTest(unittest.TestCase):
    def test_only_exact_reviewed_fixture_can_be_signed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700)
            def wallet(path):return None,('0x'+'1'*40 if 'alice' in str(path) else '0x'+'2'*40)
            with patch('public_sepolia_browser_fixture.verify_network'),patch('public_sepolia_browser_fixture.load_test_wallet',side_effect=wallet),patch('public_sepolia_browser_fixture.rpc',return_value={'timestamp':'0x64'}),patch('public_sepolia_browser_fixture.send',return_value={'txid':'a'*64}) as sender:
                initialize(root);state=json.loads((root/'sepolia-ui-action-fixture/state.json').read_text());template=json.loads((ROOT/'swap-ui/ether-escrow-template.json').read_text())
                data=template['creation']+encode(['bytes32','address','uint256'],[bytes.fromhex(state['hashlock']),state['claimant'],state['expiry']]).hex()
                tx={'from':state['refundee'],'data':'0x'+data,'value':hex(AMOUNT)}
                with self.assertRaisesRegex(ValueError,'differs'):submit(root,{**tx,'value':'0x1'})
                sender.assert_not_called();self.assertEqual(submit(root,tx)['txid'],'0x'+'a'*64);self.assertEqual(sender.call_count,1)
                with self.assertRaisesRegex(ValueError,'state'):submit(root,tx)
                self.assertEqual(sender.call_count,1)

if __name__=='__main__':unittest.main()
