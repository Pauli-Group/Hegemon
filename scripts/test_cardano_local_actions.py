import unittest
import tempfile
from pathlib import Path
from cardano_local_actions import peerless_topology,value_terms,record_prepared


class CardanoLocalActionsTest(unittest.TestCase):
    def test_topology_rejects_all_peer_sources(self):
        clean={'publicRoots':[{'accessPoints':[]}],'localRoots':[{'accessPoints':[]}],'bootstrapPeers':None,'useLedgerAfterSlot':-1}
        self.assertTrue(peerless_topology(clean))
        for changed in ({'bootstrapPeers':[{'address':'example.invalid','port':3001}]},
                        {'useLedgerAfterSlot':0},
                        {'publicRoots':[{'accessPoints':[{'address':'example.invalid','port':3001}]}]},
                        {'localRoots':None}):
            self.assertFalse(peerless_topology({**clean,**changed}))
    def test_native_assets_keep_exact_large_quantities(self):
        policy='a'*56;value=value_terms({'lovelace':'10000000',policy:{'00':'9007199254740993'}})
        self.assertEqual(value[policy]['00'],9007199254740993)
        with self.assertRaises(ValueError):value_terms({'lovelace':'10000000',policy:{'00':str(2**63)}})
    def test_recovery_record_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path=record_prepared(directory,'a'*64,{'operation':'lock'},'b'*64)
            original=path.read_bytes();self.assertEqual(path.stat().st_mode&0o077,0)
            with self.assertRaises(FileExistsError):record_prepared(directory,'a'*64,{'operation':'refund'},'b'*64)
            self.assertEqual(path.read_bytes(),original)

if __name__=='__main__':unittest.main()
