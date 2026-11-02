import hashlib
import io
import json
import unittest
from unittest.mock import patch
import cbor2
from cardano_preimage_observer import claim_preimage,observe_preimage


def fixture(*,valid=True,index=0,secret=b'\x11'*32):
    body={0:{(b'\xaa'*32,1),(b'\xbb'*32,0)}}
    witness={5:{(0,index):[cbor2.CBORTag(121,[secret]),[1,1]]}}
    raw=cbor2.dumps([body,witness,valid,None]);source=io.BytesIO(raw);source.seek(1);cbor2.CBORDecoder(source).decode()
    return hashlib.blake2b(raw[1:source.tell()],digest_size=32).hexdigest(),raw.hex(),hashlib.sha256(secret).hexdigest()


class CardanoPreimageObserverTest(unittest.TestCase):
    def test_only_matching_valid_spend_reveals_secret(self):
        txid,raw,digest=fixture();secret=claim_preimage(txid,raw,'aa'*32+'#1',digest)
        self.assertEqual(hashlib.sha256(secret).hexdigest(),digest);secret[:]=b'\0'*len(secret)
        self.assertIsNone(claim_preimage(txid,raw,'bb'*32+'#0',digest))
        self.assertIsNone(claim_preimage(txid,raw,'aa'*32+'#1','00'*32))
        txid,raw,digest=fixture(valid=False);self.assertIsNone(claim_preimage(txid,raw,'aa'*32+'#1',digest))
        txid,raw,digest=fixture(index=1);self.assertIsNone(claim_preimage(txid,raw,'aa'*32+'#1',digest))
    def test_mismatched_body_hash_and_nonlocal_endpoint_are_rejected(self):
        txid,raw,digest=fixture()
        with self.assertRaisesRegex(ValueError,'transaction ID mismatch'):claim_preimage('00'*32,raw,'aa'*32+'#1',digest)
        with self.assertRaisesRegex(ValueError,'loopback'):observe_preimage('ws://example.invalid:1337',{'slot':0,'id':'11'*32},'aa'*32+'#1',digest)
    def test_confirmation_and_rollback_handling(self):
        txid,raw,digest=fixture();point={'slot':10,'id':'12'*32}
        first={'direction':'forward','block':{'ancestor':point['id'],'id':'34'*32,'slot':11,'height':20,'transactions':[{'id':txid,'cbor':raw}]}}
        final={'direction':'forward','block':{'ancestor':'34'*32,'id':'56'*32,'slot':12,'height':21,'transactions':[]}}
        class Socket:
            def __init__(self,events):self.events=iter(events)
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def send(self,_):pass
            def recv(self,timeout=None):return json.dumps(next(self.events))
        intersection={'id':1,'result':{'intersection':point}}
        initial={'id':2,'result':{'direction':'backward','point':point}}
        with patch('cardano_preimage_observer.connect',return_value=Socket([intersection,initial,{'id':2,'result':first},{'id':2,'result':final}])):
            secret,snapshot=observe_preimage('ws://127.0.0.1:1337',point,'aa'*32+'#1',digest,confirmations=2)
        self.assertEqual(snapshot['confirmations'],2);self.assertEqual(hashlib.sha256(secret).hexdigest(),digest);secret[:]=b'\0'*len(secret)
        rollback={'id':2,'result':{'direction':'backward','point':point}}
        with patch('cardano_preimage_observer.connect',return_value=Socket([intersection,initial,{'id':2,'result':first},rollback])):
            with self.assertRaisesRegex(ValueError,'rolled back'):observe_preimage('ws://127.0.0.1:1337',point,'aa'*32+'#1',digest,confirmations=2)

if __name__=='__main__':unittest.main()
