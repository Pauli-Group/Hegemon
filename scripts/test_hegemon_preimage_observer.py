import hashlib
import unittest
from hegemon_preimage_observer import IDENTITY,released_preimage


class HegemonObserverTest(unittest.TestCase):
    def test_only_valid_matching_public_release_returns_secret(self):
        secret=b'\x31'*32;chain=b'\x21'*32;relation=b'\x32'*48;digest=hashlib.sha256(secret).hexdigest()
        body=bytearray(5788);body[:8]=b'HGPSLC02';body[8:24]=IDENTITY;body[24:72]=relation;body[72:104]=chain;body[528:536]=(1).to_bytes(8,'little');body[536:568]=secret;body[5784:]=b'SMZL'
        found=released_preimage(bytes(body),chain_id=chain,relation_prefix=relation,hashlock=digest);self.assertEqual(found,secret);found[:]=b'\0'*len(found)
        found=released_preimage(body,chain_id=chain,relation_prefix=relation,hashlock=digest);self.assertEqual(found,secret);found[:]=b'\0'*len(found)
        self.assertIsNone(released_preimage(bytes(body),chain_id=chain,relation_prefix=relation,hashlock='00'*32))
        with self.assertRaisesRegex(ValueError,'invalid private-spend carrier'):released_preimage(bytes(body),chain_id=b'\x11'*32,relation_prefix=relation,hashlock=digest)
        body[528:536]=(0).to_bytes(8,'little')
        with self.assertRaisesRegex(ValueError,'secret release'):released_preimage(bytes(body),chain_id=chain,relation_prefix=relation,hashlock=digest)

if __name__=='__main__':unittest.main()
