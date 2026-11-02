import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unlock_swap_backup import unlock_backup,save_recovered_backup


class BackupInteropTest(unittest.TestCase):
    def test_browser_export_unlock_and_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'backup.json'
            script="import {createRecovery} from './swap-ui/recovery.mjs';console.log(JSON.stringify({label:'fixture',envelope:await createRecovery('separate test passphrase')}));"
            export=subprocess.check_output(['node','--input-type=module','-e',script],text=True)
            path.write_text(export);path.chmod(0o600);entry=json.loads(export)
            secret=unlock_backup(path,bytearray(b'separate test passphrase'))
            self.assertEqual(hashlib.sha256(secret).hexdigest(),entry['envelope']['hashlock']);secret[:]=b'\0'*len(secret)
            with self.assertRaisesRegex(ValueError,'could not unlock'):unlock_backup(path,b'wrong test passphrase')
            entry['envelope']['ciphertext']='0'*96;path.write_text(json.dumps(entry))
            with self.assertRaisesRegex(ValueError,'could not unlock'):unlock_backup(path,b'separate test passphrase')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'private file'):unlock_backup(path,b'separate test passphrase')
            path.chmod(0o600);link=Path(directory)/'link';os.symlink(path,link)
            with self.assertRaises(OSError):unlock_backup(link,b'separate test passphrase')

    def test_recovered_backup_unlocks_in_browser_implementation(self):
        with tempfile.TemporaryDirectory() as directory:
            secret=bytearray(b'\x42'*32);phrase=bytearray(b'separate test passphrase');path=save_recovered_backup(directory,secret,phrase)
            self.assertEqual(path.stat().st_mode&0o077,0);envelope=json.loads(path.read_text())['envelope']
            script="import {unlockRecovery} from './swap-ui/recovery.mjs';let s='';for await(const c of process.stdin)s+=c;const x=JSON.parse(s),v=await unlockRecovery(x.envelope,x.phrase);const h=Buffer.from(await crypto.subtle.digest('SHA-256',v)).toString('hex');v.fill(0);console.log(h===x.envelope.hashlock?'verified':'mismatch');"
            result=subprocess.check_output(['node','--input-type=module','-e',script],input=json.dumps({'envelope':envelope,'phrase':phrase.decode()}),text=True)
            self.assertEqual(result.strip(),'verified');secret[:]=b'\0'*len(secret);phrase[:]=b'\0'*len(phrase)

if __name__=='__main__':unittest.main()
