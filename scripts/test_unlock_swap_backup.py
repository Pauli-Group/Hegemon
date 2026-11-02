import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unlock_swap_backup import unlock_backup


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

if __name__=='__main__':unittest.main()
