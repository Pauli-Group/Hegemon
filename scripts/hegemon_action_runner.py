"""Terminal-approved execution of typed, isolated Hegemon Development actions.

The caller must independently check the local node's isolation and network before
and after this function. HTTP clients supply no passphrases or claim preimages.
"""
import getpass
import hmac
import json
import os
import re
from pathlib import Path
from hegemon_local_actions import build_action
from local_private_spend_swap import PASS, HANDOFF, SECRET, wallet


def run_hegemon_action(*, binary, base_args, scratch, request, handoff_dir,
                        confirm=input, password=getpass.getpass):
    argv,handoff=build_action(request,handoff_dir)
    op=request['operation']
    print('\nHegemon local Development action (not an atomic swap):\n'+json.dumps(request,indent=2),flush=True)
    if handoff:print('Encrypted refund handoff will be saved as: '+str(handoff),flush=True)
    if op in ('claim','submit'):
        print('A claim preimage can become public on export or submission, including if a transaction is later orphaned.',flush=True)
    if confirm('Type APPROVE to continue this local wallet action: ').strip()!='APPROVE':raise ValueError('action declined locally')
    buffers=[]
    def prompt(label):
        value=bytearray(password(label).encode('utf-8'));buffers.append(value)
        if not value or len(value)>4096:raise ValueError('invalid local secret length')
        return value
    try:
        phrase=prompt('Hegemon encrypted wallet passphrase (local terminal only): ')
        prompts=[(PASS,phrase)]
        if op=='claim':
            secret=prompt('Claim preimage as 64 lowercase hexadecimal characters (local terminal only): ')
            if not re.fullmatch(b'[0-9a-f]{64}',secret):raise ValueError('invalid claim preimage')
            prompts.append((SECRET,secret))
        if op=='lock':
            handoff_phrase=prompt('New encrypted refund handoff passphrase (local terminal only): ')
            confirmation=prompt('Repeat refund handoff passphrase (local terminal only): ')
            if len(handoff_phrase)<12 or not hmac.compare_digest(handoff_phrase,confirmation):raise ValueError('handoff passphrases must match and contain at least 12 bytes')
            confirmation[:]=b'\0'*len(confirmation)
            prompts.append((HANDOFF,handoff_phrase))
        try:
            text,metrics=wallet(binary,[*base_args,*argv],prompts,Path(scratch),'hegemon-action')
        except RuntimeError as e:
            raise ValueError('Hegemon action failed; a reservation may remain. Check wallet status before retrying.') from e
        if op=='status':
            if len(text)>64000:raise ValueError('wallet status exceeded the response limit')
            return {'operation':op,'status':text,'metrics':metrics}
        if op=='submit':
            # The wallet verifies the node's acknowledgement against the projected
            # action ID. That 48-byte ID differs from the 32-byte journal attempt.
            match=re.search(r'\bsubmitted ([0-9a-f]{96})\b',text)
            if not match:raise ValueError('submission acknowledgement missing; check wallet status before retrying')
            return {'operation':op,'attempt':request['attempt'],'txid':match.group(1),'submitted':True,'confirmed':False,'metrics':metrics}
        match=re.search(r'\bcandidate ([0-9a-f]{64})\b',text)
        if not match:raise ValueError('candidate acknowledgement missing; check wallet status')
        result={'operation':op,'attempt':match.group(1),'submitted':False,'metrics':metrics}
        if handoff:
            if not handoff.is_file() or handoff.is_symlink() or handoff.stat().st_uid!=os.getuid() or handoff.stat().st_mode&0o077:
                raise ValueError('refund handoff is unavailable or not private; check wallet status')
            result['refund_handoff']=handoff.name
        return result
    finally:
        for value in buffers:value[:]=b'\0'*len(value)
