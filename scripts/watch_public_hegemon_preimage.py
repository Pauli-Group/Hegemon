#!/usr/bin/env python3
"""Save a confirmed v0.11 pre-mainnet Hegemon claim as an encrypted backup."""

import argparse
import getpass
import hmac
import json
import os
from pathlib import Path

from public_hegemon_preimage_observer import observe_public_hegemon_preimage
from unlock_swap_backup import save_recovered_backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hegemon-rpc', required=True)
    parser.add_argument('--action-id', required=True,
                        help='exact submitted private-spend action ID, 96 lowercase hex characters')
    parser.add_argument('--hashlock', required=True)
    parser.add_argument('--start-height', type=int, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--confirmations', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    os.umask(0o077)
    if not os.isatty(0):
        parser.error('an interactive local terminal is required for the backup passphrase')
    print('The local node and public explorer are trusted; confirmations are not finality. '
          'This observer does not establish that the action spent your intended HTLC.', flush=True)
    secret = None
    phrase = None
    try:
        secret, snapshot = observe_public_hegemon_preimage(
            args.hegemon_rpc, action_id=args.action_id, hashlock=args.hashlock,
            start_height=args.start_height,
            confirmations=args.confirmations, timeout=args.timeout)
        first = getpass.getpass('New separate encrypted backup passphrase: ')
        second = getpass.getpass('Repeat encrypted backup passphrase: ')
        if (not 12 <= len(first.encode()) <= 4096
                or not hmac.compare_digest(first.encode(), second.encode())):
            raise ValueError('backup passphrases must match and contain at least 12 bytes')
        phrase = bytearray(first.encode())
        del first, second
        path = save_recovered_backup(args.output_dir, secret, phrase,
                                     label='Observed Hegemon pre-mainnet claim')
        print(json.dumps({'saved': str(path), 'hashlock': args.hashlock,
                          'snapshot': snapshot,
                          'note': 'Independently verify this action spent the intended HTLC before any claim.'}),
              flush=True)
    finally:
        if secret is not None:
            secret[:] = b'\0' * len(secret)
        if phrase is not None:
            phrase[:] = b'\0' * len(phrase)


if __name__ == '__main__':
    main()
