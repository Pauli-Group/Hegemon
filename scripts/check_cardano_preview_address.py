#!/usr/bin/env python3
"""Check that the browser's preview HTLC address matches the pinned Aiken source."""
import re
import subprocess
import tempfile
from pathlib import Path
from public_cardano_transactions import CLI
from public_cardano_verify import AIKEN

ROOT=Path(__file__).resolve().parents[1]

def main():
    source=(ROOT/'swap-ui/cardano-preview-verifier.mjs').read_text()
    match=re.search(r"PREVIEW_HTLC_ADDRESS='(addr_test1[0-9a-z]+)'",source)
    if not match:raise ValueError('Browser Cardano preview address missing')
    compiled=subprocess.check_output([str(AIKEN),'blueprint','convert',str(ROOT/'contracts/cardano')],timeout=30)
    with tempfile.TemporaryDirectory(prefix='cardano-address-check-') as directory:
        path=Path(directory)/'validator.plutus';path.write_bytes(compiled)
        actual=subprocess.check_output([str(CLI),'conway','address','build','--payment-script-file',str(path),'--testnet-magic','2'],text=True,timeout=30).strip()
    if match.group(1)!=actual:raise ValueError('Browser address differs from the compiled Aiken validator')
    print('Cardano preview validator address matches the browser')

if __name__=='__main__':main()
