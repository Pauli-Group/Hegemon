"""Sign Cardano preview transaction bodies locally and journal submissions.

The caller must verify all input/output terms, protocol parameters, collateral
and swap recovery before signing. A signed claim contains the preimage.
"""
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from public_cardano_transactions import CLI
from public_testnet_probe import CARDANO,request
from public_testnet_submit import submit,verify_network


def _private_file(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Private file cannot be a symlink')
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>2_000_000:raise ValueError('File must be private and user-owned')
    return path


def preview_protocol_parameters():
    verify_network('cardano-preview');params=json.loads(request(CARDANO+'/cli_protocol_params'))
    required={'txFeeFixed','txFeePerByte','maxTxSize','maxTxExecutionUnits','utxoCostPerByte','costModels','protocolVersion','executionUnitPrices'}
    if not isinstance(params,dict) or not required<=set(params):raise ValueError('Cardano protocol parameters unavailable')
    return params


def sign_and_submit(journal,body,signing_key,cli=CLI):
    directory=Path(journal)
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid!=os.getuid() or stat.S_IMODE(directory.stat().st_mode)&0o077:raise ValueError('Journal directory must be private and user-owned')
    body=_private_file(body);signing_key=_private_file(signing_key)
    verify_network('cardano-preview')
    with tempfile.TemporaryDirectory(prefix='ada-sign-',dir=directory) as temp:
        signed=Path(temp)/'signed.json'
        result=subprocess.run([str(cli),'conway','transaction','sign','--tx-body-file',str(body),'--signing-key-file',str(signing_key),'--testnet-magic','2','--out-file',str(signed)],capture_output=True,text=True,timeout=30)
        if result.returncode:raise RuntimeError('Cardano signing failed')
        signed.chmod(0o600);envelope=json.loads(signed.read_text())
        if not isinstance(envelope,dict) or not isinstance(envelope.get('cborHex'),str):raise ValueError('Invalid signed Cardano transaction')
        try:raw=bytes.fromhex(envelope['cborHex'])
        except ValueError as error:raise ValueError('Invalid signed Cardano transaction') from error
        return submit(directory,'cardano-preview',raw)
