"""Persist private signed test transactions before any public broadcast.

Signed claims may contain unrevealed preimages, so raw files are secret until
broadcast. The journal intentionally contains no key, passphrase or freeform
metadata. A prepared record may already have been sent; check chain state.
"""
import hashlib
import io
import json
import os
import re
import stat
from pathlib import Path
import cbor2
from embit.transaction import Transaction
from eth_utils import keccak
from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes


def transaction_id(chain,raw):
    if not isinstance(raw,bytes) or not 1<=len(raw)<=1_000_000:raise ValueError('Invalid signed transaction')
    if chain=='bitcoin-testnet4':
        try:
            tx=Transaction.parse(raw)
            if tx.serialize()!=raw:raise ValueError('Noncanonical Bitcoin transaction')
            return tx.txid().hex()
        except Exception as error:raise ValueError('Invalid Bitcoin transaction') from error
    if chain=='ethereum-sepolia':
        if raw[0]!=2:raise ValueError('Expected EIP-1559 transaction')
        try:
            tx=TypedTransaction.from_bytes(HexBytes(raw))
            if tx.as_dict().get('chainId')!=11155111 or tx.encode()!=raw:raise ValueError('Wrong chain or noncanonical transaction')
        except Exception as error:raise ValueError('Invalid Sepolia transaction') from error
        return keccak(raw).hex()
    if chain=='cardano-preview':
        if raw[0]!=0x84:raise ValueError('Invalid Cardano transaction')
        try:
            source=io.BytesIO(raw);source.seek(1);body=cbor2.CBORDecoder(source).decode();end=source.tell()
            source.seek(0);tx=cbor2.CBORDecoder(source).decode()
            if source.tell()!=len(raw) or not isinstance(tx,list) or len(tx)!=4 or not isinstance(body,dict):raise ValueError('Invalid Cardano transaction')
        except Exception as error:raise ValueError('Invalid Cardano transaction') from error
        return hashlib.blake2b(raw[1:end],digest_size=32).hexdigest()
    raise ValueError('Unsupported testnet')


def _private_directory(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Journal directory cannot be a symlink')
    st=path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('Journal directory must be private and user-owned')
    return path


def _write_new(path,data):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(path,flags,0o600),'wb') as handle:
        handle.write(data);handle.flush();os.fsync(handle.fileno())


def prepare(directory,chain,raw):
    directory=_private_directory(directory);txid=transaction_id(chain,raw)
    if not re.fullmatch('[0-9a-f]{64}',txid):raise ValueError('Invalid transaction ID')
    name=chain+'-'+txid;raw_path=directory/(name+'.signed');record_path=directory/(name+'.json')
    _write_new(raw_path,raw)
    # Failure after this point leaves an orphan signed file and forbids retry;
    # inspect it locally rather than guessing whether it was submitted.
    record={'version':1,'chain':chain,'txid':txid,'state':'prepared_or_submitted'}
    _write_new(record_path,(json.dumps(record,sort_keys=True)+'\n').encode())
    fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(fd)
    finally:os.close(fd)
    return record
