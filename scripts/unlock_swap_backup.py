"""Unlock the browser's exported v1 preimage backup in a local process.

The caller supplies the password privately and must clear the returned mutable
buffer. Python and the crypto library can retain temporary immutable copies.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from pathlib import Path


def validate_envelope(v):
    """Validate only the public shape of an encrypted browser secret backup."""
    if not isinstance(v,dict) or set(v)!={'version','iterations','hashlock','salt','iv','ciphertext'} or type(v['version']) is not int or v['version']!=1 or type(v['iterations']) is not int or v['iterations']!=600000:raise ValueError('invalid encrypted backup')
    for name,length in (('hashlock',64),('salt',32),('iv',24),('ciphertext',96)):
        if not isinstance(v[name],str) or not re.fullmatch('[0-9a-f]{'+str(length)+'}',v[name]):raise ValueError('invalid encrypted backup')
    return v


def unlock_backup(path, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    path=Path(path)
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>4096:
            raise ValueError('backup must be a user-owned private file of at most 4096 bytes')
        raw=handle.read(4097)
        if len(raw)>4096:raise ValueError('invalid encrypted backup')
        try:entry=json.loads(raw)
        except (ValueError,UnicodeError) as e:raise ValueError('invalid encrypted backup') from e
    if not isinstance(entry,dict) or set(entry)!={'label','envelope'} or not isinstance(entry['label'],str):raise ValueError('invalid encrypted backup')
    v=validate_envelope(entry['envelope'])
    if not isinstance(password,(bytes,bytearray)) or not 12<=len(password)<=4096:raise ValueError('invalid backup passphrase')
    key=bytearray(hashlib.pbkdf2_hmac('sha256',password,bytes.fromhex(v['salt']),600000,32))
    try:
        try:secret=bytearray(AESGCM(bytes(key)).decrypt(bytes.fromhex(v['iv']),bytes.fromhex(v['ciphertext']),('hegemon.swap.secret.v1:'+v['hashlock']).encode()))
        except Exception as e:raise ValueError('could not unlock encrypted backup') from e
    finally:key[:]=b'\0'*len(key)
    if len(secret)!=32 or not hmac.compare_digest(hashlib.sha256(secret).hexdigest(),v['hashlock']):
        secret[:]=b'\0'*len(secret);raise ValueError('encrypted backup hash mismatch')
    return secret


def save_recovered_backup(directory,secret,password,label='Observed Cardano claim'):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    directory=Path(directory).resolve(strict=True);info=directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('backup directory must be user-owned and mode 0700')
    if not isinstance(secret,(bytes,bytearray)) or len(secret)!=32 or not isinstance(password,(bytes,bytearray)) or not 12<=len(password)<=4096:raise ValueError('invalid recovered secret or passphrase')
    if not isinstance(label,str) or not label.strip() or len(label)>80 or any(ord(c)<32 or ord(c)==127 for c in label):raise ValueError('invalid backup label')
    label=label.strip()
    salt=os.urandom(16);iv=os.urandom(12);digest=hashlib.sha256(secret).hexdigest()
    key=bytearray(hashlib.pbkdf2_hmac('sha256',password,salt,600000,32))
    try:cipher=AESGCM(bytes(key)).encrypt(iv,bytes(secret),('hegemon.swap.secret.v1:'+digest).encode())
    finally:key[:]=b'\0'*len(key)
    entry={'label':label,'envelope':{'version':1,'iterations':600000,'hashlock':digest,'salt':salt.hex(),'iv':iv.hex(),'ciphertext':cipher.hex()}}
    path=directory/(secrets.token_hex(16)+'.json')
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600),'w') as handle:
        json.dump(entry,handle,sort_keys=True);handle.write('\n');handle.flush();os.fsync(handle.fileno())
    fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(fd)
    finally:os.close(fd)
    return path
