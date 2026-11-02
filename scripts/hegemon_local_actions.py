"""Validated CLI construction for opt-in, isolated Hegemon Development actions.

No request field is a wallet passphrase or HTLC preimage. Callers must obtain
those directly from a local user and must verify node isolation and network
identity before executing the returned command. This module does not perform
cross-chain verification or submit anything by itself.
"""
import os
import re
import secrets
import stat
from pathlib import Path
from release_private_spend_lifecycle_io import public_v8_address_keys


def decimal(value,*,positive=False):
    if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,19}',value) or int(value)>=2**64 or (positive and value=='0'):
        raise ValueError('invalid Hegemon integer')
    return value


def address(value):
    try:public_v8_address_keys(value)
    except Exception as e:raise ValueError('invalid Hegemon address') from e
    return value


def hash32(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('invalid hash')
    return value


def private_handoff_directory(path):
    if path is None:raise ValueError('configure a private handoff directory')
    path=Path(path).resolve(strict=True);st=path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:
        raise ValueError('handoff directory must be owned by this user and mode 0700')
    return path


def build_action(data,handoff_dir=None):
    if not isinstance(data,dict) or not isinstance(data.get('operation'),str):raise ValueError('invalid Hegemon request')
    op=data['operation'];handoff=None
    if op=='status':
        if set(data)!={'operation'}:raise ValueError('invalid status fields')
        return ['status'],None
    if op=='ordinary':
        if set(data)!={'operation','inputs','recipient','amount','fee'}:raise ValueError('invalid transfer fields')
        inputs=data['inputs']
        if not isinstance(inputs,list) or not 1<=len(inputs)<=2:raise ValueError('one or two inputs required')
        inputs=[decimal(x) for x in inputs]
        if len(set(inputs))!=len(inputs):raise ValueError('duplicate inputs')
        return ['ordinary','--inputs',*inputs,'--recipient',address(data['recipient']),
                '--amount',decimal(data['amount'],positive=True),'--fee',decimal(data['fee'])],None
    if op=='lock':
        if set(data)!={'operation','inputs','claim','refund','hashlock','timeout','amount','fee'}:raise ValueError('invalid lock fields')
        inputs=data['inputs']
        if not isinstance(inputs,list) or not 1<=len(inputs)<=2:raise ValueError('one or two inputs required')
        inputs=[decimal(x) for x in inputs]
        if len(set(inputs))!=len(inputs):raise ValueError('duplicate inputs')
        directory=private_handoff_directory(handoff_dir)
        handoff=directory/(secrets.token_hex(16)+'.bin')
        if handoff.exists():raise ValueError('handoff path collision; retry')
        argv=['lock','--inputs',*inputs,'--claim',address(data['claim']),'--refund',address(data['refund']),
              '--hashlock',hash32(data['hashlock']),'--timeout',decimal(data['timeout'],positive=True),
              '--amount',decimal(data['amount'],positive=True),'--fee',decimal(data['fee']),
              '--release-secret','--refund-handoff',str(handoff)]
        return argv,handoff
    if op in ('claim','refund'):
        if set(data)!={'operation','locked','fee_input','recipient','fee'}:raise ValueError('invalid spend fields')
        argv=[op,'--locked',decimal(data['locked']),'--fee-input',decimal(data['fee_input']),
              '--recipient',address(data['recipient']),'--fee',decimal(data['fee'])]
        return argv,None
    if op=='submit':
        if set(data)!={'operation','attempt'}:raise ValueError('invalid submit fields')
        return ['submit',hash32(data['attempt'])],None
    raise ValueError('unsupported Hegemon operation')
