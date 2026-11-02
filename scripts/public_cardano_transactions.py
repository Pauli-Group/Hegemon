"""Build balanced Cardano testnet transaction bodies offline using cardano-cli.

The caller must obtain authentic preview UTxOs, protocol parameters, script
terms and execution budgets, and must independently inspect before signing or
submitting. This module does not query, sign or broadcast.
"""
import re
import subprocess
from pathlib import Path

CLI=Path('/workspace/chain-tools/cardano/bin/cardano-cli')


def _amount(value,positive=False):
    if type(value) is not int or not (1 if positive else 0)<=value<2**63:raise ValueError('Invalid Cardano quantity')
    return value


def _ref(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}#(0|[1-9][0-9]{0,9})',value):raise ValueError('Invalid Cardano outref')
    return value


def _assets(value):
    if not isinstance(value,dict):raise ValueError('Invalid Cardano asset map')
    result={}
    for name,quantity in value.items():
        if not isinstance(name,str) or not re.fullmatch(r'[0-9a-f]{56}\.(?:[0-9a-f]{2}){0,32}',name):raise ValueError('Invalid Cardano asset identity')
        result[name]=_amount(quantity,True)
    return result


def _address(value):
    if not isinstance(value,str) or not re.fullmatch('addr_test1[ac-hj-np-z02-9]+',value):raise ValueError('Expected a Cardano testnet address')
    return value


def _run(cli,args):
    result=subprocess.run([str(cli),'conway','transaction',*map(str,args)],capture_output=True,text=True,timeout=30)
    if result.returncode:raise RuntimeError('Cardano transaction build failed: '+result.stderr[-1000:])
    return result.stdout.strip()


def _output(address,amount,assets,datum=None):
    result=['--tx-out',_address(address)+'+'+str(_amount(amount,True))+''.join('+'+str(quantity)+' '+name for name,quantity in sorted(_assets(assets).items()))]
    if datum is not None:result+=['--tx-out-inline-datum-file',str(datum)]
    return result


def _minimum_output(cli,params,address,amount,assets,datum=None):
    result=_run(cli,['calculate-min-required-utxo','--protocol-params-file',params,*_output(address,amount,assets,datum)])
    match=re.fullmatch(r'Coin\s+(\d+)',result)
    if not match:raise RuntimeError('Unrecognized Cardano minimum-output result')
    if amount<int(match.group(1)):raise ValueError('Cardano output below minimum lovelace')


def build_balanced(*,inputs,outputs,change_address,params,body,collateral=None,required_signer=None,invalid_before=None,invalid_hereafter=None,cli=CLI):
    """Build a balanced body and return its conservative fee in lovelace.

    Inputs have outref, lovelace and assets; a script input additionally has
    script, redeemer and execution_units=(memory,steps). Outputs have address,
    lovelace, assets, and optional datum. Protocol parameters and datum files
    are provided by the caller. Only a single key witness is budgeted.
    """
    if not isinstance(inputs,list) or not 1<=len(inputs)<=10 or not isinstance(outputs,list) or not 1<=len(outputs)<=10:raise ValueError('Invalid Cardano input or output count')
    _address(change_address);params=Path(params);body=Path(body)
    if not params.is_file() or body.exists():raise ValueError('Missing protocol parameters or body already exists')
    refs=set();total=0;assets={};args=[];scripts=0
    for item in inputs:
        if not isinstance(item,dict) or not {'outref','lovelace','assets'}<=set(item) or set(item)-{'outref','lovelace','assets','script','redeemer','execution_units'}:raise ValueError('Invalid Cardano input')
        ref=_ref(item['outref'])
        if ref in refs:raise ValueError('Duplicate Cardano input')
        refs.add(ref);total+=_amount(item['lovelace'],True);args+=['--tx-in',ref]
        for name,qty in _assets(item['assets']).items():assets[name]=assets.get(name,0)+qty
        attached={k for k in ('script','redeemer','execution_units') if k in item}
        if attached:
            if attached!={'script','redeemer','execution_units'}:raise ValueError('Incomplete Cardano script input')
            scripts+=1;units=item['execution_units']
            if not isinstance(units,tuple) or len(units)!=2:raise ValueError('Invalid execution budget')
            memory=_amount(units[0],True);steps=_amount(units[1],True)
            if not Path(item['script']).is_file() or not Path(item['redeemer']).is_file():raise ValueError('Missing script or redeemer')
            # cardano-cli expects (steps,memory), opposite the input tuple.
            args+=['--tx-in-script-file',item['script'],'--tx-in-inline-datum-present','--tx-in-redeemer-file',item['redeemer'],'--tx-in-execution-units',f'({steps},{memory})']
    if scripts:
        if scripts!=1 or collateral is None or not isinstance(required_signer,str) or not re.fullmatch('[0-9a-f]{56}',required_signer):raise ValueError('One script, collateral and signer are required')
        collateral=_ref(collateral)
        if collateral in refs:raise ValueError('Collateral overlaps a spending input')
        args+=['--tx-in-collateral',collateral,'--required-signer-hash',required_signer,'--protocol-params-file',params]
    elif collateral is not None or required_signer is not None:raise ValueError('Unexpected Cardano collateral or signer')
    for item in outputs:
        if not isinstance(item,dict) or not {'address','lovelace','assets'}<=set(item) or set(item)-{'address','lovelace','assets','datum'}:raise ValueError('Invalid Cardano output')
        total-=_amount(item['lovelace'],True)
        for name,qty in _assets(item['assets']).items():assets[name]=assets.get(name,0)-qty
        args+=_output(item['address'],item['lovelace'],item['assets'],item.get('datum'))
    if any(v<0 for v in assets.values()):raise ValueError('Insufficient Cardano assets')
    assets={name:qty for name,qty in assets.items() if qty}
    if invalid_before is not None:args+=['--invalid-before',str(_amount(invalid_before))]
    if invalid_hereafter is not None:args+=['--invalid-hereafter',str(_amount(invalid_hereafter,True))]
    if invalid_before is not None and invalid_hereafter is not None and invalid_before>=invalid_hereafter:raise ValueError('Invalid Cardano validity interval')
    for item in outputs:_minimum_output(cli,params,item['address'],item['lovelace'],item['assets'],item.get('datum'))
    fee=2_000_000 if scripts else 200_000
    try:
        for _ in range(5):
            change=total-fee
            if change<1_500_000:raise ValueError('Insufficient lovelace for change and fees')
            _minimum_output(cli,params,change_address,change,assets)
            argv=args+_output(change_address,change,assets)+['--fee',str(fee),'--out-file',body]
            _run(cli,['build-raw',*argv])
            body.chmod(0o600)
            calculated=_run(cli,['calculate-min-fee','--tx-body-file',body,'--protocol-params-file',params,'--witness-count','1','--output-text'])
            match=re.fullmatch(r'(\d+)\s+Lovelace',calculated,re.I)
            if not match:raise RuntimeError('Unrecognized Cardano fee output')
            minimum=int(match.group(1))
            if minimum<=fee:return fee
            fee=minimum+10000
        raise RuntimeError('Could not settle Cardano fee')
    except BaseException:
        body.unlink(missing_ok=True)
        raise
