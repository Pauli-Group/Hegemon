#!/usr/bin/env python3
"""Exercise local wallet deployment primitives against isolated Anvil nodes."""
import argparse,hashlib,http.client,json,os,subprocess,sys
from pathlib import Path
from htlc_counterpart import Ethereum,ROOT,TOOLS,wait_for
from ethereum_local_anchor import ethereum_local_head
from local_private_spend_swap import require,port,stop
from release_private_spend_lifecycle_io import rpc


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--tools',type=Path,default=TOOLS)
 a=p.parse_args();os.umask(0o077);out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False);results=[]
 try:
  for kind in ('eth','erc20','erc721','erc1155'):
   c=Ethereum(out/kind,a.tools,test_token=None if kind=='eth' else kind)
   companion_proc=None
   try:
    anchor=ethereum_local_head(c.url);secret=os.urandom(32);digest=hashlib.sha256(secret).hexdigest()
    companion_dir=c.d/'companion';companion_dir.mkdir(mode=0o700);token_file=companion_dir/'token';cp=port()
    companion_proc=subprocess.Popen([sys.executable,ROOT/'scripts/local_swap_companion.py','--ethereum-rpc',c.url,'--token-file',token_file,'--port',str(cp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    pairing=wait_for(lambda:(v if len(v:=token_file.read_text().strip())==64 else None),'Ethereum companion token')
    def companion_head(credential=pairing,origin='http://127.0.0.1:8787'):
     connection=http.client.HTTPConnection('127.0.0.1',cp,timeout=30)
     try:
      connection.request('GET','/ethereum/head',headers={'Origin':origin,'Authorization':'Bearer '+credential})
      response=connection.getresponse();return response.status,json.loads(response.read())
     finally:connection.close()
    wait_for(lambda:companion_head()[0]==200,'Ethereum companion head')
    require(companion_head('0'*64)[0]==403 and companion_head(origin='http://attacker.invalid')[0]==403,'Ethereum companion authorization failed')
    status,anchored=companion_head();require(status==200 and anchored==anchor,'Ethereum companion anchor mismatch')
    terms={'kind':'eth' if kind=='eth' else str(c.token_kind),'claimant':c.alice,'refundee':c.bob,'hashlock':'0x'+digest,
           'expiry':str(int(anchor['time_seconds'])+600),'amount':str(c.amount if kind=='eth' else c.token_amount)}
    if kind!='eth':terms.update(token=c.token,tokenId=str(c.token_id))
    def submit(anchor_value,expected,step=None,terms_value=None,secret_value=None):
     run=subprocess.run(['node',ROOT/'scripts/submit_ethereum_deployment.mjs'],input=json.dumps({'url':c.url,'terms':terms_value or terms,'anchor':anchor_value,'step':step,'secret':secret_value}),text=True,capture_output=True,timeout=30)
     require((run.returncode==0)==expected,'deployment returned unexpected status: '+run.stderr[-500:]);return run
    nonce=rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])
    submit({**anchor,'genesis':'00'*32},False)
    require(rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])==nonce,'incorrect chain caused a transaction')
    response=json.loads(submit(anchor,True).stdout);require(response['submitted'] and not response['confirmed'],'invalid submission status')
    receipt=wait_for(lambda:rpc(c.url,'eth_getTransactionReceipt',[response['txid']]),'deployment receipt')
    require(int(receipt['status'],16)==1 and receipt['contractAddress'],'deployment failed')
    nonce=rpc(c.url,'eth_getTransactionCount',[c.bob,'latest']);submit(anchor,False)
    require(rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])==nonce,'stale anchor caused a second transaction')
    c.contract=receipt['contractAddress'];c.expiry=int(terms['expiry'])
    if kind!='eth':
     funding_terms={**terms,'contract':c.contract};nonce=rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])
     submit(ethereum_local_head(c.url),False,'approve',{**funding_terms,'amount':str(int(terms['amount'])+1)})
     require(rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])==nonce,'changed terms caused token approval')
     for step in ('approve','fund'):
      result=json.loads(submit(ethereum_local_head(c.url),True,step,funding_terms).stdout)
      confirmed=wait_for(lambda:rpc(c.url,'eth_getTransactionReceipt',[result['txid']]),step+' receipt')
      require(int(confirmed['status'],16)==1,step+' transaction failed')
     nonce=rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])
     submit(ethereum_local_head(c.url),False,'fund',funding_terms)
     require(rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])==nonce,'funded escrow caused a second funding transaction')
     if kind=='erc1155':
      revoked=json.loads(submit(ethereum_local_head(c.url),True,'revoke',funding_terms).stdout)
      confirmed=wait_for(lambda:rpc(c.url,'eth_getTransactionReceipt',[revoked['txid']]),'revoke receipt')
      require(int(confirmed['status'],16)==1,'operator revocation failed')
      # The disposable Sample1155 exposes its operator map as approved().
      state=rpc(c.url,'eth_call',[{'to':c.token,'data':'0xf4b16045'+c.word_address(c.bob)+c.word_address(c.contract)},'latest'])
      require(int(state,16)==0,'operator remained approved')
     rpc(c.url,'evm_mine');rpc(c.url,'evm_mine')
    else:rpc(c.url,'evm_mine');rpc(c.url,'evm_mine')
    verify_terms={'chainId':'0x7a69','contract':c.contract,**terms}
    check=subprocess.run(['node',ROOT/'scripts/verify_ethereum_escrow.mjs'],input=json.dumps({'url':c.url,'terms':verify_terms}),text=True,capture_output=True,timeout=30)
    require(check.returncode==0,'deployed escrow did not verify: '+check.stderr[-500:])
    snapshot=rpc(c.url,'evm_snapshot');refund_terms={**terms,'contract':c.contract};nonce=rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])
    submit(ethereum_local_head(c.url),False,'refund',refund_terms)
    require(rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])==nonce,'early refund was submitted')
    rpc(c.url,'evm_setNextBlockTimestamp',[c.expiry]);rpc(c.url,'evm_mine')
    result=json.loads(submit(ethereum_local_head(c.url),True,'refund',refund_terms).stdout)
    refund_receipt=wait_for(lambda:rpc(c.url,'eth_getTransactionReceipt',[result['txid']]),'refund receipt')
    require(int(refund_receipt['status'],16)==1,'refund transaction failed')
    spent=rpc(c.url,'eth_call',[{'to':c.contract,'data':'0x7ab71b7a'},'latest'])
    require(int(spent,16)==1,'refund did not mark escrow spent')
    nonce=rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])
    submit(ethereum_local_head(c.url),False,'refund',refund_terms)
    require(rpc(c.url,'eth_getTransactionCount',[c.bob,'latest'])==nonce,'repeated refund was submitted')
    require(rpc(c.url,'evm_revert',[snapshot]),'failed to restore funded local escrow for claim test')
    nonce=rpc(c.url,'eth_getTransactionCount',[c.alice,'latest'])
    submit(ethereum_local_head(c.url),False,'claim',refund_terms,'00'*32)
    require(rpc(c.url,'eth_getTransactionCount',[c.alice,'latest'])==nonce,'wrong preimage caused claim submission')
    result=json.loads(submit(ethereum_local_head(c.url),True,'claim',refund_terms,secret.hex()).stdout)
    claim_receipt=wait_for(lambda:rpc(c.url,'eth_getTransactionReceipt',[result['txid']]),'claim receipt')
    require(int(claim_receipt['status'],16)==1,'claim transaction failed')
    spent=rpc(c.url,'eth_call',[{'to':c.contract,'data':'0x7ab71b7a'},'latest'])
    require(int(spent,16)==1,'claim did not mark escrow spent')
    rpc(c.url,'evm_mine');rpc(c.url,'evm_mine')
    observation=json.loads(submit(ethereum_local_head(c.url),True,'observe',refund_terms).stdout)
    require(observation.get('matched') is True and int(observation['snapshot']['confirmations'])>=2,'confirmed Ethereum preimage was not observed')
    submit(ethereum_local_head(c.url),False,'observe',{**refund_terms,'hashlock':'0x'+'00'*32})
    c.isolated();results.append({'kind':kind,'status':'passed','transaction':response['txid'],'contract':c.contract})
    print(kind,'passed',flush=True)
   finally:stop(companion_proc);c.close()
 finally:(out/'summary.json').write_text(json.dumps({'status':'passed' if len(results)==4 else 'failed','scenarios':results},indent=2)+'\n')
 print('summary:',out/'summary.json')

if __name__=='__main__':main()
