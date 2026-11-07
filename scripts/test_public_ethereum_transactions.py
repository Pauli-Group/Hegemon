"""Check testnet-chain signing and native escrow behavior on disposable Anvil."""
import hashlib
import json
import subprocess
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch
from eth_abi import encode,decode
from eth_account import Account
from eth_utils import keccak
from local_private_spend_swap import port,stop
from public_ethereum_transactions import sign_transaction
from public_ethereum_verify import verify_native
from public_ethereum_token_verify import verify_token
from swap_engine.tools import tool, skip_unless_tools

class PublicEthereumTransactionsTest(unittest.TestCase):
    def test_large_bounded_public_estimate_is_signable(self):
        key=b'\x11'*32;sender=Account.from_key(key).address
        raw,_=sign_transaction(key,sender,nonce=0,to=None,value=0,data=b'fixture',gas=20_000_000,max_fee=2_000_000_000,priority_fee=1_000_000_000)
        self.assertEqual(Account.recover_transaction(raw),sender)
        with self.assertRaises(ValueError):sign_transaction(key,sender,nonce=0,to=None,value=0,data=b'',gas=30_000_001,max_fee=1,priority_fee=1)
    @skip_unless_tools('anvil')
    def test_local_sepolia_chainid_escrow_claim(self):
        n=port();node=subprocess.Popen([str(tool('anvil')),'--host','127.0.0.1','--port',str(n),'--chain-id','11155111','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        def rpc(method,params):
            req=urllib.request.Request(f'http://127.0.0.1:{n}',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=5) as response:out=json.load(response)
            if 'error' in out:raise RuntimeError(str(out['error']))
            return out['result']
        def receipt(txid):
            deadline=time.monotonic()+10
            while True:
                result=rpc('eth_getTransactionReceipt',[txid])
                if result is not None:return result
                if time.monotonic()>deadline:raise RuntimeError('Local transaction not mined')
                time.sleep(.05)
        try:
            deadline=time.monotonic()+20
            while True:
                try:rpc('eth_chainId',[]);break
                except OSError:
                    if node.poll() is not None or time.monotonic()>deadline:raise
                    time.sleep(.1)
            alicekey=b'\x11'*32;bobkey=b'\x22'*32;alice=Account.from_key(alicekey).address;bob=Account.from_key(bobkey).address
            rpc('anvil_setBalance',[alice,hex(10**18)]);rpc('anvil_setBalance',[bob,hex(10**18)])
            preimage=b'\x33'*32;digest=hashlib.sha256(preimage).digest();expiry=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16)+600
            artifact=json.loads((Path(__file__).resolve().parents[1]/'contracts/ethereum/out/HegemonHTLC.sol/HegemonHTLC.json').read_text())
            bytecode=bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))+encode(['bytes32','address','uint256'],[digest,bob,expiry])
            kwargs={'nonce':0,'to':None,'value':10**15,'data':bytecode,'gas':1000000,'max_fee':2_000_000_000,'priority_fee':1_000_000_000}
            with self.assertRaisesRegex(ValueError,'does not match'):sign_transaction(bobkey,alice,**kwargs)
            raw,txid=sign_transaction(alicekey,alice,**kwargs);self.assertEqual(Account.recover_transaction(raw),alice)
            self.assertEqual(rpc('eth_sendRawTransaction',['0x'+raw.hex()]),txid)
            deployed=receipt(txid);self.assertEqual(deployed['status'],'0x1');contract=deployed['contractAddress']
            rpc('evm_mine',[])
            with patch('public_ethereum_verify.verify_network'),patch('public_ethereum_verify.rpc',side_effect=rpc):
                snapshot=verify_native(contract,digest.hex(),bob,alice,expiry,10**15)
                self.assertEqual(snapshot['confirmations'],2)
                with self.assertRaisesRegex(ValueError,'code or terms'):verify_native(contract,digest.hex(),bob,alice,expiry+1,10**15)
            calldata=keccak(text='claim(bytes32)')[:4]+encode(['bytes32'],[preimage])
            raw,claimid=sign_transaction(bobkey,bob,nonce=0,to=contract,value=0,data=calldata,gas=100000,max_fee=2_000_000_000,priority_fee=1_000_000_000)
            self.assertEqual(rpc('eth_sendRawTransaction',['0x'+raw.hex()]),claimid);self.assertEqual(receipt(claimid)['status'],'0x1')
            self.assertEqual(int(rpc('eth_getBalance',[contract,'latest']),16),0)
        finally:stop(node)

    @skip_unless_tools('anvil')
    def test_local_sepolia_chainid_token_claims(self):
        n=port();node=subprocess.Popen([str(tool('anvil')),'--host','127.0.0.1','--port',str(n),'--chain-id','11155111','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        def rpc(method,params):
            req=urllib.request.Request(f'http://127.0.0.1:{n}',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=5) as response:out=json.load(response)
            if 'error' in out:raise RuntimeError(str(out['error']))
            return out['result']
        def receipt(txid):
            deadline=time.monotonic()+10
            while True:
                result=rpc('eth_getTransactionReceipt',[txid])
                if result is not None:return result
                if time.monotonic()>deadline:raise RuntimeError('Local transaction not mined')
                time.sleep(.05)
        def calldata(signature,types,args):return keccak(text=signature)[:4]+encode(types,args)
        def code(path):return bytes.fromhex(json.loads((Path(__file__).resolve().parents[1]/path).read_text())['bytecode']['object'].removeprefix('0x'))
        try:
            deadline=time.monotonic()+20
            while True:
                try:rpc('eth_chainId',[]);break
                except OSError:
                    if node.poll() is not None or time.monotonic()>deadline:raise
                    time.sleep(.1)
            alicekey=b'\x11'*32;bobkey=b'\x22'*32;alice=Account.from_key(alicekey).address;bob=Account.from_key(bobkey).address
            for address in (alice,bob):rpc('anvil_setBalance',[address,hex(10**18)])
            nonce={alice:0,bob:0}
            def send(key,address,to,data,gas=6000000):
                raw,txid=sign_transaction(key,address,nonce=nonce[address],to=to,value=0,data=data,gas=gas,max_fee=2_000_000_000,priority_fee=1_000_000_000)
                nonce[address]+=1;self.assertEqual(rpc('eth_sendRawTransaction',['0x'+raw.hex()]),txid);result=receipt(txid);self.assertEqual(result['status'],'0x1');return result
            secret=b'\x33'*32;digest=hashlib.sha256(secret).digest();expiry=int(rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16)+3600
            for kind,name,token_id,amount in ((0,'Sample20',0,100),(1,'Sample721',42,1),(2,'Sample1155',7,30)):
                token=send(bobkey,bob,None,code('contracts/ethereum/out/TokenHTLC.t.sol/'+name+'.json')+encode(['address'],[bob]))['contractAddress']
                deploy=code('contracts/ethereum/out/TokenHTLC.sol/TokenHTLC.json')+encode(['uint8','address','uint256','uint256','bytes32','address','uint256'],[kind,token,token_id,amount,digest,alice,expiry])
                escrow=send(bobkey,bob,None,deploy)['contractAddress']
                approval=calldata('setApprovalForAll(address,bool)',['address','bool'],[escrow,True]) if kind==2 else calldata('approve(address,uint256)',['address','uint256'],[escrow,amount if kind==0 else token_id])
                send(bobkey,bob,token,approval);send(bobkey,bob,escrow,calldata('fund()',[],[]));rpc('evm_mine',[])
                with patch('public_ethereum_token_verify.verify_network'),patch('public_ethereum_token_verify.rpc',side_effect=rpc):
                    self.assertEqual(verify_token(escrow,kind,token,token_id,amount,digest.hex(),alice,bob,expiry)['confirmations'],2)
                send(alicekey,alice,escrow,calldata('claim(bytes32)',['bytes32'],[secret]))
                query=calldata('balanceOf(address,uint256)',['address','uint256'],[alice,token_id]) if kind==2 else calldata('ownerOf(uint256)',['uint256'],[token_id]) if kind==1 else calldata('balanceOf(address)',['address'],[alice])
                result=rpc('eth_call',[{'to':token,'data':'0x'+query.hex()},'latest']);value=decode(['address' if kind==1 else 'uint256'],bytes.fromhex(result[2:]))[0]
                if kind==1:self.assertEqual(value.lower(),alice.lower())
                else:self.assertEqual(value,amount)
        finally:stop(node)

if __name__=='__main__':unittest.main()
