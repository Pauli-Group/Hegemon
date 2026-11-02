"""Exercise offline-built transactions on a fresh, peerless Cardano chain."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from htlc_counterpart import Cardano,wait_for
from public_cardano_transactions import build_balanced
from public_cardano_driver import sign_and_submit
from public_swap_journal import transaction_id


def value(output):
    row=output['value'];assets={policy+'.'+name:quantity for policy,names in row.items() if policy!='lovelace' for name,quantity in names.items()}
    return row['lovelace'],assets


class PublicCardanoTransactionsTest(unittest.TestCase):
    def test_rejects_duplicate_inputs_and_missing_assets(self):
        with tempfile.TemporaryDirectory(prefix='ada-offline-invalid-') as directory:
            params=Path(directory)/'params.json';params.write_text('{}');body=Path(directory)/'body.json'
            addr='addr_test1'+'q'*40;item={'outref':'11'*32+'#0','lovelace':5_000_000,'assets':{}}
            output={'address':addr,'lovelace':2_000_000,'assets':{}}
            with self.assertRaisesRegex(ValueError,'Duplicate'):build_balanced(inputs=[item,item],outputs=[output],change_address=addr,params=params,body=body)
            output['assets']={'22'*28+'.00':1}
            with self.assertRaisesRegex(ValueError,'Insufficient Cardano assets'):build_balanced(inputs=[item],outputs=[output],change_address=addr,params=params,body=body)
            self.assertFalse(body.exists())
    def test_offline_build_preserves_tokens_and_claims_script_output(self):
        with tempfile.TemporaryDirectory(prefix='ada-offline-build-') as root:
            chain=Cardano(Path(root)/'cardano',test_tokens=True,epoch_length=5000)
            try:
                chain.isolated();params=chain.d/'protocol-params.json';params.write_text(json.dumps(chain.query('protocol-parameters')))
                alice=chain.actors['alice'];bob=chain.actors['bob'];secret=b'\x77'*32;expiry_slot=chain.tip()['slot']+900
                # A locally signed native policy produces an independent fungible
                # token and one-of-one test token without asking a node to build.
                policy_file=chain.d/'offline-policy.json';policy_file.write_text(json.dumps({'type':'sig','keyHash':alice['hash']}))
                policy=chain.run('transaction','policyid','--script-file',policy_file).strip();minted={policy+'.46554e47':11,policy+'.4e4654':1}
                available=chain.utxos(alice['address']);fee_ref=chain.fee_input('alice');ada,existing=value(available[fee_ref]);body,signed=chain.files('offline-mint')
                build_balanced(inputs=[{'outref':fee_ref,'lovelace':ada,'assets':existing}],outputs=[{'address':alice['address'],'lovelace':5_000_000,'assets':minted}],change_address=alice['address'],params=params,body=body,mint=minted,mint_script=policy_file)
                _,mint_out=chain.submit(body,signed,'alice',alice['address'])
                mint_ref=next(ref for ref,out in mint_out.items() if out['value'].get(policy,{}).get('46554e47')==11 and out['value'].get(policy,{}).get('4e4654')==1)
                terms={'constructor':0,'fields':[{'bytes':hashlib.sha256(secret).hexdigest()},{'bytes':alice['hash']},{'bytes':bob['hash']},{'int':chain.start_ms+expiry_slot*chain.slot_ms}]}
                datum=chain.d/'raw-datum.json';datum.write_text(json.dumps(terms));redeemer=chain.d/'raw-redeemer.json';redeemer.write_text(json.dumps({'constructor':0,'fields':[{'bytes':secret.hex()}]}))
                available=chain.utxos(bob['address']);fee_input=chain.fee_input('bob');token_input=chain.token_input
                def make_input(ref,utxos):
                    amount,assets=value(utxos[ref]);return {'outref':ref,'lovelace':amount,'assets':assets}
                native={policy+'.'+name:quantity for policy,names in chain.tokens.items() for name,quantity in names.items()}
                body,signed=chain.files('offline-lock')
                fee=build_balanced(inputs=[make_input(fee_input,available),make_input(token_input,available)],outputs=[{'address':chain.address,'lovelace':chain.amount,'assets':native,'datum':datum}],change_address=bob['address'],params=params,body=body)
                self.assertGreaterEqual(fee,200000)
                def fake_submit(_directory,network,raw):
                    self.assertEqual(network,'cardano-preview');return {'txid':transaction_id(network,raw),'confirmed':False}
                with patch('public_cardano_driver.verify_network'),patch('public_cardano_driver.submit',side_effect=fake_submit):
                    prepared=sign_and_submit(chain.d,body,bob['skey'])
                self.assertFalse(prepared['confirmed'])
                txid,found=chain.submit(body,signed,'bob',chain.address)
                self.assertEqual(prepared['txid'],txid)
                locked=next(ref for ref,out in found.items() if out['value']['lovelace']==chain.amount and chain.has_tokens(out))
                alice_utxos=chain.utxos(alice['address']);fee_ref=mint_ref
                script_input={'outref':locked,'lovelace':chain.amount,'assets':native,'script':chain.script,'redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
                body,signed=chain.files('offline-claim')
                fee=build_balanced(inputs=[script_input,make_input(fee_ref,alice_utxos)],outputs=[{'address':alice['address'],'lovelace':chain.amount,'assets':native}],change_address=alice['address'],params=params,body=body,collateral=alice['collateral'],required_signer=alice['hash'],invalid_hereafter=expiry_slot)
                self.assertGreater(fee,0);_,received=chain.submit(body,signed,'alice',alice['address'])
                self.assertTrue(any(chain.has_tokens(out) for out in received.values()))
                self.assertTrue(any(out['value'].get(policy,{}).get('46554e47')==11 and out['value'].get(policy,{}).get('4e4654')==1 for out in received.values()))
                self.assertNotIn(locked,chain.utxos(chain.address))
                # Fund a second output and check both early and mature refund.
                token_ref=next(ref for ref,out in received.items() if chain.has_tokens(out))
                expiry_slot=chain.tip()['slot']+160
                terms['fields'][1]={'bytes':bob['hash']};terms['fields'][2]={'bytes':alice['hash']};terms['fields'][3]={'int':chain.start_ms+expiry_slot*chain.slot_ms}
                datum.write_text(json.dumps(terms));alice_utxos=chain.utxos(alice['address']);fee_ref=chain.fee_input('alice')
                body,signed=chain.files('offline-refund-lock')
                build_balanced(inputs=[make_input(token_ref,alice_utxos),make_input(fee_ref,alice_utxos)],outputs=[{'address':chain.address,'lovelace':chain.amount,'assets':native,'datum':datum}],change_address=alice['address'],params=params,body=body)
                _,found=chain.submit(body,signed,'alice',chain.address);locked=next(ref for ref,out in found.items() if chain.has_tokens(out))
                alice_utxos=chain.utxos(alice['address']);fee_ref=chain.fee_input('alice');redeemer.write_text(json.dumps({'constructor':1,'fields':[]}))
                script_input={'outref':locked,'lovelace':chain.amount,'assets':native,'script':chain.script,'redeemer':redeemer,'execution_units':(10_000_000,10_000_000_000)}
                body,signed=chain.files('offline-refund')
                build_balanced(inputs=[script_input,make_input(fee_ref,alice_utxos)],outputs=[{'address':alice['address'],'lovelace':chain.amount,'assets':native}],change_address=alice['address'],params=params,body=body,collateral=alice['collateral'],required_signer=alice['hash'],invalid_before=expiry_slot)
                chain.run('transaction','sign','--tx-body-file',body,'--signing-key-file',alice['skey'],'--testnet-magic',chain.magic,'--out-file',signed)
                early=chain.run('transaction','submit','--tx-file',signed,'--testnet-magic',chain.magic,'--socket-path',chain.socket,check=False)
                self.assertNotEqual(early.returncode,0);self.assertIn(locked,chain.utxos(chain.address))
                wait_for(lambda:chain.tip()['slot']>=expiry_slot,'Cardano refund eligibility',seconds=90)
                _,received=chain.submit(body,signed,'alice',alice['address']);self.assertTrue(any(chain.has_tokens(out) for out in received.values()))
                self.assertNotIn(locked,chain.utxos(chain.address));chain.isolated()
            finally:chain.close()

if __name__=='__main__':unittest.main()
