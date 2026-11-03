/** Read-only Sepolia escrow verification. The connected provider is trusted. */
import {verifyEtherEscrow,verifyTokenEscrow} from './ethereum-escrow.mjs';

export const SEPOLIA_CHAIN_ID='0xaa36a7';
export const SEPOLIA_GENESIS='0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9';

export async function assertSepoliaIdentity(provider){
  if(!provider||typeof provider.request!=='function')throw Error('Connect an Ethereum wallet first.');
  const [chain,genesis]=await Promise.all([provider.request({method:'eth_chainId',params:[]}),provider.request({method:'eth_getBlockByNumber',params:['0x0',false]})]);
  if(typeof chain!=='string'||!/^0x[0-9a-f]+$/i.test(chain)||BigInt(chain)!==BigInt(SEPOLIA_CHAIN_ID)||String(genesis?.hash||'').toLowerCase()!==SEPOLIA_GENESIS)throw Error('Wallet is not connected to Ethereum Sepolia.');
}

export async function verifySepoliaEscrow(provider,template,terms){
  if(!terms||!['eth','0','1','2'].includes(terms.kind))throw Error('Invalid escrow type.');
  await assertSepoliaIdentity(provider);
  const checked={...terms,chainId:SEPOLIA_CHAIN_ID};
  // Sepolia heads can advance while a wallet provider processes several RPCs.
  // A bounded read-only restart preserves the verifier's stable-head rule.
  for(let attempt=0;attempt<3;attempt++){
    try{
      const result=await (terms.kind==='eth'?verifyEtherEscrow(provider,template,checked,2,600):verifyTokenEscrow(provider,template,checked,2,600));
      await assertSepoliaIdentity(provider);return result;
    }catch(error){
      const message=String(error?.message||'');
      const transient=message==='snapshot or chain changed'||/block not found|header not found|too many requests|rate limit|\b429\b/i.test(message);
      if(!transient||attempt===2)throw error;
      if(message!=='snapshot or chain changed')await new Promise(resolve=>setTimeout(resolve,500*(attempt+1)));
    }
  }
}
