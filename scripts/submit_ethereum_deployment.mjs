#!/usr/bin/env node
// Local test adapter; the input contains public terms and no preimage or keys.
import {readFile} from 'node:fs/promises';
import {submitLocalEscrowDeployment,submitLocalTokenFundingStep} from '../swap-ui/ethereum-actions.mjs';
let raw='';for await(const chunk of process.stdin)raw+=chunk;
try{
 const {url,terms,anchor,step}=JSON.parse(raw);if(!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(url))throw Error('loopback only');
 const provider={request:async({method,params=[]})=>{const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});const data=await response.json();if(!response.ok||data.error)throw Error('RPC failed');return data.result;}};
 const template=JSON.parse(await readFile(new URL(terms.kind==='eth'?'../swap-ui/ether-escrow-template.json':'../swap-ui/token-escrow-template.json',import.meta.url),'utf8'));
 console.log(JSON.stringify(await (step?submitLocalTokenFundingStep(provider,template,terms,anchor,step):submitLocalEscrowDeployment(provider,template,terms,anchor))));
}catch(e){console.error(e.message);process.exitCode=1;}
