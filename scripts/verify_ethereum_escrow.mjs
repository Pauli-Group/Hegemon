#!/usr/bin/env node
// Local test adapter: input is public JSON {url, terms}; no wallet or secrets.
import {readFile} from 'node:fs/promises';
import {verifyTokenEscrow,verifyEtherEscrow} from '../swap-ui/ethereum-escrow.mjs';
let input='';for await (const chunk of process.stdin)input+=chunk;
try {
  const {url,terms,simulateChainSwitch,simulateLate,simulateRecentSpend}=JSON.parse(input);
  if(!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(url))throw Error('test adapter accepts loopback only');
  let chainRequests=0,currentNumber;
  const provider={request:async({method,params})=>{
    if(method==='eth_chainId' && ++chainRequests>1 && simulateChainSwitch)return '0x1';
    if(simulateRecentSpend && method==='eth_call' && params[0].data==='0x7ab71b7a' && params[1]===currentNumber)return '0x'+'0'.repeat(63)+'1';
    const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
    const data=await response.json();if(!response.ok||data.error)throw Error('RPC request failed');
    if(method==='eth_getBlockByNumber' && params[0]==='latest')currentNumber=data.result.number;
    if(simulateLate && method==='eth_getBlockByNumber' && params[0]==='latest')return {...data.result,timestamp:'0x'+(BigInt(terms.expiry)-30n).toString(16)};
    return data.result;
  }};
  const template=JSON.parse(await readFile(new URL(terms.kind==='eth'?'../swap-ui/ether-escrow-template.json':'../swap-ui/token-escrow-template.json',import.meta.url),'utf8'));
  const snapshot=await (terms.kind==='eth'?verifyEtherEscrow(provider,template,terms):verifyTokenEscrow(provider,template,terms));
  console.log(JSON.stringify({status:'verified',snapshot}));
} catch(e) {console.error(e.message);process.exitCode=1;}
