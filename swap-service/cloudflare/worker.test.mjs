import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker from './worker.mjs';

function database(){
  const db=new DatabaseSync(':memory:');db.exec(readFileSync(new URL('./schema.sql',import.meta.url),'utf8'));
  return {raw:db,async batch(statements){for(const s of statements)await s.run();},prepare(sql){const q=db.prepare(sql);let values=[];return {bind(...v){values=v;return this;},async first(){return q.get(...values)??null;},async all(){return {results:q.all(...values)};},async run(){return q.run(...values);}};}};
}
function client(db){
  const env={DB:db,ASSETS:{fetch:async()=>new Response('board')}};
  return async(path,{method='GET',token,data,ip='192.0.2.8',origin='https://swap.example'}={})=>{
    const headers={'CF-Connecting-IP':ip,origin};if(token)headers.authorization='Bearer '+token;if(data)headers['content-type']='application/json';
    const r=await worker.fetch(new Request('https://swap.example'+path,{method,headers,...(data?{body:JSON.stringify(data)}:{})}),env);
    return [r.status,await r.json()];
  };
}
const offer=()=>({visibility:'public',expires:Math.floor(Date.now()/1000)+600,give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'erc721',id:'0x'+'a'.repeat(40)+':1',amount:'1'},ownerPublicKey:'04'+'a'.repeat(128)});

test('offers, exclusive reservations, authorization and session replacement',async()=>{
  const db=database(),call=client(db);const [created,a]=await call('/offers',{method:'POST',data:offer()});assert.equal(created,201);
  const results=await Promise.all(Array.from({length:8},()=>call('/offers/'+a.id+'/reserve',{method:'POST'})));
  assert.equal(results.filter(([s])=>s===201).length,1);assert.equal(results.filter(([s])=>s===409).length,7);
  const b=results.find(([s])=>s===201)[1];
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:b.reservationToken,data:{ciphertext:'YWJj',reservationId:b.reservationId}}))[0],201);
  assert.equal((await call('/offers/'+a.id+'/messages',{token:a.ownerToken}))[1].messages.length,1);
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:a.ownerToken,data:{ciphertext:'YWJj',reservationId:'0'.repeat(64)}}))[0],409);
  db.raw.prepare('UPDATE offers SET reservation_expires=0 WHERE id=?').run(a.id);
  const [status,c]=await call('/offers/'+a.id+'/reserve',{method:'POST'});assert.equal(status,201);
  assert.equal((await call('/offers/'+a.id+'/messages',{token:b.reservationToken}))[0],401);
  assert.deepEqual((await call('/offers/'+a.id+'/messages',{token:a.ownerToken}))[1].messages,[]);
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:a.ownerToken,data:{ciphertext:'YWJj',reservationId:b.reservationId}}))[0],409);
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:c.reservationToken,data:{ciphertext:'ZGVm',reservationId:c.reservationId}}))[0],201);
  assert.equal((await call('/offers/'+a.id+'/close',{method:'POST',token:c.reservationToken}))[0],403);
  assert.equal((await call('/offers/'+a.id+'/close',{method:'POST',token:a.ownerToken}))[0],200);
  assert.equal((await call('/offers'))[1].offers.length,0);db.raw.close();
});

test('rejects invalid tokens, cross-origin actions, oversized bodies and excessive traffic',async()=>{
  const db=database(),call=client(db);const bad=offer();bad.receive.amount='2';assert.equal((await call('/offers',{method:'POST',data:bad}))[0],400);
  assert.equal((await call('/offers',{method:'POST',data:offer(),origin:'https://other.example'}))[0],403);
  assert.equal((await call('/offers',{method:'POST',data:{padding:'x'.repeat(17000)}}))[0],400);
  const [ok,a]=await call('/offers',{method:'POST',data:offer()});assert.equal(ok,201);
  assert.equal((await call('/offers/'+a.id+'/messages',{token:'0'.repeat(64)}))[0],401);
  let status;for(let i=0;i<45;i++)[status]=await call('/offers/'+a.id+'/reserve',{method:'POST',ip:'192.0.2.9'});
  assert.equal(status,429);db.raw.close();
});

test('Bitcoin testnet snapshot checks the fixed network, canonical block and current outspend',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,txid='1'.repeat(64),block='2'.repeat(64),genesis='00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';let outspends=0;
  globalThis.fetch=async input=>{
    const url=String(input);assert.ok(url.startsWith('https://blockstream.info/testnet4/api/'));
    if(url.endsWith('/block-height/0'))return new Response(genesis);
    if(url.endsWith('/blocks/tip/height'))return new Response('100');
    if(url.endsWith('/block-height/99'))return new Response(block);
    if(url.endsWith('/outspend/0')){outspends++;return Response.json({spent:false});}
    if(url.endsWith('/tx/'+txid))return Response.json({txid,status:{confirmed:true,block_height:99,block_hash:block},vout:[{value:1500,scriptpubkey:'0020'+'a'.repeat(64)}]});
    throw Error('unexpected provider request');
  };
  try{const [status,s]=await call('/bitcoin-testnet4/escrow?txid='+txid+'&vout=0');assert.equal(status,200);assert.equal(s.confirmations,2);assert.equal(s.spent,false);assert.equal(outspends,2);
    assert.equal((await call('/bitcoin-testnet4/escrow?txid='+txid+'&vout=0&host=example.com'))[0],400);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Cardano preview snapshot checks network, confirmations and repeat output',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,txid='3'.repeat(64),ref=txid+'#0';let calls=0,changed=false;
  globalThis.fetch=async(input,options)=>{
    const url=String(input);assert.ok(url.startsWith('https://preview.koios.rest/api/v1/'));
    if(url.endsWith('/genesis'))return Response.json([{networkmagic:'2',networkid:'Testnet',systemstart:1666656000}]);
    if(url.endsWith('/tip'))return Response.json([{abs_slot:1000}]);
    if(url.endsWith('/tx_status'))return Response.json([{tx_hash:txid,num_confirmations:3}]);
    if(url.endsWith('/utxo_info')){assert.deepEqual(JSON.parse(options.body)._utxo_refs,[ref]);calls++;return Response.json([{tx_hash:txid,tx_index:0,is_spent:changed&&calls%2===0}]);}
    throw Error('unexpected provider request');
  };
  try{const path='/cardano-preview/escrow?'+new URLSearchParams({outref:ref});const [status,s]=await call(path);assert.equal(status,200);assert.equal(s.confirmations,3);assert.equal(s.output.is_spent,false);assert.equal(calls,2);
    changed=true;assert.equal((await call(path))[0],502);assert.equal((await call('/cardano-preview/escrow?outref=notvalid'))[0],400);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Cardano preview parameters become exact fractions and reject a wrong network or short cost model',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch;let magic='2',model=Array.from({length:350},(_,i)=>i+1);
  globalThis.fetch=async input=>{
    const url=String(input);assert.ok(url.startsWith('https://preview.koios.rest/api/v1/'));
    if(url.endsWith('/genesis'))return Response.json([{networkmagic:magic,networkid:'Testnet',systemstart:1666656000}]);
    if(url.endsWith('/tip'))return Response.json([{abs_slot:1000,block_no:77,epoch_no:5}]);
    if(url.endsWith('/epoch_params?_epoch_no=5'))return Response.json([{epoch_no:5,min_fee_a:44,min_fee_b:155381,coins_per_utxo_size:'4310',max_tx_size:16384,price_mem:0.0577,price_step:7.21e-05,collateral_percent:150,max_collateral_inputs:3,max_tx_ex_mem:14000000,max_tx_ex_steps:10000000000,cost_models:{PlutusV3:model}}]);
    throw Error('unexpected provider request');
  };
  try{
    const [status,p]=await call('/cardano-preview/params');
    assert.equal(status,200);assert.deepEqual(p.priceMem,['577','10000']);assert.deepEqual(p.priceStep,['721','10000000']);
    assert.equal(p.minFeeA,44);assert.equal(p.coinsPerUtxoByte,4310);assert.equal(p.slot,1000);assert.equal(p.costModelV3.length,350);
    assert.equal((await call('/cardano-preview/params?x=1'))[0],404);
    model=[1,2,3];assert.equal((await call('/cardano-preview/params'))[0],502);
    model=Array.from({length:350},()=>1);magic='1';assert.equal((await call('/cardano-preview/params'))[0],502);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Cardano preview UTxO lookup returns rows in request order, null for unknown, and validates input',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,a='a'.repeat(64)+'#0',b='b'.repeat(64)+'#1',c='c'.repeat(64)+'#0';let rows;const q=list=>encodeURIComponent(list.join(','));
  globalThis.fetch=async(input,options)=>{
    const url=String(input);assert.ok(url.startsWith('https://preview.koios.rest/api/v1/'));
    if(url.endsWith('/genesis'))return Response.json([{networkmagic:'2',networkid:'Testnet',systemstart:1666656000}]);
    if(url.endsWith('/tip'))return Response.json([{abs_slot:1000,block_no:77,epoch_no:5}]);
    if(url.endsWith('/utxo_info')){const body=JSON.parse(options.body);assert.deepEqual(body._utxo_refs,[a,b,c]);assert.equal(body._extended,true);return Response.json(rows);}
    throw Error('unexpected provider request');
  };
  const row=(ref,extra={})=>({tx_hash:ref.split('#')[0],tx_index:Number(ref.split('#')[1]),address:'addr_test1x',value:'5000000',asset_list:[],is_spent:false,...extra});
  try{
    rows=[row(b),row(a)];
    const [status,body]=await call('/cardano-preview/utxos?refs='+q([a,b,c]));
    assert.equal(status,200);assert.equal(body.magic,2);assert.equal(body.slot,1000);
    assert.deepEqual(body.outputs.map(x=>x&&x.tx_hash[0]),['a','b',null]);
    rows=[row(a),row(a)];assert.equal((await call('/cardano-preview/utxos?refs='+q([a,b,c])))[0],502);
    rows=[row(c.replace('c','d'))];assert.equal((await call('/cardano-preview/utxos?refs='+q([a,b,c])))[0],502);
    rows=[row(a,{is_spent:'no'})];assert.equal((await call('/cardano-preview/utxos?refs='+q([a,b,c])))[0],502);
    for(const bad of ['','refs=','refs='+q([a,a]),'refs=zz%230','refs='+q([a])+'&x=1','refs='+q(Array.from({length:25},(_,i)=>i.toString(16).padStart(64,'0')+'#0'))])assert.equal((await call('/cardano-preview/utxos'+(bad?'?'+bad:'')))[0],400,bad);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Bitcoin testnet UTxO lookup returns only confirmed outputs with depth and rejects unsafe addresses',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,genesis='00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';
  const address='tb1q'+'q'.repeat(38),block='2'.repeat(64);let asked=[];
  globalThis.fetch=async input=>{
    const url=String(input);asked.push(url);assert.ok(url.startsWith('https://blockstream.info/testnet4/api/'));
    if(url.endsWith('/block-height/0'))return new Response(genesis);
    if(url.endsWith('/blocks/tip/height'))return new Response('100');
    if(url.endsWith('/address/'+address+'/utxo'))return Response.json([
      {txid:'1'.repeat(64),vout:1,value:500,status:{confirmed:true,block_height:99,block_hash:block}},
      {txid:'3'.repeat(64),vout:0,value:9000,status:{confirmed:false}},
      {txid:'4'.repeat(64),vout:0,value:7000,status:{confirmed:true,block_height:90,block_hash:block}}]);
    throw Error('unexpected provider request');
  };
  try{
    const [status,body]=await call('/bitcoin-testnet4/utxos?address='+address);
    assert.equal(status,200);assert.deepEqual(body.utxos.map(u=>[u.amount_sats,u.confirmations]),[[7000,11],[500,2]],'unconfirmed outputs are left out, largest first');
    for(const bad of ['bc1q'+'q'.repeat(38),'tb1p'+'q'.repeat(58),address.toUpperCase(),address+'x','../tx'])assert.equal((await call('/bitcoin-testnet4/utxos?address='+encodeURIComponent(bad)))[0],400,bad);
    assert.equal((await call('/bitcoin-testnet4/utxos?address='+address+'&x=1'))[0],400);
    asked=[];assert.equal((await call('/bitcoin-testnet4/utxos?address=tb1q'))[0],400);assert.equal(asked.length,0,'bad input never reaches the provider');
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Bitcoin testnet broadcast forwards one hex transaction and reports rejection separately from outage',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,tx='02'+'ab'.repeat(100),txid='5'.repeat(64);let mode='ok',sent=[];
  globalThis.fetch=async(input,init)=>{
    assert.equal(String(input),'https://blockstream.info/testnet4/api/tx');assert.equal(init.method,'POST');sent.push(init.body);
    if(mode==='ok')return new Response(txid);
    if(mode==='rejected')return new Response('sendrawtransaction RPC error code -26\u0000: bad-txns-inputs-missingorspent',{status:400});
    if(mode==='garbage')return new Response('<html>',{status:200});
    return new Response('down',{status:503});
  };
  try{
    assert.deepEqual(await call('/bitcoin-testnet4/broadcast',{method:'POST',data:{tx}}),[200,{txid}]);assert.deepEqual(sent,[tx]);
    mode='rejected';const [status,body]=await call('/bitcoin-testnet4/broadcast',{method:'POST',data:{tx}});
    assert.equal(status,400);assert.match(body.reason,/inputs-missingorspent/);assert.doesNotMatch(body.reason,/\u0000/);
    for(const m of ['garbage','down']){mode=m;assert.equal((await call('/bitcoin-testnet4/broadcast',{method:'POST',data:{tx}}))[0],502,m);}
    sent=[];mode='ok';
    for(const data of [{tx:'zz'},{tx:'ab'},{tx:tx.toUpperCase()},{tx,extra:1},{tx:'ab'.repeat(9000)},{}])assert.equal((await call('/bitcoin-testnet4/broadcast',{method:'POST',data}))[0],400);
    assert.equal(sent.length,0,'malformed bodies never reach the provider');
    assert.equal((await call('/bitcoin-testnet4/broadcast'))[0],404,'GET is not a broadcast');
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Bitcoin spend lookup returns the witness of the spending input, checks it spends the asked output and reports depth',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,txid='1'.repeat(64),spender='6'.repeat(64),block='2'.repeat(64),genesis='00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';
  const state={spent:true,confirmed:true,vinTxid:txid,witness:['aa','bb'.repeat(32),'01','cc']};
  globalThis.fetch=async input=>{
    const url=String(input);
    if(url.endsWith('/block-height/0'))return new Response(genesis);
    if(url.endsWith('/blocks/tip/height'))return new Response('100');
    if(url.endsWith('/block-height/99'))return new Response(block);
    if(url.endsWith('/tx/'+txid+'/outspend/1'))return Response.json(state.spent?{spent:true,txid:spender,vin:0,status:{confirmed:state.confirmed}}:{spent:false});
    if(url.endsWith('/tx/'+txid))return Response.json({txid,status:{confirmed:true,block_height:90,block_hash:block},vout:[{value:1},{value:2}]});
    if(url.endsWith('/tx/'+spender))return Response.json({txid:spender,status:state.confirmed?{confirmed:true,block_height:99,block_hash:block}:{confirmed:false},vin:[{txid:state.vinTxid,vout:1,witness:state.witness}]});
    throw Error('unexpected provider request '+url);
  };
  try{
    let [status,body]=await call('/bitcoin-testnet4/spend?txid='+txid+'&vout=1');
    assert.equal(status,200);assert.equal(body.spent,true);assert.equal(body.spend.txid,spender);assert.equal(body.spend.confirmations,2);assert.deepEqual(body.spend.witness,state.witness);
    state.confirmed=false;[status,body]=await call('/bitcoin-testnet4/spend?txid='+txid+'&vout=1');
    assert.equal(body.spend.confirmed,false);assert.equal(body.spend.confirmations,0);assert.equal(body.spend.witness.length,4,'a mempool spend still reveals the witness');
    state.spent=false;[status,body]=await call('/bitcoin-testnet4/spend?txid='+txid+'&vout=1');assert.deepEqual([status,body.spent],[200,false]);
    state.spent=true;state.vinTxid='7'.repeat(64);assert.equal((await call('/bitcoin-testnet4/spend?txid='+txid+'&vout=1'))[0],502,'a spend of some other output is refused');
    state.vinTxid=txid;state.witness=['zz'];assert.equal((await call('/bitcoin-testnet4/spend?txid='+txid+'&vout=1'))[0],502,'non-hex witness data is refused');
    for(const bad of ['?txid=zz&vout=1','?txid='+txid+'&vout=-1','?txid='+txid+'&vout=1&x=1'])assert.equal((await call('/bitcoin-testnet4/spend'+bad))[0],400);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Sepolia escrow events come from the RPC with a matching receipt, fall back to Blockscout, and never trust a disagreeing receipt',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,contract='0x'+'ab'.repeat(20),tx='0x'+'cd'.repeat(32),blockHash='0x'+'ef'.repeat(32);
  const claimed='0x0508a8b4117d9a7b3d8f5895f6413e61b4f9a2df35afbfb41e78d0ecfff1843f',data='0x'+'11'.repeat(32)+'00'.repeat(12)+'22'.repeat(20)+'00'.repeat(31)+'01';
  const log={address:contract,topics:[claimed],data,blockNumber:'0x5a',blockHash,transactionHash:tx};
  const state={code:'0x6001',spent:'0x'+'0'.repeat(63)+'1',logsFail:false,receiptStatus:'0x1',receiptBlockHash:blockHash,chain:'0xaa36a7'};
  globalThis.fetch=async(input,init)=>{
    const url=String(input);
    if(url.startsWith('https://eth-sepolia.blockscout.com/api/v2/addresses/'))return Response.json({items:[{address:{hash:contract},topics:[claimed],data,block_number:90,transaction_hash:tx}]});
    assert.equal(url,'https://ethereum-sepolia-rpc.publicnode.com');
    const {method,params}=JSON.parse(init.body),answer=result=>Response.json({jsonrpc:'2.0',id:1,result});
    if(method==='eth_chainId')return answer(state.chain);
    if(method==='eth_blockNumber')return answer(state.tip??'0x64');
    if(method==='eth_getCode')return answer(state.code);
    if(method==='eth_call')return answer(state.spent);
    if(method==='eth_getLogs'){if(state.logsFail)return Response.json({jsonrpc:'2.0',id:1,error:{code:-32000,message:'range'}});if(state.windows){state.windows.push(params[0]);return answer(state.windows.length===1?[log]:[]);}return answer([log]);}
    if(method==='eth_getTransactionReceipt')return answer({status:state.receiptStatus,blockHash:state.receiptBlockHash,blockNumber:'0x5a',logs:[log]});
    throw Error('unexpected method '+method);
  };
  try{
    const path='/sepolia/escrow-events?contract='+contract+'&from_block=80';
    let [status,body]=await call(path);
    assert.equal(status,200);assert.equal(body.source,'rpc');assert.equal(body.spent,true);assert.equal(body.events[0].kind,'claimed');assert.equal(body.events[0].confirmations,11);assert.equal(body.events[0].data,data);
    state.tip='0x'+(3_200_000).toString(16);state.windows=[];
    [status,body]=await call('/sepolia/escrow-events?contract='+contract);
    assert.equal(status,200);assert.equal(body.source,'rpc');
    assert.equal(body.scanned_from,3_200_000-360_000+1,'an unbounded request is limited to the recent scan range');
    assert.equal(state.windows.length,8);
    for(const w of state.windows)assert.ok(parseInt(w.toBlock,16)-parseInt(w.fromBlock,16)+1<=45000,'every provider request stays inside the public range cap');
    assert.equal(parseInt(state.windows.at(-1).toBlock,16),3_200_000,'the scan ends at the tip');
    assert.equal(state.windows.every((w,i)=>i===0||parseInt(w.fromBlock,16)===parseInt(state.windows[i-1].toBlock,16)+1),true,'windows are contiguous');
    state.windows.length=0;[status,body]=await call('/sepolia/escrow-events?contract='+contract+'&from_block=3199990');
    assert.equal(state.windows.length,1);assert.equal(body.scanned_from,3_199_990,'a deployment block narrows the scan');
    state.tip=undefined;state.windows=undefined;
    state.logsFail=true;[status,body]=await call(path);assert.equal(body.source,'blockscout');assert.equal(body.events[0].tx_hash,tx);assert.equal(body.events[0].confirmations,11);
    state.logsFail=false;state.receiptStatus='0x0';assert.equal((await call(path))[0],502,'a failed or disagreeing receipt is refused');state.receiptStatus='0x1';
    state.receiptBlockHash='0x'+'12'.repeat(32);assert.equal((await call(path))[0],502,'a receipt from another block is refused');state.receiptBlockHash=blockHash;
    state.spent='0x'+'0'.repeat(64);[status,body]=await call(path);assert.equal(body.spent,false,'the contract flag is reported separately from events');
    state.code='0x';[status,body]=await call(path);assert.equal(body.deployed,false);state.code='0x6001';
    state.chain='0x1';assert.equal((await call(path))[0],502,'a provider on another network is refused');state.chain='0xaa36a7';
    for(const bad of ['?contract=0xAB','?contract='+contract+'&from_block=-1','?contract='+contract+'&x=1','?from_block=1'])assert.equal((await call('/sepolia/escrow-events'+bad))[0],400);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Cardano preview spend lookup separates unspent, not yet indexed and a decoded-ready claim',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,txid='3'.repeat(64),spender='4'.repeat(64),ref=txid+'#0',script='addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv';
  const state={spent:true,address:script,addressTxs:[{tx_hash:txid},{tx_hash:spender}],info:[{tx_hash:spender,block_height:95,inputs:[{tx_hash:txid,tx_index:0}]}],cbor:[{tx_hash:spender,valid_contract:true,cbor:'84a0a0f5f6'}]};
  globalThis.fetch=async(input,init)=>{
    const url=String(input),post=init?.body?JSON.parse(init.body):null;
    if(url.endsWith('/genesis'))return Response.json([{networkmagic:'2',networkid:'Testnet',systemstart:1666656000}]);
    if(url.endsWith('/tip'))return Response.json([{abs_slot:5000,block_no:100,epoch_no:10}]);
    if(url.endsWith('/utxo_info'))return Response.json([{tx_hash:txid,tx_index:0,address:state.address,is_spent:state.spent,block_height:90,value:'1',asset_list:[]}]);
    if(url.endsWith('/address_txs'))return Response.json(state.addressTxs);
    if(url.endsWith('/tx_info'))return Response.json(state.info);
    if(url.endsWith('/tx_cbor'))return Response.json(state.cbor);
    throw Error('unexpected provider request '+url+JSON.stringify(post));
  };
  try{
    const path='/cardano-preview/spend?outref='+encodeURIComponent(ref);
    let [status,body]=await call(path);
    assert.equal(status,200);assert.deepEqual([body.spent,body.indexed,body.spender,body.confirmations,body.cbor],[true,true,spender,6,'84a0a0f5f6']);
    state.cbor=[];[status,body]=await call(path);assert.deepEqual([body.spent,body.indexed,body.spender,body.cbor],[true,false,spender,undefined],'empty tx_cbor for a spent output is pending, not a verdict');
    state.info=[];[status,body]=await call(path);assert.equal(body.indexed,false,'a lagging tx_info is pending');
    state.addressTxs=[{tx_hash:txid}];[status,body]=await call(path);assert.equal(body.indexed,false);
    state.cbor=[{tx_hash:spender,valid_contract:true,cbor:'84a0a0f5f6'}];
    const other='5'.repeat(64);state.addressTxs=[{tx_hash:txid},{tx_hash:spender},{tx_hash:other}];
    state.info=[{tx_hash:spender,inputs:[{tx_hash:txid,tx_index:0}]}];[status,body]=await call(path);assert.equal(body.indexed,false,'a lagging backend that omits a candidate never yields a verdict');
    state.info=[{tx_hash:spender,inputs:[{tx_hash:txid,tx_index:0}]},{tx_hash:'8'.repeat(64),inputs:[]}];[status,body]=await call(path);assert.equal(body.indexed,false,'rows for transactions that were not asked about are not trusted');
    state.addressTxs=[{tx_hash:txid},{tx_hash:spender}];state.info=[{tx_hash:spender,inputs:[{tx_hash:'9'.repeat(64),tx_index:0}]}];[status,body]=await call(path);assert.equal(body.indexed,false,'a candidate that does not spend the output is not the spender');
    state.info=[{tx_hash:spender,inputs:[{tx_hash:txid,tx_index:0}]}];state.cbor=[{tx_hash:spender,valid_contract:false,cbor:'84'}];assert.equal((await call(path))[0],502,'a phase-2 invalid transaction is not a claim');
    state.cbor=[{tx_hash:spender,valid_contract:true,cbor:'84a0a0f5f6'}];state.spent=false;[status,body]=await call(path);assert.deepEqual([status,body.spent],[200,false]);
    state.address='addr_test1other';assert.equal((await call(path))[0],400,'only the pinned HTLC address is served');
    for(const bad of ['?outref=zz','?outref='+ref+'&x=1','?outref='+txid+'%235000000000'])assert.equal((await call('/cardano-preview/spend'+bad))[0],400);
  }finally{globalThis.fetch=original;db.raw.close();}
});

test('Sepolia read proxy forwards only fixed read methods with strict parameters, and Bitcoin head returns the fixed network tip',async()=>{
  const db=database(),call=client(db),original=globalThis.fetch,contract='0x'+'ab'.repeat(20),genesis='00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';let sent=[],chain='0xaa36a7';
  globalThis.fetch=async(input,init)=>{
    const url=String(input);
    if(url.endsWith('/block-height/0'))return new Response(genesis);
    if(url.endsWith('/blocks/tip/height'))return new Response('321');
    assert.equal(url,'https://ethereum-sepolia-rpc.publicnode.com');
    const {method,params}=JSON.parse(init.body);sent.push(method);
    return Response.json({jsonrpc:'2.0',id:1,result:method==='eth_chainId'?chain:'0x1234'});
  };
  try{
    assert.deepEqual(await call('/sepolia/rpc',{method:'POST',data:{method:'eth_getCode',params:[contract,'latest']}}),[200,{result:'0x1234'}]);
    for(const good of [{method:'eth_blockNumber',params:[]},{method:'eth_getBlockByNumber',params:['0x10',false]},{method:'eth_getTransactionReceipt',params:['0x'+'cd'.repeat(32)]},{method:'eth_call',params:[{to:contract,data:'0x7ab71b7a'},'0x10']},{method:'eth_getBalance',params:[contract,'latest']}])assert.equal((await call('/sepolia/rpc',{method:'POST',data:good}))[0],200,good.method);
    sent=[];
    for(const bad of [{method:'eth_sendRawTransaction',params:['0x00']},{method:'eth_accounts',params:[]},{method:'eth_getBlockByNumber',params:['0x10',true]},{method:'eth_getCode',params:['0xAB','latest']},{method:'eth_getCode',params:[contract,'pending']},
      {method:'eth_call',params:[{to:contract,data:'0xa9059cbb'},'latest']},{method:'eth_call',params:[{to:contract,data:'0x7ab71b7a',from:contract},'latest']},{method:'eth_getLogs',params:[{}]},{method:'__proto__',params:[]},{method:'eth_blockNumber',params:[],extra:1},{method:'eth_blockNumber'}])assert.equal((await call('/sepolia/rpc',{method:'POST',data:bad}))[0],400,JSON.stringify(bad));
    assert.deepEqual(sent,[],'refused requests never reach the provider');
    chain='0x1';assert.equal((await call('/sepolia/rpc',{method:'POST',data:{method:'eth_chainId',params:[]}}))[0],502,'a provider on another network is refused');
    assert.equal((await call('/sepolia/rpc'))[0],404);
    assert.deepEqual(await call('/bitcoin-testnet4/head'),[200,{genesis,tip:321}]);assert.equal((await call('/bitcoin-testnet4/head?x=1'))[0],400);
  }finally{globalThis.fetch=original;db.raw.close();}
});
