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
