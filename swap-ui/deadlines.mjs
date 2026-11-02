/** Pure local deadline-watch logic. A head is trusted only after the caller
 * queries the configured local provider; it is not a proof of finality. */
const chains=new Set(['bitcoin','cardano','ethereum','hegemon']);
function decimal(value){
 if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>=1n<<64n)throw Error('invalid deadline integer');
 return BigInt(value);
}
export function validateWatch(value){
 if(!value||typeof value!=='object'||!chains.has(value.chain)||typeof value.label!=='string'||!value.label.trim()||value.label.length>80||/[\u0000-\u001f\u007f]/.test(value.label))throw Error('invalid watch label or chain');
 if(typeof value.genesis!=='string'||!/^[0-9a-f]{64}$/.test(value.genesis))throw Error('invalid genesis hash');
 if(decimal(value.deadline)===0n||decimal(value.warning)===0n)throw Error('deadline and warning must be positive');
 return {chain:value.chain,label:value.label.trim(),genesis:value.genesis,deadline:value.deadline,warning:value.warning};
}
export function evaluateWatch(value,head){
 const watch=validateWatch(value);
 if(!head||head.genesis!==watch.genesis)throw Error('connected node has a different genesis');
 const current=decimal(head.current),remaining=decimal(watch.deadline)-current;
 return {state:remaining<=0n?'expired':remaining<=decimal(watch.warning)?'near':'watching',current:current.toString(),remaining:(remaining>0n?remaining:0n).toString()};
}
