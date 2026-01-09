const { ApiPromise, WsProvider } = require('@polkadot/api');

async function main() {
  const api = await ApiPromise.create({ provider: new WsProvider('ws://127.0.0.1:9944') });
  
  // Get raw pool balance
  const poolBal = await api.query.shieldedPool.poolBalance();
  console.log('Raw poolBalance:', poolBal.toString());
  console.log('In HGM (/ 10^12):', Number(BigInt(poolBal.toString())) / 1e12);
  console.log('In HGM (/ 10^8):', Number(BigInt(poolBal.toString())) / 1e8);
  
  // Get commitment count
  const commitIdx = await api.query.shieldedPool.commitmentIndex();
  console.log('Commitment index:', commitIdx.toString());
  
  // Get current block
  const header = await api.rpc.chain.getHeader();
  console.log('Current block:', header.number.toNumber());
  
  // Calculate expected supply based on ~5 HGM per block
  const INITIAL_REWARD = 498287671; // ~4.98 HGM in raw units
  const blocks = header.number.toNumber();
  console.log('\nExpected supply (blocks * INITIAL_REWARD):', blocks * INITIAL_REWARD);
  console.log('Expected in HGM:', (blocks * INITIAL_REWARD) / 1e8);
  
  // Check decimals config
  const decimals = api.registry.chainDecimals;
  const tokens = api.registry.chainTokens;
  console.log('\nChain decimals:', decimals);
  console.log('Chain tokens:', tokens);
  
  await api.disconnect();
}
main().catch(console.error);
