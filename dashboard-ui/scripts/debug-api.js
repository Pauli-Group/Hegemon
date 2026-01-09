const { ApiPromise, WsProvider } = require('@polkadot/api');

async function main() {
  const provider = new WsProvider('ws://127.0.0.1:9944');
  const api = await ApiPromise.create({ provider });

  // Get current block
  const header = await api.rpc.chain.getHeader();
  console.log('Current block:', header.number.toNumber());

  // Get difficulty
  const diff = await api.query.difficulty.difficulty();
  console.log('Difficulty:', diff.toString());

  // Get pool balance
  const poolBal = await api.query.shieldedPool.poolBalance();
  console.log('Pool balance:', poolBal.toString());

  // Get commitment index
  const idx = await api.query.shieldedPool.commitmentIndex();
  console.log('Commitment index:', idx.toString());

  // Get total issuance
  const issuance = await api.query.balances.totalIssuance();
  console.log('Total issuance:', issuance.toString());

  // Subscribe to blocks using derive
  console.log('\nTesting block subscription...');
  const unsub = await api.derive.chain.subscribeNewHeads((header) => {
    console.log('New block via derive:', header.number.toNumber());
    unsub();
    api.disconnect();
  });
}

main().catch(console.error);
