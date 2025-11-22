import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';

const typesBundle = {
  spec: {
    'synthetic-hegemonic': {
      types: [
        {
          minmax: [0, undefined],
          types: {
            StarkHashFunction: { _enum: ['Blake3', 'Sha3'] },
            NettingKind: { _enum: ['Bilateral', 'Multilateral'] },
            Leg: { from: 'AccountId', to: 'AccountId', asset: 'u32', amount: 'u128' },
          }
        }
      ]
    }
  }
};

async function main() {
  const provider = new WsProvider(process.env.WS || 'ws://127.0.0.1:9944');
  const api = await ApiPromise.create({ provider, typesBundle });
  const keyring = new Keyring({ type: 'sr25519' });
  const submitter = keyring.addFromUri('//Alice');

  console.log('Connected to', await api.rpc.system.chain());

  const leg = api.createType('Leg', {
    from: submitter.address,
    to: submitter.address,
    asset: 0,
    amount: 1_000_000_000_000n,
  });

  const instructionTx = api.tx.settlement.submitInstruction([leg], 'Bilateral', []);
  const instructionHash = await instructionTx.signAndSend(submitter);
  console.log('Queued instruction hash', instructionHash.toString());

  // Wait a couple of blocks for the off-chain worker to pick up the queue.
  await api.rpc.engine.createBlock(true, true);
  await api.rpc.engine.createBlock(true, true);

  const pending = await api.query.settlement.pendingQueue();
  console.log('Pending queue after OCW tick', pending.toHuman());

  if (pending.length) {
    // The unsigned submission path is permitted when payload matches PendingQueue.
    const batchCall = api.tx.settlement.submitBatch(
      pending,
      api.createType('Hash', '0x' + '00'.repeat(32)),
      [],
      [api.createType('Hash', '0x' + '11'.repeat(32))],
      0
    );
    const batchHash = await batchCall.send();
    console.log('Submitted unsigned batch', batchHash.toString());
  }

  api.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
