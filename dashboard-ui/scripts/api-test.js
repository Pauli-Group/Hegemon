/**
 * Hegemon API Connection Test
 * 
 * This script validates that @polkadot/api can connect to a local Hegemon node
 * using the custom types bundle. Run with a dev node active:
 * 
 *   HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
 * 
 * Then:
 *   cd dashboard-ui/scripts
 *   npm install @polkadot/api
 *   node api-test.js
 */

const { ApiPromise, WsProvider } = require('@polkadot/api');

// Custom types bundle from docs/POLKADOTJS_BINDINGS.md
const typesBundle = {
  spec: {
    'synthetic-hegemonic': {
      types: [
        {
          minmax: [0, undefined],
          types: {
            StarkHashFunction: { _enum: ['Blake3', 'Sha3'] },
            StarkVerifierParams: {
              hash: 'StarkHashFunction',
              fri_queries: 'u16',
              blowup_factor: 'u8',
              security_bits: 'u16'
            },
            NettingKind: { _enum: ['Bilateral', 'Multilateral'] },
            Leg: { from: 'AccountId', to: 'AccountId', asset: 'u32', amount: 'u128' },
            Instruction: {
              id: 'u64',
              legs: 'Vec<Leg>',
              netting: 'NettingKind',
              memo: 'Bytes',
              submitted_at: 'u64'
            },
            BatchCommitment: {
              id: 'u64',
              instructions: 'Vec<u64>',
              commitment: 'H256',
              nullifiers: 'Vec<H256>',
              proof: 'Bytes',
              submitted_by: 'AccountId',
              disputed: 'bool'
            },
            SubmissionRules: { min_interval: 'u64', max_size: 'u32' },
            CommitmentRecord: {
              commitment: 'Bytes',
              attestation: 'Option<u32>',
              submitted_by: 'AccountId',
              submitted_at: 'u64'
            },
            FeedDetails: {
              owner: 'AccountId',
              name: 'Bytes',
              endpoint: 'Bytes',
              rules: 'SubmissionRules',
              latest_commitment: 'Option<CommitmentRecord>',
              last_ingestion: 'u64'
            }
          }
        }
      ]
    }
  }
};

async function main() {
  console.log('Connecting to Hegemon node at ws://127.0.0.1:9944...');
  
  const provider = new WsProvider('ws://127.0.0.1:9944');
  const api = await ApiPromise.create({ provider, typesBundle });

  // Chain info
  const chain = await api.rpc.system.chain();
  const props = await api.rpc.system.properties();
  const version = await api.rpc.system.version();
  
  console.log('\n=== Chain Info ===');
  console.log(`Chain: ${chain}`);
  console.log(`Version: ${version}`);
  console.log(`Token: ${props.tokenSymbol.unwrapOr('UNIT')}`);
  console.log(`Decimals: ${props.tokenDecimals.unwrapOr(12)}`);

  // Check available pallets
  console.log('\n=== Available Pallets ===');
  const pallets = Object.keys(api.query).sort();
  console.log(pallets.join(', '));

  // Check if shieldedPool pallet exists
  if (api.query.shieldedPool) {
    console.log('\n=== Shielded Pool Storage ===');
    const storageItems = Object.keys(api.query.shieldedPool);
    console.log('Storage items:', storageItems.join(', '));
  } else {
    console.log('\n⚠️  shieldedPool pallet not found in api.query');
  }

  // Check difficulty pallet
  if (api.query.difficulty) {
    console.log('\n=== Difficulty Pallet Storage ===');
    const storageItems = Object.keys(api.query.difficulty);
    console.log('Storage items:', storageItems.join(', '));
  }

  // Check coinbase pallet
  if (api.query.coinbase) {
    console.log('\n=== Coinbase Pallet Storage ===');
    const storageItems = Object.keys(api.query.coinbase);
    console.log('Storage items:', storageItems.join(', '));
  }

  // Subscribe to new blocks
  console.log('\n=== Subscribing to blocks (Ctrl+C to exit) ===');
  let blockCount = 0;
  
  const unsubHeads = await api.rpc.chain.subscribeNewHeads((header) => {
    console.log(`\nBlock #${header.number} | Hash: ${header.hash.toHex().slice(0, 18)}...`);
    blockCount++;
  }).catch(() => {
    // Fallback for newer API versions
    return api.derive.chain.subscribeNewHeads((header) => {
      console.log(`\nBlock #${header.number} | Hash: ${header.hash.toHex().slice(0, 18)}...`);
      blockCount++;
    });
  });

  // Subscribe to events
  const unsubEvents = await api.query.system.events((events) => {
    events.forEach(({ event, phase }) => {
      const section = event.section;
      const method = event.method;
      
      // Highlight shielded pool and mining-related events
      if (section === 'shieldedPool' || section === 'coinbase' || section === 'difficulty') {
        console.log(`  📢 ${section}.${method}`);
        
        // Log event data for debugging
        if (event.data.length > 0) {
          event.data.forEach((data, idx) => {
            const val = data.toString();
            if (val.length > 40) {
              console.log(`     [${idx}]: ${val.slice(0, 40)}...`);
            } else {
              console.log(`     [${idx}]: ${val}`);
            }
          });
        }
      }
    });
  });

  // Keep running for 30 seconds or until 5 blocks
  await new Promise((resolve) => {
    const checkDone = setInterval(() => {
      if (blockCount >= 5) {
        clearInterval(checkDone);
        resolve();
      }
    }, 1000);
    
    // Timeout after 60 seconds
    setTimeout(() => {
      clearInterval(checkDone);
      resolve();
    }, 60000);
  });

  console.log('\n=== Test Complete ===');
  console.log(`Observed ${blockCount} blocks`);
  
  unsubHeads();
  unsubEvents();
  await api.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
