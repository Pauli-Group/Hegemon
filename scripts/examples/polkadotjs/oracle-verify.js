import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';

const typesBundle = {
  spec: {
    'synthetic-hegemonic': {
      types: [
        {
          minmax: [0, undefined],
          types: {
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
  const provider = new WsProvider(process.env.WS || 'ws://127.0.0.1:9944');
  const api = await ApiPromise.create({ provider, typesBundle });
  const keyring = new Keyring({ type: 'sr25519' });
  const registrar = keyring.addFromUri('//Alice');
  const verifier = keyring.addFromUri('//Bob');

  console.log('Connected to', await api.rpc.system.chain());

  const feedId = 100;
  const rules = api.createType('SubmissionRules', { min_interval: 1, max_size: 64 });
  const name = api.createType('Bytes', 'demo-feed');
  const endpoint = api.createType('Bytes', 'https://example.com');

  // Register feed as root/registrar for demo purposes.
  await api.tx.oracles.registerFeed(feedId, name, endpoint, rules).signAndSend(registrar);

  const commitment = api.createType('Bytes', '0x1234');
  await api.tx.oracles.submitCommitment(feedId, commitment, null).signAndSend(registrar);

  // Signed verification path.
  const verificationHash = await api.tx.oracles.verifySubmission(feedId, commitment).signAndSend(verifier);
  console.log('Signed verification sent', verificationHash.toString());

  // Unsigned verification path (allowed while feed is pending ingestion in the queue).
  const unsignedHash = await api.tx.oracles.verifySubmission(feedId, commitment).send();
  console.log('Unsigned verification sent', unsignedHash.toString());

  api.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
