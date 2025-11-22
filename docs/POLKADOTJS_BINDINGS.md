# Polkadot.js bindings for SHC pallets

The custom pallets expose SCALE types that Polkadot.js does not know about by default. Use the snippets below to register the types bundle before constructing an API instance:

```ts
import { ApiPromise, WsProvider } from '@polkadot/api';

const provider = new WsProvider('ws://127.0.0.1:9944');
const api = await ApiPromise.create({
  provider,
  typesBundle: {
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
  }
});
```

## Settlement pallet calls and events

* **submitInstruction(legs, netting, memo)** — queues a settlement instruction. The off-chain worker batches the queue and submits **submitBatch** as either a signed or unsigned transaction when local keys are unavailable.
* **submitBatch(instructions, commitment, proof, nullifiers, key)** — finalizes a batch. Unsigned calls are accepted only when the payload matches the pending instruction queue.
* **Events**
  * `InstructionQueued { id, who, netting }`
  * `BatchSubmitted { id, who }`
  * `NullifierConsumed { nullifier }`

## Oracle pallet calls and events

* **submitCommitment(feedId, commitment, attestation?)** — feed submitters provide commitments respecting the configured submission rules.
* **verifySubmission(feedId, expectedCommitment)** — feed verifiers may sign this call, and the off-chain worker also dispatches it as an unsigned transaction when a feed is scheduled for ingestion. Successful verification drains the pending ingestion queue.
* **Events**
  * `CommitmentSubmitted { feed_id, submitter, attestation }`
  * `SubmissionVerified { feed_id, verifier }`
  * `IngestionDispatched { feed_id }`

## Sample scripts

Example end-to-end flows are available in `scripts/examples/polkadotjs`:

* `settlement-submit.js` demonstrates submitting an instruction and forcing the off-chain worker to batch it (signed path) with fallback to unsigned batch submission when no local signer exists.
* `oracle-verify.js` shows how a feed verifier can sign `verifySubmission` and how a validator can submit the same call unsigned while the feed sits in `PendingIngestions`.

Run the scripts with Node 18+ after installing `@polkadot/api`:

```bash
npm install @polkadot/api
node scripts/examples/polkadotjs/settlement-submit.js
node scripts/examples/polkadotjs/oracle-verify.js
```
