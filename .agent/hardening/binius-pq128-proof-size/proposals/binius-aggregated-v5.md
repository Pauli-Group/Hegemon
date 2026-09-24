# REJECTED proposal: Binius aggregated V5

This proposal is retained only as falsification evidence. Its one-MiB aggregate was an unmeasured allowance, not a proof result; current Binius64 exposes no production recursive verifier establishing the claimed composition; and moving leaf proofs off canonical blocks violates Hegemon's self-contained proof-carrying transaction invariant while imposing roughly 148-159 MiB of measured weak-profile proof traffic for 520 actions. It must not be implemented as consensus authority.

## Security property

Every canonical nonempty shielded block has one proof that the exact ordered actions each possess an accepted zero-knowledge leaf proof and that their public outputs produce the advertised canonical state transition. No active Poseidon relation or block-producer trust is required.

## Architecture

1. Wallet derives the 559-byte canonical statement and generates `BiniusLeafProofV5`.
2. RPC/relay transports the action and a separately bounded content-addressed proof blob.
3. Admission reconstructs the statement, verifies the leaf proof, and caches exact proof/profile/statement equality.
4. Miner orders accepted actions and proves a batch verifier circuit over their leaf proofs.
5. Canonical block contains proof-free actions and `BiniusBlockAggregateV5`.
6. Validator reconstructs ordered statements from block actions and verifies the aggregate once.

## Byte strategy

- Personalized fixed-width BLAKE2b cuts the universal relation from 158 to 85 compressions.
- Canonical block actions omit the entire leaf proof and obsolete 6,080-byte wrapper.
- Same-stage oracle columns share one row-wise commitment/multiproof where transcript ordering permits.
- Binary Merkle multiproofs are retained; measured 4-ary and 8-ary layouts are larger.
- Aggregate has one block-level public binding, not one redundant binding per action.

## Security strategy

- Typed BLAKE2b-384 semantic values.
- BLAKE2b-512 proof commitments and Fiat-Shamir transcript.
- GF(2^384) challenges.
- Complete soundness/QROM calculator; 259 classical query bits is the starting point, never release authority by itself.
- Canonical codec and exact decode before heavy work.
- Formal proof that the non-ZK aggregate witness contains leaf-proof bytes only.

## Work packages

1. Byte-native BLAKE2b relation, reference implementation, and mutation vectors.
2. Strict Binius primitives, proof codec, size tracker, and security calculator.
3. Leaf prover/verifier and separate pending-proof blob transport.
4. Homogeneous leaf-verifier aggregation and ordered state binding.
5. Proof-free V5 block, storage, sync, reorg, RPC, wallet, and light-client integration.
6. Formal/QROM/external review and fresh-genesis activation.

## Kill gates

- Leaf proof hard cap: 1.5 MiB; target: 1 MiB.
- 520-action aggregate hard cap: 1 MiB.
- 520-action aggregate prove p95: 30 seconds.
- Aggregate verify p95: 500 ms.
- Leaf verify p95: 250 ms.
- Concrete composed post-quantum security: at least 128 bits.
- Canonical block leaf-proof bytes: exactly zero.
- Maximum conservative 520-action block: 3,633,941 bytes.

Failure of any gate keeps transfers disabled; it does not authorize Poseidon or a weaker profile.
