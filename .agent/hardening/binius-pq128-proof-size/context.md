# Context: strict-PQ transaction proof size

## Objective

Minimize canonical proof bytes while preserving private transactions and a composed post-quantum security floor of at least 128 bits.

## Fixed constraints

- Fresh transaction semantics use BLAKE2b-384; Poseidon is legacy/research-only.
- A current full inline action is 128,992 bytes, including a 124,022-byte proof artifact.
- Keeping 520 actions under the 64 MiB block cap permits at most 124,080 artifact bytes per action.
- Every canonical transaction must carry its own zero-knowledge proof unchanged through relay and replay.
- Consensus must independently validate blocks; mempool admission is not authority.
- No security parameter may be justified by upstream marketing labels alone.

## Evidence

Pinned upstream Binius64 commit: `3f96163049f680b2909f6545690bd929f1b48c44`.

Measured best raw transcript sizes at the upstream 96-bit query-only/SHA-256 profile:

| BLAKE2b compressions | Wrapped Binius ZK | Direct IronSpartan |
|---:|---:|---:|
| 1 | 298,304 | 246,048 |
| 8 | 309,664 | 327,984 |
| 64 | 321,120 | 414,752 |

Current Binius64 cannot make a composed PQ128 claim: its query target is 96, its Merkle/Fiat-Shamir outputs are 256 bits, and its challenge field is GF(2^128). The exact FRI source states that the query target excludes folding and other protocol errors.

Current Flock is not a qualifying direct backend: it is non-zero-knowledge, its profiles target 100 or 120 bits, and it has no Hegemon transaction relation.

## Rejected boundary

Moving leaf proofs to a local cache and making an aggregate consensus authority violates Hegemon's self-contained proof-carrying transaction invariant. The proposed one-MiB aggregate was never measured, current Binius64 has no production recursive verifier for it, and 520 measured weak-profile leaf proofs already impose roughly 148-159 MiB per relay copy.

## Binding outcome

Require one standalone canonical proof artifact at or below 124,080 bytes with composed PQ128 security. Aggregation may only be a local verification optimization that preserves every transaction proof and exact accept/reject semantics.
