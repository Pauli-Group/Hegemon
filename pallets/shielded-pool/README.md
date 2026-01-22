# Shielded Pool Pallet

Post-quantum secure shielded transactions on Substrate.

## Overview

This pallet implements shielded transactions using **STARK proofs**.
All cryptographic operations are **post-quantum secure** using hash-based and lattice-based primitives.

## Key Components

| Component | Implementation | PQC Status |
|-----------|---------------|------------|
| Note Commitments | Poseidon hash over Goldilocks field | ✅ Hash-based |
| Nullifiers | PRF with Poseidon | ✅ Hash-based |
| Merkle Tree | Poseidon-based incremental tree | ✅ Hash-based |
| ZK Proofs | STARK (FRI-based IOP) | ✅ Transparent, no trusted setup |
| Value Balance | Verified in-circuit | ✅ Binding hash only |
| Key Encapsulation | ML-KEM (placeholder) | ✅ Lattice-based |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Shielded Transfer                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ StarkProof  │  │ Nullifiers  │  │ Note Commitments    │ │
│  │ (Vec<u8>)   │  │ ([u8;32])   │  │ ([u8;32])           │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Merkle Tree (CompactMerkleTree)            ││
│  │   - Poseidon hash function                              ││
│  │   - Incremental append with frontier                    ││
│  │   - O(log n) witness generation                        ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Modules

- **`types.rs`** - Core data structures (`StarkProof`, `Note`, `EncryptedNote`)
- **`commitment.rs`** - Note commitment scheme using Poseidon hash
- **`nullifier.rs`** - Nullifier derivation and tracking
- **`merkle.rs`** - Compact incremental Merkle tree
- **`verifier.rs`** - STARK proof verification abstraction

## Extrinsics

### `shielded_transfer(proof, nullifiers, commitments, ciphertexts, anchor, binding_hash, stablecoin, fee, value_balance)`
Execute a private transfer inside the shielded pool. `stablecoin` is optional and only used for issuance proofs; `value_balance` must be 0 (no transparent pool).

### `shielded_transfer_unsigned(proof, nullifiers, commitments, ciphertexts, anchor, binding_hash, stablecoin, fee)`
Execute an unsigned shielded-to-shielded transfer; `stablecoin` must be `None` and `value_balance` is fixed to 0.

### `shielded_transfer_sidecar(proof, nullifiers, commitments, ciphertext_hashes, ciphertext_sizes, anchor, binding_hash, stablecoin, fee, value_balance)`
Execute a transfer where ciphertext bytes are supplied out-of-band (DA sidecar). The call carries ciphertext hashes and byte sizes only.

### `shielded_transfer_unsigned_sidecar(proof, nullifiers, commitments, ciphertext_hashes, ciphertext_sizes, anchor, binding_hash, stablecoin, fee)`
Unsigned sidecar transfer; ciphertext bytes live in the DA sidecar and `stablecoin` must be `None`.

### `submit_commitment_proof(da_root, proof)` (inherent)
Attach the block commitment proof and the DA root to the block body for node-side verification and DA retrieval.

### `submit_aggregation_proof(proof)` (inherent)
Attach an aggregation proof over transaction proofs when available.

### `mint_coinbase(coinbase_data)` (inherent)
Mint a shielded coinbase note as the only issuance path.

### `update_verifying_key(vk)` (admin only)
Update the STARK verification parameters.

## Security Properties

1. **Confidentiality**: Note values and recipients hidden in encrypted ciphertexts
2. **Anonymity**: Nullifiers hide which note is being spent
3. **Integrity**: STARK proof ensures valid state transition
4. **Double-spend prevention**: Nullifier set prevents reuse
5. **Post-quantum security**: All operations use hash-based or lattice-based crypto

## Testing

```bash
cargo test -p pallet-shielded-pool
```

## TODO

- [ ] Integrate real STARK verifier from `circuits/transaction/` crate
- [ ] Implement ML-KEM key encapsulation for encrypted notes
- [ ] Add benchmarks for weight calculation
- [ ] Implement viewing key derivation
