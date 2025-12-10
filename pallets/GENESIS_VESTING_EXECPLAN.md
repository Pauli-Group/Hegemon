# Implement Genesis Vesting for Shielded Allocations

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.


## Purpose / Big Picture

After this change, genesis allocations (team tokens, advisor tokens, investor tokens, ecosystem grants) will be spendable only according to their vesting schedules. A recipient who receives 100,000 HEG with a 1-year cliff and 3-year linear unlock cannot spend any tokens for 12 months; after that, tokens unlock proportionally each block. This prevents early insiders from dumping on the market immediately after launch, aligns long-term incentives, and builds trust with the community by making vesting enforcement transparent and on-chain.

The user-visible result: anyone querying the chain state can see the vesting schedules, and any attempt to spend locked tokens will fail with a clear error. After sufficient time passes, recipients can spend their unlocked tokens normally through shielded transfers.

Because Hegemon uses a privacy-first shielded pool architecture where all balances are private (no transparent UTXOs), we cannot use Substrate's standard `pallet-vesting` which tracks transparent balances. Instead, we implement "time-locked notes" at the shielded pool layer: genesis outputs carry a `spend_after` timestamp, and the STARK proof circuit must verify that `current_block_timestamp >= spend_after` before allowing the note to be consumed.


## Progress

- [ ] Read this plan fully and understand the architecture.
- [ ] Milestone 1: Extend note metadata to include a lock-time field.
- [ ] Milestone 2: Update the shielded-pool pallet to store and check lock-times.
- [ ] Milestone 3: Update the STARK circuit to verify lock-time constraints.
- [ ] Milestone 4: Implement genesis configuration with vested allocations.
- [ ] Milestone 5: Add integration tests and update documentation.


## Surprises & Discoveries

- Observation: _None yet._
  Evidence: _Pending implementation._


## Decision Log

- Decision: Use shielded time-locks rather than transparent pallet-vesting.
  Rationale: The project architecture (per TOKENOMICS_CALCULATION.md and DESIGN.md) explicitly mandates that all balances, including genesis allocations, live in the shielded pool. There are no transparent UTXOs. Standard Substrate vesting operates on transparent balances and cannot apply here. We must build time-lock enforcement into the shielded pool circuit.
  Date/Author: 2025-12-09 / ExecPlan author.


## Outcomes & Retrospective

_Pending execution._


## Context and Orientation

The shielded pool architecture places all value in "notes" that are cryptographically hidden. When spending a note, the user creates a zero-knowledge proof demonstrating they know the note's secret data without revealing it. The proof is verified by the `pallet-shielded-pool` before state changes.

Key files and their roles:

    pallets/shielded-pool/src/lib.rs
        Main pallet code. Contains GenesisConfig, storage items (Nullifiers, MerkleTree, etc.),
        the shielded_transfer extrinsic, and proof verification hooks.
        
    pallets/shielded-pool/src/types.rs
        Defines Note, EncryptedNote, StarkProof, and related types.
        
    pallets/shielded-pool/src/verifier.rs
        Proof verification interface: ShieldedTransferInputs, VerificationResult.
        
    circuits/transaction/
        STARK circuit definitions for transaction proofs.
        
    node/src/substrate/chain_spec.rs
        Genesis configuration builder. Currently has empty balances array.
        
    config/dev-chainspec.json, config/testnet/testnet-spec.json
        Chainspec JSON files that could include genesis allocations.

Terminology:

- "Note": A hidden value commitment. Contains (amount, recipient_key, randomness, spend_after). Only the holder of the recipient_key can spend it.
- "Nullifier": A unique hash derived when spending a note, used to prevent double-spending.
- "Merkle commitment": Hash of the note added to a Merkle tree; spending requires proving membership.
- "spend_after": UNIX timestamp before which the note cannot be spent. 0 = immediately spendable.
- "Cliff": The initial period during which no tokens unlock. Implemented as spend_after = genesis_time + cliff_duration.
- "Linear vesting": After the cliff, tokens unlock proportionally over time. Implemented by splitting one large allocation into multiple notes with staggered spend_after times (see Milestone 4).


## Plan of Work

### Milestone 1: Extend Note Metadata

Modify the Note struct in `pallets/shielded-pool/src/types.rs` to include a `spend_after: u64` field representing the UNIX timestamp after which the note can be spent. For backward compatibility and simplicity, 0 means "no time-lock."

Edit `pallets/shielded-pool/src/types.rs`:

    Find the Note struct (or equivalent note definition).
    Add: pub spend_after: u64
    Update serialization/deserialization and any Default impls.
    Update the commitment computation to include spend_after in the hash.

The commitment must include spend_after so that:
1. The verifier can confirm the proven spend_after matches the committed note.
2. Notes with different spend_after times are distinguishable in the Merkle tree.


### Milestone 2: Shielded Pool Lock-Time Enforcement

In `pallets/shielded-pool/src/lib.rs`, modify the shielded_transfer verification to check that all consumed notes have `spend_after <= current_timestamp`. This requires:

1. The proof public inputs must expose `spend_after` for each input note being consumed.
2. The pallet reads `pallet_timestamp::Pallet::<T>::now()` to get the current time.
3. If any input's spend_after > current_time, reject with a new error variant `NoteLocked`.

Edit `pallets/shielded-pool/src/lib.rs`:

    In the Error enum, add: NoteLocked
    
    In shielded_transfer (around line 380+), after proof verification succeeds:
        let now = <pallet_timestamp::Pallet<T>>::get();  // returns T::Moment
        for each input note's spend_after in public_inputs:
            if spend_after > now { return Err(Error::<T>::NoteLocked.into()) }

Edit `pallets/shielded-pool/src/verifier.rs`:

    Extend ShieldedTransferInputs to include spend_after values for each input.


### Milestone 3: Update STARK Circuit

The circuits in `circuits/transaction/` must:
1. Accept spend_after as a private input for each consumed note.
2. Include spend_after in the commitment hash computation.
3. Expose spend_after as a public output so the pallet can verify the time constraint.

This milestone requires reading the circuit code structure first. The circuit must prove: "I know a note with value V, secret key SK, randomness R, and spend_after T such that H(V, SK, R, T) = claimed_commitment."

Edit circuit files (exact paths TBD after reading circuits/transaction/):

    Add spend_after to the note representation.
    Add spend_after to the public outputs.
    Ensure the commitment hash matches the new formula.

If modifying circuits is complex, document the exact changes needed and defer to a circuit-focused milestone.


### Milestone 4: Genesis Configuration with Vested Allocations

Modify genesis configuration to include pre-created notes with time-locks. Because linear vesting cannot be expressed as a single note (notes are atomic), we implement it by splitting each allocation into multiple notes:

Example: Advisor receives 100,000 HEG with 1-year cliff, 3-year linear vesting (at 60s blocks).
- Year 1: Nothing spendable (cliff).
- Year 2-4: 1/3 unlocks each year.

Implementation: Create 3 notes of ~33,333 HEG each with spend_after = genesis + 1 year, genesis + 2 years, genesis + 3 years.

Edit `node/src/substrate/chain_spec.rs`:

    Extend genesis_config to include a new "genesisAllocations" or "shieldedPool.allocations" field.
    
    Structure:
        "shieldedPool": {
            "verifyingKey": null,
            "allocations": [
                {
                    "commitment": "<32-byte hex>",
                    "encryptedNote": "<encrypted blob>",
                    "spendAfter": 1735689600  // UNIX timestamp
                },
                ...
            ]
        }

Edit `pallets/shielded-pool/src/lib.rs` GenesisConfig:

    Add: pub allocations: Vec<GenesisAllocation>
    
    struct GenesisAllocation {
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
        spend_after: u64,
    }

In genesis_build, for each allocation:
    Insert commitment into MerkleTree.
    Store encrypted_note for indexers/wallets.
    (spend_after is embedded in the commitment; no separate storage needed.)

Provide a helper script or tool to generate genesis allocations:

    scripts/generate-genesis-allocations.sh or similar.
    Input: CSV with (recipient_pubkey, amount, cliff_timestamp, vest_end_timestamp, num_tranches).
    Output: JSON blob for shieldedPool.allocations.


### Milestone 5: Integration Tests and Documentation

Add tests:

    pallets/shielded-pool/tests/vesting_test.rs
        Test 1: Create a locked note at genesis, attempt to spend before unlock time, expect NoteLocked error.
        Test 2: Fast-forward time past unlock, spend succeeds.
        Test 3: Multiple notes with different unlock times, partial spendability.

Update documentation:

    TOKENOMICS_CALCULATION.md Section 5 or 6: Document how vesting is implemented.
    README.md or docs/: Add section on genesis allocations.
    DESIGN.md: Update shielded pool section with time-lock semantics.


## Concrete Steps

Run all commands from repository root.

Step 1: Read current types structure.

    cat pallets/shielded-pool/src/types.rs | head -100

Step 2: Implement Note struct changes per Milestone 1.

Step 3: Implement pallet changes per Milestone 2.

Step 4: Review circuit structure.

    ls -la circuits/transaction/
    cat circuits/transaction/src/lib.rs | head -100

Step 5: Implement circuit changes per Milestone 3 or document needed changes.

Step 6: Implement genesis config per Milestone 4.

Step 7: Add tests.

    cargo test -p pallet-shielded-pool --lib
    cargo test -p pallet-shielded-pool vesting

Step 8: Build full node to verify compilation.

    cargo build --release -p hegemon-node

Expected output: Successful build with no errors.


## Validation and Acceptance

1. **Unit tests pass**: `cargo test -p pallet-shielded-pool` shows all tests passing, including new vesting tests.

2. **Locked note rejection**: A test creates a note with spend_after = 1 year from now, attempts immediate spend, receives `NoteLocked` error.

3. **Unlocked note success**: A test creates a note with spend_after = 0 (or past time), spends successfully.

4. **Genesis works**: A dev chainspec with test allocations loads without error.

    cargo run --release -p hegemon-node -- --dev --tmp
    
   Node starts successfully, genesis state includes the test allocations.

5. **Documentation updated**: TOKENOMICS_CALCULATION.md and DESIGN.md reflect the new time-lock mechanism.


## Idempotence and Recovery

All steps are additive. If a step fails:
- Revert file changes with `git checkout -- <file>`.
- Re-read the error, adjust the implementation, retry.

The genesis allocations are empty by default (no actual team/advisor keys yet), so test runs use placeholder data that does not affect mainnet.

Running `cargo test` multiple times is safe. Running `--dev --tmp` clears state on each run.


## Artifacts and Notes

Example GenesisAllocation JSON structure:

    {
      "shieldedPool": {
        "allocations": [
          {
            "commitment": "0x1234...abcd",
            "encryptedNote": "0x...",
            "spendAfter": 1767225600
          }
        ]
      }
    }

Example error message when spending locked note:

    Error: NoteLocked
    Description: This note cannot be spent until timestamp 1767225600 (2026-01-01).

Vesting schedule table format for documentation:

    | Recipient       | Total HEG | Cliff     | Vesting | Notes Created |
    |-----------------|-----------|-----------|---------|---------------|
    | Team Member A   | 100,000   | 1 year    | 3 years | 12 (quarterly)|
    | Advisor B       | 25,000    | 6 months  | 2 years | 8 (quarterly) |


## Interfaces and Dependencies

Dependencies:

    pallet-timestamp (already in runtime): Provides current block timestamp.
    pallet-shielded-pool: This pallet, being extended.
    circuits/transaction: STARK circuit, must be updated.

New types in pallets/shielded-pool/src/types.rs:

    pub struct Note {
        pub value: u128,
        pub recipient_key: [u8; 32],
        pub randomness: [u8; 32],
        pub spend_after: u64,  // NEW: UNIX timestamp, 0 = unlocked
    }

    pub struct GenesisAllocation {
        pub commitment: [u8; 32],
        pub encrypted_note: Vec<u8>,
        pub spend_after: u64,
    }

New error variant in pallets/shielded-pool/src/lib.rs:

    #[pallet::error]
    pub enum Error<T> {
        // ... existing variants ...
        /// The note is time-locked and cannot be spent yet.
        NoteLocked,
    }

New config trait bound (if timestamp access requires explicit dependency):

    pub trait Config: frame_system::Config + pallet_timestamp::Config {
        // ...
    }

Circuit public outputs must include (per input):

    spend_after: u64


---

Revision log:
- 2025-12-09: Initial plan created based on tokenomics discussion and project architecture review.
