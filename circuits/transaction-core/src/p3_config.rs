//! Plonky3 configuration for transaction proofs (no_std-friendly).

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{Proof, StarkConfig};

use crate::poseidon2_constants::{EXTERNAL_ROUND_CONSTANTS, INTERNAL_ROUND_CONSTANTS};

pub const DIGEST_ELEMS: usize = 6;
pub const POSEIDON2_WIDTH: usize = crate::constants::POSEIDON2_WIDTH;
pub const POSEIDON2_RATE: usize = crate::constants::POSEIDON2_RATE;

pub const FRI_LOG_BLOWUP_FAST: usize = 3;
pub const FRI_NUM_QUERIES_FAST: usize = 8;
pub const FRI_LOG_BLOWUP_PROD: usize = 4;
pub const FRI_NUM_QUERIES_PROD: usize = 32;

// Debug builds use lower FRI parameters unless the e2e feature is enabled.
//
// Note: `cfg(test)` does not apply to dependency crates, so use `debug_assertions` to keep
// integration tests fast while ensuring release builds always use production parameters.
#[cfg(all(debug_assertions, not(feature = "plonky3-e2e")))]
pub const FRI_LOG_BLOWUP: usize = FRI_LOG_BLOWUP_FAST;
#[cfg(any(not(debug_assertions), feature = "plonky3-e2e"))]
pub const FRI_LOG_BLOWUP: usize = FRI_LOG_BLOWUP_PROD;

#[cfg(all(debug_assertions, not(feature = "plonky3-e2e")))]
pub const FRI_NUM_QUERIES: usize = FRI_NUM_QUERIES_FAST;
#[cfg(any(not(debug_assertions), feature = "plonky3-e2e"))]
pub const FRI_NUM_QUERIES: usize = FRI_NUM_QUERIES_PROD;

pub const FRI_POW_BITS: usize = 0;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2Goldilocks<POSEIDON2_WIDTH>;
pub type Hash = PaddingFreeSponge<Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, DIGEST_ELEMS>;
pub type Compress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, POSEIDON2_WIDTH>;
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, DIGEST_ELEMS>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, POSEIDON2_WIDTH, POSEIDON2_RATE>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type TransactionProofP3 = Proof<Config>;

pub struct TransactionStarkConfig {
    pub config: Config,
}

fn poseidon2_perm() -> Perm {
    let external_constants =
        ExternalLayerConstants::<Goldilocks, POSEIDON2_WIDTH>::new_from_saved_array(
            EXTERNAL_ROUND_CONSTANTS,
            Goldilocks::new_array,
        );
    let internal_constants = Goldilocks::new_array(INTERNAL_ROUND_CONSTANTS).to_vec();
    Perm::new(external_constants, internal_constants)
}

pub fn default_config() -> TransactionStarkConfig {
    config_with_fri(FRI_LOG_BLOWUP, FRI_NUM_QUERIES)
}

pub fn config_with_fri(log_blowup: usize, num_queries: usize) -> TransactionStarkConfig {
    let perm = poseidon2_perm();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_config = default_fri_config(challenge_mmcs, log_blowup, num_queries);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = new_challenger(&perm);
    let config = Config::new(pcs, challenger);

    TransactionStarkConfig { config }
}

pub fn default_fri_config(
    mmcs: ChallengeMmcs,
    log_blowup: usize,
    num_queries: usize,
) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: FRI_POW_BITS,
        mmcs,
    }
}

pub fn new_challenger(perm: &Perm) -> Challenger {
    Challenger::new(perm.clone())
}
