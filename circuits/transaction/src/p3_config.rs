//! Plonky3 configuration for the transaction circuit.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{Proof, StarkConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use transaction_core::poseidon2::POSEIDON2_SEED;

pub const DIGEST_ELEMS: usize = 6;
pub const POSEIDON2_WIDTH: usize = 12;
pub const POSEIDON2_RATE: usize = 6;
// Test builds use lower FRI parameters unless the e2e feature is enabled.
#[cfg(all(test, not(feature = "plonky3-e2e")))]
pub const FRI_LOG_BLOWUP: usize = 3;
#[cfg(any(not(test), feature = "plonky3-e2e"))]
pub const FRI_LOG_BLOWUP: usize = 4;

#[cfg(all(test, not(feature = "plonky3-e2e")))]
pub const FRI_NUM_QUERIES: usize = 8;
#[cfg(any(not(test), feature = "plonky3-e2e"))]
pub const FRI_NUM_QUERIES: usize = 43;

pub const FRI_POW_BITS: usize = 0;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2Goldilocks<POSEIDON2_WIDTH>;
pub type Hash = PaddingFreeSponge<Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, DIGEST_ELEMS>;
pub type Compress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, POSEIDON2_WIDTH>;
pub type ValMmcs = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    DIGEST_ELEMS,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, POSEIDON2_WIDTH, POSEIDON2_RATE>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type TransactionProofP3 = Proof<Config>;

pub struct TransactionStarkConfig {
    pub config: Config,
}

pub fn default_config() -> TransactionStarkConfig {
    let mut rng = ChaCha20Rng::from_seed(POSEIDON2_SEED);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_config = FriParameters {
        log_blowup: FRI_LOG_BLOWUP,
        log_final_poly_len: 0,
        num_queries: FRI_NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: FRI_POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = new_challenger(&perm);
    let config = Config::new(pcs, challenger);

    TransactionStarkConfig { config }
}

pub fn new_challenger(perm: &Perm) -> Challenger {
    Challenger::new(perm.clone())
}
