//! Plonky3 configuration for the transaction circuit.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{Proof, StarkConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub const DIGEST_ELEMS: usize = 6;
pub const POSEIDON2_WIDTH: usize = 12;
pub const POSEIDON2_RATE: usize = 6;
pub const POSEIDON2_ROUNDS: u64 = 7;
// Test builds use lower FRI parameters unless the e2e feature is enabled.
#[cfg(all(test, not(feature = "plonky3-e2e")))]
pub const FRI_LOG_BLOWUP: usize = 2;
#[cfg(any(not(test), feature = "plonky3-e2e"))]
pub const FRI_LOG_BLOWUP: usize = 3;

#[cfg(all(test, not(feature = "plonky3-e2e")))]
pub const FRI_NUM_QUERIES: usize = 8;
#[cfg(any(not(test), feature = "plonky3-e2e"))]
pub const FRI_NUM_QUERIES: usize = 43;

pub const FRI_POW_BITS: usize = 0;

const POSEIDON2_SEED: [u8; 32] = *b"hegemon-tx-poseidon2-seed-2026!!";

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2<
    Val,
    Poseidon2ExternalMatrixGeneral,
    DiffusionMatrixGoldilocks,
    POSEIDON2_WIDTH,
    POSEIDON2_ROUNDS,
>;
pub type Hash = PaddingFreeSponge<Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, DIGEST_ELEMS>;
pub type Compress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, POSEIDON2_WIDTH>;
pub type ValMmcs = FieldMerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    DIGEST_ELEMS,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, POSEIDON2_WIDTH, POSEIDON2_RATE>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type TransactionProofP3 = Proof<Config>;

pub struct TransactionStarkConfig {
    pub config: Config,
    pub perm: Perm,
}

pub fn default_config() -> TransactionStarkConfig {
    let mut rng = ChaCha20Rng::from_seed(POSEIDON2_SEED);
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks::default(),
        &mut rng,
    );
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft {};
    let fri_config = FriConfig {
        log_blowup: FRI_LOG_BLOWUP,
        num_queries: FRI_NUM_QUERIES,
        proof_of_work_bits: FRI_POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let config = Config::new(pcs);

    TransactionStarkConfig { config, perm }
}

pub fn new_challenger(perm: &Perm) -> Challenger {
    Challenger::new(perm.clone())
}
