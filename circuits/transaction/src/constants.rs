/// Number of input notes supported by the base transaction circuit.
pub const MAX_INPUTS: usize = 2;

/// Number of output notes supported by the base transaction circuit.
pub const MAX_OUTPUTS: usize = 2;

/// Total balance slots equals inputs plus outputs to cover worst-case asset fan-out.
pub const BALANCE_SLOTS: usize = MAX_INPUTS + MAX_OUTPUTS;

/// Maximum note value enforced by the witness layer (64-bit unsigned integer bound).
pub const MAX_NOTE_VALUE: u128 = u64::MAX as u128;

/// Poseidon-like permutation width used by the toy STARK-friendly hash.
pub const POSEIDON_WIDTH: usize = 3;

/// Number of rounds for the poseidon-like permutation.
pub const POSEIDON_ROUNDS: usize = 5;

/// Domain separation tag for note commitments.
pub const NOTE_DOMAIN_TAG: u64 = 1;

/// Domain separation tag for nullifiers.
pub const NULLIFIER_DOMAIN_TAG: u64 = 2;

/// Domain separation tag for balance commitment/tagging.
pub const BALANCE_DOMAIN_TAG: u64 = 3;

/// Domain separation tag for Merkle tree nodes.
pub const MERKLE_DOMAIN_TAG: u64 = 4;

/// Identifier reserved for the native asset in the MASP balance rules.
pub const NATIVE_ASSET_ID: u64 = 0;
