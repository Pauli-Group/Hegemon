use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionCircuitError {
    #[error("too many input notes provided: {0}")]
    TooManyInputs(usize),

    #[error("too many output notes provided: {0}")]
    TooManyOutputs(usize),

    #[error("note value exceeds 64-bit range: {0}")]
    ValueOutOfRange(u128),

    #[error("asset identifier must be 64 bits or fewer")]
    AssetIdTooLarge,

    #[error("balance slots exhausted when assigning note asset {0}")]
    BalanceSlotOverflow(u64),

    #[error("balance delta for asset {0} does not match expected total")]
    BalanceMismatch(u64),

    #[error("value balance magnitude exceeds 64-bit range: {0}")]
    ValueBalanceOutOfRange(u128),

    #[error("balance delta for asset {0} exceeds 64-bit range: {1}")]
    BalanceDeltaOutOfRange(u64, u128),

    #[error("nullifier mismatch at index {0}")]
    NullifierMismatch(usize),

    #[error("commitment mismatch at index {0}")]
    CommitmentMismatch(usize),

    #[error("ciphertext hash mismatch at index {0}")]
    CiphertextHashMismatch(usize),

    #[error(
        "zero nullifier produced at index {0} - this indicates malicious witness construction"
    )]
    ZeroNullifier(usize),

    #[error("constraint system violated: {0}")]
    ConstraintViolation(&'static str),
}
