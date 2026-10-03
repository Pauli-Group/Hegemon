//! Canonical action-to-statement adapter for the prospective standalone
//! SHAKE256 Pay1x2 proof profile.
//!
//! This crate is deliberately isolated from production consensus. It binds a
//! fixed one-input/two-output native-asset relation statement to two exact
//! ciphertext byte strings, fixed version/backend identifiers, a typed network
//! identity, and a balance tag reconstructed only from public fields. It does
//! not authorize this wire format and does not claim to validate the wallet
//! ciphertext grammar.

#![forbid(unsafe_code)]

use core::fmt;

use hegemon_standalone_pay1x2_relation_prototype::{
    Pay1x2Statement, MAX_NOTE_VALUE, NATIVE_ASSET_ID,
};
use hegemon_standalone_shake256_prototype::{
    MerkleRoot, NoteCommitment, Nullifier, SemanticDigest, SEMANTIC_DIGEST_BYTES,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub const STATEMENT_MAGIC: [u8; 4] = *b"HGS2";
pub const STATEMENT_VERSION: StatementVersion = StatementVersion(2);
pub const CIRCUIT_VERSION: CircuitVersion = CircuitVersion(5);
pub const CRYPTO_SUITE_ID: CryptoSuiteId = CryptoSuiteId(4);
pub const BACKEND_ID: BackendId = BackendId(1);
pub const PROFILE_ID: ProfileId = ProfileId(1);
pub const INPUT_COUNT: u8 = 1;
pub const OUTPUT_COUNT: u8 = 2;
pub const CIPHERTEXT_HASH_BYTES: usize = SEMANTIC_DIGEST_BYTES;
pub const BALANCE_TAG_BYTES: usize = SEMANTIC_DIGEST_BYTES;
pub const NETWORK_BINDING_BYTES: usize = SEMANTIC_DIGEST_BYTES;
pub const CHAIN_ID_BYTES: usize = 32;
pub const BLOCK_ID_BYTES: usize = 48;
pub const RULES_HASH_BYTES: usize = 48;
pub const NETWORK_BINDING_FRAME_BYTES: usize =
    8 + 8 + 1 + 2 + CHAIN_ID_BYTES + 2 + BLOCK_ID_BYTES + 2 + RULES_HASH_BYTES;
pub const STATEMENT_BINDING_BYTES: usize = 64;
pub const MAX_CANONICAL_CIPHERTEXT_BYTES: usize = 1_048_576;

/// Exact fixed-width canonical statement length.
///
/// Layout: 30 bytes of header/monetary fields, 224 bytes of relation digests,
/// 112 bytes of ciphertext hashes, a 56-byte network binding, and a 56-byte
/// derived balance tag.
pub const CANONICAL_STATEMENT_BYTES: usize = 478;

const STATEMENT_PROFILE_TAG: [u8; 8] = *b"HEG-S4V2";
const CIPHERTEXT_HASH_ROLE_TAG: [u8; 8] = *b"ct.hshv2";
const NETWORK_BINDING_ROLE_TAG: [u8; 8] = *b"net.bdv2";
const BALANCE_TAG_ROLE_TAG: [u8; 8] = *b"bal.tgv2";
const STATEMENT_BINDING_ROLE_TAG: [u8; 8] = *b"stmt.bv2";

const OFFSET_STATEMENT_VERSION: usize = 4;
const OFFSET_CIRCUIT_VERSION: usize = 6;
const OFFSET_CRYPTO_SUITE: usize = 8;
const OFFSET_BACKEND: usize = 10;
const OFFSET_PROFILE: usize = 11;
const OFFSET_INPUT_COUNT: usize = 12;
const OFFSET_OUTPUT_COUNT: usize = 13;
const OFFSET_NATIVE_ASSET: usize = 14;
const OFFSET_FEE: usize = 22;
const OFFSET_ANCHOR: usize = 30;
const OFFSET_NULLIFIER: usize = OFFSET_ANCHOR + SEMANTIC_DIGEST_BYTES;
const OFFSET_OUTPUT_0: usize = OFFSET_NULLIFIER + SEMANTIC_DIGEST_BYTES;
const OFFSET_OUTPUT_1: usize = OFFSET_OUTPUT_0 + SEMANTIC_DIGEST_BYTES;
const OFFSET_CIPHERTEXT_0: usize = OFFSET_OUTPUT_1 + SEMANTIC_DIGEST_BYTES;
const OFFSET_CIPHERTEXT_1: usize = OFFSET_CIPHERTEXT_0 + CIPHERTEXT_HASH_BYTES;
const OFFSET_NETWORK_BINDING: usize = OFFSET_CIPHERTEXT_1 + CIPHERTEXT_HASH_BYTES;
const OFFSET_BALANCE_TAG: usize = OFFSET_NETWORK_BINDING + NETWORK_BINDING_BYTES;

mod action;
pub use action::*;

macro_rules! typed_id {
    ($name:ident, $repr:ty) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name($repr);

        impl $name {
            pub const fn get(self) -> $repr {
                self.0
            }
        }
    };
}

typed_id!(StatementVersion, u16);
typed_id!(CircuitVersion, u16);
typed_id!(CryptoSuiteId, u16);
typed_id!(BackendId, u8);
typed_id!(ProfileId, u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NativeAssetId(u64);

impl NativeAssetId {
    pub const NATIVE: Self = Self(NATIVE_ASSET_ID);

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NativeFee(u64);

impl NativeFee {
    pub fn new(value: u64) -> Result<Self, AdapterError> {
        if value > MAX_NOTE_VALUE {
            return Err(AdapterError::FeeOutOfRange(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StatementIds {
    pub statement_version: StatementVersion,
    pub circuit_version: CircuitVersion,
    pub crypto_suite: CryptoSuiteId,
    pub backend: BackendId,
    pub profile: ProfileId,
}

impl StatementIds {
    pub const PROSPECTIVE_V2: Self = Self {
        statement_version: STATEMENT_VERSION,
        circuit_version: CIRCUIT_VERSION,
        crypto_suite: CRYPTO_SUITE_ID,
        backend: BACKEND_ID,
        profile: PROFILE_ID,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ActivityShape {
    pub inputs: u8,
    pub outputs: u8,
}

impl ActivityShape {
    pub const PAY1X2: Self = Self {
        inputs: INPUT_COUNT,
        outputs: OUTPUT_COUNT,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicMonetaryFields {
    pub asset: NativeAssetId,
    pub fee: NativeFee,
}

macro_rules! typed_fixed_bytes {
    ($name:ident, $bytes:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name([u8; $bytes]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $bytes]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $bytes] {
                self.0
            }
        }
    };
}

typed_fixed_bytes!(ChainId32, CHAIN_ID_BYTES);
typed_fixed_bytes!(BlockId48, BLOCK_ID_BYTES);
typed_fixed_bytes!(RulesHash48, RULES_HASH_BYTES);
typed_fixed_bytes!(NetworkBinding56, NETWORK_BINDING_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkIdentity {
    pub chain_id: ChainId32,
    pub genesis: BlockId48,
    pub rules_hash: RulesHash48,
}

/// Deterministic identity used only by prototype KATs and backend roundtrips.
/// Production integration must inject the active node's exact identity.
pub const KAT_NETWORK_IDENTITY: NetworkIdentity = NetworkIdentity {
    chain_id: ChainId32::from_bytes([0x71; CHAIN_ID_BYTES]),
    genesis: BlockId48::from_bytes([0x82; BLOCK_ID_BYTES]),
    rules_hash: RulesHash48::from_bytes([0x93; RULES_HASH_BYTES]),
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CiphertextHash([u8; CIPHERTEXT_HASH_BYTES]);

impl CiphertextHash {
    pub const fn from_bytes(bytes: [u8; CIPHERTEXT_HASH_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CIPHERTEXT_HASH_BYTES] {
        &self.0
    }
}

impl fmt::Debug for CiphertextHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CiphertextHash(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BalanceTag([u8; BALANCE_TAG_BYTES]);

impl BalanceTag {
    pub const fn from_bytes(bytes: [u8; BALANCE_TAG_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; BALANCE_TAG_BYTES] {
        &self.0
    }
}

impl fmt::Debug for BalanceTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BalanceTag(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Bytes already accepted and canonically re-encoded by the wallet
/// ciphertext parser.
///
/// This isolated adapter can enforce only nonempty and bounded bytes. The
/// constructor name makes the remaining parser/canonical-reencoding premise
/// explicit instead of pretending this crate knows the production ciphertext
/// grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalCiphertextBytes<'a>(&'a [u8]);

impl<'a> CanonicalCiphertextBytes<'a> {
    pub fn from_validated_exact(bytes: &'a [u8]) -> Result<Self, AdapterError> {
        if bytes.is_empty() {
            return Err(AdapterError::EmptyCiphertext);
        }
        if bytes.len() > MAX_CANONICAL_CIPHERTEXT_BYTES {
            return Err(AdapterError::CiphertextTooLarge {
                maximum: MAX_CANONICAL_CIPHERTEXT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPay1x2Statement {
    pub ids: StatementIds,
    pub shape: ActivityShape,
    pub monetary: PublicMonetaryFields,
    pub anchor: MerkleRoot,
    pub nullifier: Nullifier,
    pub output_commitments: [NoteCommitment; OUTPUT_COUNT as usize],
    pub ciphertext_hashes: [CiphertextHash; OUTPUT_COUNT as usize],
    pub network_binding: NetworkBinding56,
    pub balance_tag: BalanceTag,
}

impl CanonicalPay1x2Statement {
    pub fn relation_statement(&self) -> Pay1x2Statement {
        Pay1x2Statement {
            anchor: self.anchor,
            nullifier: self.nullifier,
            output_commitments: self.output_commitments,
            fee: self.monetary.fee.get(),
        }
    }

    pub fn encode(&self) -> [u8; CANONICAL_STATEMENT_BYTES] {
        let mut output = [0u8; CANONICAL_STATEMENT_BYTES];
        output[..4].copy_from_slice(&STATEMENT_MAGIC);
        output[OFFSET_STATEMENT_VERSION..OFFSET_CIRCUIT_VERSION]
            .copy_from_slice(&self.ids.statement_version.get().to_be_bytes());
        output[OFFSET_CIRCUIT_VERSION..OFFSET_CRYPTO_SUITE]
            .copy_from_slice(&self.ids.circuit_version.get().to_be_bytes());
        output[OFFSET_CRYPTO_SUITE..OFFSET_BACKEND]
            .copy_from_slice(&self.ids.crypto_suite.get().to_be_bytes());
        output[OFFSET_BACKEND] = self.ids.backend.get();
        output[OFFSET_PROFILE] = self.ids.profile.get();
        output[OFFSET_INPUT_COUNT] = self.shape.inputs;
        output[OFFSET_OUTPUT_COUNT] = self.shape.outputs;
        output[OFFSET_NATIVE_ASSET..OFFSET_FEE]
            .copy_from_slice(&self.monetary.asset.get().to_be_bytes());
        output[OFFSET_FEE..OFFSET_ANCHOR].copy_from_slice(&self.monetary.fee.get().to_be_bytes());
        output[OFFSET_ANCHOR..OFFSET_NULLIFIER].copy_from_slice(self.anchor.as_bytes());
        output[OFFSET_NULLIFIER..OFFSET_OUTPUT_0].copy_from_slice(self.nullifier.as_bytes());
        output[OFFSET_OUTPUT_0..OFFSET_OUTPUT_1]
            .copy_from_slice(self.output_commitments[0].as_bytes());
        output[OFFSET_OUTPUT_1..OFFSET_CIPHERTEXT_0]
            .copy_from_slice(self.output_commitments[1].as_bytes());
        output[OFFSET_CIPHERTEXT_0..OFFSET_CIPHERTEXT_1]
            .copy_from_slice(self.ciphertext_hashes[0].as_bytes());
        output[OFFSET_CIPHERTEXT_1..OFFSET_NETWORK_BINDING]
            .copy_from_slice(self.ciphertext_hashes[1].as_bytes());
        output[OFFSET_NETWORK_BINDING..OFFSET_BALANCE_TAG]
            .copy_from_slice(self.network_binding.as_bytes());
        output[OFFSET_BALANCE_TAG..].copy_from_slice(self.balance_tag.as_bytes());
        output
    }

    pub fn binding_digest(&self) -> [u8; STATEMENT_BINDING_BYTES] {
        let encoded = self.encode();
        let mut frame = Vec::with_capacity(8 + 8 + 4 + encoded.len());
        frame.extend_from_slice(&STATEMENT_PROFILE_TAG);
        frame.extend_from_slice(&STATEMENT_BINDING_ROLE_TAG);
        frame.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        frame.extend_from_slice(&encoded);
        shake256_output(&frame)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    EmptyCiphertext,
    CiphertextTooLarge { maximum: usize, actual: usize },
    FeeOutOfRange(u64),
    Truncated { expected: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    BadMagic([u8; 4]),
    UnsupportedStatementVersion(u16),
    UnsupportedCircuitVersion(u16),
    UnsupportedCryptoSuite(u16),
    UnsupportedBackend(u8),
    UnsupportedProfile(u8),
    WrongActivityShape { inputs: u8, outputs: u8 },
    NonNativeAsset(u64),
    NetworkBindingMismatch,
    BalanceTagMismatch,
    ActionFieldMismatch(&'static str),
    CiphertextHashMismatch(usize),
    Fixture(String),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCiphertext => formatter.write_str("canonical ciphertext must not be empty"),
            Self::CiphertextTooLarge { maximum, actual } => write!(
                formatter,
                "canonical ciphertext is {actual} bytes; maximum is {maximum}"
            ),
            Self::FeeOutOfRange(value) => {
                write!(formatter, "native fee {value} exceeds the 61-bit range")
            }
            Self::Truncated { expected, actual } => write!(
                formatter,
                "canonical statement is truncated: expected {expected} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "canonical statement has trailing bytes: expected {expected} bytes, got {actual}"
            ),
            Self::BadMagic(magic) => write!(formatter, "bad statement magic {magic:?}"),
            Self::UnsupportedStatementVersion(value) => {
                write!(formatter, "unsupported statement version {value}")
            }
            Self::UnsupportedCircuitVersion(value) => {
                write!(formatter, "unsupported circuit version {value}")
            }
            Self::UnsupportedCryptoSuite(value) => {
                write!(formatter, "unsupported crypto suite {value}")
            }
            Self::UnsupportedBackend(value) => write!(formatter, "unsupported backend {value}"),
            Self::UnsupportedProfile(value) => write!(formatter, "unsupported profile {value}"),
            Self::WrongActivityShape { inputs, outputs } => write!(
                formatter,
                "wrong activity shape {inputs}-in/{outputs}-out; only 1-in/2-out is defined"
            ),
            Self::NonNativeAsset(value) => {
                write!(formatter, "asset {value} is not the native asset")
            }
            Self::NetworkBindingMismatch => {
                formatter.write_str("network binding does not match chain/genesis/rules identity")
            }
            Self::BalanceTagMismatch => {
                formatter.write_str("balance tag is not derived from canonical public fields")
            }
            Self::ActionFieldMismatch(field) => {
                write!(formatter, "statement does not bind action field {field}")
            }
            Self::CiphertextHashMismatch(slot) => {
                write!(formatter, "statement does not bind ciphertext slot {slot}")
            }
            Self::Fixture(error) => write!(formatter, "fixture construction failed: {error}"),
        }
    }
}

impl std::error::Error for AdapterError {}

pub fn derive_ciphertext_hash(
    output_index: u8,
    ciphertext: CanonicalCiphertextBytes<'_>,
) -> CiphertextHash {
    let bytes = ciphertext.as_bytes();
    let mut frame = Vec::with_capacity(8 + 8 + 1 + 4 + bytes.len());
    frame.extend_from_slice(&STATEMENT_PROFILE_TAG);
    frame.extend_from_slice(&CIPHERTEXT_HASH_ROLE_TAG);
    frame.push(output_index);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    CiphertextHash::from_bytes(shake256_output(&frame))
}

/// Bind the exact native chain identity into one typed SHAKE256-448 digest.
///
/// All three inputs have fixed widths and explicit big-endian length words, so
/// there is no concatenation or cross-field parsing alias. The binding is a
/// public statement field; it is not a wallet-selected label.
pub fn derive_network_binding(network: NetworkIdentity) -> NetworkBinding56 {
    let mut frame = Vec::with_capacity(NETWORK_BINDING_FRAME_BYTES);
    frame.extend_from_slice(&STATEMENT_PROFILE_TAG);
    frame.extend_from_slice(&NETWORK_BINDING_ROLE_TAG);
    frame.push(3);
    frame.extend_from_slice(&(CHAIN_ID_BYTES as u16).to_be_bytes());
    frame.extend_from_slice(network.chain_id.as_bytes());
    frame.extend_from_slice(&(BLOCK_ID_BYTES as u16).to_be_bytes());
    frame.extend_from_slice(network.genesis.as_bytes());
    frame.extend_from_slice(&(RULES_HASH_BYTES as u16).to_be_bytes());
    frame.extend_from_slice(network.rules_hash.as_bytes());
    debug_assert_eq!(frame.len(), NETWORK_BINDING_FRAME_BYTES);
    NetworkBinding56::from_bytes(shake256_output(&frame))
}

/// Reconstruct the public balance tag without hashing any hidden note value.
///
/// For this fixed native-only profile, exact private conservation is enforced
/// by the relation. The external tag commits only to the fixed shape, native
/// asset, public fee, and the complete version/backend/profile tuple.
pub fn derive_balance_tag(
    ids: StatementIds,
    shape: ActivityShape,
    monetary: PublicMonetaryFields,
) -> BalanceTag {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&STATEMENT_PROFILE_TAG);
    frame.extend_from_slice(&BALANCE_TAG_ROLE_TAG);
    frame.extend_from_slice(&ids.statement_version.get().to_be_bytes());
    frame.extend_from_slice(&ids.circuit_version.get().to_be_bytes());
    frame.extend_from_slice(&ids.crypto_suite.get().to_be_bytes());
    frame.push(ids.backend.get());
    frame.push(ids.profile.get());
    frame.push(shape.inputs);
    frame.push(shape.outputs);
    frame.extend_from_slice(&monetary.asset.get().to_be_bytes());
    frame.extend_from_slice(&monetary.fee.get().to_be_bytes());
    debug_assert_eq!(frame.len(), 42);
    BalanceTag::from_bytes(shake256_output(&frame))
}

pub fn adapt_action(
    relation: &Pay1x2Statement,
    ciphertexts: [CanonicalCiphertextBytes<'_>; OUTPUT_COUNT as usize],
    network: NetworkIdentity,
) -> Result<CanonicalPay1x2Statement, AdapterError> {
    let ids = StatementIds::PROSPECTIVE_V2;
    let shape = ActivityShape::PAY1X2;
    let monetary = PublicMonetaryFields {
        asset: NativeAssetId::NATIVE,
        fee: NativeFee::new(relation.fee)?,
    };
    Ok(CanonicalPay1x2Statement {
        ids,
        shape,
        monetary,
        anchor: relation.anchor,
        nullifier: relation.nullifier,
        output_commitments: relation.output_commitments,
        ciphertext_hashes: [
            derive_ciphertext_hash(0, ciphertexts[0]),
            derive_ciphertext_hash(1, ciphertexts[1]),
        ],
        network_binding: derive_network_binding(network),
        balance_tag: derive_balance_tag(ids, shape, monetary),
    })
}

pub fn decode_exact(bytes: &[u8]) -> Result<CanonicalPay1x2Statement, AdapterError> {
    if bytes.len() < CANONICAL_STATEMENT_BYTES {
        return Err(AdapterError::Truncated {
            expected: CANONICAL_STATEMENT_BYTES,
            actual: bytes.len(),
        });
    }
    if bytes.len() > CANONICAL_STATEMENT_BYTES {
        return Err(AdapterError::TrailingBytes {
            expected: CANONICAL_STATEMENT_BYTES,
            actual: bytes.len(),
        });
    }

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[..4]);
    if magic != STATEMENT_MAGIC {
        return Err(AdapterError::BadMagic(magic));
    }

    let ids = StatementIds {
        statement_version: StatementVersion(read_u16(bytes, OFFSET_STATEMENT_VERSION)),
        circuit_version: CircuitVersion(read_u16(bytes, OFFSET_CIRCUIT_VERSION)),
        crypto_suite: CryptoSuiteId(read_u16(bytes, OFFSET_CRYPTO_SUITE)),
        backend: BackendId(bytes[OFFSET_BACKEND]),
        profile: ProfileId(bytes[OFFSET_PROFILE]),
    };
    validate_ids(ids)?;

    let shape = ActivityShape {
        inputs: bytes[OFFSET_INPUT_COUNT],
        outputs: bytes[OFFSET_OUTPUT_COUNT],
    };
    if shape != ActivityShape::PAY1X2 {
        return Err(AdapterError::WrongActivityShape {
            inputs: shape.inputs,
            outputs: shape.outputs,
        });
    }

    let asset_value = read_u64(bytes, OFFSET_NATIVE_ASSET);
    if asset_value != NATIVE_ASSET_ID {
        return Err(AdapterError::NonNativeAsset(asset_value));
    }
    let monetary = PublicMonetaryFields {
        asset: NativeAssetId::NATIVE,
        fee: NativeFee::new(read_u64(bytes, OFFSET_FEE))?,
    };

    let anchor =
        MerkleRoot::from_digest(SemanticDigest::from_bytes(read_array(bytes, OFFSET_ANCHOR)));
    let nullifier = Nullifier::from_digest(SemanticDigest::from_bytes(read_array(
        bytes,
        OFFSET_NULLIFIER,
    )));
    let output_commitments = [
        NoteCommitment::from_digest(SemanticDigest::from_bytes(read_array(
            bytes,
            OFFSET_OUTPUT_0,
        ))),
        NoteCommitment::from_digest(SemanticDigest::from_bytes(read_array(
            bytes,
            OFFSET_OUTPUT_1,
        ))),
    ];
    let ciphertext_hashes = [
        CiphertextHash::from_bytes(read_array(bytes, OFFSET_CIPHERTEXT_0)),
        CiphertextHash::from_bytes(read_array(bytes, OFFSET_CIPHERTEXT_1)),
    ];
    let network_binding = NetworkBinding56::from_bytes(read_array(bytes, OFFSET_NETWORK_BINDING));
    let balance_tag = BalanceTag::from_bytes(read_array(bytes, OFFSET_BALANCE_TAG));
    if balance_tag != derive_balance_tag(ids, shape, monetary) {
        return Err(AdapterError::BalanceTagMismatch);
    }

    Ok(CanonicalPay1x2Statement {
        ids,
        shape,
        monetary,
        anchor,
        nullifier,
        output_commitments,
        ciphertext_hashes,
        network_binding,
        balance_tag,
    })
}

pub fn verify_action_statement(
    bytes: &[u8],
    relation: &Pay1x2Statement,
    ciphertexts: [CanonicalCiphertextBytes<'_>; OUTPUT_COUNT as usize],
    network: NetworkIdentity,
) -> Result<CanonicalPay1x2Statement, AdapterError> {
    let decoded = decode_exact(bytes)?;
    let expected = adapt_action(relation, ciphertexts, network)?;
    if decoded.anchor != expected.anchor {
        return Err(AdapterError::ActionFieldMismatch("anchor"));
    }
    if decoded.nullifier != expected.nullifier {
        return Err(AdapterError::ActionFieldMismatch("nullifier"));
    }
    if decoded.output_commitments[0] != expected.output_commitments[0] {
        return Err(AdapterError::ActionFieldMismatch("output_commitment[0]"));
    }
    if decoded.output_commitments[1] != expected.output_commitments[1] {
        return Err(AdapterError::ActionFieldMismatch("output_commitment[1]"));
    }
    if decoded.monetary.fee != expected.monetary.fee {
        return Err(AdapterError::ActionFieldMismatch("fee"));
    }
    for slot in 0..OUTPUT_COUNT as usize {
        if decoded.ciphertext_hashes[slot] != expected.ciphertext_hashes[slot] {
            return Err(AdapterError::CiphertextHashMismatch(slot));
        }
    }
    if decoded.network_binding != expected.network_binding {
        return Err(AdapterError::NetworkBindingMismatch);
    }
    Ok(decoded)
}

fn validate_ids(ids: StatementIds) -> Result<(), AdapterError> {
    if ids.statement_version != STATEMENT_VERSION {
        return Err(AdapterError::UnsupportedStatementVersion(
            ids.statement_version.get(),
        ));
    }
    if ids.circuit_version != CIRCUIT_VERSION {
        return Err(AdapterError::UnsupportedCircuitVersion(
            ids.circuit_version.get(),
        ));
    }
    if ids.crypto_suite != CRYPTO_SUITE_ID {
        return Err(AdapterError::UnsupportedCryptoSuite(ids.crypto_suite.get()));
    }
    if ids.backend != BACKEND_ID {
        return Err(AdapterError::UnsupportedBackend(ids.backend.get()));
    }
    if ids.profile != PROFILE_ID {
        return Err(AdapterError::UnsupportedProfile(ids.profile.get()));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

fn shake256_output<const N: usize>(frame: &[u8]) -> [u8; N] {
    let mut hasher = Shake256::default();
    hasher.update(frame);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; N];
    reader.read(&mut output);
    output
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationOutcome {
    pub name: &'static str,
    pub rejected: bool,
    pub reason: String,
}

/// Exercise every canonical field boundary by changing exactly one encoded or
/// source field while keeping the remainder of the action/statement fixed.
pub fn mutation_matrix() -> Result<Vec<MutationOutcome>, AdapterError> {
    let (relation, _) = hegemon_standalone_pay1x2_relation_prototype::valid_fixture()
        .map_err(|error| AdapterError::Fixture(error.to_string()))?;
    let recipient_bytes = b"canonical-recipient-ciphertext-v1";
    let change_bytes = b"canonical-change-ciphertext-v1";
    let recipient = CanonicalCiphertextBytes::from_validated_exact(recipient_bytes)?;
    let change = CanonicalCiphertextBytes::from_validated_exact(change_bytes)?;
    let network = KAT_NETWORK_IDENTITY;
    let canonical = adapt_action(&relation, [recipient, change], network)?.encode();

    let encoded_mutations = [
        ("wire.magic", 0usize),
        ("ids.statement_version", OFFSET_STATEMENT_VERSION + 1),
        ("ids.circuit_version", OFFSET_CIRCUIT_VERSION + 1),
        ("ids.crypto_suite", OFFSET_CRYPTO_SUITE + 1),
        ("ids.backend", OFFSET_BACKEND),
        ("ids.profile", OFFSET_PROFILE),
        ("shape.inputs", OFFSET_INPUT_COUNT),
        ("shape.outputs", OFFSET_OUTPUT_COUNT),
        ("monetary.native_asset", OFFSET_NATIVE_ASSET + 7),
        ("monetary.fee", OFFSET_FEE + 7),
        ("relation.anchor", OFFSET_ANCHOR),
        ("relation.nullifier", OFFSET_NULLIFIER),
        ("relation.output_commitment[0]", OFFSET_OUTPUT_0),
        ("relation.output_commitment[1]", OFFSET_OUTPUT_1),
        ("ciphertext_hash[0]", OFFSET_CIPHERTEXT_0),
        ("ciphertext_hash[1]", OFFSET_CIPHERTEXT_1),
        ("network_binding", OFFSET_NETWORK_BINDING),
        ("balance_tag", OFFSET_BALANCE_TAG),
    ];
    let mut outcomes = Vec::with_capacity(encoded_mutations.len() + 10);
    for (name, offset) in encoded_mutations {
        let mut mutated = canonical;
        mutated[offset] ^= 1;
        push_outcome(
            &mut outcomes,
            name,
            verify_action_statement(&mutated, &relation, [recipient, change], network),
        );
    }

    let mut mutated_relation = relation.clone();
    mutated_relation.fee ^= 1;
    push_outcome(
        &mut outcomes,
        "source.fee",
        verify_action_statement(&canonical, &mutated_relation, [recipient, change], network),
    );
    let mut mutated_relation = relation.clone();
    mutated_relation.anchor = flip_root(mutated_relation.anchor);
    push_outcome(
        &mut outcomes,
        "source.anchor",
        verify_action_statement(&canonical, &mutated_relation, [recipient, change], network),
    );
    let mut mutated_relation = relation.clone();
    mutated_relation.nullifier = flip_nullifier(mutated_relation.nullifier);
    push_outcome(
        &mut outcomes,
        "source.nullifier",
        verify_action_statement(&canonical, &mutated_relation, [recipient, change], network),
    );
    for slot in 0..2 {
        let mut mutated_relation = relation.clone();
        mutated_relation.output_commitments[slot] =
            flip_commitment(mutated_relation.output_commitments[slot]);
        push_outcome(
            &mut outcomes,
            if slot == 0 {
                "source.output_commitment[0]"
            } else {
                "source.output_commitment[1]"
            },
            verify_action_statement(&canonical, &mutated_relation, [recipient, change], network),
        );
    }

    let mut changed_recipient = recipient_bytes.to_vec();
    changed_recipient[0] ^= 1;
    let changed_recipient = CanonicalCiphertextBytes::from_validated_exact(&changed_recipient)?;
    push_outcome(
        &mut outcomes,
        "source.ciphertext[0]",
        verify_action_statement(&canonical, &relation, [changed_recipient, change], network),
    );
    let mut changed_change = change_bytes.to_vec();
    changed_change[0] ^= 1;
    let changed_change = CanonicalCiphertextBytes::from_validated_exact(&changed_change)?;
    push_outcome(
        &mut outcomes,
        "source.ciphertext[1]",
        verify_action_statement(&canonical, &relation, [recipient, changed_change], network),
    );

    let mut chain_id = network.chain_id.into_bytes();
    chain_id[0] ^= 1;
    let changed_chain = NetworkIdentity {
        chain_id: ChainId32::from_bytes(chain_id),
        ..network
    };
    push_outcome(
        &mut outcomes,
        "source.chain_id",
        verify_action_statement(&canonical, &relation, [recipient, change], changed_chain),
    );
    let mut genesis = network.genesis.into_bytes();
    genesis[0] ^= 1;
    let changed_genesis = NetworkIdentity {
        genesis: BlockId48::from_bytes(genesis),
        ..network
    };
    push_outcome(
        &mut outcomes,
        "source.genesis",
        verify_action_statement(&canonical, &relation, [recipient, change], changed_genesis),
    );
    let mut rules_hash = network.rules_hash.into_bytes();
    rules_hash[0] ^= 1;
    let changed_rules = NetworkIdentity {
        rules_hash: RulesHash48::from_bytes(rules_hash),
        ..network
    };
    push_outcome(
        &mut outcomes,
        "source.rules_hash",
        verify_action_statement(&canonical, &relation, [recipient, change], changed_rules),
    );

    Ok(outcomes)
}

fn push_outcome(
    outcomes: &mut Vec<MutationOutcome>,
    name: &'static str,
    result: Result<CanonicalPay1x2Statement, AdapterError>,
) {
    match result {
        Ok(_) => outcomes.push(MutationOutcome {
            name,
            rejected: false,
            reason: "accepted".to_owned(),
        }),
        Err(error) => outcomes.push(MutationOutcome {
            name,
            rejected: true,
            reason: error.to_string(),
        }),
    }
}

fn flip_root(value: MerkleRoot) -> MerkleRoot {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    MerkleRoot::from_digest(SemanticDigest::from_bytes(bytes))
}

fn flip_nullifier(value: Nullifier) -> Nullifier {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    Nullifier::from_digest(SemanticDigest::from_bytes(bytes))
}

fn flip_commitment(value: NoteCommitment) -> NoteCommitment {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    NoteCommitment::from_digest(SemanticDigest::from_bytes(bytes))
}
