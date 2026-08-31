#![no_std]

use blake2::{digest::consts::U48, Blake2b, Digest};
use core::fmt;

pub const BLAKE2B_384_FRAME_V1: &[u8] = b"hegemon.blake2b-384.frame-v1";
pub const POW_WORK_TRANSCRIPT_BYTES_V3: usize = domains::POW_WORK_V3.len() + 48 + 32;

pub type ChainId32 = [u8; 32];
pub type Nonce32 = [u8; 32];
pub type ConsensusDigest48 = [u8; 48];

/// Legacy/research-only Poseidon wire constants. Active V3 consensus forbids
/// Poseidon authority and uses distinct typed BLAKE2b-384 outputs instead.
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const POSEIDON_DIGEST_LIMBS: usize = 7;
pub const POSEIDON_DIGEST_BYTES: usize = POSEIDON_DIGEST_LIMBS * core::mem::size_of::<u64>();
pub const POSEIDON_M4_TENSOR_P4_KAT_INPUT: [u64; 16] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const POSEIDON_M4_TENSOR_P4_KAT_OUTPUT: [u64; 16] = [
    202, 209, 216, 223, 262, 269, 276, 283, 322, 329, 336, 343, 222, 229, 236, 243,
];
pub const POSEIDON_P4_TENSOR_M4_REJECTED_KAT_OUTPUT: [u64; 16] = [
    208, 223, 238, 213, 236, 251, 266, 241, 264, 279, 294, 269, 292, 307, 322, 297,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFixedBytesLength {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for InvalidFixedBytesLength {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "expected {} bytes, received {}",
            self.expected, self.actual
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidPoseidonDigest {
    InvalidLength(InvalidFixedBytesLength),
    NonCanonicalLimb { index: usize, value: u64 },
}

impl fmt::Display for InvalidPoseidonDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(error) => error.fmt(formatter),
            Self::NonCanonicalLimb { index, value } => write!(
                formatter,
                "Poseidon digest limb {index} is not canonical: {value} >= {GOLDILOCKS_MODULUS}"
            ),
        }
    }
}

macro_rules! fixed_bytes_type {
    ($name:ident, $length:expr) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
        #[cfg_attr(feature = "type-info", derive(scale_info::TypeInfo))]
        pub struct $name([u8; $length]);

        impl $name {
            pub const ZERO: Self = Self([0u8; $length]);

            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $length] {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(bytes: [u8; $length]) -> Self {
                Self::new(bytes)
            }
        }

        impl From<$name> for [u8; $length] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = InvalidFixedBytesLength;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let actual = bytes.len();
                let inner =
                    <[u8; $length]>::try_from(bytes).map_err(|_| InvalidFixedBytesLength {
                        expected: $length,
                        actual,
                    })?;
                Ok(Self::new(inner))
            }
        }

        #[cfg(feature = "codec")]
        impl codec::DecodeWithMemTracking for $name {}

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeTuple;

                let mut tuple = serializer.serialize_tuple($length)?;
                for byte in &self.0 {
                    tuple.serialize_element(byte)?;
                }
                tuple.end()
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                serde_fixed::deserialize::<D, $length>(deserializer).map(Self::new)
            }
        }
    };
}

fixed_bytes_type!(HeaderPrecommit48, 48);
fixed_bytes_type!(WorkHash48, 48);
fixed_bytes_type!(BlockId48, 48);
fixed_bytes_type!(Target48, 48);
fixed_bytes_type!(RulesHash48, 48);
fixed_bytes_type!(ActionId48, 48);
fixed_bytes_type!(ActionSemanticId48, 48);
fixed_bytes_type!(ActionRoot48, 48);
fixed_bytes_type!(HeaderMmrHash48, 48);
fixed_bytes_type!(StateRoot48, 48);
fixed_bytes_type!(NoteCommitment48, 48);
fixed_bytes_type!(Nullifier48, 48);
fixed_bytes_type!(TransactionMerkleHash48, 48);
fixed_bytes_type!(Anchor48, 48);
fixed_bytes_type!(BalanceTag48, 48);
fixed_bytes_type!(KernelRoot48, 48);
fixed_bytes_type!(NullifierAccumulatorRoot48, 48);
fixed_bytes_type!(DaRoot48, 48);
fixed_bytes_type!(ProofCommitment48, 48);
fixed_bytes_type!(TransactionStatementsCommitment48, 48);
fixed_bytes_type!(VersionCommitment48, 48);
fixed_bytes_type!(FeeCommitment48, 48);
fixed_bytes_type!(BodyHash48, 48);
fixed_bytes_type!(ActionBodyHash48, 48);
fixed_bytes_type!(CheckpointDigest48, 48);
fixed_bytes_type!(ReorgWalValueHash48, 48);
fixed_bytes_type!(LightClientVerifierHash48, 48);
fixed_bytes_type!(BridgeCheckpointOutputDigest48, 48);
fixed_bytes_type!(TransactionId48, 48);
fixed_bytes_type!(BridgePayloadHash48, 48);
fixed_bytes_type!(BridgeMessageHash48, 48);
fixed_bytes_type!(BridgeMessageRoot48, 48);
fixed_bytes_type!(BridgeReplayKey48, 48);
fixed_bytes_type!(Work64, 64);

/// Legacy/research-only seven-limb Poseidon wire type.
///
/// It remains available only for bounded legacy decoding and research
/// conformance. Active V3 consensus forbids this type: authoritative state,
/// note, nullifier, Merkle, anchor, and balance bindings use distinct typed
/// 48-byte RFC 7693 BLAKE2b-384 outputs. Its retained legacy encoding is seven
/// canonical Goldilocks limbs in little-endian order (56 bytes, no prefix).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "type-info", derive(scale_info::TypeInfo))]
pub struct PoseidonDigest56([u8; POSEIDON_DIGEST_BYTES]);

impl PoseidonDigest56 {
    pub const ZERO: Self = Self([0u8; POSEIDON_DIGEST_BYTES]);

    /// Construct from the exact 56-byte little-endian limb wire after checking
    /// every limb for canonical Goldilocks range.
    pub fn new(bytes: [u8; POSEIDON_DIGEST_BYTES]) -> Result<Self, InvalidPoseidonDigest> {
        for index in 0..POSEIDON_DIGEST_LIMBS {
            let start = index * core::mem::size_of::<u64>();
            let mut encoded = [0u8; core::mem::size_of::<u64>()];
            encoded.copy_from_slice(&bytes[start..start + core::mem::size_of::<u64>()]);
            let value = u64::from_le_bytes(encoded);
            if value >= GOLDILOCKS_MODULUS {
                return Err(InvalidPoseidonDigest::NonCanonicalLimb { index, value });
            }
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; POSEIDON_DIGEST_BYTES] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; POSEIDON_DIGEST_BYTES] {
        self.0
    }

    pub fn try_from_limbs(
        limbs: [u64; POSEIDON_DIGEST_LIMBS],
    ) -> Result<Self, InvalidPoseidonDigest> {
        let mut bytes = [0u8; POSEIDON_DIGEST_BYTES];
        for (index, limb) in limbs.iter().copied().enumerate() {
            if limb >= GOLDILOCKS_MODULUS {
                return Err(InvalidPoseidonDigest::NonCanonicalLimb { index, value: limb });
            }
            let start = index * core::mem::size_of::<u64>();
            bytes[start..start + core::mem::size_of::<u64>()].copy_from_slice(&limb.to_le_bytes());
        }
        Ok(Self(bytes))
    }

    pub fn to_limbs(self) -> [u64; POSEIDON_DIGEST_LIMBS] {
        let mut limbs = [0u64; POSEIDON_DIGEST_LIMBS];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = index * core::mem::size_of::<u64>();
            let mut encoded = [0u8; core::mem::size_of::<u64>()];
            encoded.copy_from_slice(&self.0[start..start + core::mem::size_of::<u64>()]);
            *limb = u64::from_le_bytes(encoded);
        }
        limbs
    }

    pub const fn to_le_bytes(self) -> [u8; POSEIDON_DIGEST_BYTES] {
        self.0
    }

    pub fn try_from_le_bytes(
        bytes: [u8; POSEIDON_DIGEST_BYTES],
    ) -> Result<Self, InvalidPoseidonDigest> {
        Self::new(bytes)
    }

    pub fn try_from_le_bytes_slice(bytes: &[u8]) -> Result<Self, InvalidPoseidonDigest> {
        let actual = bytes.len();
        let encoded = <[u8; POSEIDON_DIGEST_BYTES]>::try_from(bytes).map_err(|_| {
            InvalidPoseidonDigest::InvalidLength(InvalidFixedBytesLength {
                expected: POSEIDON_DIGEST_BYTES,
                actual,
            })
        })?;
        Self::try_from_le_bytes(encoded)
    }

    #[cfg(feature = "codec")]
    pub fn decode_scale_exact(bytes: &[u8]) -> Result<Self, codec::Error> {
        let mut input = bytes;
        let value = <Self as codec::Decode>::decode(&mut input)?;
        if !input.is_empty() {
            return Err("PoseidonDigest56 SCALE input has trailing bytes".into());
        }
        Ok(value)
    }
}

impl Default for PoseidonDigest56 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl TryFrom<[u64; POSEIDON_DIGEST_LIMBS]> for PoseidonDigest56 {
    type Error = InvalidPoseidonDigest;

    fn try_from(limbs: [u64; POSEIDON_DIGEST_LIMBS]) -> Result<Self, Self::Error> {
        Self::try_from_limbs(limbs)
    }
}

impl TryFrom<[u8; POSEIDON_DIGEST_BYTES]> for PoseidonDigest56 {
    type Error = InvalidPoseidonDigest;

    fn try_from(bytes: [u8; POSEIDON_DIGEST_BYTES]) -> Result<Self, Self::Error> {
        Self::try_from_le_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for PoseidonDigest56 {
    type Error = InvalidPoseidonDigest;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_le_bytes_slice(bytes)
    }
}

impl From<PoseidonDigest56> for [u64; POSEIDON_DIGEST_LIMBS] {
    fn from(value: PoseidonDigest56) -> Self {
        value.to_limbs()
    }
}

impl From<PoseidonDigest56> for [u8; POSEIDON_DIGEST_BYTES] {
    fn from(value: PoseidonDigest56) -> Self {
        value.into_bytes()
    }
}

impl AsRef<[u8]> for PoseidonDigest56 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "codec")]
impl codec::Encode for PoseidonDigest56 {
    fn size_hint(&self) -> usize {
        POSEIDON_DIGEST_BYTES
    }

    fn encode_to<T: codec::Output + ?Sized>(&self, destination: &mut T) {
        destination.write(self.as_bytes());
    }
}

#[cfg(feature = "codec")]
impl codec::Decode for PoseidonDigest56 {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut bytes = [0u8; POSEIDON_DIGEST_BYTES];
        input.read(&mut bytes)?;
        Self::try_from_le_bytes(bytes)
            .map_err(|_| "PoseidonDigest56 contains a non-canonical Goldilocks limb".into())
    }
}

#[cfg(feature = "codec")]
impl codec::DecodeWithMemTracking for PoseidonDigest56 {}

#[cfg(feature = "serde")]
impl serde::Serialize for PoseidonDigest56 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        let mut tuple = serializer.serialize_tuple(POSEIDON_DIGEST_BYTES)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PoseidonDigest56 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serde_fixed::deserialize::<D, POSEIDON_DIGEST_BYTES>(deserializer)?;
        Self::try_from_le_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
mod serde_fixed {
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};

    pub(super) fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_tuple(N, FixedBytesVisitor::<N>)
    }

    struct FixedBytesVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for FixedBytesVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "exactly {N} bytes")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = [0u8; N];
            for (index, slot) in out.iter_mut().enumerate() {
                *slot = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(index, &self))?;
            }
            if sequence.next_element::<u8>()?.is_some() {
                return Err(A::Error::invalid_length(N + 1, &self));
            }
            Ok(out)
        }
    }
}

/// RFC 7693 BLAKE2b with its native 48-byte digest-size parameter.
///
/// This is BLAKE2b configured for a 48-byte digest, not a truncation of a
/// separately computed 64-byte digest.
pub fn blake2b_384(data: &[u8]) -> ConsensusDigest48 {
    let mut hasher = Blake2b::<U48>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Domain-separated RFC 7693 BLAKE2b-384 with unambiguous part framing.
///
/// The exact transcript is
/// `frame || u64le(domain_len) || domain || (u64le(part_len) || part)*`.
/// Part count is implicit in the end of the transcript; even an empty final
/// part contributes its eight-byte zero length and therefore cannot alias an
/// omitted part.
pub fn blake2b_384_domain_hash<'a>(
    domain: &[u8],
    parts: impl IntoIterator<Item = &'a [u8]>,
) -> ConsensusDigest48 {
    let mut hasher = Blake2b384DomainHasher::new(domain);
    for part in parts {
        hasher.update_part(part);
    }
    hasher.finalize()
}

/// Allocation-free incremental form of [`blake2b_384_domain_hash`].
///
/// Only complete framed parts can be appended; this API deliberately exposes no
/// raw byte update that could omit or split a part length. It is useful for hot
/// paths with a dynamic number of already-canonical fields.
pub struct Blake2b384DomainHasher {
    hasher: Blake2b<U48>,
}

impl Blake2b384DomainHasher {
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = Blake2b::<U48>::new();
        hasher.update(BLAKE2B_384_FRAME_V1);
        hasher.update(
            u64::try_from(domain.len())
                .expect("BLAKE2b-384 domain length fits u64")
                .to_le_bytes(),
        );
        hasher.update(domain);
        Self { hasher }
    }

    pub fn update_part(&mut self, part: &[u8]) -> &mut Self {
        self.hasher.update(
            u64::try_from(part.len())
                .expect("BLAKE2b-384 part length fits u64")
                .to_le_bytes(),
        );
        self.hasher.update(part);
        self
    }

    pub fn finalize(self) -> ConsensusDigest48 {
        self.hasher.finalize().into()
    }
}

/// Fixed, allocation-free BLAKE2b-384 nonce-search context for V3 proof of work.
///
/// Construction commits exactly to
/// `hegemon.pow.work.blake2b-384.v3\0 || HeaderPrecommit48`. Each call to
/// [`Self::hash_nonce`] clones that preinitialized state, appends exactly one
/// [`Nonce32`], and finalizes a native 48-byte RFC 7693 digest. There is
/// deliberately no generic update method: callers cannot extend or reinterpret
/// the consensus work transcript.
#[derive(Clone)]
pub struct PowWorkContextV3 {
    preinitialized: Blake2b<U48>,
}

impl PowWorkContextV3 {
    pub fn new(precommit: HeaderPrecommit48) -> Self {
        let mut preinitialized = Blake2b::<U48>::new();
        preinitialized.update(domains::POW_WORK_V3);
        preinitialized.update(precommit.as_bytes());
        Self { preinitialized }
    }

    pub fn hash_nonce(&self, nonce: Nonce32) -> WorkHash48 {
        let mut hasher = self.preinitialized.clone();
        hasher.update(nonce);
        WorkHash48::new(hasher.finalize().into())
    }
}

/// One-shot form of [`PowWorkContextV3`] for verification paths.
pub fn pow_work_hash_v3(precommit: HeaderPrecommit48, nonce: Nonce32) -> WorkHash48 {
    PowWorkContextV3::new(precommit).hash_nonce(nonce)
}

pub mod domains {
    pub const RULES_MANIFEST_V3: &[u8] = b"hegemon.consensus.rules-manifest.v3";
    pub const ACTION_ID_V3: &[u8] = b"hegemon.native.action-id.v3";
    pub const ACTION_SEMANTIC_ID_V3: &[u8] = b"hegemon.native.action-semantic-id.v3";
    pub const ACTION_ROOT_V3: &[u8] = b"hegemon.native.action-root.v3";
    pub const HEADER_PRECOMMIT_V3: &[u8] = b"hegemon.consensus.header-precommit.v3";
    pub const POW_WORK_V3: &[u8] = b"hegemon.pow.work.blake2b-384.v3\0";
    pub const BLOCK_ID_V3: &[u8] = b"hegemon.consensus.block-id.v3";
    pub const HEADER_MMR_NODE_V3: &[u8] = b"hegemon.consensus.header-mmr.node.v3";
    pub const HEADER_MMR_ROOT_V3: &[u8] = b"hegemon.consensus.header-mmr.root.v3";
    pub const TRUSTED_CHECKPOINT_V3: &[u8] = b"hegemon.consensus.trusted-checkpoint.v3";
    pub const FLYCLIENT_SAMPLE_V3: &[u8] = b"hegemon.consensus.flyclient-sample.v3";
    pub const GENESIS_V3: &[u8] = b"hegemon.consensus.genesis.v3";
    pub const NATIVE_LIGHT_CLIENT_VERIFIER_V3: &[u8] = b"hegemon.native.light-client-verifier.v3";

    pub const NATIVE_BLOCK_BODY_V3: &[u8] = b"hegemon.native.block-body.v3";
    pub const NATIVE_ACTION_BODY_V3: &[u8] = b"hegemon.native.action-body.v3";
    pub const NATIVE_VERIFIED_BLOCK_RECORD_V3: &[u8] = b"hegemon.native.verified-block-record.v3";
    pub const NATIVE_CANONICAL_STATE_CHECKPOINT_V3: &[u8] =
        b"hegemon.native.canonical-state-checkpoint.v3";
    pub const NATIVE_NONCANONICAL_FORK_RECORD_V3: &[u8] =
        b"hegemon.native.noncanonical-fork-record.v3";
    pub const NATIVE_REORG_WAL_MANIFEST_V3: &[u8] = b"hegemon.native.reorg-wal-manifest.v3";
    pub const NATIVE_REORG_WAL_OP_V3: &[u8] = b"hegemon.native.reorg-wal-op.v3";
    pub const NATIVE_REORG_WAL_VALUE_V3: &[u8] = b"hegemon.native.reorg-wal-value.v3";

    pub const DA_CHUNK_LEAF_V3: &[u8] = b"hegemon.da.chunk.leaf.v3";
    pub const DA_CHUNK_NODE_V3: &[u8] = b"hegemon.da.chunk.node.v3";
    pub const DA_PAGE_LEAF_V3: &[u8] = b"hegemon.da.page.leaf.v3";
    pub const DA_PAGE_NODE_V3: &[u8] = b"hegemon.da.page.node.v3";

    pub const TRANSACTION_CIPHERTEXT_HASH_V2: &[u8] = b"hegemon.transaction.ciphertext-hash.v2";
    pub const TRANSACTION_ID_V2: &[u8] = b"hegemon.transaction.id.v2";
    pub const TRANSACTION_STATEMENT_V2: &[u8] = b"hegemon.transaction.statement.v2";
    pub const TRANSACTION_PROOF_ARTIFACT_V2: &[u8] = b"hegemon.transaction.proof-artifact.v2";
    pub const TRANSACTION_PUBLIC_INPUTS_V2: &[u8] = b"hegemon.transaction.public-inputs.v2";
    pub const TRANSACTION_VERIFIER_PROFILE_V2: &[u8] = b"hegemon.transaction.verifier-profile.v2";
    pub const TRANSACTION_MERKLE_LEAF_V3: &[u8] = b"hegemon.transaction.merkle-leaf.v3";
    pub const TRANSACTION_MERKLE_NODE_V3: &[u8] = b"hegemon.transaction.merkle-node.v3";
    pub const TRANSACTION_MERKLE_ROOT_V3: &[u8] = b"hegemon.transaction.merkle-root.v3";
    pub const TRANSACTION_BALANCE_TAG_V3: &[u8] = b"hegemon.transaction.balance-tag.v3";
    pub const CRYPTO_NOTE_COMMITMENT_V2: &[u8] = b"hegemon.crypto.note-commitment.v2";
    pub const CRYPTO_NULLIFIER_DERIVATION_V2: &[u8] = b"hegemon.crypto.nullifier-derivation.v2";
    pub const WALLET_SPEND_NULLIFIER_KEY_V3: &[u8] = b"hegemon.wallet.spend-nullifier-key.v3";
    pub const WALLET_VIEW_NULLIFIER_KEY_V3: &[u8] = b"hegemon.wallet.view-nullifier-key.v3";
    pub const WALLET_RECIPIENT_KEY_V3: &[u8] = b"hegemon.wallet.recipient-key.v3";
    pub const SMALLWOOD_SPEND_CREDENTIAL_V5: &[u8] = b"hegemon.smallwood.spend-credential.v5";
    pub const SMALLWOOD_AUTH_POLICY_V5: &[u8] = b"hegemon.smallwood.auth-policy.v5";
    pub const SMALLWOOD_AUTH_ACCUMULATOR_V5: &[u8] = b"hegemon.smallwood.auth-accumulator.v5";
    pub const SMALLWOOD_AUTH_VALUE_LOCK_V5: &[u8] = b"hegemon.smallwood.auth-value-lock.v5";
    pub const SMALLWOOD_AUTH_INTENT_V5: &[u8] = b"hegemon.smallwood.auth-intent.v5";
    pub const SMALLWOOD_RELATION_SCHEDULE_V5: &[u8] = b"hegemon.smallwood.relation-schedule.v5";

    pub const SUPERNEO_VERIFIER_PROFILE_V2: &[u8] = b"hegemon.superneo.verifier-profile.v2";
    pub const SUPERNEO_PROOF_ARTIFACT_V2: &[u8] = b"hegemon.superneo.proof-artifact.v2";
    pub const SUPERNEO_VERIFY_CACHE_V2: &[u8] = b"hegemon.superneo.verify-cache.v2";

    pub const CONSENSUS_KERNEL_ROOT_V3: &[u8] = b"hegemon.consensus.kernel-root.v3";
    pub const CONSENSUS_FEE_COMMITMENT_V3: &[u8] = b"hegemon.consensus.fee-commitment.v3";
    pub const CONSENSUS_PROOF_COMMITMENT_V3: &[u8] = b"hegemon.consensus.proof-commitment.v3";
    pub const CONSENSUS_VERSION_COMMITMENT_V3: &[u8] = b"hegemon.consensus.version-commitment.v3";
    pub const CONSENSUS_COMMITMENT_TREE_STATE_V3: &[u8] =
        b"hegemon.consensus.commitment-tree-state.v3";
    pub const CONSENSUS_BLOCK_NULLIFIER_LIST_V3: &[u8] =
        b"hegemon.consensus.block-nullifier-list.v3";

    pub const KERNEL_ACTION_STATEMENT_V2: &[u8] = b"hegemon.kernel.action-statement.v2";
    pub const KERNEL_GLOBAL_ROOT_V2: &[u8] = b"hegemon.kernel.global-root.v2";
    pub const KERNEL_STABLECOIN_POLICY_V2: &[u8] = b"hegemon.kernel.stablecoin-policy.v2";
    pub const KERNEL_PARAMS_COMMITMENT_V2: &[u8] = b"hegemon.kernel.params-commitment.v2";
    pub const KERNEL_FAMILY_COMMITMENT_V2: &[u8] = b"hegemon.kernel.family-commitment.v2";

    pub const BRIDGE_PAYLOAD_V2: &[u8] = b"hegemon.bridge.payload.v2";
    pub const BRIDGE_MESSAGE_V2: &[u8] = b"hegemon.bridge.message.v2";
    pub const BRIDGE_MESSAGE_ROOT_V2: &[u8] = b"hegemon.bridge.message-root.v2";
    pub const BRIDGE_INBOUND_REPLAY_V2: &[u8] = b"hegemon.bridge.inbound-replay.v2";
    pub const BRIDGE_CHECKPOINT_OUTPUT_V3: &[u8] = b"hegemon.bridge.checkpoint-output.v3";

    pub const NULLIFIER_MMR_LEAF_V2: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.leaf-v2";
    pub const NULLIFIER_MMR_NODE_V2: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.node-v2";
    pub const NULLIFIER_MMR_ROOT_V2: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.root-v2";
    pub const NULLIFIER_MMR_STATE_V2: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.state-v2";
    pub const NULLIFIER_MMR_LEAF_V3: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.leaf-v3";
    pub const NULLIFIER_MMR_NODE_V3: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.node-v3";
    pub const NULLIFIER_MMR_ROOT_V3: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.root-v3";
    pub const NULLIFIER_MMR_STATE_V3: &[u8] = b"hegemon.nullifier-mmr.blake2b-384.state-v3";
    pub const NATIVE_TX_LEAF_VERIFY_CACHE_V2: &[u8] = b"hegemon-native-tx-leaf-verify-cache-v2";

    pub const ALL: &[&[u8]] = &[
        RULES_MANIFEST_V3,
        ACTION_ID_V3,
        ACTION_SEMANTIC_ID_V3,
        ACTION_ROOT_V3,
        HEADER_PRECOMMIT_V3,
        POW_WORK_V3,
        BLOCK_ID_V3,
        HEADER_MMR_NODE_V3,
        HEADER_MMR_ROOT_V3,
        TRUSTED_CHECKPOINT_V3,
        FLYCLIENT_SAMPLE_V3,
        GENESIS_V3,
        NATIVE_LIGHT_CLIENT_VERIFIER_V3,
        NATIVE_BLOCK_BODY_V3,
        NATIVE_ACTION_BODY_V3,
        NATIVE_VERIFIED_BLOCK_RECORD_V3,
        NATIVE_CANONICAL_STATE_CHECKPOINT_V3,
        NATIVE_NONCANONICAL_FORK_RECORD_V3,
        NATIVE_REORG_WAL_MANIFEST_V3,
        NATIVE_REORG_WAL_OP_V3,
        NATIVE_REORG_WAL_VALUE_V3,
        DA_CHUNK_LEAF_V3,
        DA_CHUNK_NODE_V3,
        DA_PAGE_LEAF_V3,
        DA_PAGE_NODE_V3,
        TRANSACTION_CIPHERTEXT_HASH_V2,
        TRANSACTION_ID_V2,
        TRANSACTION_STATEMENT_V2,
        TRANSACTION_PROOF_ARTIFACT_V2,
        TRANSACTION_PUBLIC_INPUTS_V2,
        TRANSACTION_VERIFIER_PROFILE_V2,
        TRANSACTION_MERKLE_LEAF_V3,
        TRANSACTION_MERKLE_NODE_V3,
        TRANSACTION_MERKLE_ROOT_V3,
        TRANSACTION_BALANCE_TAG_V3,
        CRYPTO_NOTE_COMMITMENT_V2,
        CRYPTO_NULLIFIER_DERIVATION_V2,
        WALLET_SPEND_NULLIFIER_KEY_V3,
        WALLET_VIEW_NULLIFIER_KEY_V3,
        WALLET_RECIPIENT_KEY_V3,
        SMALLWOOD_SPEND_CREDENTIAL_V5,
        SMALLWOOD_AUTH_POLICY_V5,
        SMALLWOOD_AUTH_ACCUMULATOR_V5,
        SMALLWOOD_AUTH_VALUE_LOCK_V5,
        SMALLWOOD_AUTH_INTENT_V5,
        SMALLWOOD_RELATION_SCHEDULE_V5,
        SUPERNEO_VERIFIER_PROFILE_V2,
        SUPERNEO_PROOF_ARTIFACT_V2,
        SUPERNEO_VERIFY_CACHE_V2,
        CONSENSUS_KERNEL_ROOT_V3,
        CONSENSUS_FEE_COMMITMENT_V3,
        CONSENSUS_PROOF_COMMITMENT_V3,
        CONSENSUS_VERSION_COMMITMENT_V3,
        CONSENSUS_COMMITMENT_TREE_STATE_V3,
        CONSENSUS_BLOCK_NULLIFIER_LIST_V3,
        KERNEL_ACTION_STATEMENT_V2,
        KERNEL_GLOBAL_ROOT_V2,
        KERNEL_STABLECOIN_POLICY_V2,
        KERNEL_PARAMS_COMMITMENT_V2,
        KERNEL_FAMILY_COMMITMENT_V2,
        BRIDGE_PAYLOAD_V2,
        BRIDGE_MESSAGE_V2,
        BRIDGE_MESSAGE_ROOT_V2,
        BRIDGE_INBOUND_REPLAY_V2,
        BRIDGE_CHECKPOINT_OUTPUT_V3,
        NULLIFIER_MMR_LEAF_V2,
        NULLIFIER_MMR_NODE_V2,
        NULLIFIER_MMR_ROOT_V2,
        NULLIFIER_MMR_STATE_V2,
        NULLIFIER_MMR_LEAF_V3,
        NULLIFIER_MMR_NODE_V3,
        NULLIFIER_MMR_ROOT_V3,
        NULLIFIER_MMR_STATE_V3,
        NATIVE_TX_LEAF_VERIFY_CACHE_V2,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_384_known_answer() {
        assert_eq!(
            blake2b_384(b"abc"),
            hex48(
                b"6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
            )
        );
    }

    #[test]
    fn framed_known_answer_and_non_aliases() {
        let canonical = blake2b_384_domain_hash(b"domain-a", [b"ab".as_slice(), b"c"]);
        let mut incremental = Blake2b384DomainHasher::new(b"domain-a");
        incremental.update_part(b"ab").update_part(b"c");
        assert_eq!(incremental.finalize(), canonical);
        assert_eq!(
            canonical,
            hex48(
                b"b313d1b7ebd77d7ef47bc7623cdfbe2eb2ff36827289ae055c928fc69f2d753519f7c6f03e2210b5a5e4163a4761d343"
            )
        );
        assert_ne!(
            canonical,
            blake2b_384_domain_hash(b"domain-b", [b"ab".as_slice(), b"c"])
        );
        assert_ne!(
            canonical,
            blake2b_384_domain_hash(b"domain-a", [b"a".as_slice(), b"bc"])
        );
        assert_ne!(
            canonical,
            blake2b_384_domain_hash(b"domain-a", [b"ab".as_slice(), b"c", b""])
        );
    }

    #[test]
    fn pow_work_context_v3_known_answer_and_fixed_transcript() {
        assert_eq!(domains::POW_WORK_V3.len(), 32);
        assert_eq!(POW_WORK_TRANSCRIPT_BYTES_V3, 112);
        let precommit = HeaderPrecommit48::new([0x11; 48]);
        let nonce = [0x22; 32];
        let context = PowWorkContextV3::new(precommit);
        let expected = WorkHash48::new(hex48(
            b"5560947641df7a240d60f63c1c4f49b7551ff10a5ac4f4696d0662d2ecf7b4e7aa8edbc098d0a63fe21f2d71c1764f42"
        ));

        assert_eq!(context.hash_nonce(nonce), expected);
        assert_eq!(pow_work_hash_v3(precommit, nonce), expected);
        assert_ne!(context.hash_nonce([0x23; 32]), expected);
        assert_ne!(
            PowWorkContextV3::new(HeaderPrecommit48::new([0x12; 48])).hash_nonce(nonce),
            expected
        );
        assert_eq!(
            expected.into_bytes(),
            blake2b_384(&[domains::POW_WORK_V3, precommit.as_bytes(), &nonce,].concat())
        );
    }

    #[test]
    fn semantic_fixed_bytes_reject_wrong_widths() {
        assert_eq!(
            BlockId48::try_from(&[7u8; 48][..]).unwrap().as_bytes(),
            &[7u8; 48]
        );
        assert_eq!(
            Work64::try_from(&[9u8; 63][..]).unwrap_err(),
            InvalidFixedBytesLength {
                expected: 64,
                actual: 63,
            }
        );
    }

    #[test]
    fn poseidon_digest56_canonical_limb_and_little_endian_kat() {
        let limbs = [
            0,
            1,
            GOLDILOCKS_MODULUS - 1,
            0x0102_0304_0506_0708,
            42,
            0x7fff_ffff_ffff_ffff,
            GOLDILOCKS_MODULUS - 2,
        ];
        let digest = PoseidonDigest56::try_from_limbs(limbs).expect("canonical Poseidon limbs");
        let expected = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // p - 1
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xff, 0xff, 0xff, // p - 2
        ];
        assert_eq!(digest.to_le_bytes(), expected);
        assert_eq!(
            PoseidonDigest56::try_from_le_bytes(expected).unwrap(),
            digest
        );
        assert_eq!(digest.to_limbs(), limbs);

        let mut invalid_limbs = limbs;
        invalid_limbs[3] = GOLDILOCKS_MODULUS;
        assert_eq!(
            PoseidonDigest56::try_from_limbs(invalid_limbs),
            Err(InvalidPoseidonDigest::NonCanonicalLimb {
                index: 3,
                value: GOLDILOCKS_MODULUS,
            })
        );

        let mut invalid_bytes = expected;
        invalid_bytes[24..32].copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert_eq!(
            PoseidonDigest56::try_from_le_bytes(invalid_bytes),
            Err(InvalidPoseidonDigest::NonCanonicalLimb {
                index: 3,
                value: GOLDILOCKS_MODULUS,
            })
        );
        assert_eq!(
            PoseidonDigest56::try_from_le_bytes_slice(&[0u8; POSEIDON_DIGEST_BYTES + 1]),
            Err(InvalidPoseidonDigest::InvalidLength(
                InvalidFixedBytesLength {
                    expected: POSEIDON_DIGEST_BYTES,
                    actual: POSEIDON_DIGEST_BYTES + 1,
                }
            ))
        );
    }

    #[test]
    fn poseidon_external_layer_orientation_kat_rejects_legacy_order() {
        fn add(left: u64, right: u64) -> u64 {
            ((left as u128 + right as u128) % GOLDILOCKS_MODULUS as u128) as u64
        }

        fn p4(input: [u64; 4]) -> [u64; 4] {
            let sum = input.into_iter().fold(0, add);
            input.map(|value| add(value, sum))
        }

        fn m4(input: [u64; 4]) -> [u64; 4] {
            let [x0, x1, x2, x3] = input;
            let t01 = add(x0, x1);
            let t23 = add(x2, x3);
            let t0123 = add(t01, t23);
            let t01123 = add(t0123, x1);
            let t01233 = add(t0123, x3);
            [
                add(t01123, t01),
                add(t01123, add(x2, x2)),
                add(t01233, t23),
                add(t01233, add(x0, x0)),
            ]
        }

        let mut after_p4 = [0u64; 16];
        for (block, input) in POSEIDON_M4_TENSOR_P4_KAT_INPUT.chunks_exact(4).enumerate() {
            let transformed = p4(input.try_into().unwrap());
            after_p4[4 * block..4 * block + 4].copy_from_slice(&transformed);
        }
        let mut required = [0u64; 16];
        for lane in 0..4 {
            let transformed = m4([
                after_p4[lane],
                after_p4[4 + lane],
                after_p4[8 + lane],
                after_p4[12 + lane],
            ]);
            for block in 0..4 {
                required[4 * block + lane] = transformed[block];
            }
        }
        assert_eq!(required, POSEIDON_M4_TENSOR_P4_KAT_OUTPUT);

        let mut after_m4 = [0u64; 16];
        for (block, input) in POSEIDON_M4_TENSOR_P4_KAT_INPUT.chunks_exact(4).enumerate() {
            let transformed = m4(input.try_into().unwrap());
            after_m4[4 * block..4 * block + 4].copy_from_slice(&transformed);
        }
        let mut rejected = [0u64; 16];
        for lane in 0..4 {
            let transformed = p4([
                after_m4[lane],
                after_m4[4 + lane],
                after_m4[8 + lane],
                after_m4[12 + lane],
            ]);
            for block in 0..4 {
                rejected[4 * block + lane] = transformed[block];
            }
        }
        assert_eq!(rejected, POSEIDON_P4_TENSOR_M4_REJECTED_KAT_OUTPUT);
        assert_ne!(required, rejected);
    }

    #[test]
    fn consensus_domains_are_unique() {
        for (index, domain) in domains::ALL.iter().enumerate() {
            assert!(!domain.is_empty(), "domain {index} must not be empty");
            for (other_index, other) in domains::ALL.iter().enumerate().skip(index + 1) {
                assert_ne!(domain, other, "domains {index} and {other_index} alias");
            }
        }
    }

    #[cfg(feature = "codec")]
    #[test]
    fn scale_wire_is_fixed_width_without_a_length_prefix() {
        use codec::{Decode, Encode};

        let encoded = BlockId48::new([0xa5; 48]).encode();
        assert_eq!(encoded, [0xa5; 48]);
        assert_eq!(Work64::new([0x5a; 64]).encode(), [0x5a; 64]);

        let digest =
            PoseidonDigest56::try_from_limbs([0, 1, 2, 3, 4, 5, GOLDILOCKS_MODULUS - 1]).unwrap();
        let encoded = digest.encode();
        assert_eq!(encoded.len(), POSEIDON_DIGEST_BYTES);
        assert_eq!(
            PoseidonDigest56::decode_scale_exact(&encoded).unwrap(),
            digest
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(PoseidonDigest56::decode_scale_exact(&trailing).is_err());

        let mut invalid = encoded;
        invalid[..8].copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        let mut input = invalid.as_slice();
        assert!(PoseidonDigest56::decode(&mut input).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_wire_is_fixed_width_without_a_length_prefix() {
        use bincode::Options;

        let value = BodyHash48::new([0xa5; 48]);
        let encoded = bincode::serialize(&value).expect("serialize BodyHash48");
        assert_eq!(encoded, [0xa5; 48]);
        assert_eq!(
            bincode::deserialize::<BodyHash48>(&encoded).expect("deserialize BodyHash48"),
            value
        );

        let mut short = encoded.clone();
        short.pop();
        assert!(bincode::deserialize::<BodyHash48>(&short).is_err());

        let mut long = encoded.to_vec();
        long.push(0);
        assert!(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize::<BodyHash48>(&long)
            .is_err());

        let work = Work64::new([0x5a; 64]);
        assert_eq!(bincode::serialize(&work).unwrap(), [0x5a; 64]);

        let poseidon =
            PoseidonDigest56::try_from_limbs([0, 1, 2, 3, 4, 5, GOLDILOCKS_MODULUS - 1]).unwrap();
        let encoded = bincode::serialize(&poseidon).unwrap();
        assert_eq!(encoded, poseidon.to_le_bytes());
        assert_eq!(
            bincode::deserialize::<PoseidonDigest56>(&encoded).unwrap(),
            poseidon
        );

        let mut invalid = encoded.clone();
        invalid[..8].copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(bincode::deserialize::<PoseidonDigest56>(&invalid).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize::<PoseidonDigest56>(&trailing)
            .is_err());
    }

    fn hex48(hex: &[u8; 96]) -> [u8; 48] {
        fn nybble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid test hex"),
            }
        }

        let mut out = [0u8; 48];
        for (index, pair) in hex.chunks_exact(2).enumerate() {
            out[index] = (nybble(pair[0]) << 4) | nybble(pair[1]);
        }
        out
    }
}
