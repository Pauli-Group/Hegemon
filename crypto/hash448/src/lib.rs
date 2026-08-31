//! Typed SHAKE256-448 bindings for the inactive fresh-genesis V6 schema.
//!
//! This package is deliberately not re-exported by `synthetic-crypto` and is
//! not consumed by an active version map.  It owns the prospective V6 byte
//! widths, domain registry, and host-side reference functions.  Historical
//! 32-byte and 48-byte values have no conversion into these types.

#![no_std]
#![forbid(unsafe_code)]

use core::fmt;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub const SHAKE256_448_BYTES: usize = 56;
pub const SHAKE256_448_BITS: usize = SHAKE256_448_BYTES * 8;
pub const SHAKE256_448_CONSENSUS_FRAME_V1: &[u8] = b"hegemon.shake256-448.consensus-frame.v1";

pub type ConsensusDigest56 = [u8; SHAKE256_448_BYTES];

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
pub enum V6HashError {
    ZeroChainIdentity(&'static str),
}

impl fmt::Display for V6HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroChainIdentity(field) => write!(formatter, "V6 {field} must not be zero"),
        }
    }
}

macro_rules! fixed_bytes_type {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
        #[cfg_attr(feature = "type-info", derive(scale_info::TypeInfo))]
        pub struct $name([u8; SHAKE256_448_BYTES]);

        impl $name {
            pub const ZERO: Self = Self([0; SHAKE256_448_BYTES]);

            pub const fn new(bytes: [u8; SHAKE256_448_BYTES]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; SHAKE256_448_BYTES] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; SHAKE256_448_BYTES] {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl From<[u8; SHAKE256_448_BYTES]> for $name {
            fn from(bytes: [u8; SHAKE256_448_BYTES]) -> Self {
                Self::new(bytes)
            }
        }

        impl From<$name> for [u8; SHAKE256_448_BYTES] {
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
                let inner = <[u8; SHAKE256_448_BYTES]>::try_from(bytes).map_err(|_| {
                    InvalidFixedBytesLength {
                        expected: SHAKE256_448_BYTES,
                        actual,
                    }
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

                let mut tuple = serializer.serialize_tuple(SHAKE256_448_BYTES)?;
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
                serde_fixed::deserialize::<D, SHAKE256_448_BYTES>(deserializer).map(Self::new)
            }
        }
    };
}

fixed_bytes_type!(ChainId56);
fixed_bytes_type!(GenesisId56);
fixed_bytes_type!(RulesHash56);
fixed_bytes_type!(BlockId56);
fixed_bytes_type!(ActionId56);
fixed_bytes_type!(ActionSemanticId56);
fixed_bytes_type!(ActionRoot56);
fixed_bytes_type!(StateRoot56);
fixed_bytes_type!(NoteCommitment56);
fixed_bytes_type!(NullifierKey56);
fixed_bytes_type!(Nullifier56);
fixed_bytes_type!(MerkleNode56);
fixed_bytes_type!(MerkleRoot56);
fixed_bytes_type!(CommitmentTreeRoot56);
fixed_bytes_type!(NullifierAccumulatorRoot56);
fixed_bytes_type!(CiphertextHash56);
fixed_bytes_type!(BalanceTag56);
fixed_bytes_type!(ProofBinding56);

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
            let mut output = [0; N];
            for (index, slot) in output.iter_mut().enumerate() {
                *slot = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(index, &self))?;
            }
            if sequence.next_element::<u8>()?.is_some() {
                return Err(A::Error::invalid_length(N + 1, &self));
            }
            Ok(output)
        }
    }
}

pub mod domains {
    pub const RULES_MANIFEST_V6: &[u8] = b"hegemon.v6.rules-manifest.shake256-448.v1";
    pub const GENESIS_ID_V6: &[u8] = b"hegemon.v6.genesis-id.shake256-448.v1";
    pub const CHAIN_ID_V6: &[u8] = b"hegemon.v6.chain-id.shake256-448.v1";
    pub const BLOCK_ID_V6: &[u8] = b"hegemon.v6.block-id.shake256-448.v1";
    pub const ACTION_ID_V6: &[u8] = b"hegemon.v6.action-id.shake256-448.v1";
    pub const ACTION_SEMANTIC_ID_V6: &[u8] = b"hegemon.v6.action-semantic-id.shake256-448.v1";
    pub const ACTION_ROOT_V6: &[u8] = b"hegemon.v6.action-root.shake256-448.v1";
    pub const COMMITMENT_TREE_ROOT_V6: &[u8] = b"hegemon.v6.commitment-tree-root.shake256-448.v1";
    pub const NULLIFIER_ACCUMULATOR_ROOT_V6: &[u8] =
        b"hegemon.v6.nullifier-accumulator-root.shake256-448.v1";
    pub const STATE_ROOT_V6: &[u8] = b"hegemon.v6.state-root.shake256-448.v1";
    pub const TRANSACTION_PROOF_BINDING_V6: &[u8] =
        b"hegemon.v6.transaction-proof-binding.shake256-448.v1";

    pub const ALL: &[&[u8]] = &[
        RULES_MANIFEST_V6,
        GENESIS_ID_V6,
        CHAIN_ID_V6,
        BLOCK_ID_V6,
        ACTION_ID_V6,
        ACTION_SEMANTIC_ID_V6,
        ACTION_ROOT_V6,
        COMMITMENT_TREE_ROOT_V6,
        NULLIFIER_ACCUMULATOR_ROOT_V6,
        STATE_ROOT_V6,
        TRANSACTION_PROOF_BINDING_V6,
    ];
}

struct ConsensusDomainHasher {
    state: Shake256,
}

fn consensus_wire_length(length: usize) -> u64 {
    u64::try_from(length).expect("consensus frame length exceeds u64")
}

impl ConsensusDomainHasher {
    fn new(domain: &[u8]) -> Self {
        let mut state = Shake256::default();
        state.update(SHAKE256_448_CONSENSUS_FRAME_V1);
        state.update(&consensus_wire_length(domain.len()).to_be_bytes());
        state.update(domain);
        Self { state }
    }

    fn update_part(&mut self, part: &[u8]) -> &mut Self {
        self.state
            .update(&consensus_wire_length(part.len()).to_be_bytes());
        self.state.update(part);
        self
    }

    fn finalize(self) -> ConsensusDigest56 {
        finalize_448(self.state)
    }
}

fn consensus_hash(domain: &[u8], parts: &[&[u8]]) -> ConsensusDigest56 {
    let mut hasher = ConsensusDomainHasher::new(domain);
    for part in parts {
        hasher.update_part(part);
    }
    hasher.finalize()
}

fn finalize_448(state: Shake256) -> ConsensusDigest56 {
    let mut reader = state.finalize_xof();
    let mut output = [0; SHAKE256_448_BYTES];
    reader.read(&mut output);
    output
}

fn is_zero(bytes: &[u8; SHAKE256_448_BYTES]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V6ChainContext {
    pub network_id: u32,
    pub chain_id: ChainId56,
    pub genesis_id: GenesisId56,
    pub rules_hash: RulesHash56,
}

impl V6ChainContext {
    pub fn new(
        network_id: u32,
        chain_id: ChainId56,
        genesis_id: GenesisId56,
        rules_hash: RulesHash56,
    ) -> Result<Self, V6HashError> {
        for (name, bytes) in [
            ("chain id", chain_id.as_bytes()),
            ("genesis id", genesis_id.as_bytes()),
            ("rules hash", rules_hash.as_bytes()),
        ] {
            if is_zero(bytes) {
                return Err(V6HashError::ZeroChainIdentity(name));
            }
        }
        Ok(Self {
            network_id,
            chain_id,
            genesis_id,
            rules_hash,
        })
    }
}

pub fn rules_hash_v6(canonical_rules_manifest: &[u8]) -> RulesHash56 {
    RulesHash56::new(consensus_hash(
        domains::RULES_MANIFEST_V6,
        &[canonical_rules_manifest],
    ))
}

pub fn genesis_id_v6(
    network_id: u32,
    rules_hash: RulesHash56,
    canonical_genesis_body_without_id: &[u8],
) -> GenesisId56 {
    let network = network_id.to_be_bytes();
    GenesisId56::new(consensus_hash(
        domains::GENESIS_ID_V6,
        &[
            &network,
            rules_hash.as_bytes(),
            canonical_genesis_body_without_id,
        ],
    ))
}

pub fn chain_id_v6(network_id: u32, genesis_id: GenesisId56, rules_hash: RulesHash56) -> ChainId56 {
    let network = network_id.to_be_bytes();
    ChainId56::new(consensus_hash(
        domains::CHAIN_ID_V6,
        &[&network, genesis_id.as_bytes(), rules_hash.as_bytes()],
    ))
}

pub fn derive_chain_context_v6(
    network_id: u32,
    canonical_rules_manifest: &[u8],
    canonical_genesis_body_without_id: &[u8],
) -> Result<V6ChainContext, V6HashError> {
    let rules_hash = rules_hash_v6(canonical_rules_manifest);
    let genesis_id = genesis_id_v6(network_id, rules_hash, canonical_genesis_body_without_id);
    let chain_id = chain_id_v6(network_id, genesis_id, rules_hash);
    V6ChainContext::new(network_id, chain_id, genesis_id, rules_hash)
}

pub fn block_id_v6(context: V6ChainContext, canonical_block_body_without_id: &[u8]) -> BlockId56 {
    let network = context.network_id.to_be_bytes();
    BlockId56::new(consensus_hash(
        domains::BLOCK_ID_V6,
        &[
            &network,
            context.chain_id.as_bytes(),
            context.genesis_id.as_bytes(),
            context.rules_hash.as_bytes(),
            canonical_block_body_without_id,
        ],
    ))
}

/// Hash the exact canonical V6 action body excluding its embedded self-id.
/// The body includes the unchanged inline proof envelope and every other
/// consensus field.  The canonical parser must run before this function.
pub fn action_id_v6(canonical_action_body_without_id: &[u8]) -> ActionId56 {
    ActionId56::new(consensus_hash(
        domains::ACTION_ID_V6,
        &[canonical_action_body_without_id],
    ))
}

pub fn action_semantic_id_v6(action_id: ActionId56) -> ActionSemanticId56 {
    ActionSemanticId56::new(consensus_hash(
        domains::ACTION_SEMANTIC_ID_V6,
        &[action_id.as_bytes()],
    ))
}

pub fn action_root_v6(action_ids: &[ActionId56]) -> ActionRoot56 {
    let count = consensus_wire_length(action_ids.len()).to_be_bytes();
    let mut hasher = ConsensusDomainHasher::new(domains::ACTION_ROOT_V6);
    hasher.update_part(&count);
    for action_id in action_ids {
        hasher.update_part(action_id.as_bytes());
    }
    ActionRoot56::new(hasher.finalize())
}

/// Re-type the transaction relation's exact note-commitment bytes as a Merkle
/// leaf. The transaction statement module, not this consensus package, owns
/// `HEG-F6V2`, the `note.cm3` frame, and its SHAKE constraints.
pub const fn merkle_leaf_v6(commitment: NoteCommitment56) -> MerkleNode56 {
    MerkleNode56::new(commitment.into_bytes())
}

/// Re-type the final relation-computed `merk.nd2` node as the public root.
pub const fn merkle_root_v6(node: MerkleNode56) -> MerkleRoot56 {
    MerkleRoot56::new(node.into_bytes())
}

pub fn commitment_tree_root_v6(leaf_count: u64, merkle_root: MerkleRoot56) -> CommitmentTreeRoot56 {
    let leaf_count = leaf_count.to_be_bytes();
    CommitmentTreeRoot56::new(consensus_hash(
        domains::COMMITMENT_TREE_ROOT_V6,
        &[&leaf_count, merkle_root.as_bytes()],
    ))
}

pub fn nullifier_accumulator_root_v6(
    nullifier_count: u64,
    canonical_accumulator_state: &[u8],
) -> NullifierAccumulatorRoot56 {
    let count = nullifier_count.to_be_bytes();
    NullifierAccumulatorRoot56::new(consensus_hash(
        domains::NULLIFIER_ACCUMULATOR_ROOT_V6,
        &[&count, canonical_accumulator_state],
    ))
}

pub fn state_root_v6(
    context: V6ChainContext,
    height: u64,
    commitment_root: CommitmentTreeRoot56,
    nullifier_root: NullifierAccumulatorRoot56,
) -> StateRoot56 {
    let network = context.network_id.to_be_bytes();
    let height = height.to_be_bytes();
    StateRoot56::new(consensus_hash(
        domains::STATE_ROOT_V6,
        &[
            &network,
            context.chain_id.as_bytes(),
            context.genesis_id.as_bytes(),
            context.rules_hash.as_bytes(),
            &height,
            commitment_root.as_bytes(),
            nullifier_root.as_bytes(),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_202_shake256_448_known_answers() {
        assert_eq!(
            raw_shake256_448(b""),
            hex56(b"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab486")
        );
        assert_eq!(
            raw_shake256_448(b"abc"),
            hex56(b"483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4f")
        );
    }

    #[test]
    fn action_id_frame_known_answer_and_domain_separation() {
        assert_eq!(
            action_id_v6(b"abc").into_bytes(),
            hex56(b"1f077dad326e9d9d9b5cfd84be7db1ce7654eeb87d674b4a07ca5f1e44fac08823a03a73c12754fe2789855afe28254e0bc475a111999c70")
        );
        assert_ne!(
            action_id_v6(b"abc").as_bytes(),
            rules_hash_v6(b"abc").as_bytes()
        );
        assert_ne!(action_id_v6(b"ab"), action_id_v6(b"abc"));
    }

    #[test]
    fn chain_context_binds_network_rules_and_genesis_without_compression() {
        let first = derive_chain_context_v6(7, b"rules", b"genesis").unwrap();
        let network = derive_chain_context_v6(8, b"rules", b"genesis").unwrap();
        let rules = derive_chain_context_v6(7, b"ruleS", b"genesis").unwrap();
        let genesis = derive_chain_context_v6(7, b"rules", b"genesiS").unwrap();
        assert_ne!(first, network);
        assert_ne!(first, rules);
        assert_ne!(first, genesis);
        assert_ne!(first.chain_id.as_bytes(), first.genesis_id.as_bytes());
        assert_ne!(first.chain_id.as_bytes(), first.rules_hash.as_bytes());
    }

    #[test]
    fn action_root_binds_count_order_and_every_id() {
        let a = action_id_v6(b"a");
        let b = action_id_v6(b"b");
        assert_ne!(action_root_v6(&[a]), action_root_v6(&[a, b]));
        assert_ne!(action_root_v6(&[a, b]), action_root_v6(&[b, a]));
        assert_ne!(action_root_v6(&[a, b]), action_root_v6(&[a, a]));
    }

    #[test]
    fn exact_widths_reject_every_legacy_digest() {
        for legacy_width in [32usize, 48] {
            let bytes = [0xa5; 56];
            assert_eq!(
                ChainId56::try_from(&bytes[..legacy_width]),
                Err(InvalidFixedBytesLength {
                    expected: 56,
                    actual: legacy_width,
                })
            );
            assert_eq!(
                ActionId56::try_from(&bytes[..legacy_width]),
                Err(InvalidFixedBytesLength {
                    expected: 56,
                    actual: legacy_width,
                })
            );
        }
        assert_eq!(
            V6ChainContext::new(
                7,
                ChainId56::ZERO,
                GenesisId56::new([1; 56]),
                RulesHash56::new([2; 56]),
            ),
            Err(V6HashError::ZeroChainIdentity("chain id"))
        );
    }

    #[test]
    fn registered_domains_are_unique() {
        for (index, domain) in domains::ALL.iter().enumerate() {
            assert!(!domain.is_empty());
            for other in domains::ALL.iter().skip(index + 1) {
                assert_ne!(domain, other);
            }
        }
    }

    #[cfg(feature = "codec")]
    #[test]
    fn scale_wire_is_exactly_56_bytes() {
        use codec::{Decode, Encode};

        let value = ActionId56::new([0xa5; 56]);
        assert_eq!(value.encode(), [0xa5; 56]);
        let mut input = value.as_bytes().as_slice();
        assert_eq!(ActionId56::decode(&mut input).unwrap(), value);
        assert!(input.is_empty());
        let mut short = &value.as_bytes()[..55];
        assert!(ActionId56::decode(&mut short).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_wire_is_exactly_56_bytes_and_rejects_trailing() {
        use bincode::Options;

        let value = ActionId56::new([0xa5; 56]);
        let encoded = bincode::serialize(&value).unwrap();
        assert_eq!(encoded, [0xa5; 56]);
        assert_eq!(bincode::deserialize::<ActionId56>(&encoded).unwrap(), value);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize::<ActionId56>(&trailing)
            .is_err());
    }

    fn raw_shake256_448(bytes: &[u8]) -> [u8; 56] {
        let mut state = Shake256::default();
        state.update(bytes);
        finalize_448(state)
    }

    fn hex56(hex: &[u8; 112]) -> [u8; 56] {
        fn nybble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid test hex"),
            }
        }

        let mut output = [0; 56];
        for (index, pair) in hex.chunks_exact(2).enumerate() {
            output[index] = (nybble(pair[0]) << 4) | nybble(pair[1]);
        }
        output
    }
}
