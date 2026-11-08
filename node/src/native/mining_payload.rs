//! Exact additive metadata carriage for the scheduled mining version.
use super::*;
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserializer, Serializer,
};

pub(crate) const NATIVE_MINING_META_MARKER: &[u8; 32] = b"hegemon-mining-metadata-v1\0\0\0\0\0\0";
pub(crate) const NATIVE_MINING_META_PREFIX_BYTES: usize = 36;

/// Prefix length is determined before reading any attacker-sized vectors.
pub(crate) fn native_mining_meta_payload_offset(bytes: &[u8]) -> usize {
    if bytes.starts_with(NATIVE_MINING_META_MARKER) {
        NATIVE_MINING_META_PREFIX_BYTES
    } else {
        0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "NativeBlockMeta")]
struct HumanReadableMeta {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
    #[serde(default = "native_empty_digest48_default", with = "serde_array48")]
    da_root: [u8; 48],
    #[serde(default)]
    da_chunk_size: u32,
    #[serde(default)]
    da_sample_count: u32,
    #[serde(default)]
    da_blob_len: u64,
    #[serde(default)]
    da_chunk_count: u32,
    mining_version: Option<u32>,
}

#[derive(Serialize)]
struct MiningMetaRef<'a> {
    chain_id: &'a [u8; 32],
    rules_hash: &'a [u8; 32],
    height: &'a u64,
    hash: &'a [u8; 32],
    parent_hash: &'a [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: &'a [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: &'a [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: &'a [u8; 48],
    extrinsics_root: &'a [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: &'a [u8; 48],
    message_count: &'a u32,
    header_mmr_root: &'a [u8; 32],
    header_mmr_len: &'a u64,
    timestamp_ms: &'a u64,
    pow_bits: &'a u32,
    nonce: &'a [u8; 32],
    work_hash: &'a [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: &'a [u8; 48],
    supply_digest: &'a u128,
    tx_count: &'a u32,
    action_bytes: &'a Vec<Vec<u8>>,
    #[serde(with = "serde_array48")]
    da_root: &'a [u8; 48],
    da_chunk_size: &'a u32,
    da_sample_count: &'a u32,
    da_blob_len: &'a u64,
    da_chunk_count: &'a u32,
}

impl Serialize for NativeBlockMeta {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            return HumanReadableMeta::serialize(self, serializer);
        }
        if self.chain_id == *NATIVE_MINING_META_MARKER {
            return Err(serde::ser::Error::custom(
                "reserved mining metadata marker cannot be a chain identity",
            ));
        }
        let body = MiningMetaRef {
            chain_id: &self.chain_id,
            rules_hash: &self.rules_hash,
            height: &self.height,
            hash: &self.hash,
            parent_hash: &self.parent_hash,
            state_root: &self.state_root,
            kernel_root: &self.kernel_root,
            nullifier_root: &self.nullifier_root,
            extrinsics_root: &self.extrinsics_root,
            message_root: &self.message_root,
            message_count: &self.message_count,
            header_mmr_root: &self.header_mmr_root,
            header_mmr_len: &self.header_mmr_len,
            timestamp_ms: &self.timestamp_ms,
            pow_bits: &self.pow_bits,
            nonce: &self.nonce,
            work_hash: &self.work_hash,
            cumulative_work: &self.cumulative_work,
            supply_digest: &self.supply_digest,
            tx_count: &self.tx_count,
            action_bytes: &self.action_bytes,
            da_root: &self.da_root,
            da_chunk_size: &self.da_chunk_size,
            da_sample_count: &self.da_sample_count,
            da_blob_len: &self.da_blob_len,
            da_chunk_count: &self.da_chunk_count,
        };
        if let Some(version) = self.mining_version {
            let mut envelope = serializer.serialize_tuple(3)?;
            envelope.serialize_element(NATIVE_MINING_META_MARKER)?;
            envelope.serialize_element(&version)?;
            envelope.serialize_element(&body)?;
            envelope.end()
        } else {
            body.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for NativeBlockMeta {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            return HumanReadableMeta::deserialize(deserializer);
        }
        struct MetaVisitor;
        impl<'de> Visitor<'de> for MetaVisitor {
            type Value = NativeBlockMeta;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("exact historical native metadata or marked mining metadata")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                macro_rules! next {
                    ($ty:ty) => {
                        seq.next_element::<$ty>()?
                            .ok_or_else(|| A::Error::custom("truncated native mining metadata"))?
                    };
                }
                let first = next!([u8; 32]);
                let (mining_version, chain_id) = if first == *NATIVE_MINING_META_MARKER {
                    let version = next!(u32);
                    (Some(version), next!([u8; 32]))
                } else {
                    (None, first)
                };
                if chain_id == *NATIVE_MINING_META_MARKER {
                    return Err(A::Error::custom(
                        "reserved mining metadata marker cannot be a chain identity",
                    ));
                }
                Ok(NativeBlockMeta {
                    chain_id,
                    mining_version,
                    rules_hash: next!([u8; 32]),
                    height: next!(u64),
                    hash: next!([u8; 32]),
                    parent_hash: next!([u8; 32]),
                    state_root: {
                        let bytes = next!(serde_bytes::ByteBuf);
                        bytes
                            .as_ref()
                            .try_into()
                            .map_err(|_| A::Error::custom("expected 48 bytes"))?
                    },
                    kernel_root: {
                        let bytes = next!(serde_bytes::ByteBuf);
                        bytes
                            .as_ref()
                            .try_into()
                            .map_err(|_| A::Error::custom("expected 48 bytes"))?
                    },
                    nullifier_root: {
                        let bytes = next!(serde_bytes::ByteBuf);
                        bytes
                            .as_ref()
                            .try_into()
                            .map_err(|_| A::Error::custom("expected 48 bytes"))?
                    },
                    extrinsics_root: next!([u8; 32]),
                    message_root: {
                        let bytes = next!(serde_bytes::ByteBuf);
                        bytes
                            .as_ref()
                            .try_into()
                            .map_err(|_| A::Error::custom("expected 48 bytes"))?
                    },
                    message_count: next!(u32),
                    header_mmr_root: next!([u8; 32]),
                    header_mmr_len: next!(u64),
                    timestamp_ms: next!(u64),
                    pow_bits: next!(u32),
                    nonce: next!([u8; 32]),
                    work_hash: next!([u8; 32]),
                    cumulative_work: {
                        let bytes = next!(serde_bytes::ByteBuf);
                        bytes
                            .as_ref()
                            .try_into()
                            .map_err(|_| A::Error::custom("expected 48 bytes"))?
                    },
                    supply_digest: next!(u128),
                    tx_count: next!(u32),
                    action_bytes: next!(Vec<Vec<u8>>),
                    da_root: {
                        let bytes = next!(serde_bytes::ByteBuf);
                        bytes
                            .as_ref()
                            .try_into()
                            .map_err(|_| A::Error::custom("expected 48 bytes"))?
                    },
                    da_chunk_size: next!(u32),
                    da_sample_count: next!(u32),
                    da_blob_len: next!(u64),
                    da_chunk_count: next!(u32),
                })
            }
        }
        // Bincode tuples have no encoded element count. The visitor consumes
        // exactly one legacy record or the explicit prefix plus that record,
        // so metadata remains unambiguous inside vectors and sync messages.
        deserializer.deserialize_tuple(31, MetaVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen pre-upgrade bincode record: all scalar/byte values zero, exact
    // historical 48-byte serde lengths, no actions. Kept as bytes rather than
    // regenerated through the changed serializer.
    const HISTORICAL_HEX: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn mining_payload_preserves_historical_bytes_and_vector_boundaries() {
        let historical = hex::decode(HISTORICAL_HEX).unwrap();
        let old =
            bincode_deserialize_native_block_meta_exact(&historical, "historical mining fixture")
                .unwrap();
        assert_eq!(old.mining_version, None);
        assert_eq!(bincode::serialize(&old).unwrap(), historical);
        let mut rolled = old.clone();
        rolled.mining_version = Some(consensus_light_client::BITCOIN80_VERSION | 32);
        let encoded = bincode::serialize(&rolled).unwrap();
        assert_eq!(encoded.len(), historical.len() + 36);
        assert_eq!(&encoded[..32], NATIVE_MINING_META_MARKER);
        assert_eq!(
            &encoded[32..36],
            &(consensus_light_client::BITCOIN80_VERSION | 32).to_le_bytes()
        );
        assert_eq!(&encoded[36..], historical);
        assert_eq!(
            bincode_deserialize_native_block_meta_exact(&encoded, "rolled fixture").unwrap(),
            rolled
        );
        let vector = vec![old.clone(), rolled.clone(), old];
        let bytes = bincode::serialize(&vector).unwrap();
        assert_eq!(
            bincode_deserialize_exact::<Vec<NativeBlockMeta>>(&bytes, "mixed metadata vector")
                .unwrap(),
            vector
        );
        for cut in [0, 31, 32, 35, 36, encoded.len() - 1] {
            assert!(bincode_deserialize_native_block_meta_exact(
                &encoded[..cut],
                "truncated mining fixture"
            )
            .is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(
            bincode_deserialize_native_block_meta_exact(&trailing, "trailing mining fixture")
                .is_err()
        );
        let mut aliased = encoded;
        aliased[36..68].copy_from_slice(NATIVE_MINING_META_MARKER);
        assert!(
            bincode_deserialize_native_block_meta_exact(&aliased, "reserved chain identity")
                .is_err()
        );
        rolled.chain_id = *NATIVE_MINING_META_MARKER;
        assert!(bincode::serialize(&rolled).is_err());
    }

    #[test]
    fn mining_payload_budget_uses_marked_action_offset() {
        let mut bytes = Vec::from(NATIVE_MINING_META_MARKER.as_slice());
        bytes.extend_from_slice(&consensus_light_client::BITCOIN80_VERSION.to_le_bytes());
        bytes.resize(36 + NATIVE_BLOCK_META_ACTION_BYTES_OFFSET, 0);
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            validate_native_block_meta_bincode_budget(&bytes, "marked oversized action count")
                .is_err()
        );
    }
}
