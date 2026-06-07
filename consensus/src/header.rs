use crate::error::ConsensusError;
use crate::types::{
    BlockHash, DaParams, DaRoot, FeeCommitment, NullifierRoot, StarkCommitment, StateRoot,
    SupplyDigest, ValidatorSetCommitment, VersionCommitment,
};
use crypto::hashes::sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub view: u64,
    pub timestamp_ms: u64,
    pub parent_hash: BlockHash,
    pub state_root: StateRoot,
    pub kernel_root: StateRoot,
    pub nullifier_root: NullifierRoot,
    pub proof_commitment: StarkCommitment,
    pub da_root: DaRoot,
    pub da_params: DaParams,
    pub version_commitment: VersionCommitment,
    pub tx_count: u32,
    pub fee_commitment: FeeCommitment,
    pub supply_digest: SupplyDigest,
    pub validator_set_commitment: ValidatorSetCommitment,
    pub signature_aggregate: Vec<u8>,
    pub signature_bitmap: Option<Vec<u8>>,
    pub pow: Option<PowSeal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowSeal {
    pub nonce: [u8; 32],
    pub pow_bits: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusMode {
    Bft,
    Pow,
}

impl BlockHeader {
    pub fn mode(&self) -> ConsensusMode {
        if self.pow.is_some() {
            ConsensusMode::Pow
        } else {
            ConsensusMode::Bft
        }
    }

    pub fn signing_hash(&self) -> Result<BlockHash, ConsensusError> {
        Ok(sha256(&self.signing_preimage_v1()))
    }

    pub fn hash(&self) -> Result<BlockHash, ConsensusError> {
        Ok(sha256(&self.full_header_preimage_v1()))
    }

    pub fn signing_preimage_v1(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"block");
        data.extend(encode_signing_fields(self));
        data
    }

    pub fn full_header_preimage_v1(&self) -> Vec<u8> {
        encode_full_header(self)
    }

    pub fn ensure_structure(&self) -> Result<(), ConsensusError> {
        match self.mode() {
            ConsensusMode::Bft => {
                if self
                    .signature_bitmap
                    .as_ref()
                    .is_none_or(|bm| bm.is_empty())
                {
                    return Err(ConsensusError::InvalidHeader("missing signature bitmap"));
                }
            }
            ConsensusMode::Pow => {
                if let Some(seal) = &self.pow {
                    if seal.pow_bits == 0 {
                        return Err(ConsensusError::InvalidHeader("pow bits missing"));
                    }
                } else {
                    return Err(ConsensusError::InvalidHeader("pow seal missing"));
                }
            }
        }
        Ok(())
    }
}

fn encode_signing_fields(header: &BlockHeader) -> Vec<u8> {
    let mut data = Vec::with_capacity(432);
    data.extend_from_slice(&header.version.to_le_bytes());
    data.extend_from_slice(&header.height.to_le_bytes());
    data.extend_from_slice(&header.view.to_le_bytes());
    data.extend_from_slice(&header.timestamp_ms.to_le_bytes());
    data.extend_from_slice(&header.parent_hash);
    data.extend_from_slice(&header.state_root);
    data.extend_from_slice(&header.kernel_root);
    data.extend_from_slice(&header.nullifier_root);
    data.extend_from_slice(&header.proof_commitment);
    data.extend_from_slice(&header.da_root);
    data.extend_from_slice(&header.da_params.chunk_size.to_le_bytes());
    data.extend_from_slice(&header.da_params.sample_count.to_le_bytes());
    data.extend_from_slice(&header.version_commitment);
    data.extend_from_slice(&header.tx_count.to_le_bytes());
    data.extend_from_slice(&header.fee_commitment);
    data.extend_from_slice(&header.supply_digest.to_le_bytes());
    data.extend_from_slice(&header.validator_set_commitment);
    data
}

fn encode_full_header(header: &BlockHeader) -> Vec<u8> {
    let mut data = encode_signing_fields(header);
    data.extend_from_slice(&(header.signature_aggregate.len() as u32).to_le_bytes());
    data.extend_from_slice(&header.signature_aggregate);
    match &header.signature_bitmap {
        Some(bitmap) => {
            data.push(1);
            data.extend_from_slice(&(bitmap.len() as u32).to_le_bytes());
            data.extend_from_slice(bitmap);
        }
        None => data.push(0),
    }
    match &header.pow {
        Some(seal) => {
            data.push(1);
            data.extend_from_slice(&seal.nonce);
            data.extend_from_slice(&seal.pow_bits.to_le_bytes());
        }
        None => data.push(0),
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DaParams;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderVectorFile {
        schema_version: u32,
        header_preimage_cases: Vec<LeanHeaderCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderCase {
        name: String,
        version: u32,
        height: u64,
        view: u64,
        timestamp_ms: u64,
        parent_hash: String,
        state_root: String,
        kernel_root: String,
        nullifier_root: String,
        proof_commitment: String,
        da_root: String,
        da_params: LeanDaParams,
        version_commitment: String,
        tx_count: u32,
        fee_commitment: String,
        supply_digest: String,
        validator_set_commitment: String,
        signature_aggregate: String,
        signature_bitmap: Option<String>,
        pow: Option<LeanPowSeal>,
        expected_signing_preimage_len: usize,
        expected_full_header_preimage_len: usize,
        expected_signing_preimage: String,
        expected_full_header_preimage: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaParams {
        chunk_size: u32,
        sample_count: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowSeal {
        nonce: String,
        pow_bits: u32,
    }

    #[test]
    fn lean_generated_header_preimage_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_HEADER_VECTORS") else {
            eprintln!("HEGEMON_LEAN_HEADER_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean header vectors");
        let vectors: LeanHeaderVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean header vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            vectors.header_preimage_cases.len() >= 4,
            "Lean header cases cover too few preimage branches"
        );

        let mut names = std::collections::BTreeSet::new();
        let mut signing_preimages = std::collections::BTreeMap::new();
        for case in &vectors.header_preimage_cases {
            assert!(names.insert(case.name.clone()));
            let signing_preimage = verify_header_preimage_case(case);
            signing_preimages.insert(case.name.as_str(), signing_preimage);
        }

        assert_eq!(
            signing_preimages.get("pow-header-preimage"),
            signing_preimages.get("signing-preimage-auth-payload-independent"),
            "signing preimage must ignore auth payload, signature bitmap, and PoW seal fields"
        );
    }

    fn verify_header_preimage_case(case: &LeanHeaderCase) -> Vec<u8> {
        let header = BlockHeader {
            version: case.version,
            height: case.height,
            view: case.view,
            timestamp_ms: case.timestamp_ms,
            parent_hash: decode_fixed_hex(&case.parent_hash),
            state_root: decode_fixed_hex(&case.state_root),
            kernel_root: decode_fixed_hex(&case.kernel_root),
            nullifier_root: decode_fixed_hex(&case.nullifier_root),
            proof_commitment: decode_fixed_hex(&case.proof_commitment),
            da_root: decode_fixed_hex(&case.da_root),
            da_params: DaParams {
                chunk_size: case.da_params.chunk_size,
                sample_count: case.da_params.sample_count,
            },
            version_commitment: decode_fixed_hex(&case.version_commitment),
            tx_count: case.tx_count,
            fee_commitment: decode_fixed_hex(&case.fee_commitment),
            supply_digest: case
                .supply_digest
                .parse::<u128>()
                .expect("Lean supply digest fits u128"),
            validator_set_commitment: decode_fixed_hex(&case.validator_set_commitment),
            signature_aggregate: decode_hex_vec(&case.signature_aggregate),
            signature_bitmap: case.signature_bitmap.as_deref().map(decode_hex_vec),
            pow: case.pow.as_ref().map(|seal| PowSeal {
                nonce: decode_fixed_hex(&seal.nonce),
                pow_bits: seal.pow_bits,
            }),
        };

        let signing_preimage = header.signing_preimage_v1();
        let full_header_preimage = header.full_header_preimage_v1();
        assert_eq!(
            signing_preimage.len(),
            case.expected_signing_preimage_len,
            "{} signing preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            full_header_preimage.len(),
            case.expected_full_header_preimage_len,
            "{} full-header preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            signing_preimage,
            decode_hex_vec(&case.expected_signing_preimage),
            "{} signing preimage bytes drifted from Lean spec",
            case.name
        );
        assert_eq!(
            full_header_preimage,
            decode_hex_vec(&case.expected_full_header_preimage),
            "{} full-header preimage bytes drifted from Lean spec",
            case.name
        );
        signing_preimage
    }

    fn decode_fixed_hex<const N: usize>(value: &str) -> [u8; N] {
        let decoded = decode_hex_vec(value);
        decoded
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
    }

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        let Some(hex) = value.strip_prefix("0x") else {
            panic!("hex value must start with 0x");
        };
        hex::decode(hex).expect("valid hex from Lean")
    }
}
