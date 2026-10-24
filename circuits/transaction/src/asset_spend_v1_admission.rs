//! Bounded native admission for the separately identified controlled-asset path.
//!
//! This module adds framing/resource/freshness checks, not production authority.
//! The node must authenticate the current policy row and global spent-nullifier
//! set, prepare supply/collateral accounting, verify the proof, then atomically
//! append the three outputs and two nullifiers to the shared native pool.
#![forbid(unsafe_code)]

use crate::asset_policy_admin_v1::{self as admin, PolicyAdminPublicV1};
use crate::asset_spend_v1::{self as spend, AssetSpendPublic};
use transaction_core::{
    asset_registry_v1::{validate_asset_policy_v1, AssetPolicyV1, AssetRegistryErrorV1},
    poseidon2_width16::Felt,
    stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
};

pub const NATIVE_SPEND_IDENTITY: [u8; 16] = *b"HGN-ASSET-SP-V01";
pub const NATIVE_ADMIN_IDENTITY: [u8; 16] = *b"HGN-ASSET-AD-V01";
pub const ASSET_SPEND_ACTION_ID: u16 = 16;
pub const ASSET_ADMIN_ACTION_ID: u16 = 17;
pub const NATIVE_INNER_PROOF_CAP_BYTES: usize = 2 * 1024 * 1024;
pub const PRODUCTION_AUTHORIZED: bool = false;

/// Dependency-free constants for the outer native action envelope. The node
/// must check every component as well as the distinct action ID and identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAssetVersionBindingV1 {
    pub circuit: u16,
    pub profile: u16,
    pub crypto: u16,
    pub transcript_domain: u16,
    pub backend: u16,
}
pub const NATIVE_VERSION_BINDING: NativeAssetVersionBindingV1 = NativeAssetVersionBindingV1 {
    circuit: 13,
    profile: 13,
    crypto: 7,
    transcript_domain: 9,
    backend: 2,
};

/// Graph identities qualified by exact successor geometry measurement; actual
/// proof/lifecycle and conditional security receipts remain separate. The
/// byte ceilings below are admitted only for these exact source closures. A
/// graph/backend edit therefore fails before graph construction or proof parse.
pub const QUALIFIED_SPEND_SOURCE_SHA512: &str = "ca5887169d89d2f5b01ef5b48851183cc4b270c3f49f1be099a7717715dbd7b7a849f8b4494a5811ccac0b37d6c09de7b38ea9b62c0b72a6b099bf3d2580025b";
pub const QUALIFIED_ADMIN_SOURCE_SHA512: &str = "db34857cf3b8816ef59e779f129fc279bb0ef5ee03744d7ffcd4c87e394aad41ba18417a59a28dcb0c255da7737f42af65856fc63d19b69e7370c0ac26de764a";
pub const ADMIN_PROFILE_UPPER_BOUND_BYTES: usize = 158_533;

/// Supplied by authenticated native state, never by arbitrary RPC arguments.
/// Registry state is owned by AssetState; note_root is the existing native V8
/// accumulator root. For spends, the caller first authenticates this canonical
/// reference parent H within ASSET_REFERENCE_WINDOW of inclusion parent P and
/// checks its registry root still equals the current registry root; accounting
/// uses P. These fields name H and its historical note root, never a mixture of
/// H's hash/height and P's note root. Admin callers supply their separately
/// authenticated current context. This struct grants no reference authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAssetContextV1 {
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub parent_height: u64,
    pub note_root: [u64; 7],
    pub registry_root: [u64; 7],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAssetAdmissionErrorV1 {
    UnsupportedProfile,
    SourceIdentity,
    PublicShape,
    CurrentContext,
    ProofLength,
    NonCanonicalProof,
    ProofVerification,
}
impl core::fmt::Display for NativeAssetAdmissionErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native asset admission: {self:?}")
    }
}
impl std::error::Error for NativeAssetAdmissionErrorV1 {}

/// A preflight receipt is explicitly not a verification result. The verify
/// wrappers set proof_verified only after the actual candidate verifier passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct NativeAssetBudgetReceiptV1 {
    pub inner_bytes: usize,
    pub structured_payload_bytes: usize,
    pub canonical_padding_bytes: usize,
    pub projected_upper_bound_bytes: usize,
    pub native_inner_cap_bytes: usize,
    pub proof_verified: bool,
}

/// Public mode/depth selects one of five measured graphs. In particular,
/// bounded-policy depth16 has a 2,188,605-byte ceiling and is not admitted.
/// No graph is constructed by this function.
pub fn spend_profile_upper_bound_v1(
    policy_mode: u8,
    credential_depth: u8,
) -> Result<usize, NativeAssetAdmissionErrorV1> {
    let upper = match (policy_mode, credential_depth) {
        (0, 4) => 819_493,
        (0, 8) => 888_445,
        (0, 16) => 1_026_437,
        (1, 4) => 1_981_701,
        (1, 8) => 2_050_701,
        _ => return Err(NativeAssetAdmissionErrorV1::UnsupportedProfile),
    };
    if hex::encode(spend::relation_digest()) != QUALIFIED_SPEND_SOURCE_SHA512 {
        return Err(NativeAssetAdmissionErrorV1::SourceIdentity);
    }
    Ok(upper)
}

pub fn admin_profile_upper_bound_v1() -> Result<usize, NativeAssetAdmissionErrorV1> {
    if hex::encode(admin::relation_digest()) != QUALIFIED_ADMIN_SOURCE_SHA512 {
        return Err(NativeAssetAdmissionErrorV1::SourceIdentity);
    }
    Ok(ADMIN_PROFILE_UPPER_BOUND_BYTES)
}

fn parse_bounded_proof(
    proof: &[u8],
    upper: usize,
) -> Result<NativeAssetBudgetReceiptV1, NativeAssetAdmissionErrorV1> {
    // Check both limits before invoking any structured proof decoder.
    if proof.len() < 4 || proof.len() > upper || proof.len() > NATIVE_INNER_PROOF_CAP_BYTES {
        return Err(NativeAssetAdmissionErrorV1::ProofLength);
    }
    let parsed = spend::proof_wire_receipt(proof)
        .map_err(|_| NativeAssetAdmissionErrorV1::NonCanonicalProof)?;
    if parsed["inner_bytes"].as_u64() != Some(proof.len() as u64)
        || parsed["structured_payload_bytes"].as_u64() != Some(proof.len() as u64)
        || parsed["canonical_padding_bytes"].as_u64() != Some(0)
    {
        return Err(NativeAssetAdmissionErrorV1::NonCanonicalProof);
    }
    Ok(NativeAssetBudgetReceiptV1 {
        inner_bytes: proof.len(),
        structured_payload_bytes: proof.len(),
        canonical_padding_bytes: 0,
        projected_upper_bound_bytes: upper,
        native_inner_cap_bytes: NATIVE_INNER_PROOF_CAP_BYTES,
        proof_verified: false,
    })
}

pub fn preflight_spend_v1(
    public: &AssetSpendPublic,
    proof: &[u8],
    current: NativeAssetContextV1,
) -> Result<NativeAssetBudgetReceiptV1, NativeAssetAdmissionErrorV1> {
    let upper = spend_profile_upper_bound_v1(public.policy_mode, public.credential_depth)?;
    public
        .validate_structure()
        .map_err(|_| NativeAssetAdmissionErrorV1::PublicShape)?;
    if public.chain_id != current.chain_id
        || public.reference_parent_hash != current.reference_parent_hash
        || public.parent_height != current.parent_height
        || public.note_root != current.note_root
        || public.registry_root != current.registry_root
    {
        return Err(NativeAssetAdmissionErrorV1::CurrentContext);
    }
    parse_bounded_proof(proof, upper)
}

pub fn verify_spend_v1(
    public: &AssetSpendPublic,
    proof: &[u8],
    current: NativeAssetContextV1,
) -> Result<NativeAssetBudgetReceiptV1, NativeAssetAdmissionErrorV1> {
    let mut receipt = preflight_spend_v1(public, proof, current)?;
    spend::verify_candidate(public, proof)
        .map_err(|_| NativeAssetAdmissionErrorV1::ProofVerification)?;
    receipt.proof_verified = true;
    Ok(receipt)
}

pub fn preflight_admin_v1(
    public: &PolicyAdminPublicV1,
    proof: &[u8],
    current: NativeAssetContextV1,
) -> Result<NativeAssetBudgetReceiptV1, NativeAssetAdmissionErrorV1> {
    let upper = admin_profile_upper_bound_v1()?;
    public
        .validate_structure()
        .map_err(|_| NativeAssetAdmissionErrorV1::PublicShape)?;
    if public.chain_id != current.chain_id
        || public.reference_parent_hash != current.reference_parent_hash
        || public.parent_height != current.parent_height
        || public.registry_root != current.registry_root
    {
        return Err(NativeAssetAdmissionErrorV1::CurrentContext);
    }
    parse_bounded_proof(proof, upper)
}

pub fn verify_admin_v1(
    public: &PolicyAdminPublicV1,
    proof: &[u8],
    current: NativeAssetContextV1,
) -> Result<NativeAssetBudgetReceiptV1, NativeAssetAdmissionErrorV1> {
    let mut receipt = preflight_admin_v1(public, proof, current)?;
    admin::verify_candidate(public, proof)
        .map_err(|_| NativeAssetAdmissionErrorV1::ProofVerification)?;
    receipt.proof_verified = true;
    Ok(receipt)
}

/// Exact full-row representation shared by genesis manifests, node snapshots
/// and wallet setup. This codec does not authorize registration or row changes.
pub const ASSET_POLICY_ROW_BYTES_V1: usize = 69 * 8;

#[derive(Debug)]
pub enum AssetPolicyRowCodecErrorV1 {
    Codec(&'static str),
    Registry(AssetRegistryErrorV1),
}
impl From<AssetRegistryErrorV1> for AssetPolicyRowCodecErrorV1 {
    fn from(error: AssetRegistryErrorV1) -> Self {
        Self::Registry(error)
    }
}
impl core::fmt::Display for AssetPolicyRowCodecErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "asset policy row codec: {self:?}")
    }
}
impl std::error::Error for AssetPolicyRowCodecErrorV1 {}

struct PolicyRowReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl PolicyRowReader<'_> {
    fn u64(&mut self) -> Result<u64, AssetPolicyRowCodecErrorV1> {
        let end = self
            .cursor
            .checked_add(8)
            .ok_or(AssetPolicyRowCodecErrorV1::Codec("length overflow"))?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AssetPolicyRowCodecErrorV1::Codec("truncated"))?;
        self.cursor = end;
        let word = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
        if word >= hegemon_field::GOLDILOCKS_MODULUS {
            return Err(AssetPolicyRowCodecErrorV1::Codec("noncanonical field word"));
        }
        Ok(word)
    }
    fn scalar32(&mut self) -> Result<u32, AssetPolicyRowCodecErrorV1> {
        u32::try_from(self.u64()?).map_err(|_| AssetPolicyRowCodecErrorV1::Codec("u32 alias"))
    }
    fn scalar8(&mut self) -> Result<u8, AssetPolicyRowCodecErrorV1> {
        u8::try_from(self.u64()?).map_err(|_| AssetPolicyRowCodecErrorV1::Codec("u8 alias"))
    }
    fn boolean(&mut self) -> Result<bool, AssetPolicyRowCodecErrorV1> {
        match self.u64()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AssetPolicyRowCodecErrorV1::Codec("boolean alias")),
        }
    }
    fn digest(&mut self) -> Result<[Felt; 7], AssetPolicyRowCodecErrorV1> {
        let mut digest = [Felt::ZERO; 7];
        for word in &mut digest {
            *word = Felt::from_u64(self.u64()?);
        }
        Ok(digest)
    }
}

/// Complete canonical public descriptor for manifest/genesis use. This encoder
/// is not administrative authorization or asset registration.
pub fn encode_asset_policy_row(row: &AssetPolicyV1) -> Result<Vec<u8>, AssetPolicyRowCodecErrorV1> {
    validate_asset_policy_v1(row)?;
    let mut output = Vec::with_capacity(ASSET_POLICY_ROW_BYTES_V1);
    let mut fields = row
        .config
        .to_fields()
        .map(|word| word.as_canonical_u64())
        .to_vec();
    fields.extend([
        row.counters.epoch_id,
        row.counters.minted_in_epoch,
        row.counters.total_debt,
        row.counters.sequence,
    ]);
    fields.extend(row.credential_root.map(|word| word.as_canonical_u64()));
    fields.extend([
        u64::from(row.credential_depth),
        u64::from(row.frozen),
        u64::from(row.mint_enabled),
    ]);
    for word in fields {
        output.extend(word.to_le_bytes());
    }
    debug_assert_eq!(output.len(), ASSET_POLICY_ROW_BYTES_V1);
    Ok(output)
}

pub fn decode_asset_policy_row(bytes: &[u8]) -> Result<AssetPolicyV1, AssetPolicyRowCodecErrorV1> {
    if bytes.len() != ASSET_POLICY_ROW_BYTES_V1 {
        return Err(AssetPolicyRowCodecErrorV1::Codec("row length"));
    }
    let mut r = PolicyRowReader { bytes, cursor: 0 };
    let asset_id = r.scalar32()?;
    let policy_version = r.scalar32()?;
    let active = r.boolean()?;
    let enabled_at = r.u64()?;
    let retired = r.boolean()?;
    let retired_at = r.u64()?;
    if !retired && retired_at != 0 {
        return Err(AssetPolicyRowCodecErrorV1::Codec("retirement padding"));
    }
    let config = StablecoinPoseidon2V8Config {
        asset_id,
        policy_version,
        active,
        enabled_at,
        retired_at: retired.then_some(retired_at),
        issuer_commitment: r.digest()?,
        min_collateral_ratio_ppm: r.scalar32()?,
        max_mint_per_epoch: r.u64()?,
        oracle_submitted_at: r.u64()?,
        oracle_max_age: r.u64()?,
        oracle_price_numerator: r.scalar32()?,
        oracle_price_denominator: r.scalar32()?,
        collateral_amount: r.u64()?,
        attestation_created_at: r.u64()?,
        attestation_disputed: r.boolean()?,
        attestation_present: r.boolean()?,
        attestation_max_age: r.u64()?,
        policy_admin_commitment: r.digest()?,
        oracle_authority_commitment: r.digest()?,
        attestation_authority_commitment: r.digest()?,
        collateral_asset_id: r.scalar32()?,
        collateral_decimals: r.scalar8()?,
        collateral_scale: r.u64()?,
        locked_collateral_commitment: r.digest()?,
    };
    let row = AssetPolicyV1 {
        config,
        counters: StablecoinPoseidon2V8Counters {
            epoch_id: r.u64()?,
            minted_in_epoch: r.u64()?,
            total_debt: r.u64()?,
            sequence: r.u64()?,
        },
        credential_root: r.digest()?,
        credential_depth: r.scalar8()?,
        frozen: r.boolean()?,
        mint_enabled: r.boolean()?,
    };
    validate_asset_policy_v1(&row)?;
    if r.cursor != bytes.len() || encode_asset_policy_row(&row)? != bytes {
        return Err(AssetPolicyRowCodecErrorV1::Codec("row reencode"));
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_profile_allowlist_source_gate_and_cap() {
        let source_is_qualified =
            hex::encode(spend::relation_digest()) == QUALIFIED_SPEND_SOURCE_SHA512;
        for (mode, depth, expected) in [
            (0, 4, 819_493),
            (0, 8, 888_445),
            (0, 16, 1_026_437),
            (1, 4, 1_981_701),
            (1, 8, 2_050_701),
        ] {
            assert_eq!(
                spend_profile_upper_bound_v1(mode, depth),
                if source_is_qualified {
                    Ok(expected)
                } else {
                    Err(NativeAssetAdmissionErrorV1::SourceIdentity)
                }
            );
            assert!(expected <= NATIVE_INNER_PROOF_CAP_BYTES);
        }
        for pair in [(1, 16), (2, 4), (0, 0), (1, 32)] {
            assert_eq!(
                spend_profile_upper_bound_v1(pair.0, pair.1),
                Err(NativeAssetAdmissionErrorV1::UnsupportedProfile)
            );
        }
        let admin_source_is_qualified =
            hex::encode(admin::relation_digest()) == QUALIFIED_ADMIN_SOURCE_SHA512;
        eprintln!(
            "inactive asset admission fixture: spend_source_qualified={source_is_qualified}; admin_source_qualified={admin_source_is_qualified}"
        );
        assert_eq!(
            admin_profile_upper_bound_v1(),
            if admin_source_is_qualified {
                Ok(158_533)
            } else {
                Err(NativeAssetAdmissionErrorV1::SourceIdentity)
            }
        );
        assert_ne!(NATIVE_SPEND_IDENTITY, NATIVE_ADMIN_IDENTITY);
        assert_ne!(ASSET_SPEND_ACTION_ID, ASSET_ADMIN_ACTION_ID);
    }

    #[test]
    fn canonical_proof_parse_is_required_even_after_budget_passes() {
        assert_eq!(
            parse_bounded_proof(b"SMZE", 819_493),
            Err(NativeAssetAdmissionErrorV1::NonCanonicalProof)
        );
        assert_eq!(
            parse_bounded_proof(&[0; 5], 4),
            Err(NativeAssetAdmissionErrorV1::ProofLength)
        );
        assert_eq!(
            parse_bounded_proof(b"SMZEpadding", 819_493),
            Err(NativeAssetAdmissionErrorV1::NonCanonicalProof)
        );
    }

    fn row_fixture() -> AssetPolicyV1 {
        AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                policy_version: 7,
                active: true,
                enabled_at: 1,
                retired_at: Some(20_000),
                issuer_commitment: [Felt::from_u64(11); 7],
                min_collateral_ratio_ppm: 1_500_000,
                max_mint_per_epoch: 1_000_000,
                oracle_submitted_at: 8_900,
                oracle_max_age: 500,
                oracle_price_numerator: 2,
                oracle_price_denominator: 1,
                collateral_amount: 10_000,
                attestation_created_at: 8_800,
                attestation_disputed: false,
                attestation_present: true,
                attestation_max_age: 500,
                policy_admin_commitment: [Felt::from_u64(12); 7],
                oracle_authority_commitment: [Felt::from_u64(13); 7],
                attestation_authority_commitment: [Felt::from_u64(14); 7],
                collateral_asset_id: 0,
                collateral_decimals: 6,
                collateral_scale: 1_000_000,
                locked_collateral_commitment: [Felt::from_u64(15); 7],
            },
            counters: StablecoinPoseidon2V8Counters {
                epoch_id: 2,
                minted_in_epoch: 100,
                total_debt: 1000,
                sequence: 9,
            },
            credential_root: [Felt::from_u64(16); 7],
            credential_depth: 8,
            frozen: false,
            mint_enabled: true,
        }
    }

    #[test]
    fn full_row552_codec_roundtrip_and_canonical_alias_rejection() {
        let row = row_fixture();
        let bytes = encode_asset_policy_row(&row).unwrap();
        assert_eq!(bytes.len(), ASSET_POLICY_ROW_BYTES_V1);
        assert_eq!(decode_asset_policy_row(&bytes).unwrap(), row);
        assert_eq!(
            encode_asset_policy_row(&decode_asset_policy_row(&bytes).unwrap()).unwrap(),
            bytes
        );
        for (index, value) in [
            (0, 1u64 << 32),
            (2, 2),
            (4, 2),
            (6, hegemon_field::GOLDILOCKS_MODULUS),
            (46, 256),
            (67, 2),
            (68, 2),
        ] {
            let mut mutation = bytes.clone();
            mutation[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
            assert!(decode_asset_policy_row(&mutation).is_err(), "word {index}");
        }
        let mut retirement_padding = bytes.clone();
        retirement_padding[4 * 8..5 * 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            decode_asset_policy_row(&retirement_padding),
            Err(AssetPolicyRowCodecErrorV1::Codec("retirement padding"))
        ));
        assert!(decode_asset_policy_row(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_asset_policy_row(&trailing).is_err());
        let mut invalid = row;
        invalid.config.asset_id = 0;
        assert!(encode_asset_policy_row(&invalid).is_err());
    }
}
