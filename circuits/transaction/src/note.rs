use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

use crate::{
    constants::{is_canonical_asset_id, MAX_NOTE_VALUE},
    error::TransactionCircuitError,
    hashing_pq::{merkle_node, note_commitment, HashFelt},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteData {
    pub value: u64,
    pub asset_id: u64,
    #[serde(with = "crate::note::serde_bytes32")]
    pub pk_recipient: [u8; 32],
    #[serde(default, with = "crate::note::serde_bytes32")]
    pub pk_auth: [u8; 32],
    #[serde(with = "crate::note::serde_bytes32")]
    pub rho: [u8; 32],
    #[serde(with = "crate::note::serde_bytes32")]
    pub r: [u8; 32],
}

impl NoteData {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        if self.value as u128 > MAX_NOTE_VALUE {
            return Err(TransactionCircuitError::ValueOutOfRange(self.value as u128));
        }
        if !is_canonical_asset_id(self.asset_id) {
            return Err(TransactionCircuitError::AssetIdTooLarge);
        }
        Ok(())
    }

    pub fn commitment(&self) -> HashFelt {
        note_commitment(
            self.value,
            self.asset_id,
            &self.pk_recipient,
            &self.pk_auth,
            &self.rho,
            &self.r,
        )
    }
}

pub const PREDICATE_THRESHOLD_POLICY_COMMITMENT_DOMAIN: &[u8] =
    b"hegemon-predicate-threshold-policy-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateThresholdPolicyOpening {
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub policy_root: [u8; 48],
    pub threshold: u16,
    #[serde(with = "crate::note::serde_bytes32")]
    pub policy_commitment_randomness: [u8; 32],
}

impl PredicateThresholdPolicyOpening {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        if self.threshold == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "predicate threshold must be nonzero",
            ));
        }
        Ok(())
    }

    pub fn policy_commitment_key(&self) -> Result<[u8; 32], TransactionCircuitError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREDICATE_THRESHOLD_POLICY_COMMITMENT_DOMAIN);
        hasher.update(&self.policy_root);
        hasher.update(&self.threshold.to_le_bytes());
        hasher.update(&self.policy_commitment_randomness);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn to_note_data(
        &self,
        value: u64,
        asset_id: u64,
        pk_recipient: [u8; 32],
        rho: [u8; 32],
        r: [u8; 32],
    ) -> Result<NoteData, TransactionCircuitError> {
        let note = NoteData {
            value,
            asset_id,
            pk_recipient,
            pk_auth: self.policy_commitment_key()?,
            rho,
            r,
        };
        note.validate()?;
        Ok(note)
    }

    pub fn validate_bound_to_note(&self, note: &NoteData) -> Result<(), TransactionCircuitError> {
        note.validate()?;
        let committed_key = self.policy_commitment_key()?;
        if committed_key != note.pk_auth {
            return Err(TransactionCircuitError::ConstraintViolation(
                "predicate policy opening is not bound to consumed note commitment",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateThresholdSpendWitness {
    pub policy: PredicateThresholdPolicyOpening,
}

impl PredicateThresholdSpendWitness {
    pub fn validate_bound_to_note_opening(
        &self,
        note: &NoteData,
    ) -> Result<(), TransactionCircuitError> {
        self.policy.validate_bound_to_note(note)
    }
}

/// Merkle tree depth for the note commitment tree.
pub const MERKLE_TREE_DEPTH: usize = 32;

/// A Merkle authentication path: siblings from leaf to root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root (length = MERKLE_TREE_DEPTH).
    #[serde(with = "crate::note::serde_merkle_path")]
    pub siblings: Vec<crate::hashing_pq::HashFelt>,
}

impl Default for MerklePath {
    fn default() -> Self {
        Self {
            siblings: vec![[crate::hashing_pq::Felt::ZERO; 6]; MERKLE_TREE_DEPTH],
        }
    }
}

impl MerklePath {
    /// Fold this authentication path from leaf to root with the supplied node combiner.
    pub fn root_with<F>(
        &self,
        leaf_hash: crate::hashing_pq::HashFelt,
        position: u64,
        mut node: F,
    ) -> crate::hashing_pq::HashFelt
    where
        F: FnMut(
            crate::hashing_pq::HashFelt,
            crate::hashing_pq::HashFelt,
        ) -> crate::hashing_pq::HashFelt,
    {
        let mut current = leaf_hash;
        let mut pos = position;

        for sibling in &self.siblings {
            current = if pos & 1 == 0 {
                node(current, *sibling)
            } else {
                node(*sibling, current)
            };
            pos >>= 1;
        }

        current
    }

    /// Verify this path with an explicit depth and node combiner.
    pub fn verify_with_depth_and_node<F>(
        &self,
        depth: usize,
        leaf_hash: crate::hashing_pq::HashFelt,
        position: u64,
        root: crate::hashing_pq::HashFelt,
        node: F,
    ) -> bool
    where
        F: FnMut(
            crate::hashing_pq::HashFelt,
            crate::hashing_pq::HashFelt,
        ) -> crate::hashing_pq::HashFelt,
    {
        self.siblings.len() == depth && self.root_with(leaf_hash, position, node) == root
    }

    /// Verify this path connects leaf_hash at position to the given root.
    pub fn verify(
        &self,
        leaf_hash: crate::hashing_pq::HashFelt,
        position: u64,
        root: crate::hashing_pq::HashFelt,
    ) -> bool {
        self.root_with(leaf_hash, position, merkle_node) == root
    }
}

pub(crate) mod serde_merkle_path {
    use crate::hashing_pq::{bytes48_to_felts, felts_to_bytes48, HashFelt};
    use serde::{de::SeqAccess, de::Visitor, ser::SerializeSeq, Deserializer, Serializer};

    pub fn serialize<S>(value: &Vec<HashFelt>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for elem in value {
            let bytes = felts_to_bytes48(elem);
            seq.serialize_element(&bytes.to_vec())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<HashFelt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FeltVecVisitor;
        impl<'de> Visitor<'de> for FeltVecVisitor {
            type Value = Vec<HashFelt>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of 48-byte hash encodings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(val) = seq.next_element::<Vec<u8>>()? {
                    if val.len() != 48 {
                        return Err(serde::de::Error::custom("expected 48 bytes"));
                    }
                    let mut arr = [0u8; 48];
                    arr.copy_from_slice(&val);
                    let felts = bytes48_to_felts(&arr)
                        .ok_or_else(|| serde::de::Error::custom("non-canonical hash bytes"))?;
                    vec.push(felts);
                }
                Ok(vec)
            }
        }
        deserializer.deserialize_seq(FeltVecVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNoteWitness {
    #[serde(flatten)]
    pub note: NoteData,
    pub position: u64,
    #[serde(with = "crate::note::serde_bytes32")]
    pub rho_seed: [u8; 32],
    /// Merkle authentication path proving note is in the tree.
    #[serde(default)]
    pub merkle_path: MerklePath,
}

impl InputNoteWitness {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        self.note.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputNoteWitness {
    #[serde(flatten)]
    pub note: NoteData,
}

impl OutputNoteWitness {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        self.note.validate()
    }
}

pub(crate) mod serde_bytes32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    use serde::Deserialize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing_pq::{
        note_commitment, note_commitment_inputs, nullifier_inputs, Felt, HashFelt,
    };
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMerkleVectorFile {
        schema_version: u32,
        merkle_path_cases: Vec<LeanMerkleCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMerkleCase {
        name: String,
        depth: usize,
        leaf: u64,
        position: u64,
        siblings: Vec<u64>,
        expected_fold_root: u64,
        provided_root: u64,
        expected_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNoteCommitmentInputVectorFile {
        schema_version: u32,
        note_domain_tag: u64,
        note_commitment_input_cases: Vec<LeanNoteCommitmentInputCase>,
        asset_id_cases: Vec<LeanAssetIdCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNullifierInputVectorFile {
        schema_version: u32,
        nullifier_domain_tag: u64,
        nullifier_input_cases: Vec<LeanNullifierInputCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNoteCommitmentInputCase {
        name: String,
        value: u64,
        asset_id: u64,
        pk_recipient: Vec<u8>,
        pk_auth: Vec<u8>,
        rho: Vec<u8>,
        r: Vec<u8>,
        expected_inputs: Vec<u64>,
        expected_input_count: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAssetIdCase {
        name: String,
        asset_id: u64,
        expected_canonical: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNullifierInputCase {
        name: String,
        prf_key: u64,
        position: u64,
        rho: Vec<u8>,
        expected_inputs: Vec<u64>,
        expected_input_count: usize,
    }

    #[test]
    fn lean_generated_merkle_path_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_MERKLE_VECTORS") else {
            eprintln!("HEGEMON_LEAN_MERKLE_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean Merkle vectors");
        let vectors: LeanMerkleVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean Merkle vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.merkle_path_cases.is_empty(),
            "Lean Merkle path cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.merkle_path_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_merkle_case(case);
        }
    }

    #[test]
    fn lean_generated_note_commitment_input_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NOTE_COMMITMENT_INPUT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_NOTE_COMMITMENT_INPUT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean note-commitment vectors");
        let vectors: LeanNoteCommitmentInputVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean note-commitment vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(vectors.note_domain_tag, crate::constants::NOTE_DOMAIN_TAG);
        assert!(
            !vectors.note_commitment_input_cases.is_empty(),
            "Lean note-commitment input cases must not be empty"
        );
        assert!(
            !vectors.asset_id_cases.is_empty(),
            "Lean asset-id cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.note_commitment_input_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_note_commitment_input_case(case);
        }

        let mut names = BTreeSet::new();
        for case in &vectors.asset_id_cases {
            assert!(names.insert(case.name.clone()));
            assert_eq!(
                crate::constants::is_canonical_asset_id(case.asset_id),
                case.expected_canonical,
                "{} production asset-id canonicality drifted from Lean spec",
                case.name
            );
        }
    }

    #[test]
    fn lean_generated_nullifier_input_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NULLIFIER_INPUT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_NULLIFIER_INPUT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean nullifier vectors");
        let vectors: LeanNullifierInputVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean nullifier vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(
            vectors.nullifier_domain_tag,
            crate::constants::NULLIFIER_DOMAIN_TAG
        );
        assert!(
            !vectors.nullifier_input_cases.is_empty(),
            "Lean nullifier input cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.nullifier_input_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_nullifier_input_case(case);
        }
    }

    #[test]
    fn merkle_path_explicit_depth_rejects_short_authentication_path() {
        let leaf = digest_from_u64(1);
        let path = MerklePath {
            siblings: vec![digest_from_u64(2)],
        };
        let root = path.root_with(leaf, 0, merkle_node);

        assert!(path.verify(leaf, 0, root));
        assert!(!path.verify_with_depth_and_node(2, leaf, 0, root, merkle_node));
    }

    #[test]
    fn merkle_path_position_bit_orientation_changes_root() {
        let leaf = digest_from_u64(10);
        let path = MerklePath {
            siblings: vec![digest_from_u64(20), digest_from_u64(30)],
        };

        let position_zero_root = path.root_with(leaf, 0, mock_merkle_node);
        let position_one_root = path.root_with(leaf, 1, mock_merkle_node);

        assert_ne!(position_zero_root, position_one_root);
        assert!(path.verify_with_depth_and_node(2, leaf, 0, position_zero_root, mock_merkle_node));
        assert!(!path.verify_with_depth_and_node(2, leaf, 1, position_zero_root, mock_merkle_node));
    }

    #[test]
    fn note_validation_rejects_field_aliasing_asset_ids() {
        for asset_id in [
            crate::constants::BALANCE_SLOT_PADDING_FIELD_ID,
            crate::constants::FIELD_MODULUS_U64,
            crate::constants::BALANCE_SLOT_PADDING_ASSET_ID,
        ] {
            let note = NoteData {
                value: 1,
                asset_id,
                pk_recipient: [1u8; 32],
                pk_auth: [2u8; 32],
                rho: [3u8; 32],
                r: [4u8; 32],
            };
            assert!(
                matches!(
                    note.validate(),
                    Err(TransactionCircuitError::AssetIdTooLarge)
                ),
                "asset id {asset_id} must not be accepted as a real note asset"
            );
        }
    }

    #[test]
    fn predicate_note_commitment_changes_when_policy_opening_changes() {
        let policy = predicate_policy(0x20, 2);
        let note = predicate_note(&policy);

        let changed_root = PredicateThresholdPolicyOpening {
            policy_root: [0x21u8; 48],
            ..policy.clone()
        };
        let changed_threshold = PredicateThresholdPolicyOpening {
            threshold: 3,
            ..policy.clone()
        };
        let changed_randomness = PredicateThresholdPolicyOpening {
            policy_commitment_randomness: [0x22u8; 32],
            ..policy.clone()
        };

        for changed in [changed_root, changed_threshold, changed_randomness] {
            assert_ne!(
                policy.policy_commitment_key().expect("policy key"),
                changed.policy_commitment_key().expect("changed policy key")
            );
            assert_ne!(
                note.commitment(),
                predicate_note(&changed).commitment(),
                "policy_root, threshold, and policy commitment randomness must all bind the note commitment"
            );
        }
    }

    #[test]
    fn single_key_note_commitment_shape_remains_legacy() {
        let note = NoteData {
            value: 42,
            asset_id: 7,
            pk_recipient: [1u8; 32],
            pk_auth: [2u8; 32],
            rho: [3u8; 32],
            r: [4u8; 32],
        };

        let legacy_inputs = note_commitment_inputs(
            note.value,
            note.asset_id,
            &note.pk_recipient,
            &note.rho,
            &note.r,
            &note.pk_auth,
        );
        assert_eq!(
            legacy_inputs.len(),
            18,
            "single-key note commitment preimage must stay value/asset/recipient/rho/r/auth"
        );
        assert_eq!(legacy_inputs[0], Felt::from_u64(note.value));
        assert_eq!(legacy_inputs[1], Felt::from_u64(note.asset_id));

        assert_eq!(
            note.commitment(),
            note_commitment(
                note.value,
                note.asset_id,
                &note.pk_recipient,
                &note.pk_auth,
                &note.rho,
                &note.r,
            ),
            "single-key NoteData commitment must remain the legacy helper result"
        );
    }

    #[test]
    fn predicate_spend_witness_rejects_uncommitted_policy_opening() {
        let policy = predicate_policy(0x30, 2);
        let note = predicate_note(&policy);
        let witness = PredicateThresholdSpendWitness {
            policy: policy.clone(),
        };
        witness
            .validate_bound_to_note_opening(&note)
            .expect("committed predicate policy opening accepts");

        let wrong_root = PredicateThresholdSpendWitness {
            policy: PredicateThresholdPolicyOpening {
                policy_root: [0x31u8; 48],
                ..policy.clone()
            },
        };
        assert!(matches!(
            wrong_root.validate_bound_to_note_opening(&note),
            Err(TransactionCircuitError::ConstraintViolation(
                "predicate policy opening is not bound to consumed note commitment"
            ))
        ));

        let wrong_threshold = PredicateThresholdSpendWitness {
            policy: PredicateThresholdPolicyOpening {
                threshold: 3,
                ..policy.clone()
            },
        };
        assert!(matches!(
            wrong_threshold.validate_bound_to_note_opening(&note),
            Err(TransactionCircuitError::ConstraintViolation(
                "predicate policy opening is not bound to consumed note commitment"
            ))
        ));

        let wrong_randomness = PredicateThresholdSpendWitness {
            policy: PredicateThresholdPolicyOpening {
                policy_commitment_randomness: [0x32u8; 32],
                ..policy.clone()
            },
        };
        assert!(matches!(
            wrong_randomness.validate_bound_to_note_opening(&note),
            Err(TransactionCircuitError::ConstraintViolation(
                "predicate policy opening is not bound to consumed note commitment"
            ))
        ));

        let zero_threshold = PredicateThresholdSpendWitness {
            policy: PredicateThresholdPolicyOpening {
                threshold: 0,
                ..policy.clone()
            },
        };
        assert!(matches!(
            zero_threshold.validate_bound_to_note_opening(&note),
            Err(TransactionCircuitError::ConstraintViolation(
                "predicate threshold must be nonzero"
            ))
        ));

        let legacy_single_key_note = NoteData {
            value: note.value,
            asset_id: note.asset_id,
            pk_recipient: note.pk_recipient,
            pk_auth: [0x33u8; 32],
            rho: note.rho,
            r: note.r,
        };
        assert!(matches!(
            witness.validate_bound_to_note_opening(&legacy_single_key_note),
            Err(TransactionCircuitError::ConstraintViolation(
                "predicate policy opening is not bound to consumed note commitment"
            ))
        ));
    }

    fn verify_lean_merkle_case(case: &LeanMerkleCase) {
        let path = MerklePath {
            siblings: case.siblings.iter().copied().map(digest_from_u64).collect(),
        };
        let leaf = digest_from_u64(case.leaf);
        let actual_fold_root = path.root_with(leaf, case.position, mock_merkle_node);
        assert_eq!(
            digest_to_u64(actual_fold_root),
            case.expected_fold_root,
            "{} production Merkle path fold drifted from Lean spec",
            case.name
        );

        let provided_root = digest_from_u64(case.provided_root);
        assert_eq!(
            path.verify_with_depth_and_node(
                case.depth,
                leaf,
                case.position,
                provided_root,
                mock_merkle_node
            ),
            case.expected_valid,
            "{} production Merkle path admission drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_note_commitment_input_case(case: &LeanNoteCommitmentInputCase) {
        assert_eq!(
            case.pk_recipient.len(),
            32,
            "{} pk_recipient len",
            case.name
        );
        assert_eq!(case.pk_auth.len(), 32, "{} pk_auth len", case.name);
        assert_eq!(case.rho.len(), 32, "{} rho len", case.name);
        assert_eq!(case.r.len(), 32, "{} r len", case.name);
        let actual = note_commitment_inputs(
            case.value,
            case.asset_id,
            &case.pk_recipient,
            &case.rho,
            &case.r,
            &case.pk_auth,
        );
        let actual = actual
            .iter()
            .map(|felt| felt.as_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(
            actual.len(),
            case.expected_input_count,
            "{} production note-commitment input count drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual, case.expected_inputs,
            "{} production note-commitment input order/encoding drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_nullifier_input_case(case: &LeanNullifierInputCase) {
        assert_eq!(case.rho.len(), 32, "{} rho len", case.name);
        let actual = nullifier_inputs(Felt::from_u64(case.prf_key), &case.rho, case.position);
        let actual = actual
            .iter()
            .map(|felt| felt.as_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(
            actual.len(),
            case.expected_input_count,
            "{} production nullifier input count drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual, case.expected_inputs,
            "{} production nullifier input order/encoding drifted from Lean spec",
            case.name
        );
    }

    fn mock_merkle_node(left: HashFelt, right: HashFelt) -> HashFelt {
        let left = digest_to_u64(left) as u128;
        let right = digest_to_u64(right) as u128;
        let value = (left * 1_315_423_911u128 + right * 2_654_435_761u128 + 97)
            % 18_446_744_069_414_584_321u128;
        digest_from_u64(value as u64)
    }

    fn digest_from_u64(value: u64) -> HashFelt {
        let mut digest = [Felt::ZERO; 6];
        digest[0] = Felt::from_u64(value);
        digest
    }

    fn digest_to_u64(digest: HashFelt) -> u64 {
        assert!(
            digest[1..].iter().all(|limb| *limb == Felt::ZERO),
            "mock Lean Merkle digest uses only limb zero"
        );
        digest[0].as_canonical_u64()
    }

    fn predicate_policy(seed: u8, threshold: u16) -> PredicateThresholdPolicyOpening {
        PredicateThresholdPolicyOpening {
            policy_root: [seed; 48],
            threshold,
            policy_commitment_randomness: [seed.wrapping_add(1); 32],
        }
    }

    fn predicate_note(policy: &PredicateThresholdPolicyOpening) -> NoteData {
        policy
            .to_note_data(17, 9, [0x40u8; 32], [0x41u8; 32], [0x42u8; 32])
            .expect("predicate note data")
    }
}
