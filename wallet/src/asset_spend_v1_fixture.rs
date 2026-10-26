//! Public deterministic qualification material, feature-gated by the wallet.
//! Never use these disclosed keys, issuer secrets or rows for funded assets.
//! The fixture is deliberately independent of persistent wallets and RPC.

use crate::{
    asset_spend_v1::{decrypt_output_any, encrypt_outputs},
    AddressKeyMaterial, RootSecret, WalletError,
};
use hegemon_field::Goldilocks as Felt;
use rand_core09::TryCryptoRng;
use sha2::{Digest as _, Sha256};
use synthetic_crypto::asset_note_encryption_v1::AssetNoteCiphertext;
use transaction_circuit::{
    asset_registry_v1::{AssetOperationV1, AssetPolicyV1, AssetRegistryV1},
    asset_spend_v1 as relation,
    private_spend::{
        note_commitment, ordinary_owner, real_nullifier, set_note_owner, BoundedPolicy, Note,
        PolicyBranch, PrivateInput, PrivatePolicyOpening,
    },
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
        poseidon2_v8_single_key_authorization_digest, poseidon2_v8_words_from_canonical_bytes,
    },
    stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
};
use zeroize::Zeroize;

pub const FIXTURE_ID: &str = "hegemon.asset-spend-v1.disclosed-disposable-fixture.v2";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetFixtureProfileV1 {
    Ordinary,
    Bounded,
}
impl AssetFixtureProfileV1 {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Bounded => "bounded",
        }
    }
}
pub const DISCLOSED_POLICY_SECRET: [u8; 32] = [0x42; 32];
pub const CHAIN_ID: [u8; 32] = [0x61; 32];
pub const PARENT_HASH: [u8; 32] = [0x62; 32];
pub const PARENT_HEIGHT: u64 = 100;
pub const ASSET_ID: u32 = 17;
pub const POLICY_VERSION: u32 = 1;
pub const ISSUER_SECRET: relation::Digest = [31, 32, 33, 34, 35, 36, 37];
const ADDRESS_INDICES: [u32; 3] = [7, 7, 9];

fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidState(message)
}
fn tagged(tag: u64) -> [Felt; 7] {
    core::array::from_fn(|index| Felt::from_u64(tag + index as u64))
}
fn note(
    value: u64,
    asset: u32,
    recipient: [u64; 4],
    authority: relation::Digest,
    tag: u64,
) -> Result<Note, WalletError> {
    let mut note = Note {
        value,
        asset_id: u64::from(asset),
        recipient_key: recipient,
        authorization_key: [0; 4],
        rho: [tag; 4],
        randomness: [0, 0, 0, tag + 100],
    };
    set_note_owner(
        &mut note,
        ordinary_owner(authority).map_err(|_| invalid("fixture owner"))?,
    );
    Ok(note)
}

/// Public fixture metadata and private in-memory witness. No Debug or serde.
/// Ordinary builds share one credential leaf. Bounded builds use one leaf for
/// the script owner and one for ordinary asset change. Native change remains ordinary.
pub struct DisposableAssetFixtureV1 {
    pub public: relation::AssetSpendPublic,
    pub witness: relation::AssetSpendWitness,
    pub registry: AssetRegistryV1,
    pub addresses: [AddressKeyMaterial; 3],
    pub profile: AssetFixtureProfileV1,
}
impl DisposableAssetFixtureV1 {
    pub fn build(operation: u8, depth: u8) -> Result<Self, WalletError> {
        Self::build_with_profile(operation, depth, AssetFixtureProfileV1::Ordinary)
    }
    pub fn build_with_profile(
        operation: u8,
        depth: u8,
        profile: AssetFixtureProfileV1,
    ) -> Result<Self, WalletError> {
        if operation > relation::BURN || !matches!(depth, 4 | 8 | 16) {
            return Err(invalid("fixture operation or depth"));
        }
        // This seed is deliberately published and must never hold real value.
        let keys = RootSecret::from_bytes([0xa5; 32]).derive();
        let addresses = [
            keys.poseidon2_v8_address(7)?,
            keys.poseidon2_v8_address(7)?,
            keys.poseidon2_v8_address(9)?,
        ];
        let recipient = [
            poseidon2_v8_words_from_canonical_bytes(addresses[0].pk_recipient)
                .map_err(|_| invalid("fixture recipient"))?,
            poseidon2_v8_words_from_canonical_bytes(addresses[1].pk_recipient)
                .map_err(|_| invalid("fixture recipient"))?,
            poseidon2_v8_words_from_canonical_bytes(addresses[2].pk_recipient)
                .map_err(|_| invalid("fixture recipient"))?,
        ];
        let spend_key = keys.spend.poseidon2_v8_words()?;
        let authority = poseidon2_v8_single_key_authorization_digest(spend_key)
            .map_err(|_| invalid("fixture authority"))?;
        let mut bounded = BoundedPolicy::default();
        let bounded_owner = if profile == AssetFixtureProfileV1::Bounded {
            let fallback_keys = RootSecret::from_bytes([0xb6; 32]).derive();
            let fallback_authority = poseidon2_v8_single_key_authorization_digest(
                fallback_keys.spend.poseidon2_v8_words()?,
            )
            .map_err(|_| invalid("fixture fallback authority"))?;
            bounded = BoundedPolicy {
                nullifier_key: [101, 102, 103, 104, 105],
                branches: [
                    PolicyBranch {
                        enabled: 1,
                        authority,
                        not_before: 80,
                        hash_required: 1,
                        hashlock: Sha256::digest(DISCLOSED_POLICY_SECRET).into(),
                        release_secret: 1,
                    },
                    PolicyBranch {
                        enabled: 1,
                        authority: fallback_authority,
                        not_before: 200,
                        ..Default::default()
                    },
                ],
            };
            bounded
                .owner(CHAIN_ID, u64::from(ASSET_ID))
                .map_err(|_| invalid("fixture bounded owner"))?
        } else {
            [0; 7]
        };
        let credential_defaults = relation::credential_default_nodes(depth)
            .map_err(|_| invalid("fixture credential defaults"))?;
        let mut credential_siblings = credential_defaults[..usize::from(depth)].to_vec();
        let ordinary_leaf =
            relation::credential_leaf(ASSET_ID, POLICY_VERSION, recipient[1], authority, 1_000)
                .map_err(|_| invalid("fixture ordinary credential leaf"))?;
        let owner_leaf = if profile == AssetFixtureProfileV1::Bounded {
            relation::credential_leaf(ASSET_ID, POLICY_VERSION, recipient[0], bounded_owner, 1_000)
                .map_err(|_| invalid("fixture script credential leaf"))?
        } else {
            ordinary_leaf
        };
        let mut change_credential_siblings = credential_siblings.clone();
        if profile == AssetFixtureProfileV1::Bounded {
            credential_siblings[0] = ordinary_leaf;
            change_credential_siblings[0] = owner_leaf;
        }
        let credential_root = relation::credential_root(owner_leaf, 0, &credential_siblings)
            .map_err(|_| invalid("fixture credential root"))?;
        if profile == AssetFixtureProfileV1::Bounded {
            if relation::credential_root(ordinary_leaf, 1, &change_credential_siblings)
                .map_err(|_| invalid("fixture change credential root"))?
                != credential_root
            {
                return Err(invalid("fixture credential tree mismatch"));
            }
        }
        let issuer = relation::issuer_commitment(ASSET_ID, POLICY_VERSION, ISSUER_SECRET)
            .map_err(|_| invalid("fixture issuer commitment"))?;
        let policy = AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: ASSET_ID,
                policy_version: POLICY_VERSION,
                active: true,
                enabled_at: 1,
                retired_at: Some(2_000),
                issuer_commitment: issuer.map(Felt::from_u64),
                min_collateral_ratio_ppm: 1_500_000,
                max_mint_per_epoch: 1_000_000,
                oracle_submitted_at: 90,
                oracle_max_age: 500,
                oracle_price_numerator: 2,
                oracle_price_denominator: 1,
                collateral_amount: 10_000,
                attestation_created_at: 90,
                attestation_disputed: false,
                attestation_present: true,
                attestation_max_age: 500,
                policy_admin_commitment: tagged(41),
                oracle_authority_commitment: tagged(51),
                attestation_authority_commitment: tagged(61),
                collateral_asset_id: 0,
                collateral_decimals: 6,
                collateral_scale: 1_000_000,
                locked_collateral_commitment: tagged(71),
            },
            counters: StablecoinPoseidon2V8Counters {
                epoch_id: 0,
                minted_in_epoch: if operation == relation::MINT { 0 } else { 100 },
                total_debt: if operation == relation::MINT { 0 } else { 100 },
                sequence: 1,
            },
            credential_root: credential_root.map(Felt::from_u64),
            credential_depth: depth,
            frozen: false,
            mint_enabled: true,
        };
        let registry = AssetRegistryV1::from_rows(CHAIN_ID, PARENT_HEIGHT, &[policy])
            .map_err(|_| invalid("fixture registry"))?;
        let asset_input = if operation == relation::MINT {
            PrivateInput {
                dummy_secret: [91, 2, 3, 4, 5],
                ..Default::default()
            }
        } else {
            PrivateInput {
                occupied: 1,
                legacy_ordinary: 0,
                note: note(100, ASSET_ID, recipient[0], authority, 11)?,
                spend_key,
                ..Default::default()
            }
        };
        let native_input = PrivateInput {
            occupied: 1,
            legacy_ordinary: 0,
            note: note(1_000, 0, recipient[2], authority, 12)?,
            spend_key,
            ..Default::default()
        };
        let change_credential = relation::AssetCredentialWitness {
            index: u32::from(profile == AssetFixtureProfileV1::Bounded),
            expires_at: 1_000,
            siblings: change_credential_siblings,
        };
        let credential = relation::AssetCredentialWitness {
            index: 0,
            expires_at: 1_000,
            siblings: credential_siblings,
        };
        let mut witness = relation::AssetSpendWitness {
            inputs: [asset_input, native_input],
            outputs: [
                note(
                    if operation == relation::BURN { 50 } else { 70 },
                    ASSET_ID,
                    recipient[0],
                    authority,
                    21,
                )?,
                note(30, ASSET_ID, recipient[1], authority, 22)?,
                note(990, 0, recipient[2], authority, 23)?,
            ],
            output_authorities: [authority; 3],
            credentials: [
                if operation == relation::MINT {
                    relation::AssetCredentialWitness {
                        siblings: vec![[0; 7]; usize::from(depth)],
                        ..Default::default()
                    }
                } else {
                    credential.clone()
                },
                credential.clone(),
                change_credential,
            ],
            policy: PrivatePolicyOpening::default(),
            issuer_secret: if operation == relation::MINT {
                ISSUER_SECRET
            } else {
                [0; 7]
            },
        };
        if profile == AssetFixtureProfileV1::Bounded {
            witness.policy.create = 1;
            witness.policy.output = bounded.clone();
            witness.output_authorities[0] = [0; 7];
            set_note_owner(&mut witness.outputs[0], bounded_owner);
            if operation != relation::MINT {
                witness.policy.spend = 1;
                witness.policy.input = bounded.clone();
                witness.policy.selected = [1, 0];
                witness.policy.secret = DISCLOSED_POLICY_SECRET;
                set_note_owner(&mut witness.inputs[0].note, bounded_owner);
            }
        }
        bounded.nullifier_key.zeroize();
        for branch in &mut bounded.branches {
            branch.enabled.zeroize();
            branch.authority.zeroize();
            branch.not_before.zeroize();
            branch.hash_required.zeroize();
            branch.hashlock.zeroize();
            branch.release_secret.zeroize();
        }
        let defaults = poseidon2_v8_default_note_nodes();
        let leaves = [
            if operation == relation::MINT {
                defaults[0]
            } else {
                note_commitment(witness.inputs[0].note)
                    .map_err(|_| invalid("fixture asset leaf"))?
            },
            note_commitment(witness.inputs[1].note).map_err(|_| invalid("fixture native leaf"))?,
        ];
        let mut note_root = poseidon2_v8_note_tree_compress(leaves[0], leaves[1]);
        for &default in &defaults[1..32] {
            note_root = poseidon2_v8_note_tree_compress(note_root, default);
        }
        for slot in 0..2 {
            if witness.inputs[slot].occupied == 1 {
                witness.inputs[slot].position = slot as u32;
                witness.inputs[slot].siblings = core::array::from_fn(|level| defaults[level]);
                witness.inputs[slot].siblings[0] = leaves[1 - slot];
            }
        }
        let mut nullifiers = [[0; 7]; 2];
        for (slot, nullifier) in nullifiers.iter_mut().enumerate() {
            let input = &witness.inputs[slot];
            *nullifier = if input.occupied == 1 {
                let key = if slot == 0 && witness.policy.spend == 1 {
                    witness.policy.input.nullifier_key
                } else {
                    input.spend_key
                };
                real_nullifier(key, input.position, input.note)
            } else {
                relation::dummy_nullifier(CHAIN_ID, input.dummy_secret)
            }
            .map_err(|_| invalid("fixture nullifier"))?;
        }
        let mut public = relation::AssetSpendPublic {
            chain_id: CHAIN_ID,
            reference_parent_hash: PARENT_HASH,
            parent_height: PARENT_HEIGHT,
            note_root,
            registry_root: registry.root().map(|word| word.as_canonical_u64()),
            asset_id: ASSET_ID,
            policy_version: POLICY_VERSION,
            credential_root,
            credential_depth: depth,
            frozen: false,
            mint_enabled: true,
            issuer_commitment: issuer,
            operation,
            magnitude: match operation {
                relation::MINT => 100,
                relation::BURN => 20,
                _ => 0,
            },
            fee: 10,
            nullifiers,
            commitments: [[0; 7]; 3],
            ciphertext_commitments: [[0; 48]; 3],
            policy_mode: u8::from(profile == AssetFixtureProfileV1::Bounded),
            secret_release: u64::from(
                profile == AssetFixtureProfileV1::Bounded && operation != relation::MINT,
            ),
            released_secret: if profile == AssetFixtureProfileV1::Bounded
                && operation != relation::MINT
            {
                DISCLOSED_POLICY_SECRET
            } else {
                [0; 32]
            },
        };
        for slot in 0..3 {
            public.commitments[slot] = note_commitment(witness.outputs[slot])
                .map_err(|_| invalid("fixture output leaf"))?;
        }
        let accounting_operation = match operation {
            relation::MINT => AssetOperationV1::Mint,
            relation::BURN => AssetOperationV1::Burn,
            _ => AssetOperationV1::Transfer,
        };
        registry
            .prepare_accounting(
                registry.context(),
                ASSET_ID,
                POLICY_VERSION,
                policy.credential_root,
                accounting_operation,
                public.magnitude,
            )
            .map_err(|_| invalid("fixture current accounting"))?;
        Ok(Self {
            public,
            witness,
            registry,
            addresses,
            profile,
        })
    }

    /// The exact ordered commitments used to initialize this two-leaf note tree.
    /// Mint reserves the first position as the canonical empty leaf.
    pub fn initial_commitments(&self) -> Result<[relation::Digest; 2], WalletError> {
        Ok([
            if self.public.operation == relation::MINT {
                poseidon2_v8_default_note_nodes()[0]
            } else {
                note_commitment(self.witness.inputs[0].note)
                    .map_err(|_| invalid("fixture initial asset leaf"))?
            },
            note_commitment(self.witness.inputs[1].note)
                .map_err(|_| invalid("fixture initial native leaf"))?,
        ])
    }

    pub fn encrypt_and_check<R: TryCryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<[AssetNoteCiphertext; 3], WalletError> {
        let public_keys = self
            .addresses
            .each_ref()
            .map(AddressKeyMaterial::public_key);
        let ciphertexts = encrypt_outputs(
            &mut self.public,
            &self.witness,
            public_keys.each_ref(),
            ADDRESS_INDICES,
            rng,
        )?;
        for slot in 0..3 {
            let expected_owner = if slot == 0 && self.witness.policy.create == 1 {
                self.witness
                    .policy
                    .output
                    .owner(self.public.chain_id, u64::from(self.public.asset_id))
                    .map_err(|_| invalid("fixture expected script owner"))?
            } else {
                ordinary_owner(self.witness.output_authorities[slot])
                    .map_err(|_| invalid("fixture expected ordinary owner"))?
            };
            let payload = decrypt_output_any(
                &self.public,
                slot as u8,
                ciphertexts[slot].as_bytes(),
                self.addresses[slot].secret_key(),
                ADDRESS_INDICES[slot],
                self.witness.outputs[slot].recipient_key,
                expected_owner,
            )?;
            let got = payload.as_note();
            let expected = self.witness.outputs[slot];
            if got.value != expected.value
                || got.asset_id != expected.asset_id
                || got.recipient_key != expected.recipient_key
                || got.authorization_key != expected.authorization_key
                || got.rho != expected.rho
                || got.randomness != expected.randomness
            {
                return Err(invalid("fixture decrypted note mismatch"));
            }
        }
        Ok(ciphertexts)
    }
}
impl Drop for DisposableAssetFixtureV1 {
    fn drop(&mut self) {
        for input in &mut self.witness.inputs {
            input.occupied.zeroize();
            input.legacy_ordinary.zeroize();
            input.position.zeroize();
            input.siblings.zeroize();
            input.spend_key.zeroize();
            input.dummy_secret.zeroize();
            input.note.value.zeroize();
            input.note.asset_id.zeroize();
            input.note.recipient_key.zeroize();
            input.note.authorization_key.zeroize();
            input.note.rho.zeroize();
            input.note.randomness.zeroize();
        }
        for note in &mut self.witness.outputs {
            note.value.zeroize();
            note.asset_id.zeroize();
            note.recipient_key.zeroize();
            note.authorization_key.zeroize();
            note.rho.zeroize();
            note.randomness.zeroize();
        }
        self.witness.output_authorities.zeroize();
        self.witness.issuer_secret.zeroize();
        self.witness.policy.create.zeroize();
        self.witness.policy.spend.zeroize();
        self.witness.policy.selected.zeroize();
        self.witness.policy.secret.zeroize();
        for policy in [
            &mut self.witness.policy.input,
            &mut self.witness.policy.output,
        ] {
            policy.nullifier_key.zeroize();
            for branch in &mut policy.branches {
                branch.enabled.zeroize();
                branch.authority.zeroize();
                branch.not_before.zeroize();
                branch.hash_required.zeroize();
                branch.hashlock.zeroize();
                branch.release_secret.zeroize();
            }
        }
        for credential in &mut self.witness.credentials {
            credential.index.zeroize();
            credential.expires_at.zeroize();
            credential.siblings.zeroize();
        }
    }
}
