//! Public-only deterministic qualification material. Every credential/key here is disposable.
use super::*;
use crate::private_spend::{ordinary_owner, real_nullifier, set_note_owner};
use crate::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
};
use crate::smallwood_poseidon2_v8_hash_schedule::SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN;
use std::collections::{BTreeMap, BTreeSet};
use transaction_core::poseidon2_width16::{poseidon2_width16_compress14, Felt};

fn authority(key: [u64; 5]) -> Result<Digest, crate::TransactionCircuitError> {
    helpers::hash(
        SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN,
        &[key[0], key[1], key[2], key[3], key[4], 0, 0],
    )
}
fn note(
    value: u64,
    asset: u32,
    recipient: [u64; 4],
    authority: Digest,
    seed: u64,
) -> Result<Note, crate::TransactionCircuitError> {
    let mut note = Note {
        value,
        asset_id: u64::from(asset),
        recipient_key: recipient,
        authorization_key: [0; 4],
        rho: [seed; 4],
        randomness: [seed + 1; 4],
    };
    set_note_owner(&mut note, ordinary_owner(authority)?);
    Ok(note)
}
fn credential_node(level: usize, left: Digest, right: Digest) -> Digest {
    poseidon2_width16_compress14(
        CREDENTIAL_NODE_DOMAIN + level as u64,
        &left.map(Felt::from_u64),
        &right.map(Felt::from_u64),
    )
    .map(|word| word.as_canonical_u64())
}
fn credential_tree(leaves: [Digest; 3], depth: u8) -> (Digest, [Vec<Digest>; 3]) {
    let mut layer = leaves
        .into_iter()
        .enumerate()
        .map(|(index, leaf)| (index as u32, leaf))
        .collect::<BTreeMap<_, _>>();
    let mut default = [0; 7];
    let mut paths: [Vec<Digest>; 3] = core::array::from_fn(|_| Vec::new());
    for level in 0..usize::from(depth) {
        for (index, path) in paths.iter_mut().enumerate() {
            path.push(
                *layer
                    .get(&(((index as u32) >> level) ^ 1))
                    .unwrap_or(&default),
            );
        }
        let parents = layer
            .keys()
            .map(|index| index >> 1)
            .collect::<BTreeSet<_>>();
        let mut next = BTreeMap::new();
        for parent in parents {
            let left = *layer.get(&(parent * 2)).unwrap_or(&default);
            let right = *layer.get(&(parent * 2 + 1)).unwrap_or(&default);
            next.insert(parent, credential_node(level, left, right));
        }
        default = credential_node(level, default, default);
        layer = next;
    }
    (*layer.get(&0).unwrap(), paths)
}

/// Rebuild the exact two-leaf native note membership fixture after a test edit.
pub fn rebind_inputs(
    public: &mut AssetSpendPublic,
    witness: &mut AssetSpendWitness,
) -> Result<(), crate::TransactionCircuitError> {
    let defaults = poseidon2_v8_default_note_nodes();
    let leaves = witness
        .inputs
        .each_ref()
        .map(|input| crate::private_spend::note_commitment(input.note))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut root = poseidon2_v8_note_tree_compress(leaves[0], leaves[1]);
    for level in 1..32 {
        root = poseidon2_v8_note_tree_compress(root, defaults[level]);
    }
    public.note_root = root;
    for slot in 0..2 {
        if witness.inputs[slot].occupied == 0 {
            continue;
        }
        witness.inputs[slot].position = slot as u32;
        witness.inputs[slot].siblings[0] = leaves[1 - slot];
        witness.inputs[slot].siblings[1..].copy_from_slice(&defaults[1..32]);
        let nullifier_key = if slot == 0 && witness.policy.spend == 1 {
            witness.policy.input.nullifier_key
        } else {
            witness.inputs[slot].spend_key
        };
        public.nullifiers[slot] =
            real_nullifier(nullifier_key, slot as u32, witness.inputs[slot].note)?;
    }
    Ok(())
}

pub fn fixture(
    operation: u8,
    depth: u8,
) -> Result<(AssetSpendPublic, AssetSpendWitness), crate::TransactionCircuitError> {
    if operation > BURN || !matches!(depth, 4 | 8 | 16) {
        return Err(error("asset fixture operation/depth"));
    }
    let asset = 1001;
    let version = 1;
    let height = 100;
    let key_asset = [1, 2, 3, 4, 5];
    let key_native = [6, 7, 8, 9, 10];
    let auth_asset = authority(key_asset)?;
    let auth_native = authority(key_native)?;
    let auth_recipient = authority([11, 12, 13, 14, 15])?;
    let asset_recipient = [101, 102, 103, 104];
    let pay_recipient = [201, 202, 203, 204];
    let in_asset = note(10, asset, asset_recipient, auth_asset, 21)?;
    let in_native = note(5, 0, [301, 302, 303, 304], auth_native, 31)?;
    let magnitude = match operation {
        MINT => 10,
        BURN => 3,
        _ => 0,
    };
    let output_values = if operation == BURN {
        [4, 3, 3]
    } else {
        [6, 4, 3]
    };
    let outputs = [
        note(output_values[0], asset, pay_recipient, auth_recipient, 41)?,
        note(output_values[1], asset, asset_recipient, auth_asset, 51)?,
        note(output_values[2], 0, [301, 302, 303, 304], auth_native, 61)?,
    ];
    let expiries = [200, 250, 300];
    let leaves = [
        credential_leaf(asset, version, asset_recipient, auth_asset, expiries[0])?,
        credential_leaf(asset, version, pay_recipient, auth_recipient, expiries[1])?,
        credential_leaf(asset, version, asset_recipient, auth_asset, expiries[2])?,
    ];
    let (credential_root, paths) = credential_tree(leaves, depth);
    let issuer = [401, 402, 403, 404, 405, 406, 407];
    let mut witness = AssetSpendWitness {
        inputs: [
            AssetInput {
                occupied: 1,
                legacy_ordinary: 0,
                note: in_asset,
                position: 0,
                siblings: [[0; 7]; 32],
                spend_key: key_asset,
                dummy_secret: [0; 5],
            },
            AssetInput {
                occupied: 1,
                legacy_ordinary: 0,
                note: in_native,
                position: 1,
                siblings: [[0; 7]; 32],
                spend_key: key_native,
                dummy_secret: [0; 5],
            },
        ],
        outputs,
        output_authorities: [auth_recipient, auth_asset, auth_native],
        credentials: core::array::from_fn(|slot| AssetCredentialWitness {
            index: slot as u32,
            expires_at: expiries[slot],
            siblings: paths[slot].clone(),
        }),
        issuer_secret: if operation == MINT { issuer } else { [0; 7] },
        policy: Default::default(),
    };
    let mut public = AssetSpendPublic {
        chain_id: [1; 32],
        reference_parent_hash: [2; 32],
        parent_height: height,
        note_root: [0; 7],
        registry_root: [19; 7],
        asset_id: asset,
        policy_version: version,
        credential_root,
        credential_depth: depth,
        frozen: false,
        mint_enabled: true,
        issuer_commitment: issuer_commitment(asset, version, issuer)?,
        operation,
        magnitude,
        fee: 2,
        nullifiers: [[0; 7]; 2],
        commitments: core::array::from_fn(|slot| {
            crate::private_spend::note_commitment(outputs[slot]).unwrap()
        }),
        ciphertext_commitments: [[7; 48], [8; 48], [9; 48]],
        policy_mode: 0,
        secret_release: 0,
        released_secret: [0; 32],
    };
    if operation == MINT {
        witness.inputs[0] = AssetInput {
            dummy_secret: [21, 22, 23, 24, 25],
            ..Default::default()
        };
        witness.credentials[0] = AssetCredentialWitness {
            siblings: vec![[0; 7]; usize::from(depth)],
            ..Default::default()
        };
        public.nullifiers[0] = dummy_nullifier(public.chain_id, witness.inputs[0].dummy_secret)?;
    }
    rebind_inputs(&mut public, &mut witness)?;
    Ok((public, witness))
}

/// Rebuild all current credentials using the exact owner type of each asset note.
/// Script custody binds the full committed policy owner, shared by every branch.
pub fn rebind_credentials(
    public: &mut AssetSpendPublic,
    witness: &mut AssetSpendWitness,
) -> Result<(), crate::TransactionCircuitError> {
    let input_authority = if witness.policy.spend == 1 {
        crate::private_spend::policy_owner(
            public.chain_id,
            u64::from(public.asset_id),
            &witness.policy.input,
        )?
    } else {
        authority(witness.inputs[0].spend_key)?
    };
    let output_authority = if witness.policy.create == 1 {
        crate::private_spend::policy_owner(
            public.chain_id,
            u64::from(public.asset_id),
            &witness.policy.output,
        )?
    } else {
        witness.output_authorities[0]
    };
    let recipients = [
        witness.inputs[0].note.recipient_key,
        witness.outputs[0].recipient_key,
        witness.outputs[1].recipient_key,
    ];
    let authorities = [
        input_authority,
        output_authority,
        witness.output_authorities[1],
    ];
    let leaves = core::array::from_fn(|slot| {
        credential_leaf(
            public.asset_id,
            public.policy_version,
            recipients[slot],
            authorities[slot],
            witness.credentials[slot].expires_at,
        )
        .unwrap()
    });
    let (root, paths) = credential_tree(leaves, public.credential_depth);
    public.credential_root = root;
    for slot in 0..3 {
        if slot == 0 && public.operation == MINT {
            continue;
        }
        witness.credentials[slot].index = slot as u32;
        witness.credentials[slot].siblings = paths[slot].clone();
    }
    Ok(())
}

/// Disposable combined-graph fixture: holder AND height AND explicit SHA256
/// release, OR a later recovery key. Both branches consume the same policy note.
pub fn combined_fixture(
    operation: u8,
    depth: u8,
    branch: usize,
) -> Result<(AssetSpendPublic, AssetSpendWitness), crate::TransactionCircuitError> {
    use crate::private_spend::{BoundedPolicy, PolicyBranch};
    use sha2::{Digest as _, Sha256};
    if branch > 1 {
        return Err(error("asset fixture branch"));
    }
    let (mut public, mut witness) = fixture(operation, depth)?;
    public.policy_mode = 1;
    let policy = BoundedPolicy {
        nullifier_key: [71, 72, 73, 74, 75],
        branches: [
            PolicyBranch {
                enabled: 1,
                authority: authority([1, 2, 3, 4, 5])?,
                not_before: 100,
                hash_required: 1,
                hashlock: Sha256::digest([42; 32]).into(),
                release_secret: 1,
            },
            PolicyBranch {
                enabled: 1,
                authority: authority([16, 17, 18, 19, 20])?,
                not_before: 120,
                ..Default::default()
            },
        ],
    };
    let policy_owner =
        crate::private_spend::policy_owner(public.chain_id, u64::from(public.asset_id), &policy)?;
    witness.policy.create = 1;
    witness.policy.output = policy.clone();
    witness.output_authorities[0] = [0; 7];
    set_note_owner(&mut witness.outputs[0], policy_owner);
    if operation != MINT {
        witness.policy.spend = 1;
        witness.policy.input = policy;
        witness.policy.selected[branch] = 1;
        witness.inputs[0].spend_key = if branch == 0 {
            [1, 2, 3, 4, 5]
        } else {
            [16, 17, 18, 19, 20]
        };
        set_note_owner(&mut witness.inputs[0].note, policy_owner);
        public.parent_height = if branch == 0 { 100 } else { 120 };
        if branch == 0 {
            witness.policy.secret = [42; 32];
            public.secret_release = 1;
            public.released_secret = [42; 32];
        }
    }
    rebind_credentials(&mut public, &mut witness)?;
    rebind_inputs(&mut public, &mut witness)?;
    for slot in 0..3 {
        public.commitments[slot] = crate::private_spend::note_commitment(witness.outputs[slot])?;
    }
    Ok((public, witness))
}
